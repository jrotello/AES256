function psUsing() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ne $null })]
        [System.IDisposable] $InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ne $null })]
        [scriptblock] $ScriptBlock
    )

    try {
        & $ScriptBlock
    } finally {
        $InputObject.Dispose()
    }
}

function New-AesManagedObject {
    [CmdletBinding()]
    [OutputType("System.Security.Cryptography.AesManaged")]
    param(
        [Parameter()]
        [object]$Key,
        [Parameter()]
        [object]$InitializationVector
    )

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    if ($InitializationVector) {
        if ($InitializationVector.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($InitializationVector)
        }
        else {
            $aesManaged.IV = $InitializationVector
        }
    }

    if ($Key) {
        if ($Key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($Key)
        }
        else {
            $aesManaged.Key = $Key
        }
    }

    Write-Output $aesManaged
}

function New-AesKey {
    [CmdletBinding()]

    $aesManaged = New-AesManagedObject
    $aesManaged.KeySize = 256
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function New-AesIV() {
    [CmdletBinding()]

    $aesManaged = New-AesManagedObject
    $aesManaged.GenerateIV()
    [System.Convert]::ToBase64String($aesManaged.IV)
}

function Protect-Aes {
    [CmdletBinding()]
    param(
        $Key,
        $InitializationVector,
        [string]$Plaintext
    )

    psUsing ($aesManaged = New-AesManagedObject -Key $Key -InitializationVector $InitializationVector) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)

        psUsing ($encryptor = $aesManaged.CreateEncryptor()) {
            psUsing ($ms = New-Object "System.IO.MemoryStream") {
                $mode = [System.Security.Cryptography.CryptoStreamMode]::Write

                psUsing ($cryptoStream = New-Object "System.Security.Cryptography.CryptoStream" -ArgumentList $ms, $encryptor, $mode) {
                    psUsing ($writer = New-Object "System.IO.StreamWriter" -ArgumentList $cryptoStream) {
                        $writer.Write($Plaintext)
                    }

                    [System.Convert]::ToBase64String($ms.ToArray())
                }
            }
        }
    }
}

function Unprotect-Aes {
    [CmdletBinding()]
    param(
        $Key,
        $InitializationVector,
        $CipherText
    )

    psUsing ($aesManaged = New-AesManagedObject -Key $Key -InitializationVector $InitializationVector) {
        $mode = [System.Security.Cryptography.CryptoStreamMode]::Read
        $bytes = [System.Convert]::FromBase64String($CipherText)

        psusing ($ms = New-Object "System.IO.MemoryStream" -ArgumentList (,$bytes)) {
            psUsing ($decryptor = $aesManaged.CreateDecryptor()) {
                psUsing ($cryptoStream = New-Object "System.Security.Cryptography.CryptoStream" -ArgumentList $ms, $decryptor, $mode) {
                    psUsing ($reader = New-Object "System.IO.StreamReader" -ArgumentList $cryptoStream) {
                        Write-Output $reader.ReadToEnd()
                    }
                }
            }
        }
    }
}

$moduleFunctions = @(
    "New-AesKey",
    "New-AesIV",
    "Protect-Aes",
    "Unprotect-Aes"
)
Export-ModuleMember -Function $moduleFunctions