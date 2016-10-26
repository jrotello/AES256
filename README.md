# AES256
A PowerShell module for performing basic AES-256 operations. Adapted from https://gist.github.com/ctigeek/2a56648b923d198a6e60.

## Installation

## Usage

```PowerShell
Import-Module AES256

$key = New-AesKey
$iv = New-AesIv

$cipher = Protect-Aes -Key $key -InitializationVector $iv -Plaintext 'Hello, World!'
Unprotect-Aes -Key $key -InitializationVector $iv -CipherText $cipher
```
