# Pure PowerShell script to create CSP-compatible certificate
# Run this in PowerShell as Administrator

# Remove any existing certificates first
Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*clear-mutual-sailfish*" } | Remove-Item -Force

# Create certificate with explicit CSP provider
$cert = New-SelfSignedCertificate `
    -DnsName "clear-mutual-sailfish.ngrok-free.app", "*.clear-mutual-sailfish.ngrok-free.app" `
    -CertStoreLocation "cert:\LocalMachine\My" `
    -KeyUsage DigitalSignature,KeyEncipherment `
    -Type SSLServerAuthentication `
    -Provider "Microsoft RSA SChannel Cryptographic Provider" `
    -KeyLength 2048 `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(1)

# Verify the certificate was created with CSP
$privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($privateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
    Write-Host "✓ Certificate created with CSP provider (Compatible)" -ForegroundColor Green
    Write-Host "Key Container: $($privateKey.CspKeyContainerInfo.KeyContainerName)"
} else {
    Write-Host "✗ Certificate created with CNG provider (Not Compatible)" -ForegroundColor Red
    Write-Host "This may still cause issues with Media Platform"
}

# Export to PFX for backup
$pfxPath = "C:\temp\ngrok-csp-cert.pfx"
$pfxPassword = ConvertTo-SecureString -String "YourPassword123!" -Force -AsPlainText
New-Item -ItemType Directory -Force -Path "C:\temp"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword

# Add to Trusted Root for self-signed certificates
$rootStore = Get-Item "cert:\LocalMachine\Root"
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()

# Set permissions on the private key
$keyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($privateKey.CspKeyContainerInfo.KeyContainerName)"
if (Test-Path $keyPath) {
    icacls $keyPath /grant "IIS_IUSRS:(F)" /inheritance:r
    icacls $keyPath /grant "NETWORK SERVICE:(F)"
    icacls $keyPath /grant "LOCAL SERVICE:(F)"
    icacls $keyPath /grant "Everyone:(F)"
    Write-Host "✓ Permissions granted to private key" -ForegroundColor Green
} else {
    Write-Host "⚠ Could not find private key file to set permissions" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Certificate Details:"
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "Subject: $($cert.Subject)"
Write-Host "Valid From: $($cert.NotBefore)"
Write-Host "Valid To: $($cert.NotAfter)"
Write-Host ""
Write-Host "Add this to your environment:"
Write-Host "AppSettings__CertificateThumbprint=$($cert.Thumbprint)" -ForegroundColor Cyan