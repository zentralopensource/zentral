# make shure the Osquery folder exists
New-Item -Force -Path "C:\Program Files\" -Name "osquery" -ItemType Directory

# tls server cert
$tls_server_certs_file = "%TLS_SERVER_CERTS_FILE%"
$tls_server_certs = @"
%TLS_SERVER_CERTS%
"@
if (%INCLUDE_TLS_SERVER_CERTS%) {
  Set-Content -Force -Path $tls_server_certs_file -Value $tls_server_certs
}

# enrollment secret
$enrollment_secret_file = "C:\Program Files\osquery\enrollment_secret.txt"
$enrollment_secret = "%ENROLL_SECRET_SECRET%"
Set-Content -Force -Path $enrollment_secret_file -Value $enrollment_secret

# flags
$flags_file = "C:\Program Files\osquery\osquery.flags"
$flags = @"
--enroll_secret_path=$enrollment_secret_file
%EXTRA_FLAGS%
"@
Set-Content -Force -Path $flags_file -Value $flags

# restart osqueryd service
if(Get-Service -Name osqueryd -ErrorAction SilentlyContinue) {
  Write-Host "Restart osqueryd" -ForegroundColor green
  Restart-Service -Force -Name osqueryd
} else {
  Write-Host "Service osqueryd not found" -ForegroundColor red
}
