# UTF8 encoding without BOM
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False

# tls server cert
$tls_server_certs_file = '%TLS_SERVER_CERTS_FILE%'
$tls_server_certs = @"
%TLS_SERVER_CERTS%
"@
if (%INCLUDE_TLS_SERVER_CERTS%) {
  [System.IO.File]::WriteAllLines($tls_server_certs_file, $tls_server_certs, $Utf8NoBomEncoding)
}

# enrollment secret
$enrollment_secret_file = 'C:\Program Files\osquery\enrollment_secret.txt'
$enrollment_secret = "%ENROLL_SECRET_SECRET%"
[System.IO.File]::WriteAllLines($enrollment_secret_file, $enrollment_secret, $Utf8NoBomEncoding)

# flags
$flags_file = 'C:\Program Files\osquery\osquery.flags'
$flags = @"
--tls_hostname=%TLS_HOSTNAME%
--enroll_tls_endpoint=/osquery/enroll
--enroll_secret_path=$enrollment_secret_file
--config_plugin=tls
--config_tls_endpoint=/osquery/config
--logger_plugin=tls
--logger_tls_endpoint=/osquery/log
--logger_tls_period=60
--logger_tls_compress=true
--disable_distributed=false
--distributed_plugin=tls
--distributed_tls_read_endpoint=/osquery/distributed/read
--distributed_tls_write_endpoint=/osquery/distributed/write
%EXTRA_FLAGS%
"@
[System.IO.File]::WriteAllLines($flags_file, $flags, $Utf8NoBomEncoding)

# restart osqueryd service
Stop-Service osqueryd
Start-Sleep -s 2
Start-Service osqueryd
