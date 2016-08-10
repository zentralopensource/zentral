#!/bin/sh
#
# osquery setup script for https://github.com/zentralopensource/zentral
# on debian/ubuntu systems
#

set -e

restart_osqueryd () {
  if [ -x /bin/systemctl ]; then
    sudo systemctl restart osqueryd
  else
    sudo /etc/init.d/osqueryd restart
  fi
}

restart_rsyslog () {
  if [ -x /bin/systemctl ]; then
    sudo systemctl restart rsyslog
  else
    sudo service rsyslog restart
  fi
}

# add osquery repository key
sudo apt-key adv --keyserver keyserver.ubuntu.com \
                 --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B

# add osquery repository
DISTRO=$(lsb_release -c|cut -d ':' -f2| tr  -d "\t")
sudo add-apt-repository "deb [arch=amd64] https://osquery-packages.s3.amazonaws.com/$DISTRO $DISTRO main"

# update available package list
sudo apt-get update

# install osquery
sudo apt-get install osquery

# rsyslogd pipe for osquery
sudo cat << RSYSLOGD > /etc/rsyslog.d/60-osquery.conf
template(
  name="OsqueryCsvFormat"
  type="string"
  string="%timestamp:::date-rfc3339,csv%,%hostname:::csv%,%syslogseverity:::csv%,%syslogfacility-text:::csv%,%syslogtag:::csv%,%msg:::csv%\n"
)
*.* action(type="ompipe" Pipe="/var/osquery/syslog_pipe" template="OsqueryCsvFormat")
RSYSLOGD

restart_rsyslog
restart_osqueryd

# create zentral config dir
sudo mkdir -p /etc/zentral/osquery

# server certs
sudo cat << TLS_SERVER_CERT > /etc/zentral/tls_server_certs.crt
%TLS_SERVER_CERTS%
TLS_SERVER_CERT

# enroll secret
MACHINE_ID=$(cat /var/lib/dbus/machine-id)
sudo cat << ENROLL_SECRET > /etc/zentral/osquery/enroll_secret.txt
%ENROLL_SECRET_SECRET%\$SERIAL\$$MACHINE_ID
ENROLL_SECRET

# config info
sudo cat << CONFIG_INFO > /etc/zentral/info.cfg
[server]
base_url: https://%TLS_HOSTNAME%
CONFIG_INFO

# TODO log rotation

# reset db dir
sudo rm -rf /var/osquery/zentral
sudo mkdir -p /var/osquery/zentral

# flags file
sudo cat << OSQUERY_FLAGS > /etc/osquery/osquery.flags
--tls_hostname=%TLS_HOSTNAME%
--tls_server_certs=/etc/zentral/tls_server_certs.crt
--database_path=/var/osquery/zentral
--enroll_tls_endpoint=/osquery/enroll
--enroll_secret_path=/etc/zentral/osquery/enroll_secret.txt
--config_plugin=tls
--config_tls_endpoint=/osquery/config
--config_tls_refresh=120
--logger_plugin=tls
--logger_tls_endpoint=/osquery/log
--logger_tls_period=60
--disable_distributed=false
--distributed_plugin=tls
--distributed_tls_read_endpoint=/osquery/distributed/read
--distributed_tls_write_endpoint=/osquery/distributed/write
--distributed_interval=60
--disable_audit=false
--audit_allow_config=true
--audit_persist=true
OSQUERY_FLAGS

restart_osqueryd
