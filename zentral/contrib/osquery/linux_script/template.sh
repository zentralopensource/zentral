#!/bin/bash
#
# osquery setup script for https://github.com/zentralopensource/zentral
# on rpm or deb based linux distributions
#

set -e

get_machine_id () {
  if [ -e /etc/monitoringclient/client_settings.conf ]; then
    MACHINE_ID=$(python -c 'import json;print json.load(open("/etc/monitoringclient/client_settings.conf", "r"))["WatchmanID"]')
  fi
  if [ -x /usr/sbin/dmidecode ]; then
    MACHINE_ID=$(sudo dmidecode -s system-uuid)
  fi
  if [ ! "$MACHINE_ID" ]; then
    MACHINE_ID=$(cat /var/lib/dbus/machine-id)
  fi
}

restart_osqueryd () {
  if [ -x /bin/systemctl ]; then
    sudo systemctl restart osqueryd
  elif [ -x /etc/init.d/osqueryd ]; then
    sudo /etc/init.d/osqueryd restart
  else
    echo "WARNING: Could not restart osqueryd."
  fi
}

restart_rsyslog () {
  if [ -x /bin/systemctl ]; then
    sudo systemctl restart rsyslog
  elif [ -x /bin/service ]; then
    sudo service rsyslog restart
  else
    echo "WARNING: Could not restart rsyslog"
  fi
}

configure_rsyslogd () {
cat << RSYSLOGD | sudo tee /etc/rsyslog.d/60-osquery.conf
template(
  name="OsqueryCsvFormat"
  type="string"
  string="%timestamp:::date-rfc3339,csv%,%hostname:::csv%,%syslogseverity:::csv%,%syslogfacility-text:::csv%,%syslogtag:::csv%,%msg:::csv%\n"
)
*.* action(type="ompipe" Pipe="/var/osquery/syslog_pipe" template="OsqueryCsvFormat")
RSYSLOGD

restart_rsyslog
}

install_osquery_deb () {
  # add apt deps
  sudo apt-get install -y apt-transport-https dirmngr software-properties-common

  # add osquery repository key
  OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
  sudo apt-key adv --keyserver keyserver.ubuntu.com \
                   --recv-keys $OSQUERY_KEY

  # remove old osquery repository if necessary
  sudo /bin/sed -i '/^deb.*osquery.*$/d' /etc/apt/sources.list

  # add osquery repository
  sudo add-apt-repository "deb [arch=amd64] https://pkg.osquery.io/deb deb main"

  # update available package list
  sudo apt-get update

  # install osquery
  sudo apt-get install -y osquery
}

install_osquery_rpm () {
  # add osquery repository key
  curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery

  # install yum-config-manager
  sudo yum install -y yum-utils

  # add and enable osquery repository
  sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
  sudo yum-config-manager --enable osquery-s3-rpm

  # install osquery
  sudo yum install -y osquery
}

if %INSTALL_OSQUERY%; then
  if [ -x /usr/bin/apt-get ]; then
    install_osquery_deb
  elif [ -x /usr/bin/yum ]; then
    install_osquery_rpm
  else
    echo "ERROR: Could not install osquery. Could not find apt or yum."
    exit 100
  fi
  restart_osqueryd
else
  echo "INFO: Skip osquery install. Only config."
fi

# rsyslogd pipe for osquery
if [ -x /usr/sbin/rsyslogd ]; then
  configure_rsyslogd
else
  echo "WARNING: Could not configure rsyslogd."
fi

# create zentral config dir
sudo mkdir -p /etc/zentral/osquery

# server certs
cat << TLS_SERVER_CERT | sudo tee /etc/zentral/tls_server_certs.crt
%TLS_SERVER_CERTS%
TLS_SERVER_CERT

# enroll secret
get_machine_id
cat << ENROLL_SECRET | sudo tee /etc/zentral/osquery/enroll_secret.txt
%ENROLL_SECRET_SECRET%\$SERIAL\$$MACHINE_ID
ENROLL_SECRET

# config info
cat << CONFIG_INFO | sudo tee /etc/zentral/info.cfg
[server]
base_url: https://%TLS_HOSTNAME%
CONFIG_INFO

# TODO log rotation

# reset db dir
sudo rm -rf /var/osquery/zentral
sudo mkdir -p /var/osquery/zentral

# flags file
cat << OSQUERY_FLAGS | sudo tee /etc/osquery/osquery.flags
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
%DISABLE_CARVER%
OSQUERY_FLAGS

restart_osqueryd
