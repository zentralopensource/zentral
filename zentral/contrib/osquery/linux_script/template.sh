#!/bin/bash
#
# osquery setup script for https://github.com/zentralopensource/zentral
# on rpm or deb based linux distributions
#

set -e

get_do_instance_id () {
  curl -s --connect-timeout 2 http://169.254.169.254/metadata/v1/id
}

get_docker_instance_id () {
  cat /proc/self/cgroup | grep "docker" | sed s/\\//\\n/g | tail -1 | cut -c-12
}

get_ec2_instance_id () {
  curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id
}

get_gce_instance_id () {
  curl -s --connect-timeout 2 -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/id
}

get_watchman_id () {
  python -c 'import json;print json.load(open("/etc/monitoringclient/client_settings.conf", "r"))["WatchmanID"]'
}

get_host_identifier () {
  HOST_IDENTIFIER=""
  if get_watchman_id; then
    HOST_IDENTIFIER=$(get_watchman_id)
  elif get_do_instance_id; then
    HOST_IDENTIFIER="DO-$(get_do_instance_id)"
  elif get_docker_instance_id; then
    HOST_IDENTIFIER="DKR-$(get_docker_instance_id)"
  elif get_ec2_instance_id; then
    HOST_IDENTIFIER="EC2-$(get_ec2_instance_id)"
  elif get_gce_instance_id; then
    HOST_IDENTIFIER="GCE-$(get_gce_instance_id)"
  elif [ -x /usr/sbin/dmidecode ]; then
    HOST_IDENTIFIER=$(sudo dmidecode -s system-uuid)
  fi
  if [ -z "$HOST_IDENTIFIER" ]; then
    if [ -e /var/lib/dbus/machine-id ]; then
        HOST_IDENTIFIER=$(cat /var/lib/dbus/machine-id)
    else
        echo "ERROR: Could not find a HOST_IDENTIFIER"
        exit 10
    fi
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
  elif [ -x /sbin/service ] || [ -x /usr/sbin/service ]; then
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

  # install osquery and other dependencies
  sudo apt-get install -y osquery dmidecode
}

install_osquery_rpm () {
  # add osquery repository key
  curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery

  # install yum-config-manager
  sudo yum install -y yum-utils

  # add and enable osquery repository
  sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
  sudo yum-config-manager --enable osquery-s3-rpm

  # install osquery and other dependencies
  sudo yum install -y osquery dmidecode
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
if [ -x /sbin/rsyslogd ] || [ -x /usr/sbin/rsyslogd ]; then
  configure_rsyslogd
else
  echo "WARNING: Could not configure rsyslogd."
fi

# create zentral config dir
sudo mkdir -p /etc/zentral/osquery

# server certs
if %INCLUDE_TLS_SERVER_CERTS%; then
cat << TLS_SERVER_CERT | sudo tee /etc/zentral/tls_server_certs.crt
%TLS_SERVER_CERTS%
TLS_SERVER_CERT
fi

# enroll secret
cat << ENROLL_SECRET | sudo tee /etc/zentral/osquery/enroll_secret.txt
%ENROLL_SECRET_SECRET%
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
get_host_identifier
cat << OSQUERY_FLAGS | sudo tee /etc/osquery/osquery.flags
--tls_hostname=%TLS_HOSTNAME%
--database_path=/var/osquery/zentral
--enroll_tls_endpoint=/osquery/enroll
--enroll_secret_path=/etc/zentral/osquery/enroll_secret.txt
--config_plugin=tls
--config_tls_endpoint=/osquery/config
--config_tls_refresh=120
--logger_plugin=tls
--logger_tls_endpoint=/osquery/log
--logger_tls_period=60
--logger_tls_compress=true
--disable_distributed=false
--distributed_plugin=tls
--distributed_tls_read_endpoint=/osquery/distributed/read
--distributed_tls_write_endpoint=/osquery/distributed/write
--distributed_interval=60
--disable_audit=false
--audit_allow_config=true
--audit_persist=true
--host_identifier=specified
--specified_identifier="$HOST_IDENTIFIER"
%EXTRA_FLAGS%
OSQUERY_FLAGS

restart_osqueryd
