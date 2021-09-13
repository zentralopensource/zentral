#!/bin/bash
#
# osquery setup script for https://github.com/zentralopensource/zentral
# on rpm or deb based linux distributions
#

set -e
set -o pipefail

get_do_instance_id () {
  curl -s --fail --connect-timeout 2 http://169.254.169.254/metadata/v1/id
}

get_docker_instance_id () {
  grep "docker" /proc/self/cgroup | sed s/\\//\\n/g | tail -1 | cut -c-12
}

get_ec2_instance_id () {
  IMDSv2_TOKEN=$(curl -s --fail --connect-timeout 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 30")
  curl -s --fail --connect-timeout 2 -H "X-aws-ec2-metadata-token: $IMDSv2_TOKEN" http://169.254.169.254/latest/meta-data/instance-id
}

get_gce_instance_id () {
  curl -s --fail --connect-timeout 2 -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/id
}

get_watchman_id () {
  python3 -c 'import json,os,sys;p="/etc/monitoringclient/client_settings.conf";print(json.load(open(p,"r"))["WatchmanID"]) if os.path.exists(p) else sys.exit(1)'
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
  if [ -z "$HOST_IDENTIFIER" ] || [ "$HOST_IDENTIFIER" == "Not Settable" ]; then
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
  case "$(arch)" in
    aarch64) DEB_ARCH="arm64" ;;
    x86_64) DEB_ARCH="amd64" ;;
    *) echo "Unkown architecture: $(arch)" ; exit 1 ;;
  esac
  sudo add-apt-repository "deb [arch=$DEB_ARCH] https://pkg.osquery.io/deb deb main"

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
%EXTRA_FLAGS%
--database_path=/var/osquery/zentral
--enroll_secret_path=/etc/zentral/osquery/enroll_secret.txt
--disable_audit=false
--audit_allow_config=true
--audit_persist=true
--host_identifier=specified
--specified_identifier="$HOST_IDENTIFIER"
OSQUERY_FLAGS

restart_osqueryd
