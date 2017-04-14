#!/bin/bash
/usr/sbin/praudit /dev/auditpipe | /usr/local/zentral/bin/filebeat -path.config /usr/local/zentral/audit/
