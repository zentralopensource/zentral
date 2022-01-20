from email.mime.text import MIMEText
import logging
from smtplib import SMTP, SMTPException
from django.conf import settings
from zentral.core.actions.backends.base import BaseAction

logger = logging.getLogger('zentral.core.actions.backends.email')


class Action(BaseAction):
    def __init__(self, config_d):
        super().__init__(config_d)
        self.use_tls = config_d.get('smtp_use_tls', True)
        self.host = config_d['smtp_host']
        self.port = config_d['smtp_port']
        self.user = config_d.get("smtp_user")
        self.password = config_d.get("smtp_password")
        self.email_from = config_d.get('from', settings.DEFAULT_FROM_EMAIL)
        self.recipients = [e for e in config_d.get("recipients", []) if e and isinstance(e, str)]
        self.conn = None

    def _open(self):
        if self.conn:
            return
        conn = SMTP(self.host, self.port)
        conn.ehlo()
        if self.use_tls:
            conn.starttls()
            conn.ehlo()
        if self.user and self.password:
            conn.login(self.user, self.password)
        self.conn = conn

    def _close(self):
        if self.conn is None:
            return
        try:
            self.conn.quit()
        finally:
            self.conn = None

    def trigger(self, event, probe, action_config_d):
        if not self.recipients:
            return
        msg = MIMEText(event.get_notification_body(probe))
        msg['Subject'] = ' - '.join(event.get_notification_subject(probe).splitlines())
        msg['From'] = self.email_from
        msg['To'] = ",".join(self.recipients)
        try:
            self._open()
            self.conn.sendmail(self.email_from, self.recipients, msg.as_string())
            self._close()
        except SMTPException:
            logger.exception("SMTP exception")
