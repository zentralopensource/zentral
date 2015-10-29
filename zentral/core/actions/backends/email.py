from email.mime.text import MIMEText
import logging
from smtplib import SMTP_SSL, SMTPException
from zentral.conf import contact_groups
from zentral.core.actions.backends.base import BaseAction

logger = logging.getLogger('zentral.core.actions.backends.email')


class Action(BaseAction):
    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.conn = None

    def _open(self):
        if self.conn:
            return
        conn = SMTP_SSL(self.config_d['smtp_host'],
                        self.config_d['smtp_port'])
        conn.ehlo()
        conn.login(self.config_d['smtp_user'],
                   self.config_d['smtp_password'])
        self.conn = conn

    def _close(self):
        if self.conn is None:
            return
        try:
            self.conn.quit()
        finally:
            self.conn = None

    def trigger(self, event, action_config_d):
        email_from = self.config_d['email_from']
        recipients = []
        for group_name in action_config_d['groups']:
            for contact_d in contact_groups[group_name]:
                contact_email = contact_d.get('email', None)
                if contact_email:
                    recipients.append(contact_email)
        if not recipients:
            return
        msg = MIMEText(event.get_notification_body())
        msg['Subject'] = ' - '.join(event.get_notification_subject().splitlines())
        msg['From'] = email_from
        msg['To'] = ",".join(recipients)
        try:
            self._open()
            self.conn.sendmail(email_from, recipients, msg.as_string())
            self._close()
        except SMTPException:
            logger.exception("SMTP exception")
