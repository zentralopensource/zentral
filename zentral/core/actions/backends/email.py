from email.mime.text import MIMEText
import logging
from smtplib import SMTP, SMTP_SSL, SMTPException
from zentral.conf import contact_groups
from zentral.core.actions.backends.base import BaseAction, ContactGroupForm

logger = logging.getLogger('zentral.core.actions.backends.email')


class Action(BaseAction):
    action_form_class = ContactGroupForm

    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.conn = None

    def _open(self):
        if self.conn:
            return
        use_ssl = self.config_d.get('smtp_use_ssl', True)
        if use_ssl:
            opener = SMTP_SSL
        else:
            opener = SMTP
        conn = opener(self.config_d['smtp_host'],
                      self.config_d['smtp_port'])
        conn.ehlo()
        user = self.config_d.get("smtp_user")
        password = self.config_d.get("smtp_password")
        if user and password:
            conn.login(user, password)
        self.conn = conn

    def _close(self):
        if self.conn is None:
            return
        try:
            self.conn.quit()
        finally:
            self.conn = None

    def trigger(self, event, probe, action_config_d):
        email_from = self.config_d['email_from']
        recipients = []
        for group_name in action_config_d['groups']:
            for contact_d in contact_groups[group_name]:
                contact_email = contact_d.get('email', None)
                if contact_email:
                    recipients.append(contact_email)
        if not recipients:
            return
        msg = MIMEText(event.get_notification_body(probe))
        msg['Subject'] = ' - '.join(event.get_notification_subject(probe).splitlines())
        msg['From'] = email_from
        msg['To'] = ",".join(recipients)
        try:
            self._open()
            self.conn.sendmail(email_from, recipients, msg.as_string())
            self._close()
        except SMTPException:
            logger.exception("SMTP exception")
