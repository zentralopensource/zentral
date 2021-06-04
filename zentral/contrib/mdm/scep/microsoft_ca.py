import logging
import re
from django import forms
import requests
from zentral.contrib.mdm.models import SCEPChallengeType
from .base import SCEPChallengeError, SCEPChallenge


logger = logging.getLogger("zentral.contrib.mdm.scep.microsoft_ca")


class MicrosoftCAChallengeForm(forms.Form):
    url = forms.URLField(help_text="Full URL of the NDES mscep_admin/ endpoint")
    username = forms.CharField(help_text="mscep admin user (to get one time challenges)")
    password = forms.CharField(help_text="mscep admin password", widget=forms.PasswordInput(render_value=True))


class MicrosoftCAChallenge(SCEPChallenge):
    type = SCEPChallengeType.MICROSOFT_CA
    kwargs_keys = ("url", "username", "password")
    form_class = MicrosoftCAChallengeForm

    def get(self, key_usage, subject, subject_alt_name):
        try:
            r = requests.get(self.url, auth=(self.username, self.password))
            r.raise_for_status()
        except Exception as e:
            raise SCEPChallengeError(f"certsrv request error: {e}")
        else:
            try:
                page_content = r.content.decode("utf-16")
            except UnicodeDecodeError:
                raise SCEPChallengeError("Could not decode certsrv response")
            for match in re.finditer(r"challenge password is: <B> ([A-Z0-9]{16,32}) </B>", page_content):
                return match.group(1)
        raise SCEPChallengeError("Could not find challenge in certsrv response.")
