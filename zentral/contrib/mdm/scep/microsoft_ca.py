import logging
import re
from django import forms
import requests
from . import SCEPChallengeType
from .base import SCEPChallengeError, SCEPChallenge


logger = logging.getLogger("zentral.contrib.mdm.scep.microsoft_ca")


class BaseMicrosoftCAChallenge(SCEPChallenge):
    kwargs_keys = ("url", "username", "password")
    encrypted_kwargs_keys = ("password",)
    encoding = None  # To be set in subclasses
    regexp = None  # To be set in subclasses

    def get(self, key_usage, subject, subject_alt_name):
        try:
            r = requests.get(self.url, auth=(self.username, self.password))
            r.raise_for_status()
        except Exception as e:
            raise SCEPChallengeError(f"Request error: {e}")
        else:
            try:
                page_content = r.content.decode(self.encoding)
            except UnicodeDecodeError:
                raise SCEPChallengeError("Could not decode response.")
            for match in re.finditer(self.regexp, page_content):
                return match.group(1)
        raise SCEPChallengeError("Could not find challenge in response.")


class MicrosoftCAChallengeForm(forms.Form):
    url = forms.URLField(label="URL", help_text="Full URL of the NDES mscep_admin/ endpoint")
    username = forms.CharField(help_text="mscep admin user (to get one time challenges)")
    password = forms.CharField(help_text="mscep admin password", widget=forms.PasswordInput(render_value=True))


class MicrosoftCAChallenge(BaseMicrosoftCAChallenge):
    type = SCEPChallengeType.MICROSOFT_CA
    form_class = MicrosoftCAChallengeForm
    encoding = "utf-16"
    regexp = r"challenge password is: <B> ([A-Z0-9]{16,32}) </B>"


class OktaCAChallengeForm(forms.Form):
    url = forms.URLField(label="Challenge URL")
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput(render_value=True))


class OktaCAChallenge(BaseMicrosoftCAChallenge):
    type = SCEPChallengeType.OKTA_CA
    form_class = OktaCAChallengeForm
    encoding = "windows-1252"
    regexp = r"challenge password is: <B> ([a-zA-Z0-9_\-]+) </B>"
