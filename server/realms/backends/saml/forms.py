import uuid
from django import forms
from saml2 import BINDING_HTTP_POST
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from realms.forms import RealmForm


class SAMLRealmForm(RealmForm):
    login_session_expiry = forms.IntegerField(
        required=False, min_value=0, max_value=1296000,
        help_text="Session expiry in seconds. If value is 0, the user’s session"
                  " cookie will expire when the user’s Web browser is closed. "
                  "Leave blank, and the session reverts to using the "
                  "NotOnOrAfter value provided by the IDP in the SAML response."
    )
    metadata_file = forms.FileField()
    allow_idp_initiated_login = forms.BooleanField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["metadata_file"].required = self.instance is None
        if self.instance:
            self.fields["allow_idp_initiated_login"].initial = self.instance.config.get("allow_idp_initiated_login")

    def clean(self):
        super().clean()
        cleaned_data = self.cleaned_data
        metadata_file = cleaned_data.get("metadata_file")
        if not metadata_file:
            return
        try:
            idp_metadata = metadata_file.read().decode("utf-8")
        except Exception:
            self.add_error("metadata_file", forms.ValidationError("Could not read SAML metadata file"))
            return
        # try to load the settings with fake entityid and acs url
        settings = {
            "metadata": {
                "inline": [idp_metadata],
            },
            "entityid": "https://example.com/metadata",
            "service": {
                "sp": {
                    "name_id_format": NAMEID_FORMAT_EMAILADDRESS,
                    "endpoints": {
                        "assertion_consumer_service": [
                            ("https://example.com/acs", BINDING_HTTP_POST),
                        ],
                    },
                    "allow_unsolicited": True,
                    "authn_requests_signed": False,
                    "logout_requests_signed": True,
                    "want_assertions_signed": True,
                    "want_response_signed": False,
                },
            },
        }
        sp_config = Saml2Config()
        sp_config.allow_unknown_attributes = True
        try:
            sp_config.load(settings)
        except Exception:
            self.add_error("metadata_file", forms.ValidationError("Invalid SAML metadata file"))
        else:
            cleaned_data["idp_metadata"] = idp_metadata
        return cleaned_data

    def get_config(self):
        config = {}
        idp_metadata = self.cleaned_data.get("idp_metadata")
        if not idp_metadata and self.instance:
            idp_metadata = self.instance.config.get("idp_metadata")
        if idp_metadata:
            config["idp_metadata"] = idp_metadata
        if self.cleaned_data.get("allow_idp_initiated_login"):
            config["allow_idp_initiated_login"] = True
        else:
            config["allow_idp_initiated_login"] = False
        default_relay_state = None
        if self.instance:
            default_relay_state = self.instance.config.get("default_relay_state")
        if not default_relay_state:
            default_relay_state = str(uuid.uuid4())
        config["default_relay_state"] = default_relay_state
        return config
