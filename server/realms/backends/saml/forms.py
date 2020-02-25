from django import forms
from saml2 import BINDING_HTTP_POST
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from realms.forms import RealmForm


class SAMLRealmForm(RealmForm):
    CLAIM_FIELD_NAMES = [
        "{}_claim".format(prefix)
        for prefix in ("username", "email", "first_name", "last_name")
    ]

    metadata_file = forms.FileField()
    username_claim = forms.CharField()
    email_claim = forms.CharField()
    first_name_claim = forms.CharField(required=False)
    last_name_claim = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            self.fields["metadata_file"].required = False
            config = self.instance.config
            for field_name in self.CLAIM_FIELD_NAMES:
                value = config.get(field_name)
                if value:
                    self.fields[field_name].initial = value
        else:
            self.fields["metadata_file"].required = True

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
        for field_name in self.CLAIM_FIELD_NAMES:
            value = self.cleaned_data.get(field_name)
            if value:
                config[field_name] = value
        return config
