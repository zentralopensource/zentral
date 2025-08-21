import logging
from .base_microsoft_ca import BaseMicrosoftCA, BaseMicrosoftCASerializer


logger = logging.getLogger("zentral.contrib.mdm.cert_issuers.okta_ca")


# Okta CA


class OktaCASerializer(BaseMicrosoftCASerializer):
    pass


class OktaCA(BaseMicrosoftCA):
    encoding = "windows-1252"
    regexp = r"challenge password is: <B> ([a-zA-Z0-9_\-]+) </B>"
