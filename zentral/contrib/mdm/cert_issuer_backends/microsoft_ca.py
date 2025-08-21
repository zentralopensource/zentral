import logging
from .base_microsoft_ca import BaseMicrosoftCA, BaseMicrosoftCASerializer


logger = logging.getLogger("zentral.contrib.mdm.cert_issuers.microsoft_ca")


# Microsoft CA


class MicrosoftCASerializer(BaseMicrosoftCASerializer):
    pass


class MicrosoftCA(BaseMicrosoftCA):
    encoding = "utf-16"
    regexp = r"challenge password is: <B> ([A-Z0-9]{16,32}) </B>"
