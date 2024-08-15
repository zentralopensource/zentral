from rest_framework import serializers
from .models import Realm
from .backends.ldap.serializers import LDAPConfigSerializer
from .backends.openidc.serializers import OpenIDCConfigSerializer
from .backends.saml.serializers import SAMLConfigSerializer


class RealmSerializer(serializers.ModelSerializer):
    ldap_config = LDAPConfigSerializer(
        source="get_ldap_config",
        required=False,
    )
    openidc_config = OpenIDCConfigSerializer(
        source="get_openidc_config",
        required=False,
    )
    saml_config = SAMLConfigSerializer(
        source="get_saml_config",
        required=False,
    )

    class Meta:
        model = Realm
        exclude = ("config",)
