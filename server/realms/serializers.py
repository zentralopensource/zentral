from rest_framework import serializers
from .models import Realm
from .backends.ldap.serializers import LDAPConfigSerializer
from .backends.openidc.serializers import OpenIDCConfigSerializer
from .backends.saml.serializers import SAMLConfigSerializer


class RealmSerializer(serializers.ModelSerializer):
    ldap_config = LDAPConfigSerializer(
        source="get_ldap_kwargs",
        required=False,
    )
    openidc_config = OpenIDCConfigSerializer(
        source="get_openidc_kwargs",
        required=False,
    )
    saml_config = SAMLConfigSerializer(
        source="get_saml_kwargs",
        required=False,
    )

    class Meta:
        model = Realm
        exclude = ("backend_kwargs",)
