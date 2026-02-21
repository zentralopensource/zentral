import functools
import logging
import operator
from datetime import timedelta

import celpy
from django.contrib.auth.models import Permission
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers

from zentral.core.events.base import AuditEvent
from zentral.utils.oidc import verify_jws_with_discovery

from .forms import (
    make_oidc_api_token_issuer_cel_condition_validator,
    make_oidc_api_token_issuer_issuer_uri_validator,
    make_oidc_api_token_issuer_user_validator,
)
from .models import APIToken, Group, OIDCAPITokenIssuer, ProvisionedRole, User

logger = logging.getLogger("server.accounts.serializer")


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.ListField(child=serializers.CharField(min_length=1), required=False)

    class Meta:
        model = Group
        fields = (
            "name",
            "permissions",
        )

    def validate(self, data):
        data_permissions = data.pop("permissions", [])
        data = super().validate(data)
        permission_filters = []
        if data_permissions:
            for data_permission in data_permissions:
                try:
                    app_label, codename = data_permission.split(".", 1)
                except ValueError:
                    pass
                permission_filters.append(Q(content_type__app_label=app_label, codename=codename))
        if permission_filters:
            data["permissions"] = Permission.objects.filter(functools.reduce(operator.or_, permission_filters))
        else:
            data["permissions"] = []
        return data

    def create(self, validated_data):
        provisioning_uid = validated_data.pop("provisioning_uid", None)
        role = super().create(validated_data)
        if provisioning_uid:
            ProvisionedRole.objects.create(group=role, provisioning_uid=provisioning_uid)
        return role


class OIDCAPITokenIssuerSerializer(serializers.ModelSerializer):
    class Meta:
        model = OIDCAPITokenIssuer
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for attr, validator_constructor in (
            ("cel_condition", make_oidc_api_token_issuer_cel_condition_validator),
            ("issuer_uri", make_oidc_api_token_issuer_issuer_uri_validator),
            ("user", make_oidc_api_token_issuer_user_validator),
        ):
            self.fields[attr].validators.append(validator_constructor(serializers.ValidationError))


class OIDCAPITokenIssuerAuthSerializer(serializers.Serializer):
    jwt = serializers.CharField()
    name = serializers.CharField(required=False)
    validity = serializers.IntegerField(required=False, min_value=30, max_value=604800)

    def __init__(self, *args, **kwargs):
        self.issuer = kwargs.pop("issuer")
        super().__init__(*args, **kwargs)

    def validate_jwt(self, value):
        claims = verify_jws_with_discovery(
            token=value,
            issuer_uri=self.issuer.issuer_uri,
            audience=self.issuer.audience,
            exception_class=serializers.ValidationError,
        )

        if not self.issuer.cel_condition:
            return value

        # TODO cache / optimize
        env = celpy.Environment()
        try:
            ast = env.compile(self.issuer.cel_condition)
            prg = env.program(ast)
            ok = prg.evaluate({"claims": celpy.json_to_cel(claims)})
        except Exception:
            msg = "Unexpected error during CEL condition evaluation"
            logger.exception(msg)
            raise serializers.ValidationError(msg)
        else:
            if not isinstance(ok, (bool, celpy.celtypes.BoolType)):
                msg = "CEL condition evaluation didn't produce a boolean"
                logger.error(msg)
                raise serializers.ValidationError(msg)
            if not ok:
                raise serializers.ValidationError("Invalid token claims")
        return value

    def validate_validity(self, value):
        if value and value > self.issuer.max_validity:
            raise serializers.ValidationError(f"Must be ≤ {self.issuer.max_validity}s")
        return value

    def save(self):
        expiry = timezone.now() + timedelta(seconds=self.validated_data.get("validity", self.issuer.max_validity))
        name = self.validated_data.get("name") or ""
        api_token, api_key = APIToken.objects.create_for_user(
            user=self.issuer.user,
            expiry=expiry,
            name=name,
        )

        event = AuditEvent.build_from_request_and_instance(
            self.context["request"], api_token,
            action=AuditEvent.Action.CREATED,
        )

        def post_event():
            event.post()

        transaction.on_commit(post_event)

        return api_token, api_key


class APITokenUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "is_service_account")


class APITokenWithSecretSerializer(serializers.ModelSerializer):
    user = APITokenUserSerializer()
    secret = serializers.SerializerMethodField()

    class Meta:
        model = APIToken
        fields = ("id", "expiry", "name", "secret", "user")

    def __init__(self, *args, **kwargs):
        self.api_key = kwargs.pop("api_key")
        super().__init__(*args, **kwargs)

    def get_secret(self, obj):
        return self.api_key
