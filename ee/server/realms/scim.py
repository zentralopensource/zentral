import logging
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.exceptions import APIException
from accounts.models import User
from .models import realm_group_members_updated, RealmEmail, RealmGroup, RealmUser, RealmUserGroupMembership


logger = logging.getLogger("zentral.realms.scim")


class SCIMException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, detail, scim_type):
        self.scim_type = scim_type
        super().__init__(detail)


class SCIMUniquenessException(SCIMException):
    status_code = status.HTTP_409_CONFLICT

    def __init__(self, detail):
        super().__init__(detail, "uniqueness")


class SCIMGroupMember(serializers.Serializer):
    value = serializers.CharField(max_length=255)


class SCIMGroup(serializers.Serializer):
    schemas = serializers.ListSerializer(child=serializers.CharField())
    externalId = serializers.CharField(max_length=255, allow_null=True, required=False)
    displayName = serializers.CharField(max_length=255)
    members = serializers.ListSerializer(
        child=SCIMGroupMember(),
        allow_empty=True,
        required=False,
    )

    def __init__(self, *args, **kwargs):
        self.resource = kwargs.pop("resource", None)
        self.realm = kwargs.pop("realm")
        self.request = kwargs.pop("request")
        super().__init__(*args, **kwargs)

    def validate_schemas(self, value):
        if isinstance(value, list):
            unsupported_schemas = (
                set(value)
                - {"urn:ietf:params:scim:schemas:core:2.0:Group"}
            )
            if unsupported_schemas:
                logger.error("Unsupported SCIM group schemas: %s", unsupported_schemas)
                raise serializers.ValidationError("Unsupported schemas")
        return value

    def validate_externalId(self, value):
        if value:
            qs = RealmGroup.objects.filter(realm=self.realm, scim_external_id=value)
            if self.resource:
                qs = qs.exclude(pk=self.resource.pk)
            if qs.exists():
                raise SCIMUniquenessException(
                    detail="A group with this externalId already exists.",
                )
        return value

    def validate_displayName(self, value):
        if value:
            qs = RealmGroup.objects.filter(realm=self.realm, display_name=value)
            if self.resource:
                qs = qs.exclude(pk=self.resource.pk)
            if qs.exists():
                raise SCIMUniquenessException(
                    detail="A group with this displayName already exists."
                )
        return value

    def update_members(self):
        members_updated = False
        if "members" in self.validated_data:
            pk_list = [member["value"] for member in self.validated_data.get("members", [])]
            realm = self.resource.realm
            # add new groups
            groups_added = (
                RealmGroup.objects.exclude(parent=self.resource)
                                  .filter(realm=realm, pk__in=pk_list)
                                  .update(parent=self.resource)
            )
            members_updated |= groups_added > 0
            # remove old groups
            groups_removed = (
                RealmGroup.objects.filter(parent=self.resource)
                                  .exclude(pk__in=pk_list)
                                  .update(parent=None)
            )
            members_updated |= groups_removed > 0
            # add new users
            users_added = len(
                RealmUserGroupMembership.objects.bulk_create((
                    RealmUserGroupMembership(user=user, group=self.resource)
                    for user in RealmUser.objects.filter(realm=realm, pk__in=pk_list).exclude(groups=self.resource)
                ))
            )
            members_updated |= users_added > 0
            # remove old users
            users_removed, _ = (
                RealmUserGroupMembership.objects.filter(group=self.resource).exclude(user__pk__in=pk_list).delete()
            )
            members_updated |= users_removed > 0
        if members_updated:
            realm_group_members_updated.send_robust(self.__class__, realm=self.realm, request=self.request)

    def save(self):
        self.resource = RealmGroup.objects.create(
            realm=self.realm,
            scim_managed=True,
            scim_external_id=self.validated_data.get("externalId"),
            display_name=self.validated_data["displayName"],
        )
        self.update_members()
        return self.resource

    def update(self):
        self.resource.scim_managed = True
        external_id = self.validated_data.get("externalId")
        if external_id:
            self.resource.scim_external_id = external_id
        self.resource.display_name = self.validated_data["displayName"]
        self.resource.save()
        self.update_members()
        return self.resource


class SCIMUserName(serializers.Serializer):
    formatted = serializers.CharField(required=False)
    familyName = serializers.CharField(required=False)
    givenName = serializers.CharField(required=False)
    middleName = serializers.CharField(required=False)
    honorificPrefix = serializers.CharField(required=False)
    honorificSuffix = serializers.CharField(required=False)


class SCIMEmail(serializers.Serializer):
    primary = serializers.BooleanField(required=False, default=False)
    type = serializers.CharField(max_length=255)
    value = serializers.CharField(max_length=254)


class SCIMEntepriseUserManager(serializers.Serializer):
    value = serializers.CharField(required=False)
    ref = serializers.CharField(required=False)
    displayName = serializers.CharField(required=False)

    def to_internal_value(self, data):
        ref = data.pop("$ref", None)
        if ref:
            data["ref"] = ref
        return super().to_internal_value(data)


class SCIMEnterpriseUser(serializers.Serializer):
    employeeNumber = serializers.CharField(required=False)
    costCenter = serializers.CharField(required=False)
    organization = serializers.CharField(required=False)
    division = serializers.CharField(required=False)
    department = serializers.CharField(required=False)
    manager = SCIMEntepriseUserManager(required=False)


class SCIMUser(serializers.Serializer):
    schemas = serializers.ListSerializer(child=serializers.CharField())
    externalId = serializers.CharField(max_length=255, allow_null=True, required=False)
    userName = serializers.CharField()
    displayName = serializers.CharField(max_length=255, required=False)
    active = serializers.BooleanField()
    name = SCIMUserName()
    emails = serializers.ListSerializer(
        child=SCIMEmail(),
        allow_empty=True,
    )
    enterprise_user = SCIMEnterpriseUser(required=False)

    def __init__(self, *args, **kwargs):
        self.resource = kwargs.pop("resource", None)
        self.realm = kwargs.pop("realm")
        self.request = kwargs.pop("request")
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        enterprise_user = data.pop("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", None)
        if enterprise_user:
            data["enterprise_user"] = enterprise_user
        return super().to_internal_value(data)

    def validate_schemas(self, value):
        if isinstance(value, list):
            unsupported_schemas = (
                set(value)
                - {"urn:ietf:params:scim:schemas:core:2.0:User",
                   "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"}
            )
            if unsupported_schemas:
                logger.error("Unsupported SCIM user schemas: %s", unsupported_schemas)
                raise serializers.ValidationError("Unsupported schemas")
        return value

    def validate_externalId(self, value):
        if value:
            qs = RealmUser.objects.filter(realm=self.realm, scim_external_id=value)
            if self.resource:
                qs = qs.exclude(pk=self.resource.pk)
            if qs.exists():
                raise SCIMUniquenessException(
                    detail="A user with this externalId already exists.",
                )
        return value

    def validate_userName(self, value):
        if value:
            qs = RealmUser.objects.filter(realm=self.realm, username=value)
            if self.resource:
                qs = qs.exclude(pk=self.resource.pk)
            if qs.exists():
                raise SCIMUniquenessException(
                    detail="A user with this userName already exists."
                )
        return value

    def update_user(self, user, realm_user_values=None):
        if user.is_superuser:
            # the IdP would control the account: a superuser stays as it is until a superuser removes the flag
            logger.warning("Superuser %s not updated with realm user %s", user.pk, self.resource.pk)
            return
        attrs = [("first_name", "first_name"),
                 ("last_name", "last_name")]
        if user.is_remote:
            attrs.append(("is_active", "scim_active"))
            # the username and the email of a local user are credentials: a realm login matches on them,
            # and the password reset goes to the email
            for u_attr, scim_attr in (("email", "email"), ("username", "userName")):
                val = getattr(self.resource, u_attr)
                if not val:
                    # a realm login refuses an empty value: the user keeps its own
                    continue
                if getattr(user, u_attr) != val and User.objects.exclude(pk=user.pk).filter(**{u_attr: val}).exists():
                    if self.resource.scim_active:
                        raise SCIMUniquenessException(detail=f"A Zentral user with this {scim_attr} already exists.")
                    # a deactivation must reach the user. The realm user keeps its old value too: with the
                    # conflicting value, it would match two users, and no later write would reach this one
                    logger.warning("User %s %s not updated with realm user %s: conflict",
                                   user.pk, u_attr, self.resource.pk)
                    if realm_user_values is not None:
                        setattr(self.resource, u_attr, realm_user_values[u_attr])
                        self.resource.save(update_fields=[u_attr])
                    continue
                attrs.append((u_attr, u_attr))
        elif not self.resource.scim_active:
            # the IdP can deactivate a local user, not activate it: the password of a local user
            # is a login outside of the IdP, and only the operator turns it back on
            attrs.append(("is_active", "scim_active"))
        user_updated = False
        for u_attr, ru_attr in attrs:
            val = getattr(self.resource, ru_attr)
            if getattr(user, u_attr) != val:
                setattr(user, u_attr, val)
                user_updated = True
        if user_updated:
            try:
                with transaction.atomic():
                    user.save()
            except IntegrityError:
                # another write gave the email or the username to a user after the checks above
                raise SCIMUniquenessException(detail="A Zentral user with this email or userName already exists.")
            logger.info("User %s updated with realm user %s", user.pk, self.resource.pk)

    def save(self):
        self.resource = RealmUser(
            realm=self.realm,
            scim_external_id=self.validated_data.get("externalId"),
            scim_active=self.validated_data["active"],
            scim_updated_at=timezone.now(),
            username=self.validated_data["userName"],
        )
        name = self.validated_data.get("name")
        if name:
            first_name = name.get("givenName")
            if first_name:
                self.resource.first_name = first_name
            last_name = name.get("familyName")
            if last_name:
                self.resource.last_name = last_name
            formatted = name.get("formatted")
            if formatted:
                self.resource.full_name = formatted
        primary_email = ""
        emails = self.validated_data.get("emails")
        for email in emails:
            re_primary = email.get("primary", False)
            if re_primary or not primary_email:
                primary_email = email["value"]
            if re_primary:
                break
        self.resource.email = primary_email
        self.resource.save()
        for email in emails:
            RealmEmail.objects.create(
                user=self.resource,
                primary=email["primary"],
                type=email["type"],
                email=email["value"],
            )

        # update matching user
        user = self.resource.get_user_for_update()
        if user:
            self.update_user(user)
        return self.resource

    def update(self):
        # get the account user to update before updating the realm user
        user = self.resource.get_user_for_update()
        realm_user_values = {"email": self.resource.email, "username": self.resource.username}

        # key attributes
        self.resource.username = self.validated_data["userName"]
        external_id = self.validated_data.get("externalId")
        if external_id:
            self.resource.scim_external_id = external_id
        self.resource.scim_active = self.validated_data["active"]
        self.resource.scim_updated_at = timezone.now()

        # name
        self.resource.full_name = self.validated_data.get("displayName") or ""
        name = self.validated_data.get("name")
        if name:
            self.resource.first_name = name.get("givenName") or ""
            self.resource.last_name = name.get("familyName") or ""
            self.resource.full_name = name.get("formatted") or self.resource.full_name

        # emails
        primary_email = ""
        existing_realm_emails = {re.email: re for re in self.resource.realmemail_set.all()}
        found_emails = []
        for email in self.validated_data.get("emails", []):
            re_primary = email.get("primary", False)
            re_type = email["type"]
            re_email = email["value"]
            if re_primary or not primary_email:
                primary_email = re_email
            found_emails.append(re_email)
            try:
                realm_email = existing_realm_emails[re_email]
            except KeyError:
                RealmEmail.objects.create(
                    user=self.resource,
                    primary=re_primary,
                    type=re_type,
                    email=re_email,
                )
            else:
                realm_email_changed = False
                if realm_email.primary != re_primary:
                    realm_email_changed = True
                    realm_email.primary = re_primary
                if realm_email.type != re_type:
                    realm_email_changed = True
                    realm_email.type = re_type
                if realm_email_changed:
                    realm_email.save()
        self.resource.email = primary_email
        self.resource.save()
        self.resource.realmemail_set.exclude(email__in=found_emails).delete()

        # update matching user
        if user:
            self.update_user(user, realm_user_values)
        return self.resource
