import logging
from rest_framework import serializers, status
from rest_framework.exceptions import APIException
from .models import RealmEmail, RealmGroup, RealmUser, RealmUserGroupMembership


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
        super().__init__(*args, **kwargs)

    def validate_schemas(self, value):
        if value != ["urn:ietf:params:scim:schemas:core:2.0:Group"]:
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
        if "members" in self.validated_data:
            pk_list = [member["value"] for member in self.validated_data.get("members", [])]
            realm = self.resource.realm
            # add new groups
            (RealmGroup.objects.exclude(parent=self.resource)
                               .filter(realm=realm, pk__in=pk_list)
                               .update(parent=self.resource))
            # remove old groups
            (RealmGroup.objects.filter(parent=self.resource)
                               .exclude(pk__in=pk_list)
                               .update(parent=None))
            # add new users
            RealmUserGroupMembership.objects.bulk_create((
                RealmUserGroupMembership(user=user, group=self.resource)
                for user in RealmUser.objects.filter(realm=realm, pk__in=pk_list).exclude(groups=self.resource)
            ))
            # remove old users
            RealmUserGroupMembership.objects.filter(group=self.resource).exclude(user__pk__in=pk_list).delete()

    def save(self):
        self.resource = RealmGroup.objects.create(
            realm=self.realm,
            scim_external_id=self.validated_data.get("externalId"),
            display_name=self.validated_data["displayName"],
        )
        self.update_members()
        return self.resource

    def update(self):
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

    def __init__(self, *args, **kwargs):
        self.resource = kwargs.pop("resource", None)
        self.realm = kwargs.pop("realm")
        super().__init__(*args, **kwargs)

    def validate_schemas(self, value):
        if value != ["urn:ietf:params:scim:schemas:core:2.0:User"]:
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

    def update_user(self, user):
        # with SCIM, we update all the attributes of the matching user,
        # even if it is not a remote user.
        user_updated = False
        for u_attr, ru_attr in (("email", "email"),
                                ("username", "username"),
                                ("first_name", "first_name"),
                                ("last_name", "last_name"),
                                ("is_active", "scim_active")):
            val = getattr(self.resource, ru_attr)
            if getattr(user, u_attr) != val:
                setattr(user, u_attr, val)
                user_updated = True
        if user_updated:
            user.save()
            logger.info("User %s updated with realm user %s", user.pk, self.resource.pk)

    def save(self):
        self.resource = RealmUser(
            realm=self.realm,
            scim_external_id=self.validated_data.get("externalId"),
            scim_active=self.validated_data["active"],
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

        # key attributes
        self.resource.username = self.validated_data["userName"]
        external_id = self.validated_data.get("externalId")
        if external_id:
            self.resource.scim_external_id = external_id
        self.resource.scim_active = self.validated_data["active"]

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
            self.update_user(user)
        return self.resource
