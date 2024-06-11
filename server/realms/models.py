from datetime import datetime
from functools import partial
import logging
from importlib import import_module
import uuid
from django.contrib.auth.models import Group
from django.db import connection, models
from django.db.models import Q
import django.dispatch
from django.urls import reverse
from django.utils.functional import cached_property
from accounts.models import User
from .backends.registry import backend_classes


logger = logging.getLogger('zentral.realms.models')


class Realm(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    enabled_for_login = models.BooleanField(
        default=False,
        help_text="If True, users will be able to sign in to the Zentral admin console"
    )
    user_portal = models.BooleanField(
        default=False,
        help_text="If True, users will be able to sign in to this realm user portal",
    )
    login_session_expiry = models.PositiveIntegerField(null=True, default=0)

    # backend + backend config
    backend = models.CharField(max_length=255, editable=False)
    config = models.JSONField(default=dict, editable=False)

    # user claims mapping
    username_claim = models.CharField(max_length=255)
    email_claim = models.CharField(max_length=255, blank=True)
    first_name_claim = models.CharField(max_length=255, blank=True)
    last_name_claim = models.CharField(max_length=255, blank=True)
    full_name_claim = models.CharField(max_length=255, blank=True)
    custom_attr_1_claim = models.CharField(max_length=255, blank=True)
    custom_attr_2_claim = models.CharField(max_length=255, blank=True)

    # SCIM
    scim_enabled = models.BooleanField(verbose_name="SCIM enabled", default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "-created_at")

    def __str__(self):
        return self.name

    @cached_property
    def backend_instance(self):
        backend_class = backend_classes.get(self.backend)
        if backend_class:
            return backend_class(self)

    def _get_BACKEND_config(self, backend):
        if self.backend == backend:
            return self.config

    def __getattr__(self, name):
        for backend in backend_classes:
            if name == f"get_{backend}_config":
                return partial(self._get_BACKEND_config, backend)
        raise AttributeError

    def get_absolute_url(self):
        return reverse("realms:view", args=(self.uuid,))

    def iter_user_claim_mappings(self):
        for user_claim in ("username", "email",
                           "first_name", "last_name", "full_name",
                           "custom_attr_1", "custom_attr_2"):
            yield user_claim, getattr(self, "{}_claim".format(user_claim))

    def serialize_for_event(self, keys_only=False):
        d = {"pk": str(self.pk),
             "name": self.name}
        if keys_only:
            return d
        d.update({
            "enabled_for_login": self.enabled_for_login,
            "login_session_expiry": self.login_session_expiry,
            "backend": self.backend,
            "config": self.config,
            "username_claim": self.username_claim,
            "email_claim": self.email_claim,
            "first_name_claim": self.first_name_claim,
            "last_name_claim": self.last_name_claim,
            "full_name_claim": self.full_name_claim,
            "custom_attr_1_claim": self.custom_attr_1_claim,
            "custom_attr_2_claim": self.custom_attr_2_claim,
            "scim_enabled": self.scim_enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


class RealmGroup(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT)

    scim_external_id = models.CharField(max_length=255, null=True)

    display_name = models.CharField(max_length=255)

    parent = models.ForeignKey("self", null=True, on_delete=models.SET_NULL)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("realm", "display_name"),
                           ("realm", "scim_external_id"),)

    def __str__(self):
        return self.display_name

    def get_absolute_url(self):
        return reverse("realms:group", args=(self.pk,))

    def serialize_for_event(self, keys_only=False):
        d = {"pk": str(self.pk),
             "realm": self.realm.serialize_for_event(keys_only=True),
             "display_name": self.display_name}
        if keys_only:
            return d
        d.update({
            "scim_external_id": self.scim_external_id,
            "parent": self.parent.serialize_for_event(keys_only=True) if self.parent else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


class RealmUser(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT)

    scim_external_id = models.CharField(max_length=255, null=True)
    scim_active = models.BooleanField(default=False)

    groups = models.ManyToManyField(RealmGroup, through='RealmUserGroupMembership')

    claims = models.JSONField(default=dict)
    password_hash = models.JSONField(null=True)

    # mapped claims
    username = models.CharField(max_length=255)
    email = models.EmailField(blank=True)
    first_name = models.CharField(max_length=255, blank=True)
    last_name = models.CharField(max_length=255, blank=True)
    full_name = models.CharField(max_length=255, blank=True)
    custom_attr_1 = models.CharField(max_length=255, blank=True)
    custom_attr_2 = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("realm", "username"),
                           ("realm", "scim_external_id"),)

    def __str__(self):
        return self.username

    def get_absolute_url(self):
        return reverse("realms:user", args=(self.pk,))

    def get_full_name(self):
        if self.full_name:
            return self.full_name
        else:
            full_name = " ".join(s for s in (self.first_name, self.last_name) if s)
            if full_name:
                return full_name
            else:
                return self.username

    @property
    def device_username(self):
        # TODO: better
        return self.username.split("@")[0].replace(".", "")

    @property
    def email_prefix(self):
        return self.email.split("@")[0].strip()

    # user

    def get_users(self):
        if not self.realm.enabled_for_login:
            return User.objects.none()
        return User.objects.filter(Q(email=self.email) | Q(username=self.username), is_service_account=False)

    def get_user_for_update(self, raise_on_multiple=False):
        qs = self.get_users().select_for_update()
        qs_count = qs.count()
        if qs_count > 1:
            message = f"Multiple matching users for realm user {self.pk}"
            if raise_on_multiple:
                raise ValueError(message)
            else:
                logger.error(message)
        elif qs_count == 1:
            return qs.first()

    # groups

    def scim_groups(self):
        sql = (
            "WITH RECURSIVE groups(value, display, type, parent_id) AS ("
            "  SELECT rg.uuid, rg.display_name, 'direct' type, rg.parent_id"
            "  FROM realms_realmgroup rg"
            "  JOIN realms_realmusergroupmembership rugm ON (rugm.group_id = rg.uuid)"
            "  WHERE rugm.user_id = %s"
            "  UNION"
            "  SELECT prg.uuid, prg.display_name, 'indirect' type, prg.parent_id"
            "  FROM groups"
            "  JOIN realms_realmgroup prg ON (prg.uuid = groups.parent_id)"
            ") SELECT value, display, type FROM groups"
        )
        cursor = connection.cursor()
        cursor.execute(sql, [self.pk])
        columns = [col[0] for col in cursor.description]
        for result in cursor.fetchall():
            yield dict(zip(columns, result))

    def groups_with_types(self):
        scim_groups = {sg["value"]: sg["type"] for sg in self.scim_groups()}
        groups_with_types = []
        for realm_group in RealmGroup.objects.filter(pk__in=scim_groups.keys()).order_by("display_name"):
            groups_with_types.append((realm_group, scim_groups[realm_group.pk]))
        return groups_with_types

    def iter_group_names(self):
        for scim_group in self.scim_groups():
            yield scim_group["display"]

    def mapped_tags(self):
        group_names = [  # not a set, because the number should be small
            group_name.lower()
            for group_name in self.iter_group_names()
        ]
        tags_to_add = []
        tags_to_remove = []
        for tm in self.realm.realmtagmapping_set.select_related("tag").all():
            if tm.group_name.lower() in group_names:
                tags_to_add.append(tm.tag)
            else:
                tags_to_remove.append(tm.tag)
        return tags_to_add, tags_to_remove


class RealmUserGroupMembership(models.Model):
    user = models.ForeignKey(RealmUser, on_delete=models.CASCADE)
    group = models.ForeignKey(RealmGroup, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


class RealmEmail(models.Model):
    user = models.ForeignKey(RealmUser, on_delete=models.CASCADE)
    primary = models.BooleanField(default=False)
    type = models.CharField(max_length=255)
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class LocalAuthenticationSession:
    uuid = None
    realm = None
    user = None
    save_password_hash = False
    backend_state = None
    callback = ""
    callback_kwargs = {}

    @property
    def is_remote(self):
        """
        Always return False. This is a way of comparing RealmAuthenticationSession to local ones.
        """
        return False

    def get_callback_function(self):
        raise NotImplementedError

    def computed_expiry(self, default_session_expiry=300, from_dt=None):
        raise NotImplementedError


class RealmAuthenticationSession(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT)
    user = models.ForeignKey(RealmUser, on_delete=models.PROTECT, null=True)

    save_password_hash = models.BooleanField(default=False)
    backend_state = models.JSONField(null=True)

    callback = models.CharField(max_length=255)
    callback_kwargs = models.JSONField(default=dict)

    expires_at = models.DateTimeField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_remote(self):
        """
        Always return True. This is a way of comparing RealmAuthenticationSession to local ones.
        """
        return True

    def get_callback_function(self):
        module_name, function_name = self.callback.rsplit(".", 1)
        try:
            module = import_module(module_name)
        except Exception:
            logger.exception("Could not import module %s", module_name)
            return
        callback = getattr(module, function_name, None)
        if callback is None:
            logger.exception("Could not find function %s in callback module %s", module_name, function_name)
        return callback

    def computed_expiry(self, default_session_expiry=300, from_dt=None):
        # returns the effective session expiry in seconds, based on the realm settings and its on expires_at attribute
        # default to 5 min to be really annoying!
        session_expiry = default_session_expiry
        if self.realm.login_session_expiry is not None:
            # the session expiry configured in the realm takes precedence
            session_expiry = self.realm.login_session_expiry
        elif self.expires_at:
            # fall back to the session expiry attached to the realm authentication session
            if not from_dt:
                from_dt = datetime.utcnow()
            expiry_delta = self.expires_at - from_dt
            session_expiry = expiry_delta.days * 86400 + expiry_delta.seconds
            if session_expiry < 0:
                # should not happen, but who knows
                raise ValueError("This session has already expired!")
        else:
            logger.error("No session expiry found in the realm %s authentication session. "
                         "Use default expiry of %s seconds.", self.realm, session_expiry)
        return session_expiry


class RealmGroupMapping(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    realm = models.ForeignKey(Realm, on_delete=models.CASCADE)
    claim = models.CharField(max_length=255)
    separator = models.CharField(max_length=64, blank=True)
    value = models.CharField(max_length=255)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("realm", "claim", "value", "group"),)


class RealmTagMapping(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    realm = models.ForeignKey(Realm, on_delete=models.CASCADE)
    group_name = models.CharField(max_length=255)
    tag = models.ForeignKey("inventory.Tag", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("realm", "group_name", "tag"),)


realm_tagging_change = django.dispatch.Signal()
