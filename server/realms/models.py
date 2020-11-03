from datetime import datetime
import logging
from importlib import import_module
import uuid
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.urls import reverse
from django.utils.functional import cached_property
from .backends import backend_classes

logger = logging.getLogger('zentral.realms.models')


class Realm(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    enabled_for_login = models.BooleanField(default=False)
    login_session_expiry = models.PositiveIntegerField(null=True, default=0)

    # backend + backend config
    backend = models.CharField(max_length=255, editable=False)
    config = JSONField(default=dict, editable=False)

    # user claims mapping
    username_claim = models.CharField(max_length=255)
    email_claim = models.CharField(max_length=255, blank=True)
    first_name_claim = models.CharField(max_length=255, blank=True)
    last_name_claim = models.CharField(max_length=255, blank=True)
    full_name_claim = models.CharField(max_length=255, blank=True)

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

    def get_absolute_url(self):
        return reverse("realms:view", args=(self.uuid,))

    def iter_user_claim_mappings(self):
        for user_claim in ("username", "email", "first_name", "last_name", "full_name"):
            yield user_claim, getattr(self, "{}_claim".format(user_claim))


class RealmUser(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT)
    claims = JSONField(default=dict)
    password_hash = JSONField(null=True)

    # mapped claims
    username = models.CharField(max_length=255)
    email = models.EmailField(blank=True)
    first_name = models.CharField(max_length=255, blank=True)
    last_name = models.CharField(max_length=255, blank=True)
    full_name = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("realm", "username"),)

    def __str__(self):
        return self.username

    def get_full_name(self):
        if self.full_name:
            return self.full_name
        else:
            full_name = " ".join(s for s in (self.first_name, self.last_name) if s)
            if full_name:
                return full_name
            else:
                return self.username

    def get_device_username(self):
        # TODO: better
        return self.username.split("@")[0].replace(".", "")


class RealmAuthenticationSession(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT)
    user = models.ForeignKey(RealmUser, on_delete=models.PROTECT, null=True)

    save_password_hash = models.BooleanField(default=False)
    backend_state = JSONField(null=True)

    callback = models.CharField(max_length=255)
    callback_kwargs = JSONField(default=dict)

    expires_at = models.DateTimeField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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

    def finalize(self, request, realm_user, expires_at=None):
        if self.user:
            raise ValueError("Session already finalized")
        elif not isinstance(realm_user, RealmUser):
            raise ValueError("invalid realm user")
        self.user = realm_user
        self.expires_at = expires_at
        self.save()
        callback_function = self.get_callback_function()
        if callback_function:
            return callback_function(request=request, realm_authentication_session=self, **self.callback_kwargs)

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
