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


class RealmAuthenticationSession(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT)
    user = models.ForeignKey(RealmUser, on_delete=models.PROTECT, null=True)

    callback = models.CharField(max_length=255)
    callback_kwargs = JSONField(default=dict)

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

    def finalize(self, request, realm_user):
        if self.user:
            raise ValueError("Session already finalized")
        self.user = realm_user
        self.save()
        callback_function = self.get_callback_function()
        if callback_function:
            return callback_function(request=request, realm_user=realm_user, **self.callback_kwargs)
