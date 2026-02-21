import enum
import uuid
from hashlib import blake2b
from itertools import chain

import pyotp
from django.contrib.auth.models import AbstractUser, Group
from django.contrib.auth.models import UserManager as DjangoUserManager
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator, MinValueValidator, URLValidator
from django.db import models
from django.db.models import Q
from django.db.models.functions import Now
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from django_celery_results.models import TaskResult

from zentral.utils.base64 import trimmed_urlsafe_b64decode
from zentral.utils.token import (
    SERVICE_ACCOUNT_API_TOKEN,
    USER_API_TOKEN,
    generate_ztl_token,
)


class UserManager(DjangoUserManager):
    pass


class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_remote = models.BooleanField(default=False)
    is_service_account = models.BooleanField(default=False)
    password_updated_at = models.DateTimeField(blank=True, null=True, editable=False)
    description = models.TextField(blank=True)
    items_per_page = models.PositiveIntegerField(default=10)

    objects = UserManager()

    class Meta:
        ordering = ("username",)

    def __str__(self):
        if self.is_service_account:
            return self.username
        else:
            return self.email or self.username

    def get_type_display(self):
        return "user" if not self.is_service_account else "service account"

    def get_absolute_url(self):
        return reverse("accounts:user", args=(self.pk,))

    def set_password(self, *args, **kwargs):
        if not self.is_remote and not self.is_service_account:
            super().set_password(*args, **kwargs)
            self.password_updated_at = timezone.now()
        else:
            self.set_unusable_password()

    def save(self, *args, **kwargs):
        if self.is_service_account:
            # service accounts cannot be superusers
            self.is_superuser = False
        if self.is_service_account or self.is_remote:
            # service accounts or remote users cannot have a valid password
            self.set_unusable_password()
        else:
            if self.pk:
                old_user = self._meta.model.objects.get(pk=self.pk)
                if old_user.password != self.password:
                    if old_user.has_usable_password():
                        UserPasswordHistory.objects.create(
                            user=self,
                            password=old_user.password,
                            created_at=old_user.password_updated_at or old_user.date_joined
                        )
                    self.password_updated_at = timezone.now()
            elif self.password:
                self.password_updated_at = timezone.now()
        super().save(*args, **kwargs)

    def username_and_email_editable(self):
        return not self.is_remote

    def is_superuser_editable(self):
        return (not self.is_superuser or
                User.objects.exclude(pk=self.pk).filter(is_superuser=True).count() > 0)

    def editable(self):
        return self.username_and_email_editable() or self.is_superuser_editable()

    def deletable(self):
        return not self.is_superuser

    @cached_property
    def has_verification_device(self):
        return len(self._all_verification_devices) > 0

    @cached_property
    def _all_verification_devices(self):
        return list(chain(self.usertotp_set.all(),
                          self.userwebauthn_set.all()))

    def get_verification_devices(self):
        return sorted(self._all_verification_devices,
                      key=lambda vd: vd.name)

    def get_prioritized_verification_devices(self, user_agent):
        verification_devices = sorted(self._all_verification_devices,
                                      key=lambda vd: (-1 * vd.PRIORITY, vd.name))
        ua_verification_devices = [vd for vd in verification_devices if vd.test_user_agent(user_agent)]
        if not ua_verification_devices and verification_devices:
            raise ValueError("No verification devices compatible with this user agent")
        else:
            return ua_verification_devices

    @cached_property
    def group_name_set(self):
        """A set with all the group names. Used for authz."""
        return set(self.groups.values_list("name", flat=True))

    @cached_property
    def group_pk_set(self):
        """A set with all the group PKs. Used for authz."""
        return set(self.groups.values_list("pk", flat=True))

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "username": self.username, "email": self.email}
        if keys_only:
            return d

        d.update({
            "is_remote": self.is_remote,
            "is_service_account": self.is_service_account,
            "is_superuser": self.is_superuser,
            "roles":  [{"pk": group.pk, "name": group.name} for group in self.groups.all()]
        })
        return d


class UserPasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(_('password'), max_length=128)
    created_at = models.DateTimeField(editable=False)


class UserVerificationDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def get_type_for_display(self):
        return self.TYPE

    def __str__(self):
        return "{} {}".format(self.get_type_for_display(), self.name)

    def get_delete_url(self):
        return reverse(self.delete_url_name, args=(self.pk,))

    def serialize_for_event(self):
        return {"type": self.TYPE,
                "pk": self.pk}


class UserTOTP(UserVerificationDevice):
    TYPE = "TOTP"
    PRIORITY = 10
    secret = models.CharField(max_length=256)
    delete_url_name = "accounts:delete_totp"

    class Meta:
        unique_together = (("user", "name"),)

    def get_verification_url(self):
        return reverse("accounts:verify_totp")

    def verify(self, code):
        return pyotp.TOTP(self.secret).verify(code)

    def test_user_agent(self, user_agent):
        return True


class WebAuthnTransport(enum.Enum):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"

    @classmethod
    def choices(cls):
        return tuple((i.value, i.value) for i in cls)


class UserWebAuthn(UserVerificationDevice):
    TYPE = "WebAuthn"
    PRIORITY = 100
    delete_url_name = "accounts:delete_webauthn_device"
    key_handle = models.TextField()
    public_key = models.BinaryField()
    rp_id = models.TextField()
    transports = ArrayField(models.CharField(max_length=8, choices=WebAuthnTransport.choices()))
    sign_count = models.PositiveIntegerField()

    class Meta:
        unique_together = (("user", "key_handle"), ("user", "name"))

    def get_type_for_display(self):
        return "Security key"

    def get_verification_url(self):
        return reverse("accounts:verify_webauthn")

    def test_user_agent(self, user_agent):
        return True

    def get_key_handle_bytes(self):
        return trimmed_urlsafe_b64decode(self.key_handle)

    def get_appid(self):
        if self.rp_id.startswith("https://"):
            # legacy U2F registration
            return self.rp_id


class ProvisionedRole(models.Model):
    group = models.OneToOneField(Group, on_delete=models.CASCADE, related_name="provisioned_role")
    provisioning_uid = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)


class APITokenManager(models.Manager):
    use_in_migrations = True

    @staticmethod
    def _hash_key(key: str) -> str:
        h = blake2b(digest_size=32)
        h.update(key.encode("utf-8"))
        return h.hexdigest()

    def create_for_user(self, user, expiry=None, name=None):
        token_prefix = SERVICE_ACCOUNT_API_TOKEN if user.is_service_account else USER_API_TOKEN
        key = generate_ztl_token(token_prefix)
        hashed_key = self._hash_key(key)
        defaults = {"hashed_key": hashed_key}
        if expiry is not None:
            defaults.update({"expiry": expiry})
        if name is not None:
            defaults.update({"name": name})
        token, _ = self.update_or_create(user=user, hashed_key=hashed_key,
                                         defaults=defaults)
        return token, key

    def is_active(self):
        return self.filter(Q(expiry__gt=Now()) | Q(expiry=None))

    def is_expired(self):
        return self.filter(expiry__lt=Now())

    def get_active_with_key(self, key):
        hashed_key = self._hash_key(key)
        return self.is_active().select_related("user").get(hashed_key=hashed_key)


class APIToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hashed_key = models.CharField(max_length=64)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField(blank=True, null=True)
    name = models.TextField(blank=True, default="")

    objects = APITokenManager()

    class Meta:
        ordering = ['created_at']

    def is_active(self):
        return APIToken.objects.is_active().filter(pk=self.pk).exists()

    def is_expired(self):
        return APIToken.objects.is_expired().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d

        d.update({
            "user": self.user.serialize_for_event(),
            "expiry": self.expiry,
            "created_at": self.created_at,
            "hashed_key": self.hashed_key
        })
        return d


class OIDCAPITokenIssuer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=256, unique=True)
    description = models.TextField(blank=True)
    issuer_uri = models.URLField(
        validators=[URLValidator(schemes=["https"])]
    )
    audience = models.TextField()
    cel_condition = models.TextField(blank=True)
    max_validity = models.IntegerField(
        default=3600,
        validators=[
            MinValueValidator(30),
            MaxValueValidator(604800)  # 7 days
        ],
        help_text="Max validity in seconds"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def serialize_for_event(self, keys_only=False):
        d = {"pk": str(self.pk), "name": self.name}
        if keys_only:
            return d
        d.update({
            "user": self.user.serialize_for_event(keys_only=True),
            "issuer_uri": self.issuer_uri,
            "audience": self.audience,
            "max_validity": self.max_validity,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        })
        if self.cel_condition:
            d["cel_condition"] = self.cel_condition
        if self.description:
            d["description"] = self.description
        return d


class UserTask(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    task_result = models.OneToOneField(TaskResult, on_delete=models.CASCADE)
