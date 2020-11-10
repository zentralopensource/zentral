from itertools import chain
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _
import pyotp


class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_remote = models.BooleanField(default=False)
    password_updated_at = models.DateTimeField(blank=True, null=True, editable=False)

    class Meta:
        ordering = ("username",)

    def __str__(self):
        return self.email or self.username

    def set_password(self, *args, **kwargs):
        super().set_password(*args, **kwargs)
        self.password_updated_at = timezone.now()

    def save(self, *args, **kwargs):
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
                          self.useru2f_set.all()))

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
                "name": self.name}


class UserTOTP(UserVerificationDevice):
    TYPE = "TOTP"
    PRIORITY = 10
    secret = models.CharField(max_length=256)
    delete_url_name = "users:delete_totp"

    class Meta:
        unique_together = (("user", "name"),)

    def get_verification_url(self):
        return reverse("verify_totp")

    def verify(self, code):
        return pyotp.TOTP(self.secret).verify(code)

    def test_user_agent(self, user_agent):
        return True


class UserU2F(UserVerificationDevice):
    TYPE = "U2F"
    PRIORITY = 100
    delete_url_name = "users:delete_u2f_device"
    device = JSONField()

    class Meta:
        unique_together = (("user", "device"), ("user", "name"))

    def get_verification_url(self):
        return reverse("verify_u2f")

    def test_user_agent(self, user_agent):
        return user_agent and 'safari' not in user_agent.lower()
