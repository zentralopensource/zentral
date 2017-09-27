from django.contrib.auth.models import AbstractUser
from django.db import models
from django.urls import reverse
from django.utils import timezone
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

    def save(self, *args, **kwargs):
        if self.pk:
            old_user = self._meta.model.objects.get(pk=self.pk)
            if old_user.password != self.password:
                if old_user.has_usable_password():
                    UserPasswordHistory.objects.create(
                        user=self,
                        password=old_user.password,
                        created_at=old_user.password_updated_at
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

    def has_verification_device(self):
        return len(self.get_verification_devices()) > 0

    def get_verification_devices(self):
        return list(self.usertotp_set.all())


class UserPasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(_('password'), max_length=128)
    created_at = models.DateTimeField(editable=False)


class UserTOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    secret = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} {}".format(self.get_type_for_display(), self.name)

    def get_type_for_display(self):
        return "TOTP"

    def get_delete_url(self):
        return reverse("users:delete_totp", args=(self.pk,))

    def verify(self, code):
        return pyotp.TOTP(self.secret).verify(code)
