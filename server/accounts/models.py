from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_remote = models.BooleanField(default=False)

    class Meta:
        ordering = ("username",)

    def __str__(self):
        return self.email or self.username

    def username_and_email_editable(self):
        return not self.is_remote

    def is_superuser_editable(self):
        return (not self.is_superuser or
                User.objects.exclude(pk=self.pk).filter(is_superuser=True).count() > 0)

    def editable(self):
        return self.username_and_email_editable() or self.is_superuser_editable()

    def deletable(self):
        return not self.is_superuser
