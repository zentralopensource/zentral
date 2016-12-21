from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_remote = models.BooleanField(default=False)

    class Meta:
        ordering = ("username",)

    def __str__(self):
        return self.email or self.username
