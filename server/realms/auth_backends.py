import logging
from django.contrib.auth.backends import ModelBackend
from accounts.models import User
from .models import RealmUser


logger = logging.getLogger("server.accounts.auth_backends")


class RealmBackend(ModelBackend):
    def authenticate(self, request, realm_user):
        if not realm_user or not isinstance(realm_user, RealmUser):
            return None
        username = realm_user.username
        defaults = {"is_remote": True}
        for attr in ("email", "first_name", "last_name"):
            defaults[attr] = realm_user.claims.get("_zentral", {}).get(attr) or ""

        try:
            user, created = User.objects.update_or_create(username=username, defaults=defaults)
        except Exception:
            logger.error("Could not update or create user from realm user %s", realm_user.pk)
        else:
            if not created and user.has_usable_password():
                logger.error("User %s with password exists", username)
            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
