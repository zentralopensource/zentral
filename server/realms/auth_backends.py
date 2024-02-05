import logging
from django.contrib.auth.backends import ModelBackend
from django.db import transaction, IntegrityError
from django.db.models import Q
from accounts.models import User
from .models import RealmUser


logger = logging.getLogger("server.accounts.auth_backends")


class RealmBackend(ModelBackend):
    @staticmethod
    def update_user(user, realm_user):
        # Update user if necessary
        # Do not change the is_remote attribute because matching local users can login with a realm.
        if not user.is_remote:
            return
        user_updated = False
        for attr in ("first_name", "last_name"):
            val = getattr(realm_user, attr)
            if val and getattr(user, attr) != val:
                setattr(user, attr, val)
                user_updated = True
        if user_updated:
            user.save()

    def authenticate(self, request, realm_user):
        if not realm_user or not isinstance(realm_user, RealmUser):
            return None
        if not realm_user.realm.enabled_for_login:
            raise ValueError("Realm not enabled for login")
        username = realm_user.username
        email = realm_user.email
        if not username or not email:
            raise ValueError("Cannot authenticate user with empty email or username")
        with transaction.atomic():
            user = realm_user.get_user_for_update(raise_on_multiple=True)
            if user:
                self.update_user(user, realm_user)
                return user
            else:
                try:
                    with transaction.atomic():
                        # Create user
                        user = User(email=email,
                                    username=username,
                                    is_remote=True,
                                    first_name=realm_user.first_name or "",
                                    last_name=realm_user.last_name or "")
                        user.set_unusable_password()
                        user.save()
                    return user
                except IntegrityError as e:
                    # A similar user was created in the meantime
                    try:
                        user = User.objects.select_for_update().get(Q(email=email) | Q(username=username))
                    except User.MultipleObjectsReturned:
                        # Should not happen
                        raise ValueError("Multiple existing users with same email or username")
                    except User.DoesNotExist:
                        # Should not happen
                        raise e
                    else:
                        if user.is_service_account:
                            logger.error("Realm user %s match with service account %s", realm_user.pk, user.pk)
                        else:
                            self.update_user(user, realm_user)
                            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
