import logging
from django.contrib.auth.backends import ModelBackend
from django.db import transaction, IntegrityError
from django.db.models import Q
from accounts.models import User
from .models import RealmUser


logger = logging.getLogger("server.accounts.auth_backends")


class RealmBackend(ModelBackend):
    def authenticate(self, request, realm_user):
        if not realm_user or not isinstance(realm_user, RealmUser):
            return None
        username = realm_user.username
        email = realm_user.email
        if not username or not email:
            raise ValueError("Cannot authenticate user with empty email or username")
        with transaction.atomic():
            users = User.objects.select_for_update().filter(Q(email=email) | Q(username=username))
            user_count = users.count()
            if user_count > 1:
                raise ValueError("Multiple existing users with same email or username")
            elif user_count == 1:
                # Update user if necessary
                user = users.first()
                # Do not change the is_remote attribute!
                # we allow matching local users to login with a realm.
                user_updated = False
                # Only update first_name and last_name if user is remote.
                if user.is_remote:
                    if realm_user.first_name:
                        user.first_name = realm_user.first_name
                        user_updated = True
                    if realm_user.last_name:
                        user.last_name = realm_user.last_name
                        user_updated = True
                if user_updated:
                    user.save()
                return user
            else:
                try:
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
                        user = User.objects.select_for_update().get(email=email, username=username)
                    except User.MultipleObjectsReturned:
                        # Should not happen
                        raise ValueError("Multiple existing users with same email or username")
                    except User.DoesNotExist:
                        # Should not happen
                        raise e
                    else:
                        # Do not change the is_remote attribute!
                        # We allow matching local users to login with a realm,
                        # even here, where a race is less than likely.
                        if user.has_usable_password():
                            logger.warning("User %s / %s has a usable password", username, email)
                        if not user.is_remote:
                            logger.warning("Local user %s / %s exists", username, email)
                        else:
                            # Only update first_name and last_name if user is remote.
                            user_updated = False
                            if realm_user.first_name:
                                user.first_name = realm_user.first_name
                                user_updated = True
                            if realm_user.last_name:
                                user.last_name = realm_user.last_name
                                user_updated = True
                            if user_updated:
                                user.save()
                        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
