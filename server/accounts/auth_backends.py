import logging
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from .models import User


logger = logging.getLogger("server.accounts.auth_backends")


class Saml2Backend(ModelBackend):
    def authenticate(self, request, session_info):
        username = None
        ava = session_info.get('ava')
        if ava:
            uid = ava.get('uid')
            if uid:
                username = uid[0]
        if not username and 'name_id' in session_info:
            username = session_info['name_id'].text
        if not username:
            logger.error("NO USERNAME FOUND")
            return None
        try:
            validate_email(username)
        except ValidationError:
            email = "{}@invalid-domain.com".format(username)
        else:
            email = username
        user, created = User.objects.update_or_create(username=username,
                                                      defaults={"email": email,
                                                                "is_remote": True})
        if not created:
            if user.has_usable_password():
                logger.error("User %s with password exists", username)
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
