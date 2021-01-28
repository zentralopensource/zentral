from django.contrib.auth.backends import ModelBackend


class ZentralBackend(ModelBackend):
    def user_can_authenticate(self, user):
        return not user.is_service_account and super().user_can_authenticate(user)
