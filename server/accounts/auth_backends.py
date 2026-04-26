from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from .pbac.engine import engine

UserModel = get_user_model()


class ZentralBaseBackend(ModelBackend):
    def user_can_authenticate(self, user):
        return not user.is_service_account and super().user_can_authenticate(user)

    # Override legacy permission methods

    def get_user_permissions(self, user_obj, obj=None):
        # should not be used
        return set()

    async def aget_user_permissions(self, user_obj, obj=None):
        # should not be used
        return set()

    def get_group_permissions(self, user_obj, obj=None):
        # should not be used
        return set()

    async def aget_group_permissions(self, user_obj, obj=None):
        # should not be used
        return set()

    def get_all_permissions(self, user_obj, obj=None):
        # should not be used
        return set()

    async def aget_all_permissions(self, user_obj, obj=None):
        # should not be used
        return set()

    def with_perm(self, perm, is_active=True, include_superusers=True, obj=None):
        # should not be used.
        return UserModel._default_manager.none()

    def has_perm(self, user_obj, perm, obj=None):
        # bypass legacy permissions by default
        return False

    async def ahas_perm(self, user_obj, perm, obj=None):
        # should not be used
        return False

    def has_module_perms(self, user_obj, app_label):
        # bypass legacy permissions by default
        return False

    async def ahas_module_perms(self, user_obj, app_label):
        # should not be used
        return False


class ZentralBackend(ZentralBaseBackend):
    # Evaluate the permission against the policies

    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return False
        if user_obj.is_superuser:
            return True
        return engine.has_legacy_perm(user_obj, perm)

    def has_module_perms(self, user_obj, app_label):
        if not user_obj.is_active or user_obj.is_anonymous:
            return False
        if user_obj.is_superuser:
            return True
        return engine.has_module_legacy_perms(user_obj, app_label)
