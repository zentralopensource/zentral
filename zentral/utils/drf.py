from django.core.exceptions import ImproperlyConfigured
from rest_framework.permissions import BasePermission


class DjangoPermissionRequired(BasePermission):
    def has_permission(self, request, view):
        permissions = getattr(view, "permission_required", None)
        if not permissions:
            raise ImproperlyConfigured(
                f'{view.__class__.__name__} is missing the permission_required attribute.'
            )
        if not isinstance(permissions, (list, tuple)):
            permissions = [permissions]
        return request.user.has_perms(permissions)
