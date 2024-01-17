from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.permissions import BasePermission, DjangoModelPermissions
from zentral.core.events.base import AuditEvent


# permissions


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


class DefaultDjangoModelPermissions(DjangoModelPermissions):
    """
    Like the DjangoModelPermissions but with the "view" required permission
    """
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': ['%(app_label)s.view_%(model_name)s'],
        'HEAD': ['%(app_label)s.view_%(model_name)s'],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }


# views with audit events


class ListCreateAPIViewWithAudit(generics.ListCreateAPIView):
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)

    def on_commit_callback_extra(self, instance):
        pass

    def perform_create(self, serializer):
        super().perform_create(serializer)

        def on_commit_callback():
            instance = serializer.instance
            event = AuditEvent.build_from_request_and_instance(
                self.request, instance,
                action=AuditEvent.Action.CREATED,
            )
            event.post()
            self.on_commit_callback_extra(instance)

        transaction.on_commit(on_commit_callback)


class RetrieveUpdateDestroyAPIViewWithAudit(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [DefaultDjangoModelPermissions]

    def on_commit_callback_extra(self, instance):
        pass

    def perform_update(self, serializer):
        prev_value = serializer.instance.serialize_for_event()
        super().perform_update(serializer)

        def on_commit_callback():
            instance = serializer.instance
            event = AuditEvent.build_from_request_and_instance(
                self.request, instance,
                action=AuditEvent.Action.UPDATED,
                prev_value=prev_value,
            )
            event.post()
            self.on_commit_callback_extra(instance)

        transaction.on_commit(on_commit_callback)

    def perform_destroy(self, instance):
        prev_pk = instance.pk
        prev_value = instance.serialize_for_event()
        super().perform_destroy(instance)

        def on_commit_callback():
            instance.pk = prev_pk  # re-hydrate the primary key
            event = AuditEvent.build_from_request_and_instance(
                self.request, instance,
                action=AuditEvent.Action.DELETED,
                prev_value=prev_value,
            )
            event.post()
            self.on_commit_callback_extra(instance)

        transaction.on_commit(on_commit_callback)
