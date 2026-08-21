import logging

from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django_filters import rest_framework as filters
from pbac.engine import engine
from rest_framework import generics
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import BasePermission, DjangoModelPermissions
from zentral.core.events.base import AuditEvent


logger = logging.getLogger("zentral.utils.drf")


# pagination


class MaxLimitOffsetPagination(LimitOffsetPagination):
    default_limit = 50
    max_limit = 500


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


class PBACPermission(BasePermission):
    """Authorize the PBAC request the view builds, the DRF counterpart of PBACViewMixin.

    The view is asked for the request instead of declaring an action, so it can carry the
    resource and the context the policies are written against.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            # an anonymous user has no principal to build a request with. DRF turns the
            # refusal into a 401 when no authenticator succeeded
            return False
        pbac_request = view.get_pbac_request(request)
        engine.authorize_request(pbac_request)
        if not pbac_request.is_authorized:
            logger.error("Permission denied %s", pbac_request, extra={"request": request})
        return pbac_request.is_authorized


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

    def get_audit_machine_serial_number(self):
        return None

    def on_commit_callback_extra(self, instance):
        pass

    def perform_create(self, serializer):
        super().perform_create(serializer)

        def on_commit_callback():
            instance = serializer.instance
            event = AuditEvent.build_from_request_and_instance(
                self.request, instance,
                action=AuditEvent.Action.CREATED,
                machine_serial_number=self.get_audit_machine_serial_number(),
            )
            event.post()
            self.on_commit_callback_extra(instance)

        transaction.on_commit(on_commit_callback)


class RetrieveUpdateAPIViewWithAudit(generics.RetrieveUpdateAPIView):
    permission_classes = [DefaultDjangoModelPermissions]
    # Zentral only does full updates — PATCH is a 405 everywhere, so the serializers' update()
    # methods can rely on every declared field being present in validated_data
    http_method_names = ["get", "head", "options", "put"]

    def get_audit_machine_serial_number(self):
        return None

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
                machine_serial_number=self.get_audit_machine_serial_number(),
            )
            event.post()
            self.on_commit_callback_extra(instance)

        transaction.on_commit(on_commit_callback)


class RetrieveUpdateDestroyAPIViewWithAudit(RetrieveUpdateAPIViewWithAudit,
                                            generics.RetrieveUpdateDestroyAPIView):
    http_method_names = RetrieveUpdateAPIViewWithAudit.http_method_names + ["delete"]

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
                machine_serial_number=self.get_audit_machine_serial_number(),
            )
            event.post()
            self.on_commit_callback_extra(instance)

        transaction.on_commit(on_commit_callback)
