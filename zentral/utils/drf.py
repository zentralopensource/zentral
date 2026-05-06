import io
import json
import zlib
from gzip import GzipFile

from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.exceptions import ParseError, UnsupportedMediaType
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.parsers import BaseParser
from rest_framework.permissions import BasePermission, DjangoModelPermissions

from zentral.core.events.base import AuditEvent

# parsers


class ZentralEncodedJSONParser(BaseParser):
    """JSON parser that also understands the Content-Encoding values our agents send.

    Mirrors the behavior of the (now-superseded) JSONPostAPIView.post body-decoding step:
      - Content-Encoding: deflate                                → zlib.decompress
      - Content-Encoding: zlib  + User-Agent contains "santa"    → zlib.decompress
      - Content-Encoding: gzip  + User-Agent == "Zentral/mnkpf 0.1" → zlib.decompress
      - Content-Encoding: gzip                                   → gzip.GzipFile
      - any other Content-Encoding                               → 415 Unsupported Media Type
      - empty body                                               → returns None
    """
    media_type = "application/json"

    def parse(self, stream, media_type=None, parser_context=None):
        request = (parser_context or {}).get("view").request if parser_context else None
        if request is None:
            # parser_context["request"] is the canonical lookup
            request = (parser_context or {}).get("request")
        raw = stream.read()
        if not raw:
            return None
        if request is not None:
            content_encoding = request.META.get("HTTP_CONTENT_ENCODING")
            if content_encoding:
                user_agent = request.META.get("HTTP_USER_AGENT", "")
                if (
                    content_encoding == "deflate"
                    or (content_encoding == "zlib" and "santa" in user_agent)
                    or (content_encoding == "gzip" and user_agent == "Zentral/mnkpf 0.1")
                ):
                    raw = zlib.decompress(raw)
                elif content_encoding == "gzip":
                    raw = GzipFile(fileobj=io.BytesIO(raw)).read()
                else:
                    raise UnsupportedMediaType(content_encoding)
        encoding = (parser_context or {}).get("encoding", "utf-8")
        try:
            payload = raw.decode(encoding)
        except UnicodeDecodeError as exc:
            raise ParseError(f"Could not decode payload with encoding {encoding}") from exc
        try:
            return json.loads(payload)
        except ValueError as exc:
            raise ParseError("Payload is not valid json") from exc

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
