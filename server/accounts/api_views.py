from datetime import datetime

import celpy
from celpy import celtypes

import logging

from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import status
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from ee.server.realms.backends.openidc.lib import verify_jws_with_discovery

from zentral.core.events.base import AuditEvent
from zentral.utils.drf import (ListCreateAPIViewWithAudit,
                               RetrieveUpdateDestroyAPIViewWithAudit,
                               MaxLimitOffsetPagination)

from accounts.models import APIToken, OIDCAPITokenIssuer, User
from accounts.serializers import (
    OIDCAPITokenIssuerSerializer,
    OIDCAPITokenExchangeInputSerializer,
    OIDCAPITokenExchangeResponseSerializer,
)

logger = logging.getLogger("server.accounts.api_views")


class OIDCAPITokenExchangeView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, issuer_id):
        issuer = get_object_or_404(OIDCAPITokenIssuer, id=issuer_id)

        in_ = OIDCAPITokenExchangeInputSerializer(data=request.data)
        in_.is_valid(raise_exception=True)

        jwt_ = in_.validated_data["jwt"]

        try:
            claims = verify_jws_with_discovery(
                token=jwt_,
                audience=issuer.audience,
                issuer_uri=issuer.issuer_uri
            )
        except Exception:
            logger.exception("Invalid token")
            return Response(
                {"detail": "Invalid token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if issuer.cel_condition:
            try:
                ok = self._evaluate_cel(issuer.cel_condition, claims)
            except Exception:
                logger.exception("Invalid CEL policy")
                return Response(
                    {"detail": "Invalid CEL policy"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            if not ok:
                return Response(
                    {"detail": "Token not allowed by policy"},
                    status=status.HTTP_403_FORBIDDEN,
                )

        duration = in_.get_duration(max_duration=issuer.max_duration)
        name = in_.get_name(default_name=issuer.name)

        api_token, api_key = self._create_api_token(
            user=issuer.user,
            expiry=timezone.now() + duration,
            name=name
        )

        out = OIDCAPITokenExchangeResponseSerializer({
            "user": issuer.user,
            "token": {
                "pk": api_token.id,
                "name": api_token.name,
                "expiry": api_token.expiry,
                "secret": api_key
            }
        })
        return Response(out.data, status=status.HTTP_200_OK)

    def _create_api_token(self, user: User, expiry: datetime, name: str):
        api_token, api_key = APIToken.objects.create_for_user(
            user=user,
            expiry=expiry,
            name=name)

        def on_commit_callback():
            event = AuditEvent.build_from_request_and_instance(
                self.request, api_token,
                action=AuditEvent.Action.CREATED,
            )
            event.post()
        transaction.on_commit(on_commit_callback)

        return api_token, api_key

    def _evaluate_cel(self, expr: str, claims: dict) -> bool:
        # TODO: Cache/Optimize
        env = celpy.Environment(
            annotations={
                "claims": celtypes.MapType,
            }
        )

        ast = env.compile(expr)
        prg = env.program(ast)

        activation = {"claims": celpy.json_to_cel(claims)}

        result = prg.evaluate(activation)

        return bool(result)


class OIDCAPITokenIssuerViewList(ListCreateAPIViewWithAudit):
    queryset = OIDCAPITokenIssuer.objects.all()
    serializer_class = OIDCAPITokenIssuerSerializer
    ordering_fields = ('created_at',)
    ordering = ['-created_at']
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    filterset_fields = ('name',)
    pagination_class = MaxLimitOffsetPagination


class OIDCAPITokenIssuerViewDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = OIDCAPITokenIssuer.objects.all()
    serializer_class = OIDCAPITokenIssuerSerializer
