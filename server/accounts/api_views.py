import logging

from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import OIDCAPITokenIssuer
from accounts.serializers import (
    APITokenWithSecretSerializer,
    OIDCAPITokenIssuerAuthSerializer,
    OIDCAPITokenIssuerSerializer,
)
from zentral.utils.drf import (
    ListCreateAPIViewWithAudit,
    MaxLimitOffsetPagination,
    RetrieveUpdateDestroyAPIViewWithAudit,
)

logger = logging.getLogger("server.accounts.api_views")


class OIDCAPITokenIssuerAuth(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, issuer_id):
        issuer = get_object_or_404(OIDCAPITokenIssuer, pk=issuer_id)
        serializer = OIDCAPITokenIssuerAuthSerializer(
            data=request.data,
            context={"request": self.request},
            issuer=issuer,
        )
        if serializer.is_valid():
            api_token, api_key = serializer.save()
            response_serializer = APITokenWithSecretSerializer(api_token, api_key=api_key)
            return Response(response_serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
