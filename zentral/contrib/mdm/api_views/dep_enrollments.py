from rest_framework.exceptions import ValidationError
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from zentral.utils.drf import (ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit,
                               MaxLimitOffsetPagination)
from zentral.contrib.mdm.models import DEPEnrollment, DEPEnrollmentCustomView, EnrollmentCustomView
from zentral.contrib.mdm.serializers import (DEPEnrollmentSerializer, DEPEnrollmentDetailSerializer,
                                             EnrollmentCustomViewSerializer, DEPEnrollmentCustomViewSerializer)


class DEPEnrollmentList(ListCreateAPIViewWithAudit):
    queryset = DEPEnrollment.objects.all()
    serializer_class = DEPEnrollmentSerializer
    filterset_fields = ('name', )
    ordering_fields = ('created_at',)
    ordering = ['-created_at']
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    pagination_class = MaxLimitOffsetPagination


class DEPEnrollmentDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = DEPEnrollment.objects.all()
    serializer_class = DEPEnrollmentDetailSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This DEP enrollment cannot be deleted')
        return super().perform_destroy(instance)


class EnrollmentCustomViewList(ListCreateAPIViewWithAudit):
    queryset = EnrollmentCustomView.objects.all()
    serializer_class = EnrollmentCustomViewSerializer
    filterset_fields = ('name', )
    ordering_fields = ('created_at',)
    ordering = ['-created_at']
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    pagination_class = MaxLimitOffsetPagination


class EnrollmentCustomViewDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = EnrollmentCustomView.objects.all()
    serializer_class = EnrollmentCustomViewSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This enrollment custome view cannot be deleted')
        return super().perform_destroy(instance)


class DEPEnrollmentCustomViewList(ListCreateAPIViewWithAudit):
    queryset = DEPEnrollmentCustomView.objects.all()
    serializer_class = DEPEnrollmentCustomViewSerializer
    ordering_fields = ('created_at',)
    ordering = ['-created_at']
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    pagination_class = MaxLimitOffsetPagination


class DEPEnrollmentCustomViewDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = DEPEnrollmentCustomView.objects.all()
    serializer_class = DEPEnrollmentCustomViewSerializer
