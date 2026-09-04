from django.db.models import Q
from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..command_backends import CommandBackend
from ..models import Command, Configuration
from ..serializers import CommandSerializer


class CommandFilter(filters.FilterSet):
    name = filters.CharFilter()
    backend = filters.ChoiceFilter(choices=CommandBackend.choices)
    # the configuration a command runs in is reached through its Job's schedules, matching the UI
    # "Scheduled in" search
    configuration = filters.ModelChoiceFilter(queryset=Configuration.objects.all(),
                                              method="filter_configuration")

    def filter_configuration(self, queryset, name, value):
        return queryset.filter(Q(job__recurringjob__configuration=value)
                               | Q(job__onetimejob__configuration=value)).distinct()


class CommandList(ListCreateAPIViewWithAudit):
    queryset = Command.objects.select_related("job").order_by("name")
    serializer_class = CommandSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_class = CommandFilter


class CommandDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Command.objects.select_related("job").all()
    serializer_class = CommandSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This command cannot be deleted")
        return super().perform_destroy(instance)
