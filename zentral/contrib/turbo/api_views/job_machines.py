from collections import defaultdict
from functools import cached_property

from django.http import Http404
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from pbac.scoping import visible_rows
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.drf import MaxLimitOffsetPagination, PBACPermission
from ..models import (JobUpload, OneTimeJob, OneTimeJobMachine, RecurringJob, RecurringJobMachine,
                      resolve_upload_schedules)
from ..pbac import (DownloadJobUploadRequest, ViewOneTimeJobMachineRequest, ViewRecurringJobMachineRequest,
                    authorize_job_upload_rows)
from ..serializers import OneTimeJobMachineSerializer, RecurringJobMachineSerializer
from ..uploads import build_download_response


class BaseScheduleMachineList(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("serial_number",)
    pagination_class = MaxLimitOffsetPagination
    schedule_model = None
    job_machine_model = None
    schedule_field = None
    pbac_request_class = None

    @cached_property
    def schedule(self):
        return get_object_or_404(self.schedule_model, pk=self.kwargs["pk"])

    def get_queryset(self):
        # a serial number is unique for a schedule, so the order is total
        return (self.job_machine_model.objects.filter(**{self.schedule_field: self.schedule})
                                              .select_related(f"{self.schedule_field}__configuration",
                                                              f"{self.schedule_field}__job")
                                              .order_by("serial_number"))

    def filter_queryset(self, queryset):
        # A machine that the caller cannot see is not in the list, so a caller without a policy gets an empty
        # list, not a 403.
        return visible_rows(self.request.user, self.pbac_request_class, super().filter_queryset(queryset))


class OneTimeJobMachineList(BaseScheduleMachineList):
    """
    List the state of a one-time job on its machines, with the artifacts of each machine
    """
    serializer_class = OneTimeJobMachineSerializer
    schedule_model = OneTimeJob
    job_machine_model = OneTimeJobMachine
    schedule_field = "one_time_job"
    pbac_request_class = ViewOneTimeJobMachineRequest

    def paginate_queryset(self, queryset):
        page = super().paginate_queryset(queryset)
        # the artifacts of the machines of the page only, each with its own decisions
        uploads = (JobUpload.objects.filter(schedule_pk=self.schedule.pk,
                                            serial_number__in={row.serial_number for row in page})
                                    .order_by("created_at", "pk"))
        artifacts = defaultdict(list)
        for upload in authorize_job_upload_rows(self.request.user, uploads):
            artifacts[upload.serial_number].append(upload)
        for row in page:
            row.artifacts = artifacts[row.serial_number]
        return page


class RecurringJobMachineList(BaseScheduleMachineList):
    """
    List the state of a recurring job on its machines
    """
    serializer_class = RecurringJobMachineSerializer
    schedule_model = RecurringJob
    job_machine_model = RecurringJobMachine
    schedule_field = "recurring_job"
    pbac_request_class = ViewRecurringJobMachineRequest


class ArtifactDownload(generics.GenericAPIView):
    """
    Download an artifact that a job collected
    """
    permission_classes = [PBACPermission]
    queryset = JobUpload.objects.all()

    def get_pbac_request(self, request):
        self.upload = self.get_object()
        schedule = resolve_upload_schedules([self.upload]).get(self.upload.schedule_pk)
        if schedule is None:
            # no schedule: no configuration and no job for the decision
            raise Http404
        return DownloadJobUploadRequest(request.user, self.upload, MetaMachine(self.upload.serial_number), schedule)

    def get(self, request, *args, **kwargs):
        return build_download_response(request, self.upload)
