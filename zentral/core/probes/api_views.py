from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from .models import Action, ProbeSource
from .serializers import ActionSerializer, ProbeSourceSerializer
from .sync import signal_probe_change


class ActionDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Action.objects.all()
    serializer_class = ActionSerializer

    def on_commit_callback_extra(self, instance):
        signal_probe_change()

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This action cannot be deleted")
        return super().perform_destroy(instance)


class ActionList(ListCreateAPIViewWithAudit):
    queryset = Action.objects.all()
    serializer_class = ActionSerializer
    filterset_fields = ('name',)

    def on_commit_callback_extra(self, instance):
        signal_probe_change()


class ProbeDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = ProbeSource.objects.all()
    serializer_class = ProbeSourceSerializer


class ProbeList(ListCreateAPIViewWithAudit):
    queryset = ProbeSource.objects.all()
    serializer_class = ProbeSourceSerializer
    filterset_fields = ('name',)
