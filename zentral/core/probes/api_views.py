from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from zentral.utils.drf import (DjangoPermissionRequired,
                               ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit)
from .feeds import sync_feed, FeedError
from .models import Action, Feed
from .serializers import ActionSerializer
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


class UpdateProbeFeedView(APIView):
    permission_required = "probes.change_feed"
    permission_classes = [DjangoPermissionRequired]

    def put(self, request, *args, **kwargs):
        feed = get_object_or_404(Feed, pk=kwargs["pk"])
        status = 200
        try:
            operations = sync_feed(feed, request.data)
        except FeedError as e:
            status = 400
            msg = f"Could not sync feed: {e.message}"
        else:
            if operations:
                msg = "Probes {}.".format(", ".join(f"{label}: {value}" for label, value in operations.items()))
            else:
                msg = "No changes."
        return Response({"result": msg}, status=status)
