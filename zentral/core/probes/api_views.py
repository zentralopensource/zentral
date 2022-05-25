from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from zentral.utils.drf import DjangoPermissionRequired
from .feeds import sync_feed, FeedError
from .models import Feed


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
