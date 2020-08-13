import json
import logging
import celery.states
from django_celery_results.models import TaskResult
from django.core.files.storage import default_storage
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.response import Response


logger = logging.getLogger("server.base.api_views")


class TaskResultView(APIView):
    def get(self, request, *args, **kwargs):
        task_id = str(kwargs["task_id"])
        try:
            task_result = TaskResult.objects.get(task_id=task_id)
        except TaskResult.DoesNotExist:
            response = {"status": "UNKNOWN",
                        "unready": True}
        else:
            response = {"status": task_result.status,
                        "unready": task_result.status in celery.states.UNREADY_STATES}
            if task_result.status == "SUCCESS":
                try:
                    result = json.loads(task_result.result)
                except (TypeError, ValueError):
                    logger.exception("Could not load task result")
                else:
                    filepath = result.get("filepath")
                    if filepath:
                        response["download_url"] = reverse("base_api:task_result_file_download", args=(task_id,))
        return Response(response)


class TaskResultFileDownloadView(APIView):
    def get(self, request, *args, **kwargs):
        task_result = get_object_or_404(TaskResult, task_id=str(kwargs["task_id"]), status="SUCCESS")
        result = json.loads(task_result.result)
        filepath = result["filepath"]
        if not default_storage.exists(filepath):
            raise Http404
        try:
            filepath = default_storage.path(filepath)
        except NotImplementedError:
            url = default_storage.url(filepath)
            return redirect(url)
        else:
            response = FileResponse(open(filepath, "rb"))
            for k, v in result.get("headers").items():
                response[k] = v
            return response
