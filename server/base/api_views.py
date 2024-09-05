import json
import logging
import celery.states
from django_celery_results.models import TaskResult
from django.core.files.storage import default_storage
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.functional import cached_property
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from accounts.api_authentication import APITokenAuthentication
from zentral.utils.storage import file_storage_has_signed_urls


logger = logging.getLogger("server.base.api_views")


class TaskResultView(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]

    def get(self, request, *args, **kwargs):
        task_id = str(kwargs["task_id"])
        try:
            task_result = TaskResult.objects.get(task_id=task_id)
        except TaskResult.DoesNotExist:
            response = {"id": task_id,
                        "status": "UNKNOWN",
                        "unready": True}
        else:
            response = {"name": task_result.task_name,
                        "id": task_id,
                        "status": task_result.status,
                        "unready": task_result.status in celery.states.UNREADY_STATES}
            if task_result.status == "SUCCESS":
                try:
                    result = json.loads(task_result.result)
                except (TypeError, ValueError):
                    logger.exception("Could not load task result")
                else:
                    filepath = result.pop("filepath", None)
                    if filepath:
                        response["download_url"] = reverse("base_api:task_result_file_download", args=(task_id,))
                    response["result"] = result
        return Response(response)


class TaskResultFileDownloadView(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]

    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def get(self, request, *args, **kwargs):
        task_result = get_object_or_404(TaskResult, task_id=str(kwargs["task_id"]), status="SUCCESS")
        try:
            result = json.loads(task_result.result)
        except (TypeError, ValueError):
            logger.exception("Could not load task result")
            raise Http404
        try:
            filepath = result["filepath"]
            assert isinstance(filepath, str) and len(filepath) > 0
        except (AssertionError, KeyError):
            logger.error("No file found in task %s result", task_result.task_id)
            raise Http404
        if self._redirect_to_files:
            return redirect(default_storage.url(filepath))
        else:
            if not default_storage.exists(filepath):
                raise Http404
            response = FileResponse(default_storage.open(filepath))
            for k, v in result.get("headers").items():
                response[k] = v
            return response
