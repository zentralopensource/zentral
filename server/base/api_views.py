import json
import logging
import os.path
from urllib.parse import urlencode
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
from accounts.models import task_results_for_user
from zentral.utils.storage import file_storage_has_signed_urls, file_storage_signed_url_expiration
from zentral.utils.time import naive_utcnow


logger = logging.getLogger("server.base.api_views")


def get_manifest_location(result):
    manifest = result.get("manifest")
    if isinstance(manifest, dict):
        location = manifest.get("location")
        if isinstance(location, str) and location:
            return location


class BaseTaskResultView(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]

    def get_task_results(self):
        return task_results_for_user(self.request.user)


class TaskResultView(BaseTaskResultView):
    def get(self, request, *args, **kwargs):
        task_id = str(kwargs["task_id"])
        try:
            task_result = self.get_task_results().get(task_id=task_id)
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
                    location = get_manifest_location(result)
                    if location:
                        del result["manifest"]["location"]
                    if filepath or location:
                        response["download_url"] = reverse("base_api:task_result_file_download", args=(task_id,))
                    response["result"] = result
        return Response(response)


class TaskResultFileDownloadView(BaseTaskResultView):
    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def get(self, request, *args, **kwargs):
        task_result = get_object_or_404(self.get_task_results(), task_id=str(kwargs["task_id"]), status="SUCCESS")
        try:
            result = json.loads(task_result.result)
        except (TypeError, ValueError):
            logger.exception("Could not load task result")
            raise Http404
        location = get_manifest_location(result)
        file_key = request.GET.get("file")
        if file_key is not None:
            # the key is checked against the manifest before it reaches the storage
            if not location or file_key not in result["manifest"].get("files", {}):
                raise Http404
            return self._file_response(location + file_key, filename=os.path.basename(file_key))
        filepath = result.get("filepath")
        if isinstance(filepath, str) and filepath:
            return self._file_response(filepath, headers=result.get("headers"))
        if location:
            return Response(self._manifest_with_urls(task_result.task_id, result["manifest"]))
        logger.error("No file found in task %s result", task_result.task_id)
        raise Http404

    def _file_response(self, filepath, headers=None, filename=None):
        if self._redirect_to_files:
            return redirect(default_storage.url(filepath))
        if not default_storage.exists(filepath):
            raise Http404
        response = FileResponse(default_storage.open(filepath), as_attachment=bool(filename), filename=filename or "")
        for k, v in (headers or {}).items():
            response[k] = v
        return response

    def _manifest_with_urls(self, task_id, manifest):
        manifest = dict(manifest)
        location = manifest.pop("location")
        download_url = reverse("base_api:task_result_file_download", args=(task_id,))
        expiration = file_storage_signed_url_expiration() if self._redirect_to_files else None
        files = {}
        for key, file_info in manifest.get("files", {}).items():
            file_info = dict(file_info)
            file_info["download_url"] = f"{download_url}?{urlencode({'file': key})}"
            if self._redirect_to_files:
                signed_at = naive_utcnow()
                file_info["url"] = default_storage.url(location + key)
                if expiration:
                    file_info["expires_at"] = f"{signed_at + expiration:%Y-%m-%dT%H:%M:%SZ}"
            files[key] = file_info
        manifest["files"] = files
        return manifest
