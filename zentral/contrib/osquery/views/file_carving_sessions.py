import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.utils.functional import cached_property
from django.views.generic import View
from zentral.contrib.osquery.models import FileCarvingSession
from zentral.utils.storage import file_storage_has_signed_urls


logger = logging.getLogger('zentral.contrib.osquery.views.file_carving_sessions')


class DownloadFileCarvingSessionArchiveView(LoginRequiredMixin, View):
    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def get(self, request, *args, **kwargs):
        file_carving_session = get_object_or_404(FileCarvingSession, pk=kwargs["pk"], archive__isnull=False)
        if self._redirect_to_files:
            return HttpResponseRedirect(default_storage.url(file_carving_session.archive.name))
        else:
            return FileResponse(file_carving_session.archive,
                                content_type='application/x-tar',
                                as_attachment=True,
                                filename=file_carving_session.get_archive_name())
