import logging
from datetime import timedelta
from dateutil import parser
from django.http import JsonResponse, HttpResponseForbidden
from django.utils import timezone
from django.views.generic import View
from zentral.utils.api_views import CheckAPISecretView
from . import api_secret
from .events import post_munki_events
from .models import MunkiState

logger = logging.getLogger('zentral.contrib.munki.views')


class BaseView(CheckAPISecretView):
    api_secret = api_secret


class JobDetailsView(BaseView):
    max_binaryinfo_age = timedelta(hours=1)

    def get(self, request, *args, **kwargs):
        msn = kwargs['machine_serial_number']
        response_d = {'include_santa_binaryinfo': True}
        try:
            munki_state = MunkiState.objects.get(machine_serial_number=msn)
        except MunkiState.DoesNotExist:
            pass
        else:
            response_d['last_seen_sha1sum'] = munki_state.sha1sum
            if munki_state.binaryinfo_last_seen:
                response_d['include_santa_binaryinfo'] = (timezone.now() - munki_state.binaryinfo_last_seen) >= self.max_binaryinfo_age
        return JsonResponse(response_d)


class PostJobView(BaseView):
    def post(self, request, *args, **kwargs):
        msn = self.data['machine']['serial_number']
        reports = [(parser.parse(r.pop('start_time')),
                    parser.parse(r.pop('end_time')),
                    r) for r in self.data['reports']]
        # Events
        post_munki_events(msn,
                          self.user_agent,
                          self.ip,
                          (r for _, _, r in reports))
        # MunkiState
        reports.sort()
        if reports:
            start_time, end_time, report = reports[-1]
            update_dict = {'munki_version': report.get('munki_version', None),
                           'user_agent': self.user_agent,
                           'ip': self.ip,
                           'sha1sum': report['sha1sum'],
                           'run_type': report['run_type'],
                           'start_time': start_time,
                           'end_time': end_time}
            if self.data.get('santa_binaryinfo_included', False):
                update_dict['binaryinfo_last_seen'] = timezone.now()
            MunkiState.objects.update_or_create(machine_serial_number=msn,
                                                defaults=update_dict)
        return JsonResponse({})
