import logging
from dateutil import parser
from django.http import JsonResponse, HttpResponseForbidden
from django.views.generic import View
from zentral.utils.api_views import CheckAPISecretView
from . import api_secret
from .events import post_munki_events
from .models import LastReport

logger = logging.getLogger('zentral.contrib.munki.views')


class BaseView(CheckAPISecretView):
    api_secret = api_secret


class LastSeenReportView(BaseView):
    def get(self, request, *args, **kwargs):
        msn = kwargs['machine_serial_number']
        try:
            last_report = LastReport.objects.get(machine_serial_number=msn)
        except LastReport.DoesNotExist:
            response_d = {}
        else:
            response_d = {'sha1sum': last_report.sha1sum}
        return JsonResponse(response_d)


class PostReportsView(BaseView):
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
        # LastReport
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
            LastReport.objects.update_or_create(machine_serial_number=msn,
                                                defaults=update_dict)
        return JsonResponse({})
