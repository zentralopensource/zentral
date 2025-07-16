import logging
from django.apps import apps
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse, JsonResponse
from django.views.generic import TemplateView, View
from zentral.core.stores.conf import stores


logger = logging.getLogger("server.base.views")


class HealthCheckView(View):
    def get(self, request, *args, **kwargs):
        return HttpResponse('OK')


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "base/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        app_list = []
        for app_name, app_config in apps.app_configs.items():
            if not self.request.user.has_module_perms(app_name):
                continue
            events_module = getattr(app_config, "events_module", None)
            if not events_module:
                continue
            if getattr(events_module, "ALL_EVENTS_SEARCH_DICT", None):
                app_list.append(app_name)
        app_list.sort()
        context["apps"] = app_list
        return context


class AppHistogramDataView(LoginRequiredMixin, View):
    INTERVAL_DATE_FORMAT = {
        "hour": "%H:%M",
        "day": "%d/%m",
        "week": "%d/%m",
        "month": "%m/%y",
    }

    def get(self, request, *args, **kwargs):
        app = kwargs['app']
        try:
            zentral_app = apps.app_configs[app]
            search_dict = getattr(zentral_app.events_module, "ALL_EVENTS_SEARCH_DICT")
        except (KeyError, AttributeError):
            raise Http404
        if set(search_dict.keys()) != {"tag"} or not isinstance(search_dict["tag"], str):
            logger.error("Incompatible app %s all event search dict", app)
            raise Http404
        if not self.request.user.has_module_perms(app):
            raise PermissionDenied("Not allowed")
        interval = kwargs["interval"]
        bucket_number = int(kwargs["bucket_number"])
        app_tag = search_dict["tag"]
        try:
            date_format = self.INTERVAL_DATE_FORMAT[interval]
        except KeyError:
            raise Http404
        labels = []
        event_count_data = []
        unique_msn_data = []
        for dt, event_count, unique_msn in stores.admin_console_store.get_app_hist_data(
            interval, bucket_number, app_tag
        ):
            labels.append(dt.strftime(date_format))
            event_count_data.append(event_count)
            unique_msn_data.append(unique_msn)
        datasets = {"event_count": {
                        "label": "{} events".format(app),
                        "backgroundColor": "rgb(122, 199, 189, 0.7)",
                        "data": event_count_data
                    },
                    "unique_msn": {
                        "label": "{} machines".format(app),
                        "backgroundColor": "rgb(234, 81, 101, 0.7)",
                        "data": unique_msn_data
                    }}
        return JsonResponse({"app": app,
                             "labels": labels,
                             "datasets": datasets})
