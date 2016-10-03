from django.apps import apps
from django.http import Http404, HttpResponse, JsonResponse
from django.views import generic
from zentral.core.stores import frontend_store


class HealthCheckView(generic.View):
    def get(self, request, *args, **kwargs):
        return HttpResponse('OK')


class IndexView(generic.TemplateView):
    template_name = "base/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        app_list = []
        for app_name, app_config in apps.app_configs.items():
            if hasattr(app_config, "events_module"):
                app_list.append(app_name)
        context["apps"] = app_list
        return context


class AppHistogramDataView(generic.View):
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
        interval = kwargs["interval"]
        try:
            date_format = self.INTERVAL_DATE_FORMAT[interval]
        except KeyError:
            raise Http404
        labels = []
        event_count_data = []
        unique_msn_data = []
        for dt, event_count, unique_msn in frontend_store.get_app_hist_data(interval, int(kwargs["bucket_number"]), **search_dict):
            labels.append(dt.strftime(date_format))
            event_count_data.append(event_count)
            unique_msn_data.append(unique_msn)
        datasets = {"event_count": {
                        "label": "{} events".format(app),
                        "backgroundColor": "rgba(120, 198, 188, 0.7)",
                        "data": event_count_data
                    },
                    "unique_msn": {
                        "label": "{} machines".format(app),
                        "backgroundColor": "rgba(234, 81, 100, 0.7)",
                        "data": unique_msn_data
                    }}
        return JsonResponse({"app": app,
                             "labels": labels,
                             "datasets": datasets})
