from datetime import datetime, timedelta
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core import signing
from django.http import HttpResponseRedirect
from django.views.generic import TemplateView, View
from zentral.core.events import event_types
from zentral.core.stores import frontend_store, stores


class EventsViewMixin(PermissionRequiredMixin):
    store_method_scope = None
    default_time_range = "now-7d"

    def get_object(self, **kwargs):
        return None

    def get_fetch_kwargs_extra(self):
        return {}

    def get_fetch_url(self):
        return None

    def get_redirect_url(self):
        return None

    def get_store_redirect_url(self):
        return None

    def clean_fetch_kwargs(self):
        kwargs = self.get_fetch_kwargs_extra()
        event_type = self.request.GET.get("et")
        if event_type:
            if event_type not in event_types:
                raise ValueError("Unknown event type")
            else:
                kwargs["event_type"] = event_type
        time_range = self.request.GET.get("tr")
        if not time_range:
            if self.default_time_range:
                time_range = self.default_time_range
            else:
                raise ValueError("Missing time range")
        kwargs["to_dt"] = None
        now = datetime.utcnow()
        if time_range == "now-24h":
            kwargs["from_dt"] = now - timedelta(hours=24)
        elif time_range == "now-7d":
            kwargs["from_dt"] = now - timedelta(days=7)
        elif time_range == "now-14d":
            kwargs["from_dt"] = now - timedelta(days=14)
        elif time_range == "now-30d":
            kwargs["from_dt"] = now - timedelta(days=30)
        else:
            raise ValueError("Unknown time range")
        raw_cursor = self.request.GET.get("rc")
        if raw_cursor:
            try:
                cursor = signing.loads(raw_cursor)
            except signing.BadSignature:
                raise ValueError("Bad cursor")
            else:
                kwargs["cursor"] = cursor
        return kwargs


class EventsView(EventsViewMixin, TemplateView):
    def get(self, request, *args, **kwargs):
        self.object = self.get_object(**kwargs)
        try:
            self.fetch_kwargs = self.clean_fetch_kwargs()
        except ValueError:
            return HttpResponseRedirect(self.get_redirect_url())
        self.fetch_kwargs.pop("cursor", None)
        self.request_event_type = self.fetch_kwargs.pop("event_type", None)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        # time range options
        selected_time_range = self.request.GET.get("tr", self.default_time_range)
        ctx["time_range_options"] = [
            (v, selected_time_range == v, l)
            for v, l in (("now-24h", "Last 24h"),
                         ("now-7d", "Last 7 days"),
                         ("now-14d", "Last 14 days"),
                         ("now-30d", "Last 30 days"))
        ]

        # event type options
        total_event_count = 0
        event_type_options = []
        store_method = getattr(frontend_store, f"get_aggregated_{self.store_method_scope}_event_counts")
        for event_type, count in store_method(**self.fetch_kwargs).items():
            total_event_count += count
            event_type_options.append(
                (event_type,
                 self.request_event_type == event_type,
                 "{} ({})".format(event_type.replace('_', ' ').title(), count))
            )
        event_type_options.sort()
        event_type_options.insert(
            0,
            ('',
             self.request_event_type in [None, ''],
             'All ({})'.format(total_event_count))
        )
        ctx['event_type_options'] = event_type_options

        # fetch url
        qd = self.request.GET.copy()
        if "tr" not in qd:
            qd["tr"] = self.default_time_range
        ctx['fetch_url'] = "{}?{}".format(self.get_fetch_url(), qd.urlencode())

        # store links
        store_links = []
        store_redirect_url = self.get_store_redirect_url()
        for store in stores.iter_events_url_store_for_user(self.store_method_scope, self.request.user):
            store_links.append((store_redirect_url, store.name))
        ctx["store_links"] = store_links

        return ctx


class FetchEventsView(EventsViewMixin, TemplateView):
    template_name = "core/stores/events_events.html"
    paginate_by = 20
    include_machine_info = True

    def get(self, request, *args, **kwargs):
        self.object = self.get_object(**kwargs)
        try:
            self.fetch_kwargs = self.clean_fetch_kwargs()
        except ValueError:
            return HttpResponseRedirect(self.get_redirect_url())
        self.fetch_kwargs["limit"] = self.paginate_by
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        store_method = getattr(frontend_store, f"fetch_{self.store_method_scope}_events")
        ctx["include_machine_info"] = self.include_machine_info
        ctx["events"], next_cursor = store_method(**self.fetch_kwargs)
        if next_cursor:
            qd = self.request.GET.copy()
            qd.update({"rc": signing.dumps(next_cursor)})
            ctx["fetch_url"] = "{}?{}".format(self.get_fetch_url(), qd.urlencode())
        return ctx


class EventsStoreRedirectView(EventsViewMixin, View):
    def get(self, request, *args, **kwargs):
        self.object = self.get_object(**kwargs)
        try:
            fetch_kwargs = self.clean_fetch_kwargs()
        except ValueError:
            pass
        else:
            event_store_name = request.GET.get("es")
            for store in stores.iter_events_url_store_for_user(self.store_method_scope, self.request.user):
                if not store.name == event_store_name:
                    continue
                store_method = getattr(store, f"get_{self.store_method_scope}_events_url")
                url = store_method(**fetch_kwargs)
                if url:
                    return HttpResponseRedirect(url)
                break
        return HttpResponseRedirect(self.get_redirect_url())
