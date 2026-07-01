from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import F
from zentral.utils.views import UserPaginationListView


class SearchFormListView(PermissionRequiredMixin, UserPaginationListView):
    # a list view driven by a search form exposing get_queryset(); subclasses set search_form_class
    search_form_class = None

    def get(self, request, *args, **kwargs):
        self.form = self.search_form_class(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            ctx["reset_link"] = f"?{qd.urlencode()}"
        return ctx


class JobDetailMixin:
    # shared by ScriptView / MSCPCheckView: the scheduled and one-time jobs that run this definition
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        job = self.object.job
        ctx["recurring_jobs"] = (
            job.recurringjob_set.select_related("configuration")
            .prefetch_related("tags", "excluded_tags")
            .order_by("configuration__name", "pk")
        )
        ctx["one_time_jobs"] = (
            job.onetimejob_set.select_related("configuration")
            .prefetch_related("tags", "excluded_tags")
            .order_by(F("not_before").desc(nulls_last=True), "-created_at")
        )
        return ctx
