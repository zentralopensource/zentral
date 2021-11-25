import logging
import math
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView
from zentral.contrib.santa.models import Target
from zentral.contrib.santa.forms import TargetSearchForm

logger = logging.getLogger('zentral.contrib.santa.views.targets')


# configuration / enrollment


class TargetsView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.view_target"
    template_name = "santa/targets.html"
    paginate_by = 10

    def dispatch(self, request, *args, **kwargs):
        self.form = TargetSearchForm(self.request.GET)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["form"] = self.form

        # current page
        try:
            page = int(self.request.GET.get("page", 1))
        except Exception:
            page = 1
        page = max(1, page)
        offset = (page - 1) * self.paginate_by

        # fetch results
        ctx["targets"] = Target.objects.search(q=self.form.cleaned_data.get("q"),
                                               target_type=self.form.cleaned_data.get("target_type"),
                                               offset=offset, limit=self.paginate_by)

        # total
        try:
            total = ctx["targets"][0]["full_count"]
        except IndexError:
            total = 0
        ctx["target_count"] = total

        # export links
        ctx['export_links'] = []
        for fmt in ("xlsx", "zip"):
            qd = self.request.GET.copy()
            qd.pop("page", None)
            qd["export_format"] = fmt
            ctx['export_links'].append((
                fmt, f'{reverse("santa_api:targets_export")}?{qd.urlencode()}'
            ))

        # pagination
        ctx["page_num"] = page
        ctx["num_pages"] = math.ceil(total / self.paginate_by) or 1
        if page > 1:
            qd = self.request.GET.copy()
            qd["page"] = page - 1
            ctx["previous_url"] = f"?{qd.urlencode()}"
            qd.pop("page")
            ctx["reset_link"] = f"?{qd.urlencode()}"
        if offset + self.paginate_by < total:
            qd = self.request.GET.copy()
            qd["page"] = page + 1
            ctx["next_url"] = f"?{qd.urlencode()}"

        return ctx
