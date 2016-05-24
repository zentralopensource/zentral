from django.core.urlresolvers import reverse
from django.http import Http404
from django.views.generic import TemplateView
from .conf import all_probes_dict


class BaseProbeView(TemplateView):
    template_name = "core/probes/probe.html"

    def get_extra_context_data(self, probe):
        return {}

    def get_context_data(self, **kwargs):
        context = super(BaseProbeView, self).get_context_data(**kwargs)
        context[self.section] = True
        try:
            probe = all_probes_dict[kwargs['probe_key']]
        except KeyError:
            raise Http404
        context['probe'] = probe
        context['breadcrumbs'] = [(reverse('%s:probes' % self.section),
                                   '%s probes' % self.section.title()),
                                  (None, probe.get('name', '?'))]
        context.update(self.get_extra_context_data(probe))
        return context
