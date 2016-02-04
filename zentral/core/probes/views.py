from django.core.urlresolvers import reverse
from django.http import Http404
from django.views.generic import TemplateView
from zentral.conf import probes


class BaseProbeView(TemplateView):
    template_name = "core/probes/probe.html"

    def get_probe(self, **kwargs):
        # TODO log(1)
        for probe_name, probe_d in probes.items():
            if probe_name == kwargs['probe_key']:
                return probe_d
                break

    def get_extra_context_data(self, probe):
        return {}

    def get_context_data(self, **kwargs):
        context = super(BaseProbeView, self).get_context_data(**kwargs)
        context[self.section] = True
        probe = self.get_probe(**kwargs)
        if not probe:
            raise Http404
        context['probe'] = probe
        context['breadcrumbs'] = [(reverse('%s:probes' % self.section),
                                   '%s probes' % self.section.title()),
                                  (None, probe.get('name', '?'))]
        context.update(self.get_extra_context_data(probe))
        return context
