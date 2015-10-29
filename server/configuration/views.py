from django.views import generic
from zentral.conf import probes
from zentral.contrib.osquery.models import DistributedQuery
from zentral.core.stores import stores


class IndexView(generic.TemplateView):
    template_name = "configuration/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        probe_l = [(k, probe) for k, probe in probes.items()]
        probe_l.sort()
        context['probes'] = probe_l
        context['configuration'] = True
        context['last_dq'] = DistributedQuery.objects.all()[:10]
        return context


class ProbeView(generic.TemplateView):
    template_name = "configuration/probe.html"

    def get_context_data(self, **kwargs):
        context = super(ProbeView, self).get_context_data(**kwargs)
        probe = probes[kwargs['probe_key']]
        context['probe'] = probe
        context['configuration'] = True
        probe_links = []
        schedule = []
        file_paths = {}
        if 'osquery' in probe:
            for store in stores:
                url = store.get_osquery_probe_visu_url(probe['name'])
                if url:
                    probe_links.append((store.name, url))
            for idx, osquery in enumerate(probe['osquery']['schedule']):
                query_links = []
                query_name = "{}_{}".format(probe['name'], idx)
                for store in stores:
                    url = store.get_osquery_query_visu_url(query_name)
                    if url:
                        query_links.append((store.name, url))
                query_links.sort()
                schedule.append((osquery, query_links))
            file_paths = probe['osquery'].get('file_paths', {})
        probe_links.sort()
        context['probe_links'] = probe_links
        context['osquery_schedule'] = schedule
        context['osquery_file_paths'] = file_paths
        return context
