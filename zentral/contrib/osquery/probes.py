from zentral.core.probes import register_probe_class, BaseProbe
from zentral.core.stores import stores
from zentral.utils.sql import format_sql


class OSQueryProbe(BaseProbe):
    def check(self):
        err_list = super(OSQueryProbe, self).check()
        if "osquery" not in self.probe_d:
            raise ValueError("probe source without osquery section")
        osquery = self.probe_d["osquery"]
        if not isinstance(osquery, dict):
            err_list.append("osquery probe section not a hash/dict")
            return err_list
        if not osquery:
            err_list.append("osquery probe section is empty")
            return err_list
        self.schedule = osquery.get("schedule", [])
        if not isinstance(self.schedule, list):
            err_list.append("osquery schedule is not a list")
            return err_list
        if not self.schedule:
            err_list.append("osquery schedule is empty")
            return err_list
        self.file_paths = osquery.get("file_paths", {})
        if not isinstance(self.file_paths, dict):
            err_list.append("osquery file_paths is not a hash/dict")
            return err_list
        if not self.metadata_filters:
            self.metadata_filters = [{'type': 'osquery_result'}]
        else:
            # TODO: tags
            for metadata_filter in self.metadata_filters:
                if metadata_filter.setdefault('type', "osquery_result") != "osquery_result":
                    err_list.append("Wrong metadata filter")
                    return err_list

    def iter_schedule_queries(self):
        for idx, osquery_query in enumerate(self.schedule):
            yield ('%s_%d' % (self.name, idx), osquery_query)

    def get_probe_links(self):
        # query name starts with probe name.
        probe_links = []
        for store in stores:
            url = store.get_visu_url({'name__startswith': [self.name]})
            if url:
                probe_links.append((store.name, url))
        probe_links.sort()
        return probe_links

    def get_extra_context(self):
        # queries
        schedule = []
        for query_name, osquery_query in self.iter_schedule_queries():
            # query links. match query_name.
            osquery_ctx = {}
            query_links = []
            for store in stores:
                url = store.get_visu_url({'name': [query_name]})
                if url:
                    query_links.append((store.name, url))
            query_links.sort()
            osquery_ctx['links'] = query_links
            osquery_ctx['html_query'] = format_sql(osquery_query['query'])
            osquery_ctx['interval'] = osquery_query.get('interval', None)
            osquery_ctx['value'] = osquery_query.get('value', None)
            osquery_ctx['description'] = osquery_query.get('description', None)
            schedule.append(osquery_ctx)
        return {'osquery_schedule': schedule,
                'osquery_file_paths': self.file_paths}


register_probe_class(OSQueryProbe)
