from zentral.core.probes import register_probe_class, BaseProbe
from zentral.core.stores import stores


class SantaProbe(BaseProbe):
    def check(self):
        err_list = super(SantaProbe, self).check()
        if "santa" not in self.probe_d:
            raise ValueError("probe source without santa section")
        self.policies = self.probe_d['santa']
        if not isinstance(self.policies, list):
            err_list.append("santa section is not a list")
            return err_list
        if not self.policies:
            err_list.append("santa section is empty")
            return err_list
        if not self.metadata_filters:
            self.metadata_filters = [{'type': 'santa_event'}]
        else:
            # TODO: tags
            for metadata_filter in self.metadata_filters:
                if metadata_filter.setdefault('type', "santa_event") != "santa_event":
                    err_list.append("Wrong metadata filter")
                    return err_list

    def get_probe_links(self):
        # probe links. match all sha256 in the probe.
        probe_links = []
        probe_search_dict = {}
        all_file_sha256 = []
        all_certificate_sha256 = []
        for policy in self.policies:
            sha256 = policy['sha256']
            if policy['rule_type'] == 'CERTIFICATE':
                all_certificate_sha256.append(sha256)
            else:
                all_file_sha256.append(sha256)
        if all_file_sha256:
            probe_search_dict['file_sha256'] = all_file_sha256
        if all_certificate_sha256:
            probe_search_dict['certificate_sha256'] = all_certificate_sha256
        if probe_search_dict:
            for store in stores:
                url = store.get_visu_url(probe_search_dict)
                if url:
                    probe_links.append((store.name, url))
        probe_links.sort()
        return probe_links

    def get_extra_context(self):
        context = {}
        # policies
        policies = []
        for policy in self.policies:
            # policy links. match policy sha256.
            policy_links = []
            sha256 = policy['sha256']
            if policy['rule_type'] == 'CERTIFICATE':
                search_dict = {'signing_chain.sha256': [sha256]}
            else:
                search_dict = {'file_sha256': [sha256]}
            for store in stores:
                # match
                url = store.get_visu_url(search_dict)
                if url:
                    policy_links.append((store.name, url))
            policy_links.sort()
            policies.append((policy, policy_links))
        context['santa_policies'] = policies
        return context


register_probe_class(SantaProbe)
