from django.core import signing
from django.urls import reverse
from django.utils.functional import cached_property
from zentral.conf import settings
from zentral.utils.api_views import API_SECRET, APIAuthError


class PuppetConf(object):
    @cached_property
    def instances(self):
        return {d["puppetdb_url"]: d for d in settings["apps"]["zentral.contrib.puppet"]["instances"]}

    def get_instances_with_secrets(self):
        for instance in self.instances.values():
            secret = signing.dumps({"url": instance["puppetdb_url"]}, key=API_SECRET)
            path = reverse("puppet:post_report", args=(secret,))
            url = "{}{}".format(settings['api']['tls_hostname'], path)
            yield instance, url

    def get_instance_with_secret(self, secret):
        try:
            data = signing.loads(secret, key=API_SECRET)
        except signing.BadSignature:
            raise APIAuthError("Bad secret signature")
        else:
            return self.instances[data["url"]]


puppet_conf = PuppetConf()
