from zentral.conf import settings
from zentral.core.probes import probe_classes


def extra_links(request):
    """Django context processor to add the extra links from base.json"""
    return {'zentral_extra_links': settings.get('extra_links', [])}


def probe_creation_links(request):
    creation_links = sorted(({"anchor_text": "{} probe".format(pc.model_display),
                              "url": pc.create_url}
                             for pc in probe_classes.values()),
                            key=lambda l: l["anchor_text"])
    return {'probe_extra_links': {'create': creation_links}}
