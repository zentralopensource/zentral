from zentral.conf import settings
from zentral.core.probes import probe_classes


def extra_links(request):
    """Django context processor to add the extra links from base.json"""
    extra_links = []
    for link in settings.get('extra_links', []):
        authorized_groups = link.get("authorized_groups", None)
        if authorized_groups and not request.user.is_superuser:
            if not request.user.group_name_set:
                # user is not a member of any group, it cannot be a match
                continue
            if not request.user.group_name_set.intersection(authorized_groups):
                # no common groups
                continue
        extra_links.append(link)
    return {'zentral_extra_links': extra_links}


def probe_creation_links(request):
    creation_links = sorted(({"anchor_text": "{} probe".format(pc.model_display),
                              "url": pc.create_url,
                              "permissions": ("probes.add_probesource",)}
                             for pc in probe_classes.values()),
                            key=lambda l: l["anchor_text"])
    return {'probe_extra_links': {'create': creation_links}}
