from zentral.conf import settings


def extra_links(request):
    """Django context processor to add the extra links from base.json"""
    return {'zentral_extra_links': settings.get('extra_links', [])}
