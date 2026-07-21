"""
Custom drf-spectacular documentation views.

Kept out of this package's __init__ (which settings.py imports at settings-load
time) because these views pull in DRF and drf-spectacular view classes — importing
those before the app registry is ready would be fragile. Only imported from urls.py,
once apps are loaded.
"""
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView

from drf_spectacular.plumbing import get_relative_url, set_query_parameters
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import AUTHENTICATION_CLASSES


class SpectacularElementsView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    permission_classes = spectacular_settings.SERVE_PERMISSIONS
    authentication_classes = AUTHENTICATION_CLASSES
    url_name = 'schema'
    url = None
    template_name = 'openapi/elements.html'
    title = spectacular_settings.TITLE

    @extend_schema(exclude=True)
    def get(self, request, *args, **kwargs):
        # Elements' JS/CSS are bundled locally via webpack (see elements.html);
        # the template references them directly, so no dist URLs are passed here.
        return Response(
            data={
                'title': self.title,
                'schema_url': self._get_schema_url(request),
            },
            template_name=self.template_name
        )

    def _get_schema_url(self, request):
        schema_url = self.url or get_relative_url(reverse(self.url_name, request=request))
        return set_query_parameters(
            url=schema_url,
            lang=request.GET.get('lang'),
            version=request.GET.get('version')
        )
