from django.test import SimpleTestCase
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from zentral.utils.drf import FileDownloadContentNegotiation


class FileDownloadContentNegotiationTestCase(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.negotiation = FileDownloadContentNegotiation()

    def build_request(self, accept=None, path="/"):
        headers = {"Accept": accept} if accept else {}
        return Request(self.factory.get(path, headers=headers))

    def test_select_parser(self):
        parser = JSONParser()
        self.assertIs(self.negotiation.select_parser(self.build_request(), [parser]), parser)

    def test_select_renderer_no_accept(self):
        renderer = JSONRenderer()
        self.assertEqual(self.negotiation.select_renderer(self.build_request(), [renderer]),
                         (renderer, "application/json"))

    def test_select_renderer_accept_other_media_type(self):
        renderer = JSONRenderer()
        self.assertEqual(self.negotiation.select_renderer(self.build_request("text/plain"), [renderer]),
                         (renderer, "application/json"))

    def test_select_renderer_unknown_format(self):
        renderer = JSONRenderer()
        request = self.build_request(path="/?format=yolo")
        self.assertEqual(self.negotiation.select_renderer(request, [renderer], "yolo"), (renderer, "application/json"))
