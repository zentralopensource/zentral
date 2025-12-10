from django.test import SimpleTestCase
from zentral.core.incidents.templatetags.incidents_extras import incident_severity


class IncidentsExtrasTestCase(SimpleTestCase):
    def test_incident_severity(self):
        for severity, display, color in ((300, "Critical", "ff0000"),
                                         (200, "Major", "ff9900"),
                                         (100, "Minor", "DDDD00"),):
            result = (
                '<span class="label rounded p-1" '
                f'style="white-space:nowrap;background-color:#{color};color:#FFF">'
                f'{display}&nbsp;<i class="bi bi-exclamation-triangle-fill"></i>'
                '</span>'
            )
            self.assertEqual(incident_severity(severity), result)
        self.assertEqual(incident_severity(None), "")
