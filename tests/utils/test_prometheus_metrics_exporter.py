from unittest.mock import patch
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from prometheus_client import generate_latest, REGISTRY
from zentral.utils.prometheus import PrometheusMetricsExporter


class PrometheusMetricsExporterTestCase(SimpleTestCase):
    def test_init_without_extra_label_values(self):
        pme = PrometheusMetricsExporter(1234)
        self.assertEqual(pme.port, 1234)
        self.assertEqual(pme.counters, {})
        self.assertEqual(pme.default_labels, [])
        self.assertEqual(pme.default_label_values, ())

    def test_init_with_extra_label_values(self):
        pme = PrometheusMetricsExporter(1234, worker="test worker", yolo="fomo")
        self.assertEqual(pme.port, 1234)
        self.assertEqual(pme.counters, {})
        self.assertEqual(pme.default_labels, ["worker", "yolo"])
        self.assertEqual(pme.default_label_values, ("test worker", "fomo"))

    @patch("zentral.utils.prometheus.logger.error")
    def test_inc_missing_counter(self, logger_error):
        pme = PrometheusMetricsExporter(1234)
        missing_counter_name = get_random_string(12)
        pme.inc(missing_counter_name, "1", "2")
        logger_error.assert_called_once_with("Missing counter %s", missing_counter_name)

    def test_add_inc_without_extra_label_values(self):
        pme = PrometheusMetricsExporter(1234)
        counter_name = "test_" + get_random_string(12)
        pme.add_counter(counter_name, ["un", "deux"])
        pme.inc(counter_name, "1", "2")
        self.assertIn(
            f'{counter_name}_total{{deux="2",un="1"}} 1.0',
            generate_latest(REGISTRY).decode("utf-8"),
        )

    def test_add_inc_with_extra_label_values(self):
        worker_name = get_random_string(12)
        pme = PrometheusMetricsExporter(1234, worker=worker_name, a="b")
        counter_name = "test_" + get_random_string(12)
        pme.add_counter(counter_name, ["un", "deux"])
        pme.inc(counter_name, "1", "2")
        self.assertIn(
            f'{counter_name}_total{{a="b",deux="2",un="1",worker="{worker_name}"}} 1.0',
            generate_latest(REGISTRY).decode("utf-8"),
        )
