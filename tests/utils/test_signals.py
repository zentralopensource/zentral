import signal
import threading
from unittest.mock import Mock, patch
from django.test import SimpleTestCase
from zentral.utils.signals import setup_signal_handler


class SetupSignalHandlerTestCase(SimpleTestCase):
    @patch("zentral.utils.signals.signal.signal")
    def test_wires_given_signals_on_main_thread(self, signal_signal):
        signal_signal.return_value = "previous"
        handler = Mock()
        previous = setup_signal_handler(handler, signal.SIGTERM, signal.SIGINT)
        self.assertEqual(previous, {signal.SIGTERM: "previous", signal.SIGINT: "previous"})
        signal_signal.assert_any_call(signal.SIGTERM, handler)
        signal_signal.assert_any_call(signal.SIGINT, handler)
        self.assertEqual(signal_signal.call_count, 2)

    @patch("zentral.utils.signals.signal.signal")
    def test_defaults_to_sigint_and_sigterm(self, signal_signal):
        setup_signal_handler(Mock())
        self.assertEqual(
            {c.args[0] for c in signal_signal.call_args_list},
            {signal.SIGINT, signal.SIGTERM},
        )

    @patch("zentral.utils.signals.signal.signal")
    def test_skips_wiring_off_main_thread(self, signal_signal):
        results = {}

        def worker():
            results["previous"] = setup_signal_handler(Mock(), signal.SIGTERM)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        self.assertEqual(results["previous"], {})
        signal_signal.assert_not_called()
