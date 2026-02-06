from datetime import datetime, timedelta
from typing import List
from unittest.mock import Mock

from celpy import celtypes, json_to_cel
from django.test import TestCase

from zentral.core.events.transformers import CELEventTranformer, EventTransformerError


class CELEventTranformerTestCase(TestCase):
    def setUp(self):
        self.src_cel = """
        {"serial_number": "machine_serial_number" in metadata ? metadata.machine_serial_number : null,
        "not_after": metadata.created_at}
        """
        self.data = {
            "godzilla": "yo",
            "_zentral": {
                "machine_serial_number": "012345678910",
                "created_at": "2026-01-14T19:06:44.979100+00:00",
                "id": "fdf645b2-e347-4235-bbf2-bb7333419738",
                "index": 0,
                "type": "event_type_3",
                "namespace": "event_type_3",
            },
        }

    def test_cel_verify_false(self):
        with self.assertRaises(ValueError) as cm:
            CELEventTranformer('{"iamwrong":}')
        self.assertEqual(cm.exception.args[0], "Could not load CEL source")

    def test_cel_transform(self):
        cel_trans = CELEventTranformer(self.src_cel)
        self.assertEqual(
            cel_trans.transform(self.data),
            {"serial_number": "012345678910",
             "not_after": "2026-01-14T19:06:44.979100+00:00"},
        )

    def test_cel_transform_no_event(self):
        cel_trans = CELEventTranformer(self.src_cel)
        with self.assertRaises(EventTransformerError) as cm:
            cel_trans.transform({"yolo": {"json": "but no data"}})
        self.assertEqual(cm.exception.args[0], "No zentral event given")

    def test_cel_transform_failed(self):
        cel_trans = CELEventTranformer(self.src_cel)
        with self.assertRaises(EventTransformerError) as cm:
            cel_trans.transform({"_zentral": {"machine_serial_xxx": "wrong index"}})
        self.assertEqual(cm.exception.args[0], "CEL evaluation error")

    def test_cel_transform_exception(self):
        cel_trans = CELEventTranformer(self.src_cel)
        cel_trans.program = Mock()
        cel_trans.program.evaluate.side_effect = Exception()
        with self.assertRaises(Exception) as cm:
            cel_trans.transform({"_zentral": {"something": "wrong something"}})
        self.assertEqual(cm.exception.args[0], "Unknown evaluation error")

    def test_cel_transform_to_python(self):
        cel_trans = CELEventTranformer(self.src_cel)
        cel_context = json_to_cel({
            "list": ["apple", "banana", "cherry"],
            "boolean": True,
            "time": datetime.now(),
        })
        result = cel_trans.to_python(cel_object=cel_context)
        self.assertEqual(isinstance(result['boolean'], bool), True)
        self.assertEqual(isinstance(result['list'], List), True)
        cel_context = json_to_cel({
            "timedelta": timedelta(days=13, seconds=12, microseconds=11)
        })
        with self.assertRaises(EventTransformerError) as cm:
            cel_trans.to_python(cel_object=cel_context)
        self.assertEqual(cm.exception.args[0], "DurationType is not supported")
        cel_context = celtypes.BytesType(b'Bytes me')
        with self.assertRaises(EventTransformerError) as cm:
            cel_trans.to_python(cel_object=cel_context)
        self.assertEqual(cm.exception.args[0], "BytesType is not supported")
        cel_context = celtypes.TypeType(type)
        with self.assertRaises(EventTransformerError) as cm:
            cel_trans.to_python(cel_object=cel_context)
        self.assertEqual(cm.exception.args[0], "TypeType / type is not supported")
