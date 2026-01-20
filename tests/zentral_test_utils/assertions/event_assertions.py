from abc import ABC
from zentral.core.events.base import AuditEvent


class EventAssertions(ABC):

    def __init__(self):
        super().__init__()

    def _assertNoEventPublished(self, callbacks, post_event):
        self._assertEventsPublished(0, callbacks, post_event)

    def _assertEventsPublished(self, expected_number_of_events, callbacks, post_event):
        self.assertEqual(len(callbacks), expected_number_of_events)
        self.assertEqual(len(post_event.call_args_list), expected_number_of_events)

    def _assertIsAuditEvent(self, expected_payload, expected_metadata_objects, post_event,
                            expected_order=0, expected_tags=["accounts", "zentral"]):
        event = post_event.call_args_list[expected_order].args[0]
        self.assertIsInstance(event, AuditEvent)

        self.assertEqual(
            event.payload,
            expected_payload
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], expected_metadata_objects)
        self.assertEqual(sorted(metadata["tags"]), expected_tags)
