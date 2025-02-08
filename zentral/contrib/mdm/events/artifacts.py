import logging
import uuid
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


logger = logging.getLogger('zentral.contrib.mdm.events.artifacts')


# Target Artifact


class TargetArtifactUpdateEvent(BaseEvent):
    event_type = "target_artifact_update"
    tags = ["mdm"]

    def get_linked_objects_keys(self):
        keys = {}
        # artifact, artifact version
        try:
            av = self.payload["target_artifact"]["artifact_version"]
            av_pk = av["pk"]
            a_pk = av["artifact"]["pk"]
        except KeyError:
            logging.warning("Missing event information")
        else:
            keys["mdm_artifact"] = [(a_pk,)]
            keys["mdm_artifactversion"] = [(av_pk,)]
        # enrolled user
        try:
            eu_pk = self.payload["enrolled_user"]["pk"]
        except KeyError:
            pass
        else:
            keys["mdm_enrolleduser"] = [(eu_pk,)]
        return keys


register_event_type(TargetArtifactUpdateEvent)


def post_target_artifact_update_events(target, payloads):
    event_uuid = uuid.uuid4()
    for index, payload in enumerate(payloads):
        event_metadata = EventMetadata(
            uuid=event_uuid, index=index,
            machine_serial_number=target.serial_number,
        )
        event = TargetArtifactUpdateEvent(event_metadata, payload)
        event.post()
