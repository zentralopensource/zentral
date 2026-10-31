from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


__all__ = [
    "MDMStatusReportCleanupFinished",
    "MDMStatusReportCleanupStarted",
    "post_status_report_cleanup_finished_event",
    "post_status_report_cleanup_started_event",
]


class BaseMDMStatusReportCleanupEvent(BaseEvent):
    namespace = "mdm_status_report_cleanup"
    tags = ["mdm", "mdm_status_report_cleanup", "zentral"]


class MDMStatusReportCleanupStarted(BaseMDMStatusReportCleanupEvent):
    event_type = "mdm_status_report_cleanup_started"


register_event_type(MDMStatusReportCleanupStarted)


def post_status_report_cleanup_started_event(payload):
    MDMStatusReportCleanupStarted(EventMetadata(), {"cleanup": payload}).post()


class MDMStatusReportCleanupFinished(BaseMDMStatusReportCleanupEvent):
    event_type = "mdm_status_report_cleanup_finished"


register_event_type(MDMStatusReportCleanupFinished)


def post_status_report_cleanup_finished_event(payload):
    MDMStatusReportCleanupFinished(EventMetadata(), {"cleanup": payload}).post()
