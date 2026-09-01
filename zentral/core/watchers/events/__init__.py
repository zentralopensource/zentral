import logging
from enum import Enum

from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent


logger = logging.getLogger("zentral.core.watchers.events")


ALL_EVENTS_SEARCH_DICT = {"tag": "watch"}


class WatchStatus(Enum):
    """What a watch event says about its subject.

    One event type per watch carries all of these rather than one type per outcome: a pager wants the
    alert and its resolution on the same stream, or the page never closes on its own. Reading it off the
    payload rather than off `reasons` being empty is deliberate — emptiness is not something every filter
    can express, and a status is something a human can read.
    """
    DEGRADED = "degraded"
    RECOVERED = "recovered"
    UNWATCHED = "unwatched"


class SubjectUnwatchedEvent(BaseEvent):
    """A subject was still degraded when it stopped being watched at all.

    Not a recovery: nothing was fixed. The subject left the watch's domain — deleted, archived, or simply
    out of scope, which is why the name says nothing about it still existing. It exists because an
    incident can only be closed by an event carrying the update, and leaving one open on a subject nobody
    watches makes it unclosable: the state row is gone, so no later tick will ever emit about it again.
    """
    event_type = "subject_unwatched"
    namespace = "watch"
    tags = ["watch"]


register_event_type(SubjectUnwatchedEvent)
