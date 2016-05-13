import logging
from zentral.core.events import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.zendesk.events')


class ZendeskTicketCreationEvent(BaseEvent):
    event_type = "zendesk_ticket_creation"

register_event_type(ZendeskTicketCreationEvent)


class ZendeskCommentCreationEvent(BaseEvent):
    event_type = "zendesk_comment_creation"

register_event_type(ZendeskCommentCreationEvent)


def post_zendesk_event(user_agent, ip, data):
    if data['type'] == 'ticket':
        event_class = ZendeskTicketCreationEvent
    else:
        logger.error("Unknown zendesk event type '%s'", data['type'])
        return
    msn = None  # TODO!!!
    metadata = EventMetadata(event_class.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip))
    event = event_class(metadata, data)
    event.post()
