import logging
import re
from zentral.core.events import BaseEvent, EventMetadata, EventRequest, register_event_type, CommandEvent

COMMAND_RE = re.compile(r"zentral\$(?P<command>[a-zA-Z_]+)\$"
                        "(?P<serial_numbers>(?:[a-zA-Z0-9]+\$)+)+"
                        "(?P<arg>[a-zA-Z0-9]+)")

logger = logging.getLogger('zentral.contrib.zendesk.events')


class ZendeskTicketCreationEvent(BaseEvent):
    event_type = "zendesk_ticket_creation"

register_event_type(ZendeskTicketCreationEvent)


class ZendeskCommentCreationEvent(BaseEvent):
    event_type = "zendesk_comment_creation"

register_event_type(ZendeskCommentCreationEvent)


def post_zendesk_event(user_agent, ip, data):
    data_type = data['type']
    data = data['data']
    if data_type == 'ticket':
        event_class = ZendeskTicketCreationEvent
    elif data_type == 'comment':
        event_class = ZendeskCommentCreationEvent
        if not data['is_public']:
            for command, serial_numbers, arg in COMMAND_RE.findall(data['value']):
                for serial_number in serial_numbers.split('$'):
                    if serial_number:
                        command_metadata = EventMetadata(CommandEvent.event_type,
                                                         machine_serial_number=serial_number,
                                                         tags=['zendesk'])
                        command_event = CommandEvent(command_metadata,
                                                     {'command': command,
                                                      'arg': arg,
                                                      'source': data['ticket']['url']})
                        command_event.post()
    else:
        logger.error("Unknown zendesk event type '%s'", data_type)
        return
    msn = None  # TODO!!!
    metadata = EventMetadata(event_class.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip))
    event = event_class(metadata, data)
    event.post()
