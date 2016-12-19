import logging
from zentral.core.events.base import BaseEvent, register_event_type, post_command_events


logger = logging.getLogger('zentral.contrib.zendesk.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "zendesk"}


class BaseZendeskEvent(BaseEvent):
    tags = ["zendesk"]


class ZendeskTicketCreationEvent(BaseZendeskEvent):
    event_type = "zendesk_ticket_creation"


register_event_type(ZendeskTicketCreationEvent)


class ZendeskCommentCreationEvent(BaseZendeskEvent):
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
            post_command_events(data['value'], data['ticket']['url'], ['zendesk'])
    else:
        logger.error("Unknown zendesk event type '%s'", data_type)
        return
    msn = None  # TODO!!!
    event_class.post_machine_request_payloads(msn, user_agent, ip, [data])
