import json
import requests
from django.conf import settings
from django.utils.log import AdminEmailHandler

API_ENDPOINT = "https://slack.com/api/chat.postMessage"


class SlackHandler(AdminEmailHandler):
    def send_mail(self, subject, message, *args, **kwargs):
        args = {'text': "\n\n".join([subject, message])}
        if hasattr(settings, 'SLACK_ERROR_REPORTING_WEBHOOK'):
            url = settings.SLACK_ERROR_REPORTING_WEBHOOK
        else:
            args.update({'token': settings.SLACK_ERROR_REPORTING_TOKEN,
                         'channel': settings.SLACK_ERROR_REPORTING_CHANNEL,
                         'username': settings.SLACK_ERROR_REPORTING_USERNAME})
            url = API_ENDPOINT
        requests.post(url, headers={'Accept': 'application/json'}, data=json.dumps(args))
