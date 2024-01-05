from importlib import import_module
import json
import logging
from urllib.parse import urlparse
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template import loader
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.functional import SimpleLazyObject
from django.utils.http import urlsafe_base64_encode
from zentral.conf import settings


logger = logging.getLogger('zentral.accounts.password_reset')


class BasePasswordResetHandler:
    def __init__(self, config):
        pass

    @staticmethod
    def generate_password_reset_url(user):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        if isinstance(uid, bytes):
            uid = uid.decode("ascii")
        token = default_token_generator.make_token(user)
        return "{}{}".format(
            settings["api"]["tls_hostname"],
            reverse('password_reset_confirm', args=(uid, token))
        )

    @classmethod
    def get_password_reset_context(cls, user, invitation=False):
        return {
            "email": getattr(user, user.get_email_field_name()),
            "username": user.get_username(),
            "fqdn": settings["api"]["fqdn"],
            "reset_url": cls.generate_password_reset_url(user),
            "invitation": invitation,
        }

    def send_password_reset(self, user, invitation=False):
        context = self.get_password_reset_context(user, invitation)
        reset_type = "invitation" if invitation else "password reset"
        try:
            self.send_password_reset_context(context)
        except Exception:
            logger.exception(
                "%s: could not send %s to user %s",
                self.__class__.__name__,
                reset_type,
                user.pk
            )
        else:
            logger.info(
                "%s: %s sent to user %s",
                self.__class__.__name__,
                reset_type,
                user.pk
            )
        return context

    def send_password_reset_context(self, context):
        raise NotImplementedError


class EmailPasswordResetHandler(BasePasswordResetHandler):
    def send_password_reset_context(self, context):
        template_prefix = "invitation" if context["invitation"] else "password_reset"
        subject = loader.render_to_string(f"registration/{template_prefix}_subject.txt", context)
        subject = ''.join(subject.splitlines())
        body = loader.render_to_string(f"registration/{template_prefix}_email.html", context)
        send_mail(subject, body, None, [context["email"]])


class AWSSQSPasswordResetHandler(BasePasswordResetHandler):
    def __init__(self, config):
        self.queue_url = config["queue_url"]
        pr = urlparse(self.queue_url)
        prefix, self.region_name, domain = pr.netloc.split(".", 2)
        assert prefix == "sqs" and domain == "amazonaws.com"
        self._client = None

    def get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("sqs", region_name=self.region_name)
        return self._client

    def send_password_reset_context(self, context):
        self.get_client().send_message(
            QueueUrl=self.queue_url,
            MessageBody=json.dumps(context)
        )


class GCPPubSubPasswordResetHandler(BasePasswordResetHandler):
    def __init__(self, config):
        self.topic = config["topic"]
        self._client = None

    def get_client(self):
        if self._client is None:
            from google.cloud import pubsub_v1
            self._client = pubsub_v1.PublisherClient()
        return self._client

    def send_password_reset_context(self, context):
        self.get_client().publish(
            self.topic,
            json.dumps(context).encode("utf-8"),
        )


def get_password_reset_handler():
    config = settings.get("password_reset_handler", {})
    backend = config.get("backend", "accounts.password_reset.EmailPasswordResetHandler")
    logger.debug("Load password reset handler %s", backend)
    module, class_name = backend.rsplit(".", 1)
    handler_class = getattr(import_module(module), class_name)
    return handler_class(config)


handler = SimpleLazyObject(get_password_reset_handler)
