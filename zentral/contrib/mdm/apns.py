import logging
import random
import time
import threading
from django.utils.functional import SimpleLazyObject
import httpx
from zentral.utils.ssl import create_client_ssl_context
from .events import build_mdm_device_notification_event
from .models import PushCertificate


logger = logging.getLogger('zentral.contrib.mdm.apns')


# client


class APNSClient:
    apns_production_base_url = "https://api.push.apple.com"
    timeout = 5
    max_retries = 2

    def __init__(self, topic, not_after, cert, privkey):
        self.topic = topic
        self.not_after = not_after
        ssl_context = create_client_ssl_context(cert, privkey)
        self.client = httpx.Client(
            base_url=self.apns_production_base_url,
            http2=True,
            verify=ssl_context,
            timeout=self.timeout
        )

    @classmethod
    def from_push_certificate(cls, push_certificate):
        return cls(
            push_certificate.topic,
            push_certificate.not_after,
            push_certificate.certificate,
            push_certificate.get_private_key(),
        )

    def send_notification(self, token, push_magic, priority=10, expiration_seconds=3600):
        if isinstance(token, (bytes, memoryview)):
            token = token.hex()

        log_tmpl = "Notify topic %s, device %s, priority %d, expiration %ds"
        logger.debug(log_tmpl, self.topic, token, priority, expiration_seconds)

        url = f"/3/device/{token}"
        payload = {"mdm": push_magic}
        headers = {"apns-push-type": "mdm",
                   "apns-expiration": str(int(time.time()) + expiration_seconds),
                   "apns-priority": str(priority),
                   "apns-topic": self.topic}

        success = False

        for retry_num in range(self.max_retries + 1):
            try:
                r = self.client.post(url, json=payload, headers=headers)
            except Exception:
                logger.exception(f"{log_tmpl}: error", self.topic, token, priority, expiration_seconds)
            else:
                if r.status_code == httpx.codes.OK:
                    logger.debug(f"{log_tmpl}: OK", self.topic, token, priority, expiration_seconds)
                    success = True
                    break
                logger.error(f"{log_tmpl}: status %d", self.topic, token, priority, expiration_seconds, r.status_code)
                if r.status_code < 500:
                    # only retry 500s
                    break
            sleep_time = random.random() * 2 ** retry_num
            logger.warning(f"{log_tmpl}: sleep %.2f seconds before retry %s of %s.",
                           self.topic, token, priority, expiration_seconds,
                           sleep_time, retry_num, self.max_retries)
            time.sleep(sleep_time)

        return success


# client cache


class APNSClientCache:
    def __init__(self):
        self._clients = {}
        self._lock = threading.Lock()

    def get_or_create(self, topic, not_after, push_cert=None):
        assert push_cert is None or (push_cert.topic == topic and push_cert.not_after == not_after)
        with self._lock:
            client = self._clients.get(topic)
            if not client or client.not_after < not_after:
                if push_cert is None:
                    try:
                        push_cert = PushCertificate.objects.get(topic=topic)
                    except PushCertificate.DoesNotExist:
                        logger.warning("Could not find push certificate with topic %s", topic)
                        return
                client = APNSClient.from_push_certificate(push_cert)
                self._clients[topic] = client
            return client

    def get_or_create_with_push_cert(self, push_cert):
        return self.get_or_create(push_cert.topic, push_cert.not_after, push_cert)


apns_client_cache = SimpleLazyObject(lambda: APNSClientCache())


# utils


def _send_target_notification(enrolled_device, token, user_id=None, priority=10, expiration_seconds=3600):
    target_type = "device" if user_id is None else "user"
    target_pk = enrolled_device.pk if user_id is None else user_id
    if not enrolled_device.can_be_poked() or not token:
        logger.error("Enrolled %s %s cannot be poked.", target_type, target_pk)
        return False, None
    client = apns_client_cache.get_or_create_with_push_cert(enrolled_device.push_certificate)
    success = client.send_notification(token, enrolled_device.push_magic, priority, expiration_seconds)
    return success, build_mdm_device_notification_event(
        enrolled_device.serial_number, enrolled_device.udid,
        priority, expiration_seconds,
        success, user_id
    )


def send_enrolled_user_notification(enrolled_user, post_event=True):
    success, event = _send_target_notification(
        enrolled_user.enrolled_device, enrolled_user.token, enrolled_user.user_id
    )
    if post_event and event:
        event.post()
    return success, event


def send_enrolled_device_notification(enrolled_device, post_event=True):
    success, event = _send_target_notification(
        enrolled_device, enrolled_device.token
    )
    if post_event and event:
        event.post()
    return success, event
