import logging
import random
from tempfile import NamedTemporaryFile
import time
import httpx
from zentral.core.events.base import EventMetadata
from .events import MDMDeviceNotificationEvent


logger = logging.getLogger('zentral.contrib.mdm.apns')


class APNSClient(object):
    apns_production_base_url = "https://api.push.apple.com"
    timeout = 5
    max_retries = 2

    def __init__(self, push_certificate):
        self.push_certificate = push_certificate
        # We have to materialize the certificate
        # Python SSL contexts cannot load cert and key from memory
        # TODO update when the Python API is available
        with NamedTemporaryFile() as tmp_cert_file:
            tmp_cert_file.write(self.push_certificate.certificate.tobytes())
            tmp_cert_file.flush()
            with NamedTemporaryFile() as tmp_key_file:
                tmp_key_file.write(self.push_certificate.private_key.tobytes())
                tmp_key_file.flush()
                self.client = httpx.Client(base_url=self.apns_production_base_url,
                                           http2=True,
                                           verify=True,
                                           cert=(tmp_cert_file.name, tmp_key_file.name),
                                           timeout=self.timeout)

    def _send_notification(self, enrolled_device, target, priority, expiration_seconds):
        logger.debug("APNS notify device %s, target %s", enrolled_device, target)
        path = "/3/device/{}".format(target.token.hex())
        json_data = {"mdm": enrolled_device.push_magic}
        headers = {"apns-expiration": str(int(time.time()) + expiration_seconds),
                   "apns-priority": str(priority),
                   "apns-topic": self.push_certificate.topic}

        status = "failure"
        for retry_num in range(self.max_retries + 1):
            try:
                r = self.client.post(path, json=json_data, headers=headers)
            except Exception:
                logger.exception("Could not send notification")
            else:
                if r.status_code == httpx.codes.OK:
                    status = "success"
                    break
                elif r.status_code < 500:
                    # only retry 500s
                    break
                else:
                    logger.error("Status code: %s", r.status_code)

            sleep_time = random.random() * 2 ** retry_num
            logger.warning("Could not send notification. Sleep %.2f seconds before retry %s of %s.",
                           sleep_time, retry_num, self.MAX_RETRIES)
            time.sleep(sleep_time)

        event_metadata = EventMetadata(machine_serial_number=enrolled_device.serial_number)
        event_payload = {"status": status, "udid": enrolled_device.udid,
                         "apns_priority": priority, "apns_expiration_seconds": expiration_seconds}
        if target != enrolled_device:
            event_payload["user_id"] = target.user_id
        event = MDMDeviceNotificationEvent(event_metadata, event_payload)
        event.post()

        return status

    def _verify_enrolled_device(self, enrolled_device):
        if enrolled_device.push_certificate != self.push_certificate:
            raise ValueError("Enrolled device {} has a different push certificate".format(enrolled_device.pk))
        if not enrolled_device.can_be_poked():
            raise ValueError("Cannot send notification to enrolled device {}".format(enrolled_device.pk))

    def send_device_notification(self, enrolled_device, priority=10, expiration_seconds=3600):
        self._verify_enrolled_device(enrolled_device)
        return self._send_notification(enrolled_device, enrolled_device, priority, expiration_seconds)

    def send_user_notification(self, enrolled_user, priority=10, expiration_seconds=3600):
        enrolled_device = enrolled_user.enrolled_device
        self._verify_enrolled_device(enrolled_device)
        return self._send_notification(enrolled_device, enrolled_user, priority, expiration_seconds)
