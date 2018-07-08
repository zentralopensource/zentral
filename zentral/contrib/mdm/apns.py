import json
import logging
import os
import random
import tempfile
import time
from hyper import HTTP20Connection
from hyper.tls import init_context
from zentral.core.events.base import EventMetadata
from .events import MDMDeviceNotificationEvent


logger = logging.getLogger('zentral.contrib.mdm.apns')


class APNSClient(object):
    APNs_PRODUCTION_SERVER = "api.push.apple.com"
    STATUS_SUCCESS = "success"
    STATUS_FAILURE = "failure"
    STATUS_INVALID_TOKEN = "invalid_token"
    MAX_RETRIES = 3

    def __init__(self, push_certificate):
        self.push_certificate = push_certificate
        self.conn = None

    def get_ssl_context(self):
        # sadly have to materialize the certificate for apns2 and the ssl context
        # TODO: verify
        tmp_cert_fd, tmp_cert = tempfile.mkstemp()
        with os.fdopen(tmp_cert_fd, "wb") as f:
            f.write(self.push_certificate.certificate)
        tmp_key_fd, tmp_key = tempfile.mkstemp()
        with os.fdopen(tmp_key_fd, "wb") as f:
            f.write(self.push_certificate.private_key)

        # load the certificates in a ssl context
        ssl_context = init_context()
        ssl_context.load_cert_chain(tmp_cert, tmp_key)

        # remove the temp files
        os.unlink(tmp_cert)
        os.unlink(tmp_key)

        return ssl_context

    def get_connection(self):
        self.conn = HTTP20Connection(self.APNs_PRODUCTION_SERVER,
                                     force_proto="h2",
                                     port=443, secure=True,
                                     ssl_context=self.get_ssl_context())

    def build_event(self, enrolled_device, response_status, **payload):
        status = self.STATUS_FAILURE
        if response_status == 200:
            status = self.STATUS_SUCCESS
        elif response_status == 410:
            status = self.STATUS_INVALID_TOKEN
        metadata = EventMetadata(MDMDeviceNotificationEvent.event_type,
                                 machine_serial_number=enrolled_device.serial_number,
                                 tags=MDMDeviceNotificationEvent.tags)
        payload.update({"status": status,
                        "response_status": response_status})
        return MDMDeviceNotificationEvent(metadata, payload)

    def send_device_notification(self, enrolled_device, apns_expiration=3600, apns_priority=5):
        if enrolled_device.push_certificate != self.push_certificate:
            raise ValueError("Enrolled device {} has a different push certificate".format(enrolled_device.pk))
        if not enrolled_device.can_be_poked():
            raise ValueError("Cannot send notification to enrolled device {}".format(enrolled_device.pk))
        url = "/3/device/{}".format(enrolled_device.token.hex())
        body = json.dumps({"mdm": enrolled_device.push_magic}).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8",
                   "apns-expiration": str(apns_expiration),
                   "apns-priority": str(apns_priority),
                   "apns-topic": self.push_certificate.topic}
        if self.conn is None:
            self.get_connection()
        for retry_num in range(self.MAX_RETRIES + 1):
            if retry_num > 0:
                sleep_time = random.random() * 2 ** retry_num
                logger.warning("Could not send notification to device %s. "
                               "Sleep %.2f seconds before retry %s of %s.",
                               enrolled_device.serial_number, sleep_time, retry_num, self.MAX_RETRIES)
                time.sleep(sleep_time)
            try:
                if retry_num > 0:
                    self.get_connection()
                stream_id = self.conn.request("POST", url, body=body, headers=headers)
                if stream_id:
                    args = [stream_id]
                else:
                    args = []
                response = self.conn.get_response(*args)
            except Exception:
                if retry_num == self.MAX_RETRIES:
                    logger.exception("Could not send notification to device %s.", enrolled_device.serial_number)
                else:
                    continue
            else:
                return self.build_event(enrolled_device, response.status,
                                        apns_expiration=apns_expiration,
                                        apns_priority=apns_priority)
