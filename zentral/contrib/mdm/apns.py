import json
import os
import tempfile
from hyper import HTTP20Connection
from hyper.tls import init_context


APNs_PRODUCTION_SERVER = "api.push.apple.com"


def get_apns_client(push_certificate):
    # sadly have to materialize the certificate for apns2 and the ssl context
    tmp_cert_fd, tmp_cert = tempfile.mkstemp()
    with os.fdopen(tmp_cert_fd, "wb") as f:
        f.write(push_certificate.certificate)
    tmp_key_fd, tmp_key = tempfile.mkstemp()
    with os.fdopen(tmp_key_fd, "wb") as f:
        f.write(push_certificate.private_key)

    ssl_context = init_context()
    ssl_context.load_cert_chain(tmp_cert, tmp_key)
    os.unlink(tmp_cert)
    os.unlink(tmp_key)
    return HTTP20Connection(APNs_PRODUCTION_SERVER, force_proto="h2",
                            port=443, secure=True, ssl_context=ssl_context)


def send_device_notification(enrolled_device):
    conn = get_apns_client(enrolled_device.push_certificate)
    stream_id = conn.request("POST",
                             "/3/device/{}".format(enrolled_device.token.hex()),
                             body=json.dumps({"mdm": enrolled_device.push_magic}).encode("utf-8"),
                             headers={"Content-Type": "application/json; charset=utf-8",
                                      "apns-expiration": "3600",
                                      "apns-priority": "5",
                                      "apns-topic": enrolled_device.push_certificate.topic,
                                      })
    if stream_id:
        args = [stream_id]
    else:
        args = []
    response = conn.get_response(*args)
    if response.status == 410:
        # device token invalid. TODO what ???
        pass
    return response.status == 200
