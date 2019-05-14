#!/usr/bin/python3
import base64
import os
from asn1crypto import csr
import requests

ZENTRAL_API_HEADERS = {
    "Content-Type": "application/json",
    "Zentral-API-Secret": os.environ["ZENTRAL_API_SECRET"]
}


def parse(data):
    d = {}
    yolo = csr.CertificationRequest.load(data)
    info = yolo["certification_request_info"]

    # subject
    subject = info["subject"]
    for rdn_idx, rdn in enumerate(subject.chosen):
        for type_val_idx, type_val in enumerate(rdn):
            d[type_val["type"].native] = type_val['value'].native

    # attributes
    for attribute in info["attributes"]:
        if attribute["type"].native == "challenge_password":
            d["challenge_password"] = "".join(v.native for v in attribute["values"])
            break
    return d


def enrollment_secret_verification_dict(data):
    return {"csr": base64.b64encode(data).decode("ascii")}


def url(csr_d):
    path = base64.b64decode(csr_d["challenge_password"].encode("ascii")).decode("utf-8")
    return "{}{}".format(os.environ["ZENTRAL_API_BASE_URL"].rstrip("/"), path)


def post_verification_d(url, v_d):
    r = requests.post(url, json=v_d, headers=ZENTRAL_API_HEADERS)
    r.raise_for_status()
    return r.json


def verify_csr(data):
    return post_verification_d(
        url(parse(data)),
        enrollment_secret_verification_dict(data)
    )


if __name__ == "__main__":
    import pprint
    import sys
    pprint.pprint(verify_csr(sys.stdin.buffer.read()))
