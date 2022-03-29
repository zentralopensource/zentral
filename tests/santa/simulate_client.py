import pprint
import sys
import time
import requests


def do_preflight(enrollment_url, uuid, sn, verify_tls=True):
    payload = {
        "serial_num": sn,
        "os_build": "19H2",
        "os_version": "10.15.7",
        "hostname": "rocchetto",
        "santa_version": "1.15.0",
    }
    kwargs = {"json": payload}
    if not verify_tls:
        kwargs["verify"] = False
    r = requests.post(f"{enrollment_url}preflight/{uuid}", **kwargs)
    r.raise_for_status()
    pprint.pprint(r.json())


def do_rules_download(enrollment_url, uuid):
    while True:
        r = requests.post(f"{enrollment_url}ruledownload/{uuid}", json={})
        r.raise_for_status()
        pprint.pprint(r.json())
        time.sleep(1)


if __name__ == "__main__":
    # enrollment_url, uuid, sn = sys.argv[1:]
    # enrollment_url = "https://zentral.sidewalklabs.com/santa/sync/kb9hMOLwSCVyTtlErd0hTWzubB22iZksbCqiVbOohYQWqrbRXobodiNfSy0nMnef/"
    # enrollment_url = "https://zaio.zentral.dev/santa/sync/uyQ5ssb4wwx5RNEwireWwo9nVEaFxQuZo4It3yf37xoJdsO7dmcM4K4fFn6a9s0Q/"
    enrollment_url = "https://zentral/santa/sync/dIMvUv8xzcDOw4twfq55SPtAfqlpf4cXzmpwDwLZtNZmFLSRcoXt45Ut1FaXLDcB/"
    verify_tls = False
    uuid = "564DEB9A-4C88-D431-75BC-A30036909992"
    sn = "VMth6/W37nj3"
    do_preflight(enrollment_url, uuid, sn, verify_tls)
    input("OK? ")
    do_rules_download(enrollment_url, uuid)
