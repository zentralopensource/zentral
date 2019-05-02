#!/usr/bin/python
import argparse
import json
import ssl
import urllib2

URL = "%TLS_HOSTNAME%/nagios/post_event/"
USER_AGENT = "Zentral/neh 0.1"
HEADER = "Zentral-API-Secret"
SECRET = "%SECRET%"
ZENTRAL_FULLCHAIN = u"""
%FULLCHAIN%
"""


ARGS = {
    "host": (
        ("state", "$HOSTSTATE$", str),
        ("state_type", "$HOSTSTATETYPE$", str),
        ("attempt", "$HOSTATTEMPT$", int),
        ("name", "$HOSTNAME$", str),
        ("display_name", "$HOSTDISPLAYNAME$", str),
        ("address", "$HOSTADDRESS$", str),
        ("check_output", "$LONGHOSTOUTPUT$", str),
    ),
    "service": (
        ("state", "$SERVICESTATE$", str),
        ("state_type", "$SERVICESTATETYPE$", str),
        ("attempt", "$SERVICEATTEMPT$", int),
        ("description", "$SERVICEDESC$", str),
        ("check_output", "$LONGSERVICEOUTPUT$", str),
    ),
}


def build_payload(args):
    event_type = args.event_type
    payload_d = {"event_type": "nagios_{}_event".format(event_type)}
    for attr, _, _ in ARGS[event_type]:
        v = getattr(args, attr, None)
        if v:
            payload_d[attr] = v[0]
    return json.dumps(payload_d)


def post_event(args):
    req = urllib2.Request(URL)
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', USER_AGENT)
    req.add_header(HEADER, SECRET)
    ctx = ssl.create_default_context(cadata=ZENTRAL_FULLCHAIN.strip() or None)
    data = build_payload(args)
    response = urllib2.urlopen(req, data=data, context=ctx)
    return json.load(response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Post nagios event to Zentral.')
    subparsers = parser.add_subparsers(title="event types",
                                       description="valid event types",
                                       dest="event_type")
    for event_type, event_type_args in ARGS.items():
        subparser = subparsers.add_parser(event_type, help="Post nagios {} event to Zentral.".format(event_type))
        for attr, nagios_macro, attr_type in event_type_args:
            subparser.add_argument(attr, type=attr_type, nargs=1, help=nagios_macro)
    args = parser.parse_args()
    post_event(args)
