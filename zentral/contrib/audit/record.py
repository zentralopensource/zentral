from datetime import timedelta
import re
from dateutil import parser


MSEC_RE = re.compile('^\s*\+ (?P<msec>[0-9]+) msec$')


def parse_token(line, attrs):
    d = {}
    for (attr_name, attr_type), val in zip(attrs, line.split(",")[1:]):
        val = val.strip()
        if not val:
            continue
        if attr_type is not None:
            val = attr_type(val)
        d[attr_name] = val
    return d


def parse_header_token(line):
    attrs = [('length', int),
             ('version', int),
             ('event_id', str),
             ('event_id_modifier', str),
             ('time', None),
             ('msec', None)]
    d = parse_token(line, attrs)
    rec_time, msec = d.pop("time", None), d.pop("msec", None)
    if rec_time and msec:
        msec = int(MSEC_RE.match(msec).group("msec"))
        if msec < 1000:  # TODO better ?
            msec = msec * 1000
        d['created_at'] = parser.parse(rec_time) + timedelta(microseconds=msec)
    return d


def parse_subject_token(line):
    attrs = [('audit_uid', str),
             ('uid', str),
             ('gid', str),
             ('real_uid', str),
             ('real_gid', str),
             ('process_id', int),
             ('session_id', int),
             ('terminal_id', str)]
    return parse_token(line, attrs)


def parse_expanded_subject_token(line):
    attrs = [('audit_uid', str),
             ('uid', str),
             ('gid', str),
             ('real_uid', str),
             ('real_gid', str),
             ('process_id', int),
             ('session_id', int),
             ('terminal_port', int),
             ('terminal_ip_address', str)]
    return parse_token(line, attrs)


def parse_text_token(line):
    attrs = [('string', str)]
    return parse_token(line, attrs)['string']


def parse_return_token(line):
    attrs = [('status', str),
             ('value', str)]
    return parse_token(line, attrs)


def parse_argument_token(line):
    attrs = [('id', int),
             ('value', str),
             ('text', str)]
    return parse_token(line, attrs)


def parse_record(record):
    parsed_rec = {}
    for line in record.splitlines():
        for token_id, token_parser, token_destination in (("header", parse_header_token, 'header'),
                                                          ("return", parse_return_token, 'attribute'),
                                                          ("subject", parse_subject_token, 'attribute'),
                                                          ("subject_ex", parse_expanded_subject_token, 'attribute'),
                                                          ("argument", parse_argument_token, 'list'),
                                                          ("text", parse_text_token, 'list')):
            if line.startswith("{},".format(token_id)):
                d = token_parser(line)
                if token_destination == 'header':
                    parsed_rec.update(d)
                elif token_destination == 'attribute':
                    parsed_rec[token_id] = d
                elif token_destination == 'list':
                    parsed_rec.setdefault(token_id, []).append(d)
    return parsed_rec
