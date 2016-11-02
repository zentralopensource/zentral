# from https://github.com/pifantastic/python-rison
# encode a json payload in rison
# used in kibana urls

import re

IDCHAR_PUNCTUATION = '_-./~'

NOT_IDCHAR = ''.join([c for c in (chr(i) for i in range(127))
                      if not (c.isalnum() or c in IDCHAR_PUNCTUATION)])

# Additionally, we need to distinguish ids and numbers by first char.
NOT_IDSTART = '-0123456789'

# Regexp string matching a valid id.
IDRX = ('[^' + NOT_IDSTART + NOT_IDCHAR + '][^' + NOT_IDCHAR + ']*')

# Regexp to check for valid rison ids.
ID_OK_RE = re.compile('^' + IDRX + '$', re.M)


class Encoder(object):

    def __init__(self):
        pass

    @staticmethod
    def encoder(v):
        if isinstance(v, list):
            return Encoder.list
        elif isinstance(v, str):
            return Encoder.string
        elif isinstance(v, bool):
            return Encoder.bool
        elif isinstance(v, (float, int)):
            return Encoder.number
        elif isinstance(v, type(None)):
            return Encoder.none
        elif isinstance(v, dict):
            return Encoder.dict
        else:
            raise AssertionError('Unable to encode type: {0}'.format(type(v)))

    @staticmethod
    def encode(v):
        encoder = Encoder.encoder(v)
        return encoder(v)

    @staticmethod
    def list(x):
        a = ['!(']
        b = None
        for i in range(len(x)):
            v = x[i]
            f = Encoder.encoder(v)
            if f:
                v = f(v)
                if isinstance(v, str):
                    if b:
                        a.append(',')
                    a.append(v)
                    b = True
        a.append(')')
        return ''.join(a)

    @staticmethod
    def number(v):
        return str(v).replace('+', '')

    @staticmethod
    def none(_):
        return '!n'

    @staticmethod
    def bool(v):
        return '!t' if v else '!f'

    @staticmethod
    def string(v):
        if v == '':
            return "''"

        if ID_OK_RE.match(v):
            return v

        def replace(match):
            if match.group(0) in ["'", '!']:
                return '!' + match.group(0)
            return match.group(0)

        v = re.sub(r'([\'!])', replace, v)

        return "'" + v + "'"

    @staticmethod
    def dict(x):
        a = ['(']
        b = None
        ks = sorted(x.keys())
        for i in ks:
            v = x[i]
            f = Encoder.encoder(v)
            if f:
                v = f(v)
                if isinstance(v, str):
                    if b:
                        a.append(',')
                    a.append(Encoder.string(i))
                    a.append(':')
                    a.append(v)
                    b = True

        a.append(')')
        return ''.join(a)


def dumps(o):
    if not isinstance(o, (dict, list)) or o is None:
        raise TypeError('object must be a dict a list or None')
    return Encoder.encode(o)
