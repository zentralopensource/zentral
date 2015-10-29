import re
import requests

LINE_RE = re.compile(r'^(?P<metric_name>[a-zA-Z_:][a-zA-Z0-9_:]*)'
                     r'(?P<labels>\{.*\})?\s+(?P<value>(?:-?[0-9]+(?:\.[0-9]+)?'
                     r'(?:e[+-][0-9]+)?|NaN|Inf|-Inf))(?:\s+(?P<timestamp>[0-9]+))?$')
LABEL_RE = re.compile(r'(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)="(?P<value>[^"\n\\]*)"')


class GatewayClient(object):
    def __init__(self, gw_host):
        self.gw_host = gw_host

    @staticmethod
    def _parse_labels(s):
        if not s:
            return {}
        ll = []
        s = s.replace(r'\\', '\\').replace(r'\n', '\n').replace(r'\"', '"')  # TODO: HACK ! INCORRECT !
        for m in LABEL_RE.findall(s):
            ll.append(m)
        return dict(ll)

    def _parse_line(self, line):
        line = line.strip()
        m = LINE_RE.match(line)
        if not m:
            raise ValueError('Unknown line structure %s', line)
        else:
            d = {'metric_name': m.group('metric_name'),
                 'labels': self._parse_labels(m.group('labels'))}
            val = m.group('value')
            if val == 'NaN':
                val = None
            else:
                d['value'] = float(val.lower())
            ts = m.group('timestamp')
            if ts:
                d['timestamp'] = int(ts)
            return d

    def get_metrics(self, prefix=""):
        resp = requests.get("http://{}/metrics".format(self.gw_host))
        for line in resp.text.splitlines():
            if line.startswith('#'):
                continue
            if not prefix or line.startswith(prefix):
                yield self._parse_line(line)

if __name__ == '__main__':
    import sys
    gwc = GatewayClient(sys.argv[1])
    for m in gwc.get_metrics():
        print(m)
