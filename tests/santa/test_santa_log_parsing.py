import datetime
from dateutil.tz.tz import tzlocal
from django.test import TestCase
from zentral.contrib.santa.utils import parse_santa_log_message


LOG1 = ("[2019-09-16T13:53:17.187Z] I santad: action=EXEC|decision=ALLOW|reason=CERT|"
        "sha256=be3d62846149af4526a2836db6d957425bd318f1dacf75d7528e750b95bf531f|"
        "cert_sha256=2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32|"
        "cert_cn=Software Signing|pid=55133|ppid=55125|uid=0|user=root|gid=0|group=wheel|mode=M|"
        "path=/usr/bin/sed|args=sed -E s/[^:]*:[[:space:]]+// /var/db/.NoMADCreateUser")
RES1 = {'timestamp': datetime.datetime(2019, 9, 16, 13, 53, 17, 187000, tzinfo=tzlocal()),
        'action': 'EXEC',
        'decision': 'ALLOW',
        'reason': 'CERT',
        'sha256': 'be3d62846149af4526a2836db6d957425bd318f1dacf75d7528e750b95bf531f',
        'cert_sha256': '2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32',
        'cert_cn': 'Software Signing',
        'pid': 55133,
        'ppid': 55125,
        'uid': 0,
        'user': 'root',
        'gid': 0,
        'group': 'wheel',
        'mode': 'M',
        'path': '/usr/bin/sed',
        'args': ['sed', '-E', 's/[^:]*:[[:space:]]+//', '/var/db/.NoMADCreateUser']}


class SantaLogParsingTestCase(TestCase):
    def test_santa_log_1(self):
        self.assertEqual(parse_santa_log_message(LOG1), RES1)
