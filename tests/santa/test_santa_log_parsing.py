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

LOG2 = ("[2020-11-28T23:32:11.105Z] I santad: action=EXEC|decision=ALLOW|reason=BINARY|"
        "explain=critical system binary|sha256=51b74196098caa8ad5bb7ec8474e608bb615738d12927b475075bffb52876d15|"
        "cert_sha256=2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32|cert_cn=Software Signing|"
        "pid=53758|ppid=1|uid=0|user=root|gid=0|group=wheel|mode=M|"
        "path=/usr/libexec/xpcproxy|args=xpcproxy com.apple.systemstats.daily")
RES2 = {'timestamp': datetime.datetime(2020, 11, 28, 23, 32, 11, 105000, tzinfo=tzlocal()),
        'action': 'EXEC',
        'decision': 'ALLOW',
        'reason': 'BINARY',
        'explain': 'critical system binary',
        'sha256': '51b74196098caa8ad5bb7ec8474e608bb615738d12927b475075bffb52876d15',
        'cert_sha256': '2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32',
        'cert_cn': 'Software Signing',
        'pid': 53758,
        'ppid': 1,
        'uid': 0,
        'user': 'root',
        'gid': 0,
        'group': 'wheel',
        'mode': 'M',
        'path': '/usr/libexec/xpcproxy',
        'args': ['xpcproxy', 'com.apple.systemstats.daily']}

LOG3 = ("[2020-11-29T09:31:15.754Z] I santad: action=DISKAPPEAR|mount=|volume=EFI|bsdname=disk2s1|fs=msdos|"
        "model=WD Elements 25A1|serial=575836314435384644485035|bus=USB|dmgpath=|appearance=2020-11-29T09:31:15.688Z")
RES3 = {'timestamp': datetime.datetime(2020, 11, 29, 9, 31, 15, 754000, tzinfo=tzlocal()),
        'action': 'DISKAPPEAR',
        'mount': '',
        'volume': 'EFI',
        'bsdname': 'disk2s1',
        'fs': 'msdos',
        'model': 'WD Elements 25A1',
        'serial': '575836314435384644485035',
        'bus': 'USB',
        'dmgpath': '',
        'appearance': '2020-11-29T09:31:15.688Z'}


class SantaLogParsingTestCase(TestCase):
    def test_santa_log_1(self):
        self.assertEqual(parse_santa_log_message(LOG1), RES1)

    def test_santa_log_2(self):
        self.assertEqual(parse_santa_log_message(LOG2), RES2)

    def test_santa_log_3(self):
        self.assertEqual(parse_santa_log_message(LOG3), RES3)

    def test_santa_log_rubbish_data(self):
        self.assertEqual(parse_santa_log_message(42 * "\x00\x0a" + LOG1), RES1)

    def test_santa_log_fail_hard(self):
        with self.assertRaises(ValueError, msg="Could not find timestamp"):
            parse_santa_log_message(": action=D")
