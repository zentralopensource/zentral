from django.test import SimpleTestCase
from zentral.utils.token import (generate_ztl_token, verify_ztl_token, _prefix, _generate_checksum, _checksum,
                                 _wo_checksum, _to_base62)


class TokenTestCase(SimpleTestCase):

    def test_generate_checksum(self):
        string = "MyToken"
        crc = _generate_checksum(string)
        self.assertEqual('3JX0Cw', crc)

    def test_base62_prefix(self):
        base62 = _to_base62(110)
        self.assertEqual('1M', base62)
        base62 = _to_base62(0)
        self.assertEqual('0', base62)

    def test_token_prefix(self):
        token = "xxx"
        prefix = _prefix(token)
        self.assertNotEqual('u', prefix)
        token = "ztlu_lala"
        prefix = _prefix(token)
        self.assertEqual('u', prefix)

    def test_slice_token(self):
        token = "ztls_V73y8qp0fEJJqwjyCHBKW4VhUS74ao35DYcM"
        prefix = _prefix(token)
        chksum = _checksum(token)
        token_wo_chksum = _wo_checksum(token)
        self.assertEqual('s', prefix)
        self.assertEqual('35DYcM', chksum)
        self.assertEqual('ztls_V73y8qp0fEJJqwjyCHBKW4VhUS74ao', token_wo_chksum)

    def test_token_generate(self):
        token = generate_ztl_token('u')
        self.assertTrue(token.startswith("ztlu_"))
        self.assertTrue(verify_ztl_token(token, ['u']))
        token = generate_ztl_token('s')
        self.assertTrue(token.startswith("ztls_"))
        self.assertTrue(verify_ztl_token(token, ['u', 's']))
        with self.assertRaises(ValueError):
            generate_ztl_token('lala')
        with self.assertRaises(ValueError):
            generate_ztl_token('%')

    def test_token_valid(self):
        token = "ztls_DdUzwH5zV95ofmvcJq1JP5FkhThLv40ZenRv"
        self.assertTrue(verify_ztl_token(token, ['u', 's']))
        # false prefix
        self.assertFalse(verify_ztl_token(token, ['x']))
        # without token
        self.assertFalse(verify_ztl_token('', ['u', 's']))
        # without valid prefixes
        self.assertFalse(verify_ztl_token(token, []))
        # without checksum
        self.assertFalse(verify_ztl_token("ztls", ['s']))
        # without full payload
        self.assertFalse(verify_ztl_token("ztls_DdUzwH5zV95ofmvcJq1JP5FkhThLv4", ['s']))
        # tampered token
        token = "ztls_xxxzwH5zV95ofmvcJq1JP5FkhThLv40ZenRv"
        self.assertFalse(verify_ztl_token(token, ['s']))
