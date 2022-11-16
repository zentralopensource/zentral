import os
from tempfile import NamedTemporaryFile
from unittest.mock import call, Mock
from django.test import SimpleTestCase
from zentral.conf.config import ConfigDict, ConfigList
from zentral.conf import ZentralSettings


class ConfTestCase(SimpleTestCase):
    def test_config_dict_eq_different_type(self):
        self.assertFalse(ConfigDict({"un": 1}) == {"un": 1})

    def test_config_dict_eq_different(self):
        self.assertFalse(ConfigDict({"un": 1, "deux": 2}) == ConfigDict({"un": 1, "deux": 3}))

    def test_update_config_dict_key_values(self):
        d = ConfigDict({"un": 1})
        d.update(deux=2, trois=3)
        r = d.serialize()
        self.assertEqual(r, {"un": 1, "deux": 2, "trois": 3})

    def test_update_config_dict_iter(self):
        d = ConfigDict({"un": 1})
        d.update((("deux", 2), ("trois", 3)))
        r = d.serialize()
        self.assertEqual(r, {"un": 1, "deux": 2, "trois": 3})

    def test_update_config_dict_dict(self):
        d = ConfigDict({"un": 1})
        d.update({"deux": 2, "trois": 3})
        r = d.serialize()
        self.assertEqual(r, {"un": 1, "deux": 2, "trois": 3})

    def test_config_dict_copy(self):
        d = ConfigDict({"un": 1})
        d2 = d.copy()
        self.assertIsInstance(d2, ConfigDict)
        self.assertFalse(d is d2)
        self.assertEqual(d, d2)

    def test_config_dict_popitem(self):
        d = ConfigDict({"un": 1})
        d["deux"] = 2
        self.assertEqual(d.popitem(), ("deux", 2))
        self.assertEqual(d.serialize(), {"un": 1})

    def test_config_dict_pop(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(d.pop("un"), 1)
        self.assertEqual(d.serialize(), {})
        self.assertEqual(d.pop("deux", 2), 2)

    def test_config_dict_setdefault(self):
        d = ConfigDict({"un": 1})
        d.setdefault("deux", {}).update({"trois": 3})
        self.assertEqual(d.serialize(), {"un": 1, "deux": {"trois": 3}})

    def test_config_dict_clear(self):
        d = ConfigDict({"un": 1})
        d.clear()
        self.assertEqual(d.serialize(), {})

    def test_config_dict_items(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(list(d.items()), [("un", 1)])

    def test_config_dict_values(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(list(d.values()), [1])

    def test_config_dict_keys(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(list(d.keys()), ["un"])

    def test_config_dict_get(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(d.get("un"), 1)
        self.assertIsNone(d.get("deux"))
        self.assertEqual(d.get("deux", 2), 2)

    def test_config_dict_getitem(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(d["un"], 1)

    def test_config_dict_setitem(self):
        d = ConfigDict({"un": 1})
        d["deux"] = 2
        self.assertEqual(d.serialize(), {"un": 1, "deux": 2})

    def test_config_dict_delitem(self):
        d = ConfigDict({"un": 1, "deux": 2})
        del d["deux"]
        self.assertEqual(d, ConfigDict({"un": 1}))

    def test_config_dict_len(self):
        d = ConfigDict({"un": 1, "deux": 2})
        self.assertEqual(len(d), 2)

    def test_config_dict_iter(self):
        d = ConfigDict({"un": 1})
        self.assertEqual(list(k for k in d), ["un"])

    def test_config_list_serialize(self):
        cl = ConfigList(["un"])
        self.assertEqual(cl.serialize(), ["un"])

    def test_config_list_iter(self):
        cl = ConfigList(["un"])
        self.assertEqual(list(elm for elm in cl), ["un"])

    def test_config_list_getitem(self):
        cl = ConfigList(["un", "deux", "trois"])
        self.assertEqual(cl[0], "un")
        self.assertEqual(cl[:2], ["un", "deux"])

    def test_config_list_setitem(self):
        cl = ConfigList(["un", "quatre", "trois"])
        cl[1] = "deux"
        self.assertEqual(cl.serialize(), ["un", "deux", "trois"])

    def test_config_list_delitem(self):
        cl = ConfigList(["un", "quatre"])
        del cl[1]
        self.assertEqual(cl, ConfigList(["un"]))

    def test_config_list_len(self):
        cl = ConfigList(["un", "quatre"])
        self.assertEqual(len(cl), 2)

    def test_config_list_pop(self):
        cl = ConfigList(["un", "deux"])
        self.assertEqual(cl.pop(1), "deux")
        self.assertEqual(cl.pop(), "un")
        self.assertEqual(cl.serialize(), [])

    def test_config_list_eq_different_types(self):
        self.assertFalse(ConfigList(["un", "deux"]) == ConfigDict({"un": 1, "deux": 2}))

    def test_config_list_eq_different_length(self):
        self.assertFalse(ConfigList(["un", "deux"]) == ConfigList(["un"]))

    def test_config_list_eq_different_item(self):
        self.assertFalse(ConfigList(["un", "deux"]) == ConfigList(["un", "trois"]))

    def test_config_file_resolver_cache(self):
        with NamedTemporaryFile() as tmp_file:
            tmp_file.write(b"un")
            tmp_file.flush()
            c = ConfigDict({"f": f'{{{{ file:{tmp_file.name} }}}}'})
            # first read operation
            m0 = Mock(return_value=0)
            c._resolver._get_time = m0
            self.assertEqual(c["f"], "un")
            m0.assert_called_once()
            tmp_file.seek(0)
            tmp_file.write(b"undeux")
            tmp_file.flush()
            # read from cache
            m599 = Mock(return_value=599)
            c._resolver._get_time = m599
            self.assertEqual(c["f"], "un")
            m599.assert_called_once()
            # force expiry (time > 0 + default ttl)
            m601 = Mock(return_value=601)
            c._resolver._get_time = m601
            self.assertEqual(c["f"], "undeux")
            m601.assert_has_calls([call(), call()])

    def test_config_file_jsondecode_element_resolvers(self):
        base_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), "base.json")
        c = ConfigDict({"api": f'{{{{ file:{base_json}|jsondecode|element:api }}}}'})
        self.assertEqual(c["api"]["tls_hostname"], "https://zentral")

    def test_config_file_default_webhook_fqdn(self):
        c = ZentralSettings({"api": {"fqdn": "zentraldj2o3i2dj"}})
        self.assertEqual(c["api"]["webhook_fqdn"], "zentraldj2o3i2dj")

    def test_config_file_webhook_fqdn(self):
        c = ZentralSettings({"api": {"fqdn": "zentraldj2o3i2dj",
                                     "webhook_fqdn": "webhooksyolo"}})
        self.assertEqual(c["api"]["webhook_fqdn"], "webhooksyolo")

    def test_config_file_default_tls_hostnames(self):
        c = ZentralSettings({"api": {"fqdn": "zentral", "fqdn_mtls": "zentral-mtls"}})
        self.assertEqual(c["api"]["tls_hostname"], "https://zentral")
        self.assertEqual(c["api"]["tls_hostname_for_client_cert_auth"], "https://zentral-mtls")

    def test_config_file_legacy_tls_hostnames(self):
        c = ZentralSettings({"api": {"tls_hostname": "https://zentral",
                                     "tls_hostname_for_client_cert_auth": "https://zentral-mtls"}})
        self.assertEqual(c["api"]["fqdn"], "zentral")
        self.assertEqual(c["api"]["fqdn_mtls"], "zentral-mtls")
