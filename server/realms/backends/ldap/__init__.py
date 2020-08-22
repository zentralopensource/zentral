import base64
import logging
from django.urls import reverse
import ldap
from realms.backends.base import BaseBackend
from realms.exceptions import RealmUserError
from realms.utils import build_password_hash_dict


logger = logging.getLogger("zentral.realms.backends.ldap")


# global option
# TODO 10 seconds ldap timeout hard coded
ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)


def cleanup_value(v):
    if isinstance(v, bytes):
        try:
            v = v.decode("utf-8")
        except Exception:
            v = base64.b64encode(v).decode("utf-8")
    elif isinstance(v, list):
        v = [cleanup_value(i) for i in v]
    elif isinstance(v, dict):
        v = {i: cleanup_value(j) for i, j in v.items()}
    return v


def cleanup_user_attributes(d):
    return cleanup_value(d)


def get_ldap_connection(host):
    conn = ldap.initialize("ldap://{}".format(host))
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
    conn.start_tls_s()
    return conn


class LDAPRealmBackend(BaseBackend):
    name = "LDAP"
    can_get_password = True

    def __init__(self, instance):
        super().__init__(instance)
        self._conn = None

    def extra_attributes_for_display(self):
        config = self.instance.config
        return [
            ("Host", config.get("host"), False),
            ("Bind DN", config.get("bind_dn"), False),
            ("Bind password", config.get("bind_password"), True),
            ("Users base DN", config.get("users_base_dn"), False),
        ]

    def _get_ldap_conn(self):
        if self._conn is None:
            self._conn = get_ldap_connection(self.instance.config.get("host"))
        return self._conn

    def _get_user_dn(self, username):
        return "uid={},{}".format(ldap.dn.escape_dn_chars(username), self.instance.config.get("users_base_dn"))

    def authenticate(self, username, password):
        conn = self._get_ldap_conn()
        user_dn = self._get_user_dn(username)
        try:
            conn.simple_bind_s(user_dn, password)
        except ldap.LDAPError:
            return False
        else:
            return True

    def get_user_info(self, username):
        conn = self._get_ldap_conn()
        conn.simple_bind_s(self.instance.config.get("bind_dn"), self.instance.config.get("bind_password"))
        user_dn = self._get_user_dn(username)
        results = conn.search_s(user_dn, ldap.SCOPE_BASE, attrlist=["*"])
        return cleanup_value(results[0][1])

    def initialize_session(self, request, callback, save_password_hash=False, **callback_kwargs):
        from realms.models import RealmAuthenticationSession
        ras = RealmAuthenticationSession(
            realm=self.instance,
            save_password_hash=save_password_hash,
            callback=callback,
            callback_kwargs=callback_kwargs
        )
        ras.save()

        return reverse("realms:ldap_login", args=(ras.realm.pk, ras.pk))

    def update_or_create_realm_user(self, username, password):
        user_info = self.get_user_info(username)

        # default realm user attributes for update or create
        realm_user_defaults = {"claims": user_info}

        # password
        if password:
            realm_user_defaults["password_hash"] = build_password_hash_dict(password)
        else:
            realm_user_defaults["password_hash"] = {}

        for user_claim, user_claim_source in self.instance.iter_user_claim_mappings():
            value = user_info.get(user_claim_source)
            if value and isinstance(value, list):
                value = value[0]
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            if not value:
                value = ""
            realm_user_defaults[user_claim] = value

        # the username for the claim mappings
        if "username" not in realm_user_defaults or not realm_user_defaults["username"]:
            raise RealmUserError("No username found in ID token", realm_user_defaults)

        username = realm_user_defaults.pop("username", None)
        from realms.models import RealmUser
        realm_user, _ = RealmUser.objects.update_or_create(
            realm=self.instance,
            username=username,
            defaults=realm_user_defaults
        )
        return realm_user

    @staticmethod
    def get_form_class():
        # to avoid import loop
        # backends loaded from models
        # but backend form loads models…
        from .forms import LDAPRealmForm
        return LDAPRealmForm
