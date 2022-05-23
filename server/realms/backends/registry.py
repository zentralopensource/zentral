from realms.backends.ldap import LDAPRealmBackend
from realms.backends.openidc import OpenIDConnectRealmBackend
from realms.backends.saml import SAMLRealmBackend


backend_classes = {
    "ldap": LDAPRealmBackend,
    "openidc": OpenIDConnectRealmBackend,
    "saml": SAMLRealmBackend,
}
