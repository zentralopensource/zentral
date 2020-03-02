from .ldap import LDAPRealmBackend
from .openidc import OpenIDConnectRealmBackend
from .saml import SAMLRealmBackend


backend_classes = {
    "ldap": LDAPRealmBackend,
    "openidc": OpenIDConnectRealmBackend,
    "saml": SAMLRealmBackend,
}
