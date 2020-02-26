from .openidc import OpenIDConnectRealmBackend
from .saml import SAMLRealmBackend


backend_classes = {
    "openidc": OpenIDConnectRealmBackend,
    "saml": SAMLRealmBackend,
}
