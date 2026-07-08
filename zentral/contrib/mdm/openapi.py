from zentral.utils.drf_spectacular import register_enum_name_overrides
from .cert_issuer_backends import CertIssuerBackend
from .models import Blueprint, Platform


register_enum_name_overrides(
    # "backend": cert-issuer backends collide with the store/repository/action
    # backends that spectacular already names cleanly.
    CertIssuerBackendEnum=CertIssuerBackend,
    # "platform": one of three distinct choice sets across modules (see also
    # inventory and osquery).
    MdmPlatformEnum=Platform,
    # one IntegerChoices reached via collect_apps/collect_certificates/collect_profiles.
    InventoryItemCollectionOptionEnum=Blueprint.InventoryItemCollectionOption,
    # One key-usage bitmask choice set, defined as an inline tuple (no named class)
    # on SCEPIssuer.key_usage, SCEPConfig.key_usage and ACMEIssuer.usage_flags.
    # spectacular keys enums on their values, so the literal choice set here names
    # all three at once. A list of dotted field paths does NOT work — the value
    # must be a real choices iterable.
    KeyUsageEnum=[
        (0, "None (0)"),
        (1, "Signing (1)"),
        (4, "Encryption (4)"),
        (5, "Signing & Encryption (1 | 4 = 5)"),
    ],
)
