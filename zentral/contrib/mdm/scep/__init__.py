import enum
import logging


logger = logging.getLogger("zentral.contrib.mdm.scep")


class SCEPChallengeType(enum.Enum):
    STATIC = "Static"
    MICROSOFT_CA = "Microsoft CA Web Enrollment (certsrv)"
    OKTA_CA = "Okta CA Dynamic Challenge"

    @classmethod
    def choices(cls):
        return [(i.name, i.value) for i in cls]


def get_scep_challenge(scep_config, load=False):
    if scep_config.challenge_type == SCEPChallengeType.STATIC.name:
        from .static import StaticChallenge
        return StaticChallenge(scep_config, load)
    elif scep_config.challenge_type == SCEPChallengeType.MICROSOFT_CA.name:
        from .microsoft_ca import MicrosoftCAChallenge
        return MicrosoftCAChallenge(scep_config, load)
    elif scep_config.challenge_type == SCEPChallengeType.OKTA_CA.name:
        from .microsoft_ca import OktaCAChallenge
        return OktaCAChallenge(scep_config, load)
    else:
        raise ValueError(f"Unknown challenge type: {scep_config.challenge_type}")


def load_scep_challenge(scep_config):
    return get_scep_challenge(scep_config, load=True)


def update_scep_payload(scep_payload, scep_config):
    # always RSA https://developer.apple.com/documentation/devicemanagement/scep/payloadcontent
    scep_payload["Key Type"] = "RSA"
    # fill in the missing attributes
    for db_attr, pl_attr in (("name", "Name"),
                             ("url", "URL"),
                             ("key_usage", "Key Usage"),
                             ("key_is_extractable", "KeyIsExtractable"),
                             ("keysize", "Keysize"),
                             ("allow_all_apps_access", "AllowAllAppsAccess")):
        if pl_attr not in scep_payload:
            scep_payload[pl_attr] = getattr(scep_config, db_attr)

    # add challenge if necessary
    if "Challenge" not in scep_payload:
        scep_challenge = load_scep_challenge(scep_config)
        # TODO: flatten Subject and SubjectAltName for future challenge implementations
        scep_payload["Challenge"] = scep_challenge.get(scep_payload["Key Usage"],
                                                       scep_payload.get("Subject"),
                                                       scep_payload.get("SubjectAltName"))
