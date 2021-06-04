import logging
from zentral.contrib.mdm.models import SCEPChallengeType, SCEPConfig
from .microsoft_ca import MicrosoftCAChallenge
from .static import StaticChallenge


logger = logging.getLogger("zentral.contrib.mdm.scep")


def load_scep_challenge(scep_config):
    if scep_config.challenge_type == SCEPChallengeType.STATIC.name:
        return StaticChallenge(scep_config)
    elif scep_config.challenge_type == SCEPChallengeType.MICROSOFT_CA.name:
        return MicrosoftCAChallenge(scep_config)
    else:
        raise ValueError(f"Unknown challenge type: {scep_config.challenge_type}")


def process_scep_payload(scep_payload):
    # does the payload have a name?
    name = scep_payload.get("Name")
    if not name:
        # nothing to do
        return

    # do we have a matching config in the DB?
    try:
        scep_config = SCEPConfig.objects.get(name=name)
    except SCEPConfig.DoesNotExist:
        # nothing to do
        return

    # fill in the missing attributes
    for db_attr, pl_attr in (("url", "URL"),
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


def process_scep_payloads(profile_payload):
    for payload in profile_payload.get("PayloadContent", []):
        if payload.get("PayloadType") == "com.apple.security.scep":
            process_scep_payload(payload["PayloadContent"])
