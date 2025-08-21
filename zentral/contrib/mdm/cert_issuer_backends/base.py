from zentral.utils.backend_model import Backend


class CertIssuerError(Exception):
    pass


class CertIssuer(Backend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance_version = self.instance.version

    def __eq__(self, other):
        if not super().__eq__(other):
            return False
        return self.instance_version == other.instance_version

    def update_acme_payload_with_instance(self, acme_payload, hardware_bound, attest):
        for db_attr, pl_attr in (("directory_url", "DirectoryURL"),
                                 ("key_size", "KeySize"),
                                 ("key_type", "KeyType"),
                                 ("usage_flags", "UsageFlags"),
                                 ("extended_key_usage", "ExtendedKeyUsage"),
                                 ("hardware_bound", "HardwareBound"),
                                 ("attest", "Attest")):
            if pl_attr not in acme_payload:
                val = getattr(self.instance, db_attr)
                if db_attr == "hardware_bound":
                    val &= hardware_bound
                elif db_attr == "attest":
                    val &= (hardware_bound and attest)
                elif db_attr == "key_type":
                    val = str(val)
                elif db_attr == "extended_key_usage" and not val:
                    continue
                acme_payload[pl_attr] = val

    def update_scep_payload_with_instance(self, scep_payload):
        # always RSA https://developer.apple.com/documentation/devicemanagement/scep/payloadcontent
        scep_payload["Key Type"] = "RSA"
        # fill in the missing attributes
        for db_attr, pl_attr in (("name", "Name"),
                                 ("url", "URL"),
                                 ("key_usage", "Key Usage"),
                                 ("key_size", "Keysize")):
            if pl_attr not in scep_payload:
                scep_payload[pl_attr] = getattr(self.instance, db_attr)

    def update_acme_payload(
        self, acme_payload, hardware_bound, attest,
        enrollment_session, enrolled_user=None,
    ):
        raise NotImplementedError

    def update_scep_payload(self, scep_payload, enrollment_session, enrolled_user=None):
        raise NotImplementedError
