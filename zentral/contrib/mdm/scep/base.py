from zentral.core.secret_engines import decrypt_str, encrypt_str, rewrap


class SCEPChallengeError(Exception):
    pass


class SCEPChallenge:
    type = None
    kwargs_keys = ()
    encrypted_kwargs_keys = ()
    form_class = None

    def __init__(self, scep_config, load=True):
        self.scep_config = scep_config
        if load:
            self.load()

    def load(self):
        challenge_kwargs = self.get_kwargs()
        for key in self.kwargs_keys:
            try:
                val = challenge_kwargs[key]
            except KeyError:
                raise SCEPChallengeError(
                    f"'{key}' key missing from Static SCEP challenge kwargs {self.scep_config.pk}"
                )
            else:
                if not val:
                    raise SCEPChallengeError(
                        f"'{key} key empty in Static SCEP challenge kwargs {self.scep_config.pk}"
                    )
                setattr(self, key, val)

    def get(self, key_usage, subject, subject_alt_name):
        raise NotImplementedError

    # secrets

    def _secret_engine_kwargs(self, subfield):
        name = self.scep_config.name
        if not name:
            raise ValueError("SCEPConfig must have a name")
        return {"field": f"challenge_kwargs.{subfield}",
                "model": "mdm.scepconfig",
                "name": name}

    def get_kwargs(self):
        if not isinstance(self.scep_config.challenge_kwargs, dict):
            raise ValueError("SCEPConfig hasn't been initialized")
        return {
            k: decrypt_str(v, **self._secret_engine_kwargs(k)) if k in self.encrypted_kwargs_keys else v
            for k, v in self.scep_config.challenge_kwargs.items()
        }

    def set_kwargs(self, kwargs):
        self.scep_config.challenge_kwargs = {
            k: encrypt_str(v, **self._secret_engine_kwargs(k)) if k in self.encrypted_kwargs_keys else v
            for k, v in kwargs.items()
        }

    def rewrap_kwargs(self):
        self.scep_config.challenge_kwargs = {
            k: rewrap(v, **self._secret_engine_kwargs(k)) if k in self.encrypted_kwargs_keys else v
            for k, v in self.scep_config.challenge_kwargs.items()
        }
