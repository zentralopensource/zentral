class SCEPChallengeError(Exception):
    pass


class SCEPChallenge:
    type = None
    kwargs_keys = ()
    form_class = None

    def __init__(self, scep_config):
        self.scep_config = scep_config
        for key in self.kwargs_keys:
            try:
                val = self.scep_config.challenge_kwargs[key]
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
