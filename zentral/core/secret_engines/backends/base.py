class BaseSecretEngine:
    def __init__(self, config_d):
        self.name = config_d['secret_engine_name']
        self.default = config_d.get("default", False)

    def encrypt(self, data, **context):
        raise NotImplementedError

    def decrypt(self, data, **context):
        raise NotImplementedError
