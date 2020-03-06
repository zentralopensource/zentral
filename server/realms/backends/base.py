class BaseBackend:
    can_get_password = False

    def __init__(self, instance):
        self.instance = instance
