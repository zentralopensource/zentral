class RealmUserError(Exception):
    def __init__(self, message, claims=None):
        super().__init__(message)
        self.claims = claims
