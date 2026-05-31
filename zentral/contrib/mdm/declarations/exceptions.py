__all__ = [
    "DeclarationError",
    "TokenError",
    "TokenSignatureError",
    "TokenTargetNotFoundError",
    "TokenSessionNotFoundError",
    "TokenUserNotFoundError",
]


class DeclarationError(Exception):
    pass


class TokenError(Exception):
    """Base for failures while loading a public-endpoint token."""


class TokenSignatureError(TokenError):
    """Token signature didn't verify or the body couldn't be deserialised."""


class TokenTargetNotFoundError(TokenError):
    """The signature was valid but the primary referenced object is gone."""

    def __init__(self, target_pk):
        self.target_pk = target_pk
        super().__init__(f"Token target not found: {target_pk}")


class TokenSessionNotFoundError(TokenError):
    """The signature was valid and the target resolved, but the enrollment
    session referenced by the token is gone."""

    def __init__(self, target, session_model, session_pk):
        self.target = target
        self.session_model = session_model
        self.session_pk = session_pk
        super().__init__(f"Token session not found: {session_model} {session_pk}")


class TokenUserNotFoundError(TokenError):
    """The signature was valid, the target and the session resolved, but the
    enrolled user referenced by the token (eupk) is gone."""

    def __init__(self, target, enrollment_session, user_pk):
        self.target = target
        self.enrollment_session = enrollment_session
        self.user_pk = user_pk
        super().__init__(f"Token enrolled user not found: {user_pk}")
