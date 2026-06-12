import clickhouse_connect

CLIENT_KWARGS_KEYS = (
    # connection
    "host",
    "port",
    "secure",
    "verify",
    "compress",
    # auth
    "username",
    "database",
    "password",
    "access_token",
    # timeouts
    "connect_timeout",
    "send_receive_timeout",
)


def get_clickhouse_client(get_kwarg):
    client_kwargs = {}
    for key in CLIENT_KWARGS_KEYS:
        val = get_kwarg(key)
        if val is not None:
            client_kwargs[key] = val
    return clickhouse_connect.get_client(
        autogenerate_session_id=False,  # we do run queries concurrently
        **client_kwargs
    )
