class BaseBackend:
    can_get_password = False

    def __init__(self, instance):
        self.instance = instance

    @property
    def _ras_session_key(self):
        return "realm_{}_session".format(self.instance.pk)

    def _add_ras_to_session(self, request, ras):
        request.session[self._ras_session_key] = str(ras.pk)

    def verify_session_state(self, request, state):
        try:
            session_state = request.session[self._ras_session_key]
        except KeyError:
            return False
        else:
            return session_state == str(state)
