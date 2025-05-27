import uuid
from django.utils.crypto import get_random_string
from zentral.core.probes.models import Action, ActionBackend


def force_action(backend=ActionBackend.HTTP_POST, backend_kwargs=None):
    if backend_kwargs is None:
        if backend == ActionBackend.HTTP_POST:
            backend_kwargs = {"url": "https://www.example.com/post"}
        elif backend == ActionBackend.SLACK_INCOMING_WEBHOOK:
            backend_kwargs = {"url": "https://www.example.com/post"}
    action = Action(
        id=uuid.uuid4(),
        name=get_random_string(12),
        description=get_random_string(12),
        backend=backend,
    )
    action.set_backend_kwargs(backend_kwargs)
    action.save()
    return action
