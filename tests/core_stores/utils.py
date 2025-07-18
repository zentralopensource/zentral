from django.utils.crypto import get_random_string
from django.utils.text import slugify
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.all import get_store_backend
from zentral.core.stores.models import Store


def build_login_event(username=None, routing_key=None):
    if username is None:
        username = get_random_string(12)
    return LoginEvent(EventMetadata(routing_key=routing_key), {"user": {"username": username}})


def force_store(backend=None, backend_kwargs=None, name=None, event_filters=None, provisioned=False):
    name = name or get_random_string(12)
    backend = backend or "HTTP"
    backend_kwargs = backend_kwargs or {"endpoint_url": "https://www.example.com"}
    event_filters = event_filters or {}
    store = Store.objects.create(
        name=name,
        slug=slugify(name),
        event_filters=event_filters,
        backend=backend,
        backend_kwargs={}
    )
    store.set_backend_kwargs(backend_kwargs)
    if provisioned:
        store.provisioning_uid = get_random_string(12)
    store.save()
    return get_store_backend(store, load=True)
