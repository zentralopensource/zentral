import secrets
import uuid
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from zentral.core.terraform.models import Lock, State, StateVersion


def build_lock_info(lock_id=None):
    if lock_id is None:
        lock_id = str(uuid.uuid4())
    return {
        'ID': lock_id,
        'Operation': 'OperationTypeApply',
        'Info': '',
        'Who': 'yolo@fomo',
        'Version': '1.8.5',
        'Created': '2024-06-29T15:28:31.558912Z',
        'Path': ''
    }


def force_state(slug=None, locked=False):
    if slug is None:
        slug = slugify(get_random_string(12))
    state = State.objects.create(slug=slug, created_by_username=get_random_string(12))
    if locked:
        lock_id = str(uuid.uuid4())
        Lock.objects.create(
            state=state,
            uid=lock_id,
            info=build_lock_info(lock_id),
            created_by_username=state.created_by_username,
        )
    return state


def force_state_version(state=None, data=None):
    if state is None:
        state = force_state()
    sv = StateVersion.objects.create(
        state=state,
        created_by_username=get_random_string(12)
    )
    if data is None:
        data = secrets.token_bytes()
    sv.set_data(data)
    sv.save()
    return sv
