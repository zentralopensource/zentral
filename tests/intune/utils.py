import uuid
from django.utils.crypto import get_random_string
from zentral.contrib.intune.models import Tenant
from zentral.contrib.inventory.models import MetaBusinessUnit


def force_tenant(bu=None):
    if not bu:
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        bu = mbu.create_enrollment_business_unit()
    tenant = Tenant.objects.create(
        business_unit=bu,
        name=get_random_string(12),
        description=get_random_string(30),
        tenant_id=str(uuid.uuid4()),
        client_id=str(uuid.uuid4()),
    )
    tenant.set_client_secret(get_random_string(12))
    tenant.save()
    tenant.refresh_from_db()
    return tenant
