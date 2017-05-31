import logging
from django.db import connection, models
from zentral.contrib.inventory.models import Certificate, OSXApp
from zentral.utils.mt_models import AbstractMTObject, MTObjectManager

logger = logging.getLogger("zentral.contrib.santa.models")


class CollectedApplicationManager(MTObjectManager):
    def search(self, **kwargs):
        qs = self.all()
        name = kwargs.get("name")
        if name:
            qs = qs.filter(name__icontains=name)
            return qs.select_related("bundle").order_by("bundle__bundle_name", "name")
        else:
            return []

    def search_certificates(self, **kwargs):
        q = kwargs.get("query")
        if not q:
            return []
        else:
            query = (
                "WITH RECURSIVE certificates AS ("
                "SELECT c1.id, c1.signed_by_id "
                "FROM inventory_certificate AS c1 "
                "JOIN santa_collectedapplication ca ON (ca.signed_by_id = c1.id) "

                "UNION "

                "SELECT c2.id, c2.signed_by_id "
                "FROM inventory_certificate AS c2 "
                "JOIN certificates c ON (c.signed_by_id = c2.id)"
                ") SELECT * FROM inventory_certificate c3 "
                "JOIN certificates AS c ON (c.id = c3.id) "
                "WHERE UPPER(c3.common_name) LIKE UPPER(%s) "
                "OR UPPER(c3.organization) LIKE UPPER(%s) "
                "OR UPPER(c3.organizational_unit) LIKE UPPER(%s) "
                "ORDER BY c3.common_name, c3.organization, c3.organizational_unit;"
            )
            print(query)
            q = "%{}%".format(connection.ops.prep_for_like_query(q))
            return Certificate.objects.raw(query, [q, q, q])


class CollectedApplication(AbstractMTObject):
    name = models.TextField()
    path = models.TextField()
    sha_256 = models.CharField(max_length=64, db_index=True)
    bundle = models.ForeignKey(OSXApp, blank=True, null=True, on_delete=models.PROTECT)
    bundle_path = models.TextField(blank=True, null=True)
    signed_by = models.ForeignKey(Certificate, blank=True, null=True, on_delete=models.PROTECT)

    objects = CollectedApplicationManager()
