# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import connection, migrations, transaction


FIND_CONSTRAINT_NAME_QUERY = """
SELECT tc.constraint_name
FROM
information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
ON ccu.constraint_name = tc.constraint_name
WHERE
tc.table_name = %s
AND kcu.column_name = %s
AND ccu.table_name = %s
AND ccu.column_name = %s
"""

CONSTRAINTS = (
    ("inventory_machinesnapshot_certificates", "machinesnapshot_id", "inventory_machinesnapshot", "id"),
)

DROP_CONSTRAINT_QUERY = """
ALTER TABLE {}
DROP CONSTRAINT {}
"""

ADD_CONSTRAINT_QUERY = """
ALTER TABLE {}
ADD CONSTRAINT {}
FOREIGN KEY ({})
REFERENCES {}({})
ON DELETE CASCADE
DEFERRABLE INITIALLY DEFERRED
"""


def alter_constraints(apps, schema_editor):
    with transaction.atomic():
        with connection.cursor() as cursor:
            for table, fk, ref_table, ref_attr in CONSTRAINTS:
                cursor.execute(FIND_CONSTRAINT_NAME_QUERY, [table, fk, ref_table, ref_attr])
                t = cursor.fetchone()
                constraint_name = t[0]
                cursor.execute(DROP_CONSTRAINT_QUERY.format(table, constraint_name))
                cursor.execute(ADD_CONSTRAINT_QUERY.format(table, constraint_name, fk, ref_table, ref_attr))


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0048_auto_20190930_1300'),
    ]

    operations = [
        migrations.RunPython(alter_constraints)
    ]
