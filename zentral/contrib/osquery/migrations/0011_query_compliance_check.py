# Generated by Django 2.2.24 on 2021-12-24 18:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('compliance_checks', '0001_initial'),
        ('osquery', '0010_auto_20210629_0723'),
    ]

    operations = [
        migrations.AddField(
            model_name='query',
            name='compliance_check',
            field=models.OneToOneField(
                editable=False, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='query', to='compliance_checks.ComplianceCheck'),
        ),
    ]
