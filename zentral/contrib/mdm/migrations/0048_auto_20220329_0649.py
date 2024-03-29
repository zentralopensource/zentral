# Generated by Django 3.2.12 on 2022-03-29 06:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0047_auto_20210612_1119'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blueprint',
            name='activation',
            field=models.JSONField(default=dict, editable=False),
        ),
        migrations.AlterField(
            model_name='blueprint',
            name='declaration_items',
            field=models.JSONField(default=dict, editable=False),
        ),
        migrations.AlterField(
            model_name='depenrollment',
            name='admin_password_hash',
            field=models.JSONField(editable=False, null=True),
        ),
        migrations.AlterField(
            model_name='devicecommand',
            name='error_chain',
            field=models.JSONField(null=True),
        ),
        migrations.AlterField(
            model_name='devicecommand',
            name='kwargs',
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name='enterpriseapp',
            name='bundles',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='enterpriseapp',
            name='manifest',
            field=models.JSONField(),
        ),
        migrations.AlterField(
            model_name='scepconfig',
            name='challenge_kwargs',
            field=models.JSONField(editable=False),
        ),
        migrations.AlterField(
            model_name='usercommand',
            name='error_chain',
            field=models.JSONField(null=True),
        ),
        migrations.AlterField(
            model_name='usercommand',
            name='kwargs',
            field=models.JSONField(default=dict),
        ),
    ]
