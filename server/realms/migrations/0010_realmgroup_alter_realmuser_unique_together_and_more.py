# Generated by Django 4.2.8 on 2024-02-01 16:08

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0077_file_signing_id'),
        ('realms', '0009_realm_custom_attr_1_claim_realm_custom_attr_2_claim_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='RealmGroup',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('scim_external_id', models.CharField(max_length=255, null=True)),
                ('display_name', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('parent', models.ForeignKey(null=True,
                                             on_delete=django.db.models.deletion.SET_NULL, to='realms.realmgroup')),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='realmuser',
            unique_together={('realm', 'username')},
        ),
        migrations.AddField(
            model_name='realm',
            name='scim_enabled',
            field=models.BooleanField(default=False, verbose_name='SCIM enabled'),
        ),
        migrations.AddField(
            model_name='realmuser',
            name='scim_active',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='realmuser',
            name='scim_external_id',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterUniqueTogether(
            name='realmuser',
            unique_together={('realm', 'username'), ('realm', 'scim_external_id')},
        ),
        migrations.CreateModel(
            name='RealmUserGroupMembership',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='realms.realmgroup')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='realms.realmuser')),
            ],
        ),
        migrations.AddField(
            model_name='realmgroup',
            name='realm',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='realms.realm'),
        ),
        migrations.CreateModel(
            name='RealmEmail',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('primary', models.BooleanField(default=False)),
                ('type', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='realms.realmuser')),
            ],
        ),
        migrations.AddField(
            model_name='realmuser',
            name='groups',
            field=models.ManyToManyField(through='realms.RealmUserGroupMembership', to='realms.realmgroup'),
        ),
        migrations.CreateModel(
            name='RealmTagMapping',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('group_name', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('realm', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='realms.realm')),
                ('tag', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='inventory.tag')),
            ],
            options={
                'unique_together': {('realm', 'group_name', 'tag')},
            },
        ),
        migrations.AlterUniqueTogether(
            name='realmgroup',
            unique_together={('realm', 'display_name'), ('realm', 'scim_external_id')},
        ),
    ]
