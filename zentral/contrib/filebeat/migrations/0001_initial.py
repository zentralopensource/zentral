# Generated by Django 2.2.1 on 2019-05-10 12:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('inventory', '0045_auto_20190426_1611'),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='Configuration',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=256, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Enrollment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.PositiveSmallIntegerField(default=1, editable=False)),
                ('distributor_pk', models.PositiveIntegerField(editable=False, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('filebeat_release', models.CharField(blank=True, max_length=64, null=True)),
                ('configuration', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='filebeat.Configuration')),
                ('distributor_content_type', models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='contenttypes.ContentType')),
                ('secret', models.OneToOneField(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='filebeat_enrollment', to='inventory.EnrollmentSecret')),
            ],
            options={
                'abstract': False,
                'unique_together': {('distributor_content_type', 'distributor_pk')},
            },
        ),
        migrations.CreateModel(
            name='EnrolledMachine',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('serial_number', models.TextField(db_index=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('enrollment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='filebeat.Enrollment')),
            ],
        ),
    ]
