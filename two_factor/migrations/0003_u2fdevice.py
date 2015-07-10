# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('two_factor', '0002_auto_20150110_0810'),
    ]

    operations = [
        migrations.CreateModel(
            name='U2FDevice',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(help_text=b'The human-readable name of this device.', max_length=64)),
                ('confirmed', models.BooleanField(default=True, help_text=b'Is this device ready for use?')),
                ('public_key', models.TextField()),
                ('key_handle', models.TextField()),
                ('app_id', models.TextField()),
                ('counter', models.PositiveIntegerField(default=0, help_text=b'The non-volatile login counter most recently used by this device.')),
                ('challenge', models.TextField()),
                ('last_used_at', models.DateTimeField(null=True)),
                ('user', models.ForeignKey(help_text=b'The user that this device belongs to.', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'verbose_name': 'U2F device',
            },
        ),
    ]
