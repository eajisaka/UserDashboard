# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2019-07-23 20:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userDashboard', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='read_status',
            field=models.IntegerField(null=True),
        ),
    ]
