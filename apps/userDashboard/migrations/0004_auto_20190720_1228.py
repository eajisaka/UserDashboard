# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2019-07-20 19:28
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('userDashboard', '0003_auto_20190720_1153'),
    ]

    operations = [
        migrations.AlterField(
            model_name='comment',
            name='the_message',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='userDashboard.Message'),
        ),
    ]
