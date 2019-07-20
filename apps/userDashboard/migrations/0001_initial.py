# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2019-07-20 22:29
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('comment', models.TextField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(max_length=255)),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('pw_hash', models.CharField(max_length=100)),
                ('admin_level', models.CharField(max_length=10)),
                ('description', models.TextField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name='message',
            name='receiver',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_by', to='userDashboard.User'),
        ),
        migrations.AddField(
            model_name='message',
            name='sender',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_by', to='userDashboard.User'),
        ),
        migrations.AddField(
            model_name='comment',
            name='commenter',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='commented_by', to='userDashboard.User'),
        ),
        migrations.AddField(
            model_name='comment',
            name='recipient',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='commented_to', to='userDashboard.User'),
        ),
        migrations.AddField(
            model_name='comment',
            name='the_message',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='userDashboard.Message'),
        ),
    ]
