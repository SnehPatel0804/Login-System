# Generated by Django 5.1.4 on 2024-12-27 11:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_remove_customuser_failed_login_attempts_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='failed_attempts',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='customuser',
            name='lock_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
