# Generated by Django 4.2.1 on 2023-06-12 13:20

import authy.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("authy", "0003_alter_useraccount_first_name_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="useraccount",
            name="is_active",
            field=models.BooleanField(
                default=False,
                help_text="Designates whether the user has completed validation and is active.",
                verbose_name="Activate Account",
            ),
        ),
        migrations.AlterField(
            model_name="useraccount",
            name="is_deleted",
            field=models.BooleanField(
                default=False,
                help_text="Designates whether this entry should be soft-deleted.",
                verbose_name="Deactivate Account",
            ),
        ),
        migrations.AlterField(
            model_name="useraccount",
            name="phone_number",
            field=models.CharField(
                max_length=20,
                unique=True,
                validators=[authy.validators.validate_phone_number],
            ),
        ),
    ]
