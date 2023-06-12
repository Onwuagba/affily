from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = get_user_model()
        fields = '__all__'

    def validate(self, data):
        error = {}
        if not data.get("password") or not data.get("confirm_password"):
            error["password"] = "Please enter a password and confirm it"
        if data.get("password") != data.get("confirm_password"):
            error["password"] = "Your passwords do not match"

        if error:
            raise serializers.ValidationError(error)
        return data

    def create(self, validated_data):
        password = validated_data.pop('password', None)

        user = self.Meta.model.objects.create(**validated_data)

        user.set_password(password)
        user.save()
        # token = Token.objects.create(user=user)
        # uid = urlsafe_b64encode(bytes(str(user.uid), "utf-8")).decode("utf-8")

        # email_content = {
        #     "subject": "Confirm your account on Gifty",
        #     "sender": email_sender,
        #     "recipient": self.validated_data["email"],
        #     "template": "confirm_email.html",
        # }
        # confirm_url = request.build_absolute_uri(f"confirm_email/{uid}/{token}")
        # print(confirm_url)
        # context = {"name": self.validated_data["first_name"], "url": confirm_url}

        # confirm_mail, result = send_mail_now(email_content, context)
        # if not result:
        #     raise serializers.ValidationError(confirm_mail)
        return user
