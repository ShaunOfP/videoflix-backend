from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator


class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirmed_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["password"] != data["confirmed_password"]:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"})
        if User.objects.filter(email=data["email"]).exists():
            raise serializers.ValidationError(
                {"email": "Email already in use"})
        return data

    def create(self, validated_data):
        email = validated_data["email"]
        password = validated_data["password"]

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            is_active=False
        )

        token = default_token_generator.make_token(user)

        return {
            "user": user,
            "token": token
        }

class LoginSerializer(serializers.Serializer):
    pass


class ConfirmPasswordSerializer():
    pass