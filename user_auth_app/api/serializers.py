from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirmed_password = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Validates the registration data.
        """
        if data["password"] != data["confirmed_password"]:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"})
        if User.objects.filter(email=data["email"]).exists():
            raise serializers.ValidationError(
                {"email": "Email already in use"})
        return data

    def create(self, validated_data):
        """
        Creates a new user with the provided data and generates an activation token.
        """
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


class ConfirmPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def save(self):
        """
        Saves the updated password for the user.
        """
        new_password = self.validated_data['new_password']
        confirmed_password = self.validated_data['confirm_password']

        if new_password != confirmed_password:
            raise serializers.ValidationError(
                {'error': 'Passwords do not match'})

        user = self.context.get('user')

        if user is None:
            raise serializers.ValidationError({'error': 'User not provided'})

        user.set_password(new_password)
        user.save()
        return user


User = get_user_model()


class LoginSerializer(TokenObtainPairSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        """
        Initializes the serializer and removes the username field.
        """
        super().__init__(*args, **kwargs)

        if "username" in self.fields:
            self.fields.pop("username")

    def validate(self, attrs):
        """
        Validates the login credentials and returns the token pair if valid.
        """
        email = attrs.get("email")
        password = attrs.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid credentials")

        if not user.is_active:
            raise serializers.ValidationError("Account is not active")

        data = super().validate(
            {"username": user.username, "password": password})

        data["user"] = {
            "id": user.id,
            "email": user.email
        }

        return data
