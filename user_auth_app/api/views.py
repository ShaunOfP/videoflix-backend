from rest_framework.generics import CreateAPIView
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView, TokenBlacklistView
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
import django_rq
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import RegistrationSerializer, ConfirmPasswordSerializer, LoginSerializer
from user_auth_app.utils.send_mail import send_activation_mail
from user_auth_app.utils.reset_password import send_reset_mail
from .permissions import IsRefreshTokenAvailable
from django.conf import settings


class RegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)

        if serializer.is_valid():
            data = serializer.save()
            user = data["user"]
            token = data["token"]

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            activation_link = f"http://localhost:8000/api/activate/{uid}/{token}/"

            queue = django_rq.get_queue("default")
            queue.enqueue(
                send_activation_mail,
                user.email,
                activation_link,
            )

            return Response(
                {
                    "user": {
                        "id": user.id,
                        "email": user.email
                    },
                    "token": token
                },
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivationView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            user_id = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=user_id)
        except Exception:
            return Response({'error': 'Activation failed'}, status=400)

        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid or expired token.'}, status=400)

        if user.is_active:
            return Response({'message': 'Account already activated'}, status=200)

        user.is_active = True
        user.save()

        return Response({'message': 'Account successfully activated.'}, status=200)


class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = serializer.user

        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        response = Response()

        response.set_cookie(
            key='access_token',
            value=tokens['access'],
            httponly=True,
            secure=settings.SECURE_COOKIES,
            samesite='Lax',
        )

        response.set_cookie(
            key='refresh_token',
            value=tokens['refresh'],
            httponly=True,
            secure=settings.SECURE_COOKIES,
            samesite='Lax',
        )

        response.data = {
            'detail': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username
            }
        }

        return response


class LogoutView(TokenBlacklistView):
    permission_classes = [IsRefreshTokenAvailable]

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return Response({'error': 'Refresh-Token missing'}, status=400)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            return Response({'error': 'Invalid refresh token'}, status=400)

        response = Response(
            {'detail': 'Logout successful! All tokens will be deleted. Refresh token is now invalid.'}, status=200)

        response.delete_cookie('access_token', samesite='Lax')
        response.delete_cookie('refresh_token', samesite='Lax')

        return response


class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = [IsRefreshTokenAvailable]

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token is None:
            return Response({'error': 'Refresh-Token missing'}, status=400)

        serializer = self.get_serializer(data={'refresh': refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except:
            return Response({'error': 'Invalid Refresh-Token'}, status=401)

        access_token = serializer.validated_data.get('access')
        response = Response({'detail': 'Token refreshed',
                             'access': access_token},
                            status=200)

        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=True,
            samesite='Lax'
        )

        return response


class PasswordResetView(CreateAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'No Email provided'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'The email is not registered'}, status=400)

        token = default_token_generator.make_token(user)

        user_id = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://localhost:8000/api/password_confirm/{user_id}/{token}/"

        queue = django_rq.get_queue("default")
        queue.enqueue(
            send_reset_mail,
            user.email,
            reset_link,
        )

        return Response(
            {'detail': 'An email has been sent to reset your password.'}, status=200)


class PasswordConfirmView(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = [ConfirmPasswordSerializer]

    def post(self, request, uidb64, token):
        try:
            user_id = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=user_id)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            return Response({'error': 'Invalid link'}, status=400)

        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid or expired token'}, status=400)

        serializer = ConfirmPasswordSerializer(
            data=request.data, context={'user': user})

        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Your Password has been successfully reset.'}, status=200)
        else:
            return Response(serializer.errors, status=400)
