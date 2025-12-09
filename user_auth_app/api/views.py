from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

class RegistrationView(CreateAPIView):
    pass


class ActivationView(RetrieveAPIView):
    pass


class LoginView(TokenObtainPairView):
    pass


class LogoutView(CreateAPIView):
    pass


class CustomTokenRefreshView(TokenRefreshView):
    pass


class PasswordResetView(CreateAPIView):
    pass


class PasswordConfirmView(CreateAPIView):
    pass