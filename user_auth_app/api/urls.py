from django.urls import path

from .views import RegistrationView, ActivationView, LoginView, LogoutView, CustomTokenRefreshView, PasswordResetView, PasswordConfirmView

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='user-registration'),
    path('activate/<uidb64>/<token>/', ActivationView.as_view(), name='user-activation'),
    path('login/', LoginView.as_view(), name='user-login'),
    path('logout/', LogoutView.as_view(), name='user-logout'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token-refresh'),
    path('password_reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password_confirm/<uidb64>/<token>/', PasswordConfirmView.as_view(), name='password-confirm'),
]