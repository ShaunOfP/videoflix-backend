from django.contrib.auth import get_user_model
from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken


class IsRefreshTokenAvailable(BasePermission):
    def has_permission(self, request, view):
        """
        Checks if the refresh token is available in the request cookies.
        """
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return False
        try:
            token = RefreshToken(refresh_token)
            if token.get('token_type') != 'refresh':
                return False
            user_id = token.get('user_id')
            if not user_id:
                return False
            user = get_user_model().objects.get(pk=user_id)
            request.user = user
        except (TokenError, get_user_model().DoesNotExist, KeyError):
            return False

        return True


class IsAuthenticatedWithAccessToken(BasePermission):
    def has_permission(self, request, view):
        """
        Checks if the access token is available in the request cookies.
        """
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return False
        try:
            token = AccessToken(access_token)
            user_id = token.get('user_id')
            if not user_id:
                return False
            user = get_user_model().objects.get(pk=user_id)
            request.user = user
        except (TokenError, get_user_model().DoesNotExist, KeyError):
            return False

        return True
