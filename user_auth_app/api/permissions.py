from rest_framework.permissions import BasePermission


class IsRefreshTokenAvailable(BasePermission):
    def has_permission(self, request, view):
        """
        Checks if the refresh token is available in the request cookies.
        """
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
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
        return True
