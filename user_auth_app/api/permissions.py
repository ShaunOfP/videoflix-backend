from rest_framework.permissions import BasePermission

class IsRefreshTokenAvailable(BasePermission):
    def has_permission(self, request, view):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return False
        return True