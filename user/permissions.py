from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework_simplejwt.tokens import AccessToken

from user.models import User


class IsAdmin(BasePermission):

    def has_permission(self, request, view):
        try:
            user_jwt = request.META.get('HTTP_AUTHORIZATION')
            if user_jwt is not None:
                decoded_token = AccessToken(user_jwt)
                user = User.objects.get(id=decoded_token["user_id"])
                return bool(user.type_id == 1)
            else:
                return False
        except:
            return False


# -----------------------------------------------------------------------


class IsAdminOrReadOnly(BasePermission):

    def has_permission(self, request, view):
        try:
            user_jwt = request.META.get('HTTP_AUTHORIZATION')
            if user_jwt is not None:
                decoded_token = AccessToken(user_jwt)
                user = User.objects.get(id=decoded_token["user_id"])
                return bool(user.type_id == 1)
            elif request.method in SAFE_METHODS:
                return True
            else:
                return False
        except:
            return False


# -----------------------------------------------------------------------


class IsAdminOrDelivery(BasePermission):

    def has_permission(self, request, view):
        try:
            user_jwt = request.META.get('HTTP_AUTHORIZATION')
            if user_jwt is not None:
                decoded_token = AccessToken(user_jwt)
                user = User.objects.get(id=decoded_token["user_id"])
                return bool(user.type_id == 1 or user.type_id == 2)
            else:
                return False
        except:
            return False


# -----------------------------------------------------------------------


class IsAuthenticated(BasePermission):

    def has_permission(self, request, view):
        try:
            user_jwt = request.META.get('HTTP_AUTHORIZATION')
            if user_jwt is not None:
                decoded_token = AccessToken(user_jwt)
                user = User.objects.get(id=decoded_token["user_id"])
                return bool(user)
            else:
                return False
        except:
            return False


class IsOwner(BasePermission):

    def has_object_permission(self, request, view, obj):
        try:
            user_jwt = request.META.get('HTTP_AUTHORIZATION')
            if user_jwt is not None:
                decoded_token = AccessToken(user_jwt)
                user = User.objects.get(id=decoded_token["user_id"])
                return bool(user and user == obj)
            else:
                return False
        except:
            return False

