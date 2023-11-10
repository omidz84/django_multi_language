from django.utils.translation import gettext as _

from rest_framework import status
from rest_framework.generics import CreateAPIView, GenericAPIView, RetrieveUpdateAPIView
from rest_framework.request import Request
from rest_framework.response import Response

from .models import User
from . import serializers
from .permissions import IsOwner

# Create your views here.


class RegisterUserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = serializers.RegisterUserSerializer


class LoginUserView(GenericAPIView):
    serializer_class = serializers.LoginUserSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status.HTTP_200_OK)


class LogoutUserView(GenericAPIView):
    serializer_class = serializers.LogoutUserSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': _('logout OK.')}, status.HTTP_200_OK)


class RefreshTokenView(GenericAPIView):
    serializer_class = serializers.RefreshTokenSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status.HTTP_200_OK)


class UserProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsOwner]
    queryset = User.objects.all()
    serializer_class = serializers.UserSerializer


class ForgotPasswordPhoneNumberView(GenericAPIView):
    serializer_class = serializers.ForgotPasswordPhoneNumberSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status.HTTP_200_OK)


class ForgotPasswordOtpCodeView(GenericAPIView):
    serializer_class = serializers.ForgotPasswordOtpCodeSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.session.get('phone_number', str)
        request.session['phone_number'] = serializer.validated_data['phone_number']
        request.session.modified = True
        return Response({'msg': _('code ok.')}, status.HTTP_200_OK)


class ForgotPasswordNewPasswordView(GenericAPIView):
    serializer_class = serializers.ForgotPasswordNewPasswordSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            phone_number = request.session.get('phone_number', str)
            user = User.objects.get(phone_number=phone_number)
            user.password = serializer.validated_data['password']
            user.save()
            del request.session['phone_number']
        except:
            return Response({'msg': _('You are not authorized')}, status.HTTP_400_BAD_REQUEST)

        return Response({'msg': _('Password changed successfully')}, status.HTTP_200_OK)
