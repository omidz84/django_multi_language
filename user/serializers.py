import random

from django.conf import settings
from django.utils.translation import gettext as _
from django.core.exceptions import ValidationError

from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .utils import get_tokens, send_sms


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'id',
            'first_name',
            'last_name',
            'phone_number',
            'code_melli',
            'email',
            'address',
            'location',
        ]


class RegisterUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(min_length=8, label=_('confirm password'), write_only=True, required=True)
    token = serializers.SerializerMethodField(read_only=True, label=_('token'))

    class Meta:
        model = User
        fields = [
            'id',
            'first_name',
            'last_name',
            'phone_number',
            'code_melli',
            'email',
            'address',
            'location',
            'password',
            'password2',
            'token'
        ]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def get_token(self, obj):
        user = User.objects.get(phone_number=obj.phone_number)
        token = get_tokens(user)
        refresh = token['refresh']
        access = token['access']
        settings.REDIS_JWT_TOKEN.set(name=refresh, value=refresh, ex=settings.REDIS_REFRESH_TIME)
        return {'access': access, 'refresh': refresh}

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise ValidationError(_('The passwords must match'))
        return data

    def create(self, validated_data):
        data = validated_data
        user = User.objects.create(
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone_number=data['phone_number'],
            code_melli=data['code_melli'],
            address=data['address'],
            location=data['location'],
            password=data['password']
        )
        return user


class LoginUserSerializer(serializers.Serializer):
    phone_number = serializers.CharField(label=_('phone_number'), required=True, write_only=True)
    password = serializers.CharField(label=_('password'), required=True, write_only=True)
    response = serializers.SerializerMethodField(read_only=True)

    def get_response(self, obj):
        try:
            user = User.objects.get(phone_number=obj['phone_number'])
            if user.check_password(obj['password']) and user.is_active:
                token = get_tokens(user)
                refresh = token['refresh']
                access = token['access']
                settings.REDIS_JWT_TOKEN.set(name=refresh, value=refresh, ex=settings.REDIS_REFRESH_TIME)
                s_user = UserSerializer(instance=user)
                return {'user': s_user.data, 'token': {'access': access, 'refresh': refresh}}
            return {'msg': _('The mobile number or password is not correct')}
        except:
            return {'msg': _('The mobile number or password is not correct')}


class LogoutUserSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=1000, required=True, label=_('refresh'))

    def validate_refresh(self, data):
        if settings.REDIS_JWT_TOKEN.get(name=data):
            settings.REDIS_JWT_TOKEN.delete(data)
            return data
        else:
            raise ValidationError(_('Token is invalid or expired'))


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=1000, required=True, label=_('refresh'), write_only=True)
    token = serializers.SerializerMethodField(read_only=True, label=_('token'))

    def validate_refresh(self, data):
        if settings.REDIS_JWT_TOKEN.get(name=data):
            return data
        else:
            raise ValidationError(_('Token is invalid or expired'))

    def get_token(self, obj):
        refresh = settings.REDIS_JWT_TOKEN.get(name=obj['refresh'])
        token_refresh = RefreshToken(refresh)
        user = User.objects.get(id=token_refresh['user_id'])
        settings.REDIS_JWT_TOKEN.delete(refresh)
        token = get_tokens(user)
        access = token['access']
        refresh = token['refresh']
        settings.REDIS_JWT_TOKEN.set(name=refresh, value=refresh, ex=settings.REDIS_REFRESH_TIME)
        data = {'access': access, 'refresh': refresh}
        return data


class ForgotPasswordPhoneNumberSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=True, label=_('phone number'))

    def validate_phone_number(self, data):
        try:
            user = User.objects.get(phone_number=data)
        except:
            raise ValidationError(_('phone number invalid'))
        otp_code = random.randint(10000, 99999)
        if settings.REDIS_OTP_CODE.get(name=data):
            raise ValidationError(_('The code has been sent'))
        settings.REDIS_OTP_CODE.set(name=data, value=otp_code, ex=settings.REDIS_OTP_CODE_TIME)
        send_sms(phone_number=data, msg=otp_code)
        return otp_code


class ForgotPasswordOtpCodeSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=True, label=_('phone number'))
    otp_code = serializers.CharField(required=True, label=_('code'))

    def validate_phone_number(self, data):
        try:
            user = User.objects.get(phone_number=data)
            return data
        except:
            raise ValidationError(_('phone number invalid'))

    def validate_otp_code(self, data):
        try:
            phone_number = self.initial_data.get('phone_number')
            redis_code = settings.REDIS_OTP_CODE.get(name=phone_number)
            redis_code = redis_code.decode('utf-8')
        except:
            raise ValidationError(_('code is not valid'))
        if redis_code == data:
            return data
        else:
            raise ValidationError(_('code is not valid'))


class ForgotPasswordNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, label=_('new password'), write_only=True, required=True)
    password2 = serializers.CharField(min_length=8, label=_('confirm password'), write_only=True, required=True)

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise ValidationError(_('The passwords must match'))
        else:
            return data
