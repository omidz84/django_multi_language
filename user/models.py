from django.contrib.auth.hashers import make_password
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.utils.translation import gettext as _
from django.contrib.gis.db import models as model

from .validators import check_phone, isnumeric


# Create your models here.


class MyUserManager(UserManager):
    """
        Creating a new user manager for our customized django user.
    """

    def create_superuser(self, username=None, email=None, password=None, **extra_fields):
        extra_fields.setdefault('first_name', 'admin')
        username = extra_fields['phone_number']
        return super().create_superuser(username, email, password, **extra_fields)

    def create_user(self, username=None, email=None, password=None, **extra_fields):
        username = extra_fields['phone_number']
        return super().create_user(username, email, password, **extra_fields)


class User(AbstractUser):
    USERNAME_FIELD = 'phone_number'
    phone_number = models.CharField(
        max_length=11,
        db_index=True,
        unique=True,
        validators=[check_phone],
        verbose_name=_('phone number')
    )
    code_melli = models.CharField(
        max_length=10,
        db_index=True,
        unique=True,
        validators=[isnumeric],
        verbose_name=_('code melli')
    )
    address = models.TextField(verbose_name=_('address'))
    location = model.GeometryField(geography=True, db_index=True, verbose_name=_('Location'))
    objects = MyUserManager()

    def save(self, *args, **kwargs):
        self.username = self.phone_number
        self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.last_name} | {self.phone_number}'

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
