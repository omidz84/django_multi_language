from django.urls import path

from . import views


app_name = 'user'
urlpatterns = [
    path('register/', views.RegisterUserView.as_view(), name='register'),
    path('login/', views.LoginUserView.as_view(), name='login'),
    path('logout/', views.LogoutUserView.as_view(), name='logout'),
    path('token/refresh/', views.RefreshTokenView.as_view(), name='token-refresh'),
    path('<int:pk>/profile/', views.UserProfileView.as_view(), name='profile'),
    path('forgot-password/', views.ForgotPasswordPhoneNumberView.as_view(), name='forgot-password'),
    path('forgot-password/verify/', views.ForgotPasswordOtpCodeView.as_view(), name='forgot-password-verify'),
    path('forgot-password/new-password/', views.ForgotPasswordNewPasswordView.as_view(), name='forgot-password-new-password'),
]
