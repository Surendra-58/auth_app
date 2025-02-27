# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.Home, name='home'),
#     path('register/', views.RegisterView,name='register'),
#     path('login/',views.LoginView, name = 'login'),
#     path('logout/', views.LogoutView, name='logout'),
#     path('forget-password/',views.ForgetPassword, name='forget-password'),
#     path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
#     path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),   


# ]

from django.urls import path
from .views import (
    Home, RegisterView, LoginView, LogoutView,
    ForgetPassword, PasswordResetSent, ResetPassword
)

urlpatterns = [
    path('', Home, name='home'),
    path('register/', RegisterView, name='register'),
    path('login/', LoginView, name='login'),
    path('logout/', LogoutView, name='logout'),
    
    # Password Reset URLs
    path('forget-password/', ForgetPassword, name='forget-password'),
    path('password-reset-sent/', PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:signed_token>/', ResetPassword, name='reset-password'),
]
