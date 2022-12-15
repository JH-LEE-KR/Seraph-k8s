from django.urls import path
from . import views

app_name = 'accounts'
urlpatterns = [
    path('profile/', views.profile, name='profile'),
    path('', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('signup/', views.signup, name='signup'),
    path('delete/', views.delete, name='delete'),
    path('update/', views.update, name='update'),
    path('update_pw/', views.update_pw, name='update_pw'),
    path('emailVerification/<uidb64>/<token>', views.activate, name='emailActivate'),
]