from django.urls import path

from . import views

app_name = "app"

urlpatterns = [
    path("", views.homepage, name="homepage"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout_view, name="logout"),
]
