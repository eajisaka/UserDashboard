from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.home),
    url(r'^add_new$', views.add_new),
    url(r'^add_user$', views.add_user),
    url(r'^admin_edit_password/(?P<user_id>\d+)$', views.admin_edit_password),
    url(r'^admin_edit_user/(?P<user_id>\d+)$', views.admin_edit_user),
    url(r'^comment/(?P<user_id>\d+)/(?P<message_id>\d+)$', views.comment),
    url(r'^dashboard$', views.dashboard),
    url(r'^dashboard/admin$', views.admin_dashboard),
    url(r'^delete/(?P<user_id>\d+)$', views.delete_user),
    url(r'^edit$', views.edit),
    url(r'^edit_description', views.edit_description),
    url(r'^edit_password$', views.edit_password),
    url(r'^edit/profile/(?P<user_id>\d+)$', views.admin_edit_profile),
    url(r'^edit_user$', views.edit_user),
    url(r'^logout', views.logout),
    url(r'^message/(?P<user_id>\d+)$', views.message),
    url(r'^profile/(?P<user_id>\d+)$', views.profile),
    url(r'^registration$', views.register),
    url(r'^register_user$', views.register_user),
    url(r'^signin$', views.signin),
    url(r'^signin_user$', views.signin_user),
]