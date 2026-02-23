# for future use from django.contrib import admin

# Register your models here.
from django.contrib import admin

from .models import UploadSession
from .models import UploadTask


@admin.register(UploadSession)
class UploadSessionAdmin(admin.ModelAdmin):
    list_display = ["id", "openbis_username", "space_name", "status", "created_at"]
    list_filter = ["status", "created_at"]
    search_fields = ["openbis_username", "space_name"]


@admin.register(UploadTask)
class UploadTaskAdmin(admin.ModelAdmin):
    list_display = ["task_id", "task_type", "state", "progress_current", "created_at"]
    list_filter = ["state", "task_type"]
    search_fields = ["task_id"]
