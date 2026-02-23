from django.db import models
from django.utils.translation import gettext_lazy as _


class UploadSession(models.Model):
    """
    Tracks upload sessions for users.

    Each upload session represents a complete upload workflow:
    1. User uploads files
    2. Files are processed (via Celery task)
    3. Files are submitted to OpenBIS

    This model allows tracking multiple uploads from different users
    without blocking each other.
    """

    # OpenBIS username (from session, not Django auth)
    openbis_username = models.CharField(
        max_length=255,
        help_text=_("OpenBIS username who initiated this upload session"),
    )

    # OpenBIS metadata
    space_name = models.CharField(
        max_length=255,
        help_text=_("OpenBIS space name"),
    )
    project_name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("OpenBIS project name (optional)"),
    )
    collection_name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("OpenBIS collection/experiment name (optional)"),
    )

    # Session state
    STATUS_CHOICES = [
        ("PENDING", _("Pending")),  # Files uploaded, waiting for processing
        ("PROCESSING", _("Processing")),  # Celery task is running
        ("COMPLETED", _("Completed")),  # Successfully processed
        ("FAILED", _("Failed")),  # Processing failed
        ("CANCELLED", _("Cancelled")),  # User cancelled
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="PENDING",
        help_text=_("Current status of the upload session"),
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("When this session was created"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Last update timestamp"),
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When processing was completed"),
    )

    # Error tracking
    error_message = models.TextField(
        blank=True,
        default="",
        help_text=_("Error message if status is FAILED"),
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = _("Upload Session")
        verbose_name_plural = _("Upload Sessions")
        indexes = [
            models.Index(fields=["openbis_username", "-created_at"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"Upload {self.id} - {self.openbis_username} ({self.status})"


class UploadTask(models.Model):
    """
    Tracks Celery tasks associated with an upload session.

    Each task represents a background job:
    - process_uploaded_files: Parses and uploads files to OpenBIS
    - cleanup_temporary_files: Cleans up temporary directories

    This allows monitoring task progress and status from the web interface.
    """

    # Relationship to the upload session
    upload_session = models.ForeignKey(
        UploadSession,
        on_delete=models.CASCADE,
        related_name="tasks",
        help_text=_("Upload session this task belongs to"),
    )

    # Celery task metadata
    task_id = models.CharField(
        max_length=255,
        unique=True,
        help_text=_("Celery task UUID"),
    )

    # Task type
    TASK_TYPE_CHOICES = [
        ("PROCESS_FILES", _("Process Files")),  # run_parser() in background
        ("CLEANUP_FILES", _("Cleanup Files")),  # Remove temporary files
    ]
    task_type = models.CharField(
        max_length=20,
        choices=TASK_TYPE_CHOICES,
        help_text=_("Type of task"),
    )

    # Task state (mirrors Celery states)
    STATE_CHOICES = [
        ("PENDING", _("Pending")),  # Task is waiting to be picked up by worker
        ("STARTED", _("Started")),  # Worker has started executing
        ("PROGRESS", _("In Progress")),  # Task is running (intermediate updates)
        ("SUCCESS", _("Success")),  # Task completed successfully
        ("FAILURE", _("Failure")),  # Task failed with exception
        ("RETRY", _("Retry")),  # Task is being retried
        ("CANCELLED", _("Cancelled")),  # Task was cancelled
    ]
    state = models.CharField(
        max_length=20,
        choices=STATE_CHOICES,
        default="PENDING",
        help_text=_("Current Celery task state"),
    )

    # Progress tracking
    progress_current = models.IntegerField(
        default=0,
        help_text=_("Current progress (0-100)"),
    )
    progress_total = models.IntegerField(
        default=100,
        help_text=_("Total progress units"),
    )
    progress_status = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text=_("Human-readable progress status"),
    )

    # Result/Error tracking
    result = models.JSONField(
        null=True,
        blank=True,
        help_text=_("Task result (success data)"),
    )
    error_message = models.TextField(
        blank=True,
        default="",
        help_text=_("Error message if state is FAILURE"),
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("When this task was created"),
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the task started"),
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the task completed"),
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = _("Upload Task")
        verbose_name_plural = _("Upload Tasks")
        indexes = [
            models.Index(fields=["upload_session", "task_type"]),
            models.Index(fields=["state"]),
            models.Index(fields=["task_id"]),
        ]

    def __str__(self):
        return (
            f"Task {self.task_id[:8]} - {self.get_task_type_display()} ({self.state})"
        )

    @property
    def is_complete(self) -> bool:
        """Check if task is in a terminal state."""
        return self.state in ("SUCCESS", "FAILURE", "CANCELLED")

    @property
    def is_failed(self) -> bool:
        """Check if task failed."""
        return self.state == "FAILURE"

    @property
    def is_success(self) -> bool:
        """Check if task succeeded."""
        return self.state == "SUCCESS"
