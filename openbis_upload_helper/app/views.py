import datetime
import os
import tarfile
import tempfile
import uuid
import zipfile

from bam_masterdata.logger import logger
from decouple import config as environ
from django.conf import settings
from django.contrib.auth import logout
from django.core.cache import cache
from django.shortcuts import redirect
from django.shortcuts import render
from django.views.decorators.http import require_POST
from pybis import Openbis

from .models import UploadSession
from .models import UploadTask
from .tasks import cleanup_temporary_files
from .tasks import process_uploaded_files
from .utils import FileLoader
from .utils import FilesParser
from .utils import encrypt_password
from .utils import extract_name
from .utils import get_openbis_from_cache
from .utils import log_results
from .utils import preload_context_request
from .utils import reorganize_spaces


def login(request):
    error = None

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        personal_access_token = request.POST.get("personal_access_token")
        try:
            # Prefer personal access token when provided
            o = Openbis(settings.OPENBIS_URL)
            if personal_access_token:
                # authenticate with PAT
                o.set_token(personal_access_token, save_token=True)
                encrypted_password = encrypt_password(personal_access_token)
                session_id = str(uuid.uuid4())
                # reuse existing session keys (password holds encrypted secret)
                request.session["openbis_username"] = username or ""
                request.session["openbis_password"] = encrypted_password
                request.session["openbis_session_id"] = session_id
                cache.set(
                    session_id, o, timeout=60 * 60
                )  # Cache for 1 hour (adjustable)
                return redirect("app:homepage")

            # fall back to classic username/password login
            o.login(username, password, save_token=True)
            encrypted_password = encrypt_password(password)
            session_id = str(uuid.uuid4())
            request.session["openbis_username"] = username
            request.session["openbis_password"] = encrypted_password
            request.session["openbis_session_id"] = session_id
            cache.set(session_id, o, timeout=60 * 60)  # Cache for 1 hour (adjustable)
            return redirect("app:homepage")

        except Exception as e:
            logger.error(f"Login failed for user '{username}': {e}", exc_info=True)
            error = "Invalid username/password or personal access token."

    return render(request, "login.html", {"error": error})


def logout_view(request):
    request.session.flush()  # Clear all session data
    logout(request)
    return redirect("app:login")


def homepage(request):
    # Check if the user is logged in
    o = get_openbis_from_cache(request)
    if not o:
        logger.info("User not logged in, redirecting to login page.")
        return redirect("app:login")
    context = {}
    available_parsers, parser_choices = preload_context_request(request, context)

    # load
    filter_list = environ("SPACE_FILTER", default=["ELN_SETTINGS"])

    # exclude spaces whose code/identifier/name matches an entry in filter_list
    filtered_spaces = []
    for s in o.get_spaces():
        code = extract_name(s)
        if code not in filter_list:
            filtered_spaces.append(code)
    filtered_spaces = reorganize_spaces(filtered_spaces)

    context["spaces"] = filtered_spaces
    context["available_parsers"] = available_parsers

    # selected_space default
    selected_space = None
    projects = []
    collections = []

    # Get to filter after space selection
    if request.method == "GET" and request.GET.get("space_select"):
        selected_space = request.GET.get("space")
        if selected_space:
            try:
                projects_raw = o.get_projects(space=selected_space)
            except TypeError:
                projects_raw = o.get_projects()
            try:
                collections_raw = o.get_experiments(space=selected_space)
            except TypeError:
                collections_raw = o.get_experiments()

            # Filter
            try:
                projects = [extract_name(p) for p in projects_raw]
            except Exception:
                projects = [extract_name(p) for p in projects_raw]

            try:
                collections = [extract_name(c) for c in collections_raw]
            except Exception:
                collections = [extract_name(c) for c in collections_raw]

            # context["projects"] = projects
            # context["collections"] = collections

    else:
        projects = []
        collections = []

    context["selected_space"] = selected_space
    context["projects"] = projects
    context["collections"] = collections

    # Reset session if requested with button
    if request.method == "GET" and "reset" in request.GET:
        for key in ["uploaded_files", "checker_logs"]:
            request.session.pop(key, None)
        return redirect("app:homepage")

    # CARD 1: Select files
    if request.method == "POST" and "upload" in request.POST:
        space = request.POST.get("selected_space")
        project_name = request.POST.get("project_name")
        collection_name = request.POST.get("collection_name")
        uploaded_files = request.FILES.getlist("files[]")
        selected_files_str = request.POST.get("selected_files", "")
        selected_files = selected_files_str.split(",") if selected_files_str else []

        if not uploaded_files:
            context["error"] = "No files uploaded."
            return render(request, "homepage.html", context)
        try:
            file_loader = FileLoader(uploaded_files, selected_files)
            saved_file_names = file_loader.load_files()

            # Save for card 2
            request.session["selected_space"] = space
            request.session["project_name"] = project_name
            request.session["collection_name"] = collection_name
            request.session["uploaded_files"] = saved_file_names
            request.session["parsers_assigned"] = False
            request.session.pop("checker_logs", None)
            return redirect("app:homepage")

        except Exception as e:
            logger.exception("Error while uploading files")
            context["error"] = str(e)
            return render(request, "homepage.html", context)

    # CARD 2: Select parser
    elif request.method == "POST" and "assign_parsers" in request.POST:
        uploaded_files = request.session.get("uploaded_files", [])
        parser_choices = request.session.get("parser_choices", [])

        if not uploaded_files:
            context["error"] = "No files uploaded. Please upload files first."
            return render(request, "homepage.html", context)

        context["uploaded_files"] = [name for name, _ in uploaded_files]
        context["parser_choices"] = parser_choices
        available_parsers = context["available_parsers"]

        try:
            # Create UploadSession to track this upload
            upload_session = UploadSession.objects.create(
                openbis_username=request.session.get("openbis_username"),
                space_name=request.session.get("selected_space"),
                project_name=request.session.get("project_name", ""),
                collection_name=request.session.get("collection_name", ""),
                status="PROCESSING",
            )

            # Assign parsers to files
            files_parser_class = FilesParser(uploaded_files, available_parsers, o)
            parsed_files, files_parser = files_parser_class.assign_parsers(request)

            # Start Celery task for processing files asynchronously
            # Note: We use parsed_files (dict with parser names as keys) instead of files_parser
            # because files_parser has object instances as keys which can't be JSON serialized
            process_task = process_uploaded_files.delay(
                parsed_files=parsed_files,
                project_name=request.session.get("project_name", ""),
                collection_name=request.session.get("collection_name", ""),
                space_name=request.session.get("selected_space"),
                openbis_session_id=request.session.get("openbis_session_id"),
            )

            # Create UploadTask to track the Celery task
            upload_task = UploadTask.objects.create(
                upload_session=upload_session,
                task_id=process_task.id,
                task_type="PROCESS_FILES",
                state="PENDING",
            )

            logger.info(
                f"Started async file processing task {process_task.id} for user {request.session.get('openbis_username')}"
            )

            # Start cleanup task (will run after processing)
            cleanup_task = cleanup_temporary_files.delay(
                uploaded_files=uploaded_files,
            )

            # Create another UploadTask for cleanup
            UploadTask.objects.create(
                upload_session=upload_session,
                task_id=cleanup_task.id,
                task_type="CLEANUP_FILES",
                state="PENDING",
            )

            logger.info(
                f"Started async cleanup task {cleanup_task.id} for user {request.session.get('openbis_username')}"
            )

            # Clear session for next upload
            request.session.pop("uploaded_files", None)
            request.session.pop("parsers_assigned", None)
            request.session.pop("checker_logs", None)

            # save Logs
            context_logs = log_results(request, parsed_files, context)

            context["logs"] = context_logs
            request.session["checker_logs"] = context_logs
            request.session["parsers_assigned"] = True
            return redirect("app:homepage")

        except Exception as e:
            logger.exception("Error while assigning parsers")
            context["error"] = str(e)
            return render(request, "homepage.html", context)

    # GET request
    # for card 1 forms
    context["project_name"] = request.session.get("project_name", "")
    context["collection_name"] = request.session.get("collection_name", "")
    # for card 3/2
    context["parser_assigned"] = request.session.get("parsers_assigned", False)
    uploaded_files = request.session.get("uploaded_files", [])
    context["uploaded_files"] = (
        [name for name, _ in uploaded_files] if uploaded_files else None
    )
    context["parser_choices"] = request.session.get("parser_choices", [])
    context["logs"] = request.session.get("checker_logs")
    return render(request, "homepage.html", context)


@require_POST
def clear_state(request):
    request.session.pop("checker_logs", None)
    return redirect("app:homepage")
