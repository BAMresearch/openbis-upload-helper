from types import SimpleNamespace
from unittest.mock import patch

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.test import RequestFactory
from django.test import override_settings
from django.test.client import MULTIPART_CONTENT
from django.urls import reverse

from openbis_upload_helper.app import views

factory = RequestFactory()


@override_settings(OPENBIS_URL="https://openbis.example")
@patch("openbis_upload_helper.app.views.cache")
@patch("openbis_upload_helper.app.views.encrypt_password")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_success(
    mock_openbis_class,
    mock_encrypt,
    mock_cache,
    mock_openbis,
    attach_session,
):
    mock_openbis_class.return_value = mock_openbis
    mock_encrypt.return_value = "encrypted"

    request = attach_session(
        factory.post(
            "/login",
            {"username": "testuser", "password": "correct_password"},
        ),
    )
    response = views.login(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("homepage")
    mock_openbis_class.assert_called_once_with("https://openbis.example")
    mock_openbis.login.assert_called_once_with(
        "testuser",
        "correct_password",
        save_token=True,
    )
    assert request.session["openbis_username"] == "testuser"
    assert request.session["openbis_password"] == "encrypted"
    assert "openbis_session_id" in request.session
    assert mock_openbis.logged_in is True
    mock_cache.set.assert_called_once()


@override_settings(OPENBIS_URL="https://openbis.example")
@patch("openbis_upload_helper.app.views.cache")
@patch("openbis_upload_helper.app.views.encrypt_password")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_token(
    mock_openbis_class,
    mock_encrypt,
    mock_cache,
    mock_openbis,
    attach_session,
):
    mock_openbis_class.return_value = mock_openbis
    mock_encrypt.return_value = "encrypted"

    request = attach_session(
        factory.post("/login", {"personal_access_token": "mytoken"}),
    )
    response = views.login(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("homepage")
    mock_openbis_class.assert_called_once_with("https://openbis.example")
    mock_openbis.set_token.assert_called_once_with(
        "mytoken",
        save_token=True,
    )
    assert request.session["openbis_username"] == ""
    assert request.session["openbis_password"] == "encrypted"
    assert "openbis_session_id" in request.session
    assert mock_openbis.logged_in is True
    mock_cache.set.assert_called_once()


@override_settings(OPENBIS_URL="https://openbis.example")
@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_failure(
    mock_openbis_class, mock_render, mock_openbis, attach_session
):
    mock_openbis_class.return_value = mock_openbis
    mock_render.return_value = HttpResponse("login")

    request = attach_session(
        factory.post("/login", {"username": "testuser", "password": "wrongpass"}),
    )
    response = views.login(request)

    assert isinstance(response, HttpResponse)
    mock_openbis_class.assert_called_once_with("https://openbis.example")
    mock_openbis.login.assert_called_once_with(
        "testuser",
        "wrongpass",
        save_token=True,
    )
    assert mock_render.called
    context = mock_render.call_args[0][2]
    assert context["error"] == "Invalid username/password or personal access token."
    assert mock_openbis.logged_in is False


@override_settings(OPENBIS_URL="https://openbis.example")
@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_set_token_failure(
    mock_openbis_class,
    mock_render,
    mock_openbis,
    attach_session,
):
    mock_openbis_class.return_value = mock_openbis
    mock_render.return_value = HttpResponse("login")

    request = attach_session(
        factory.post("/login", {"personal_access_token": "invalidtoken"}),
    )
    response = views.login(request)

    assert isinstance(response, HttpResponse)
    mock_openbis_class.assert_called_once_with("https://openbis.example")
    mock_openbis.set_token.assert_called_once_with(
        "invalidtoken",
        save_token=True,
    )
    assert mock_render.called
    context = mock_render.call_args[0][2]
    assert context["error"] == "Invalid username/password or personal access token."
    assert mock_openbis.logged_in is False


@patch("openbis_upload_helper.app.views.render")
def test_login_view_get(mock_render, attach_session):
    mock_render.return_value = HttpResponse("login")

    request = attach_session(factory.get("/login"))
    response = views.login(request)

    assert isinstance(response, HttpResponse)
    mock_render.assert_called_once()
    context = mock_render.call_args[0][2]
    assert context["error"] is None


@patch("openbis_upload_helper.app.views.logout")
def test_logout_view_flushes_session_and_redirects(mock_logout, attach_session):
    request = attach_session(factory.get("/logout"))

    response = views.logout_view(request)

    assert request.session.flushed is True
    mock_logout.assert_called_once_with(request)
    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("login")


@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_redirects_when_not_logged_in(mock_get_openbis, attach_session):
    mock_get_openbis.return_value = None

    request = attach_session(factory.get("/"))
    response = views.homepage(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("login")


@patch("openbis_upload_helper.app.views.reorganize_spaces")
@patch("openbis_upload_helper.app.views.extract_name")
@patch("openbis_upload_helper.app.views.preload_context_request")
@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
@patch("openbis_upload_helper.app.views.render")
def test_homepage_get_space_select(
    mock_render,
    mock_get_openbis,
    mock_preload,
    mock_extract_name,
    mock_reorganize,
    mock_openbis,
    attach_session,
):
    mock_openbis.get_spaces.return_value = [SimpleNamespace(code="BAM_1")]
    mock_openbis.get_projects.return_value = [SimpleNamespace(code="P1")]
    mock_openbis.get_experiments.return_value = [SimpleNamespace(code="C1")]
    mock_get_openbis.return_value = mock_openbis
    mock_preload.return_value = ({}, [])
    mock_extract_name.side_effect = ["BAM_1", "P1", "C1"]
    mock_reorganize.return_value = ["BAM_1"]
    mock_render.return_value = HttpResponse("home")

    request = attach_session(
        factory.get("/?space_select=1&space=TEST"),
    )
    response = views.homepage(request)

    assert isinstance(response, HttpResponse)
    context = mock_render.call_args[0][2]
    assert context["selected_space"] == "TEST"
    assert context["projects"] == ["P1"]
    assert context["collections"] == ["C1"]
    assert context["spaces"] == ["BAM_1"]


@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_get_reset_clears_session_and_redirects(
    mock_get_openbis,
    mock_openbis,
    attach_session,
):
    mock_get_openbis.return_value = mock_openbis

    request = attach_session(factory.get("/?reset=1"))
    request.session["uploaded_files"] = [("f.txt", "/tmp/f.txt")]
    request.session["checker_logs"] = ["log"]

    response = views.homepage(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("homepage")
    assert "uploaded_files" not in request.session
    assert "checker_logs" not in request.session


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_upload_no_files(
    mock_get_openbis,
    mock_render,
    mock_openbis,
    attach_session,
):
    mock_get_openbis.return_value = mock_openbis
    mock_render.return_value = HttpResponse("home")

    request = attach_session(
        factory.post("/", {"upload": "1"}),
    )
    response = views.homepage(request)

    assert isinstance(response, HttpResponse)
    context = mock_render.call_args[0][2]
    assert context["error"] == "No files uploaded."


@patch("openbis_upload_helper.app.views.FileLoader")
@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_upload_success(
    mock_get_openbis,
    mock_file_loader,
    mock_openbis,
    attach_session,
    make_uploaded_file,
):
    mock_get_openbis.return_value = mock_openbis
    loader_instance = mock_file_loader.return_value
    loader_instance.load_files.return_value = [("f.txt", "/tmp/f.txt")]

    request = attach_session(
        factory.post(
            "/",
            {
                "upload": "1",
                "selected_space": "SPACE",
                "project_name": "PROJ",
                "collection_name": "COLL",
                "selected_files": "f.txt",
            },
            content_type=MULTIPART_CONTENT,
        ),
    )
    request.FILES.setlist("files[]", [make_uploaded_file("f.txt")])

    response = views.homepage(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("homepage")
    assert request.session["selected_space"] == "SPACE"
    assert request.session["project_name"] == "PROJ"
    assert request.session["collection_name"] == "COLL"
    assert request.session["uploaded_files"] == [("f.txt", "/tmp/f.txt")]
    assert request.session["parsers_assigned"] is False


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_assign_parsers_no_files(
    mock_get_openbis,
    mock_render,
    mock_openbis,
    attach_session,
):
    mock_get_openbis.return_value = mock_openbis
    mock_render.return_value = HttpResponse("home")

    request = attach_session(factory.post("/", {"assign_parsers": "1"}))
    response = views.homepage(request)

    assert isinstance(response, HttpResponse)
    context = mock_render.call_args[0][2]
    assert context["error"] == "No files uploaded. Please upload files first."


@patch("openbis_upload_helper.app.views.FileRemover")
@patch("openbis_upload_helper.app.views.log_results")
@patch("openbis_upload_helper.app.views.run_parser")
@patch("openbis_upload_helper.app.views.FilesParser")
@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_assign_parsers_success(
    mock_get_openbis,
    mock_files_parser,
    mock_run_parser,
    mock_log_results,
    mock_file_remover,
    mock_openbis,
    attach_session,
):
    mock_get_openbis.return_value = mock_openbis
    files_parser_instance = mock_files_parser.return_value
    files_parser_instance.assign_parsers.return_value = (
        {"ParserA": ["file1.txt"]},
        {object(): ["/tmp/file1.txt"]},
    )
    mock_log_results.return_value = [
        {"event": "ok", "timestamp": "t", "level": "info"},
    ]

    request = attach_session(factory.post("/", {"assign_parsers": "1"}))
    request.session["uploaded_files"] = [("file1.txt", "/tmp/file1.txt")]
    request.session["parser_choices"] = ["ParserA"]
    request.session["project_name"] = "PROJ"
    request.session["collection_name"] = "COLL"
    request.session["selected_space"] = "SPACE"

    response = views.homepage(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("homepage")
    mock_run_parser.assert_called_once()
    assert request.session["checker_logs"] == mock_log_results.return_value
    assert request.session["parsers_assigned"] is True
    mock_file_remover.return_value.cleanup.assert_called_once()


@patch("openbis_upload_helper.app.views.FileRemover")
@patch("openbis_upload_helper.app.views.FilesParser")
@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_homepage_assign_parsers_error(
    mock_get_openbis,
    mock_render,
    mock_files_parser,
    mock_file_remover,
    mock_openbis,
    attach_session,
):
    mock_get_openbis.return_value = mock_openbis
    mock_render.return_value = HttpResponse("home")
    mock_files_parser.return_value.assign_parsers.side_effect = ValueError("boom")

    request = attach_session(factory.post("/", {"assign_parsers": "1"}))
    request.session["uploaded_files"] = [("file1.txt", "/tmp/file1.txt")]
    request.session["parser_choices"] = ["ParserA"]

    response = views.homepage(request)

    assert isinstance(response, HttpResponse)
    context = mock_render.call_args[0][2]
    assert context["error"] == "boom"
    mock_file_remover.return_value.cleanup.assert_called_once()


@patch("openbis_upload_helper.app.views.get_openbis_from_cache")
def test_clear_state(mock_get_openbis, mock_openbis, attach_session):
    mock_get_openbis.return_value = mock_openbis
    request = attach_session(factory.post("/clear"))
    request.session["checker_logs"] = ["log"]

    response = views.clear_state(request)

    assert isinstance(response, HttpResponseRedirect)
    assert response.url == reverse("homepage")
    assert "checker_logs" not in request.session
