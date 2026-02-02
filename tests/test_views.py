from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from django.test import RequestFactory

from openbis_upload_helper.app.views import login

factory = RequestFactory()


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_success(mock_openbis_class, mock_render):
    mock_render.return_value = None

    mock_openbis = MagicMock()
    mock_openbis.logged_in = False
    mock_openbis_class.return_value = mock_openbis

    mock_openbis.login.side_effect = lambda *args, **kwargs: setattr(
        mock_openbis,
        "logged_in",
        True,
    )

    request = factory.post(
        "/login",
        {"username": "testuser", "password": "correct_password"},
    )
    _ = login(request)

    mock_openbis_class.assert_called_once()
    mock_openbis.login.assert_called_once_with(
        "testuser",
        "correct_password",
        save_token=True,
    )
    assert mock_openbis.logged_in is True


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_token(mock_openbis_class, mock_render):
    mock_render.return_value = None

    mock_openbis = MagicMock()
    mock_openbis.logged_in = False
    mock_openbis_class.return_value = mock_openbis

    mock_openbis.login.side_effect = lambda *args, **kwargs: setattr(
        mock_openbis,
        "logged_in",
        True,
    )

    request = factory.post("/login", {"personal_access_token": "mytoken"})
    _ = login(request)

    mock_openbis_class.assert_called_once()
    assert mock_openbis.logged_in is True


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_failure(mock_openbis_class, mock_render):
    mock_render.return_value = None

    mock_openbis = MagicMock()
    mock_openbis_class.return_value = mock_openbis
    mock_openbis.logged_in = False

    mock_openbis.login.side_effect = RuntimeError("Login failed")

    request = factory.post("/login", {"username": "testuser", "password": "wrongpass"})

    with pytest.raises(RuntimeError):
        _ = login(request)
