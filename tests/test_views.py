from unittest.mock import patch

from django.test import RequestFactory

from openbis_upload_helper.app.views import login

factory = RequestFactory()


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_success(mock_openbis_class, mock_render, mock_openbis):
    mock_render.return_value = None

    mock_openbis_class.return_value = mock_openbis

    # Simulate a POST request with username and password
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
def test_login_view_token(mock_openbis_class, mock_render, mock_openbis):
    mock_render.return_value = None

    mock_openbis_class.return_value = mock_openbis

    # simulate a POST request with a personal access token
    request = factory.post("/login", {"personal_access_token": "mytoken"})
    _ = login(request)

    mock_openbis_class.assert_called_once()
    mock_openbis.set_token.assert_called_once_with(
        "mytoken",
        save_token=True,
    )
    assert mock_openbis.logged_in is True


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_login_view_failure(mock_openbis_class, mock_render, mock_openbis):
    mock_render.return_value = None

    mock_openbis_class.return_value = mock_openbis

    # Simulate a POST request with incorrect username/password
    request = factory.post("/login", {"username": "testuser", "password": "wrongpass"})

    _ = login(request)

    mock_openbis_class.assert_called_once()
    mock_openbis.login.assert_called_once_with(
        "testuser",
        "wrongpass",
        save_token=True,
    )
    # Check that the error message is passed to the template
    assert mock_render.called
    call_args = mock_render.call_args
    assert "error" in call_args[0][2]
    assert (
        call_args[0][2]["error"]
        == "Invalid username/password or personal access token."
    )
    assert mock_openbis.logged_in is False


@patch("openbis_upload_helper.app.views.render")
@patch("openbis_upload_helper.app.views.Openbis")
def test_set_token_failure(mock_openbis_class, mock_render, mock_openbis):
    mock_render.return_value = None

    mock_openbis_class.return_value = mock_openbis
    # Simulate a POST request with an invalid personal access token
    request = factory.post("/login", {"personal_access_token": "invalidtoken"})
    _ = login(request)

    mock_openbis_class.assert_called_once()
    mock_openbis.set_token.assert_called_once_with(
        "invalidtoken",
        save_token=True,
    )
    # Check that the error message is passed to the template
    assert mock_render.called
    call_args = mock_render.call_args
    assert "error" in call_args[0][2]
    assert (
        call_args[0][2]["error"]
        == "Invalid username/password or personal access token."
    )
    assert mock_openbis.logged_in is False
