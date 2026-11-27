from time import perf_counter
from urllib.parse import urlparse

import requests
from pybis import Openbis
from pydantic import BaseModel, Field

from openbis_upload_helper.timing import log_timing


class LoginRequest(BaseModel):
    server_url: str
    username: str = ""
    password: str = ""
    personal_access_token: str = ""


class LoginResult(BaseModel):
    success: bool
    username: str | None = None
    token: str | None = None
    spaces: list[str] = Field(default_factory=list)
    error: str | None = None


class AuthRequest(BaseModel):
    server_url: str
    token: str


class ProjectsRequest(AuthRequest):
    space: str


class CollectionsRequest(AuthRequest):
    space: str
    project: str


class SpacesResult(BaseModel):
    success: bool
    spaces: list[str] = Field(
        default_factory=list,
    )
    error: str | None = None


class ProjectsResult(BaseModel):
    success: bool
    projects: list[str] = Field(
        default_factory=list,
    )
    error: str | None = None


class CollectionOption(BaseModel):
    code: str
    label: str


class CollectionsResult(BaseModel):
    success: bool
    collections: list[CollectionOption] = Field(
        default_factory=list,
    )
    error: str | None = None


def validate_server_url(server_url: str) -> None:
    parsed = urlparse(server_url)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid openBIS server URL.")


def _exception_text(exc: Exception) -> str:
    return str(exc).lower()


def _is_connection_error(exc: Exception) -> bool:
    if isinstance(
        exc,
        (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.SSLError,
        ),
    ):
        return True

    text = _exception_text(exc)

    indicators = (
        "connection refused",
        "connection error",
        "failed to establish",
        "max retries",
        "name or service not known",
        "temporary failure in name resolution",
        "network is unreachable",
        "timed out",
        "timeout",
        "ssl",
        "certificate",
        "newconnectionerror",
        "connection aborted",
    )

    return any(indicator in text for indicator in indicators)


def _is_authentication_error(exc: Exception) -> bool:
    text = _exception_text(exc)

    indicators = (
        "401",
        "unauthorized",
        "authentication",
        "invalid session",
        "session token",
        "session expired",
        "token expired",
        "invalid token",
    )

    return any(indicator in text for indicator in indicators)


def _is_permission_error(exc: Exception) -> bool:
    text = _exception_text(exc)

    indicators = (
        "403",
        "forbidden",
        "permission",
        "access denied",
        "not authorized",
    )

    return any(indicator in text for indicator in indicators)


def openbis_error_message(exc: Exception, *, fallback: str) -> str:
    if isinstance(exc, ValueError) and str(exc) == "Invalid openBIS server URL.":
        return (
            "The openBIS server URL is invalid. Use a complete http:// or https:// URL."
        )

    if _is_connection_error(exc):
        return (
            "Could not connect to the openBIS server. "
            "Check the server URL and network connection."
        )

    if _is_authentication_error(exc):
        return (
            "The openBIS authentication session is "
            "invalid or has expired. Please log in again."
        )

    if _is_permission_error(exc):
        return "You do not have permission to perform this operation in openBIS."

    return fallback


def get_authenticated_openbis(request: AuthRequest) -> Openbis:
    validate_server_url(request.server_url)

    started = perf_counter()

    openbis = Openbis(request.server_url)

    openbis.set_token(request.token, save_token=False)

    log_timing(f"openbis_client_setup_ms={(perf_counter() - started) * 1000:.0f}")

    return openbis


def login(request: LoginRequest) -> LoginResult:
    try:
        validate_server_url(request.server_url)

        openbis_started = perf_counter()
        openbis = Openbis(request.server_url)
        log_timing(
            f"login_openbis_client_ms={(perf_counter() - openbis_started) * 1000:.0f}"
        )

        if request.personal_access_token:
            token_started = perf_counter()

            openbis.set_token(request.personal_access_token, save_token=False)

            log_timing(
                f"login_set_token_ms={(perf_counter() - token_started) * 1000:.0f}"
            )

            validation_started = perf_counter()

            raw_spaces = openbis.get_spaces()

            log_timing(
                f"login_pat_validation_ms="
                f"{(perf_counter() - validation_started) * 1000:.0f}"
            )

            spaces = sorted((space.code for space in raw_spaces), key=str.casefold)

            return LoginResult(
                success=True,
                username=(request.username or None),
                token=openbis.token,
                spaces=spaces,
            )

        if not request.username or not request.password:
            return LoginResult(
                success=False,
                error=("Username and password are required."),
            )

        login_started = perf_counter()
        openbis.login(
            request.username,
            request.password,
            save_token=False,
        )
        log_timing(
            f"login_authentication_ms={(perf_counter() - login_started) * 1000:.0f}"
        )

        return LoginResult(
            success=True,
            username=request.username,
            token=openbis.token,
        )

    except Exception as exc:
        if request.personal_access_token:
            fallback = "The personal access token is invalid or has expired."
        else:
            fallback = "Invalid username or password."

        error = openbis_error_message(exc, fallback=fallback)

        return LoginResult(success=False, error=error)


def get_spaces(request: AuthRequest) -> SpacesResult:
    try:
        openbis = get_authenticated_openbis(request)

        started = perf_counter()

        raw_spaces = openbis.get_spaces()

        log_timing(
            f"openbis_request=spaces "
            f"openbis_request_ms="
            f"{(perf_counter() - started) * 1000:.0f}"
        )

        spaces = sorted((space.code for space in raw_spaces), key=str.casefold)

        return SpacesResult(success=True, spaces=spaces)

    except Exception as exc:
        return SpacesResult(
            success=False,
            error=openbis_error_message(
                exc,
                fallback=("Could not retrieve spaces from openBIS."),
            ),
        )


def get_projects(request: ProjectsRequest) -> ProjectsResult:
    try:
        openbis = get_authenticated_openbis(request)

        started = perf_counter()

        raw_projects = openbis.get_projects(space=request.space)

        log_timing(
            f"openbis_request=projects "
            f"openbis_request_ms="
            f"{(perf_counter() - started) * 1000:.0f}"
        )

        projects = sorted((project.code for project in raw_projects), key=str.casefold)

        return ProjectsResult(success=True, projects=projects)

    except Exception as exc:
        return ProjectsResult(
            success=False,
            error=openbis_error_message(
                exc,
                fallback=("Could not retrieve projects from openBIS."),
            ),
        )


def get_collection_label(collection) -> str:
    name = None

    try:
        name = collection.p.get("$name")
    except Exception:
        pass

    if name:
        name = str(name).strip()

    return name or collection.code


def get_collections(request: CollectionsRequest) -> CollectionsResult:
    try:
        openbis = get_authenticated_openbis(request)

        started = perf_counter()

        raw_collections = openbis.get_collections(
            space=request.space,
            project=request.project,
            props=["$name"],
        )

        log_timing(
            f"openbis_request=collections "
            f"openbis_request_ms="
            f"{(perf_counter() - started) * 1000:.0f}"
        )

        collections = [
            CollectionOption(
                code=collection.code,
                label=get_collection_label(collection),
            )
            for collection in raw_collections
        ]

        collections.sort(key=lambda collection: collection.label.casefold())

        return CollectionsResult(success=True, collections=collections)

    except Exception as exc:
        return CollectionsResult(
            success=False,
            error=openbis_error_message(
                exc,
                fallback=("Could not retrieve collections from openBIS."),
            ),
        )
