from urllib.parse import urlparse

from pybis import Openbis
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    server_url: str
    username: str = ""
    password: str = ""
    personal_access_token: str = ""


class LoginResult(BaseModel):
    success: bool
    username: str | None = None
    token: str | None = None
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


class CollectionsResult(BaseModel):
    success: bool
    collections: list[str] = Field(
        default_factory=list,
    )
    error: str | None = None


def validate_server_url(
    server_url: str,
) -> None:
    parsed = urlparse(
        server_url,
    )

    if (
        parsed.scheme
        not in {
            "http",
            "https",
        }
        or not parsed.netloc
    ):
        raise ValueError("Invalid openBIS server URL.")


def _exception_text(
    exc: Exception,
) -> str:
    return str(exc).lower()


def _is_connection_error(
    exc: Exception,
) -> bool:
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
    )

    return any(indicator in text for indicator in indicators)


def _is_authentication_error(
    exc: Exception,
) -> bool:
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


def _is_permission_error(
    exc: Exception,
) -> bool:
    text = _exception_text(exc)

    indicators = (
        "403",
        "forbidden",
        "permission",
        "access denied",
        "not authorized",
    )

    return any(indicator in text for indicator in indicators)


def openbis_error_message(
    exc: Exception,
    *,
    fallback: str,
) -> str:
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


def get_authenticated_openbis(
    request: AuthRequest,
) -> Openbis:
    validate_server_url(
        request.server_url,
    )

    openbis = Openbis(
        request.server_url,
    )

    openbis.set_token(
        request.token,
        save_token=False,
    )

    return openbis


def login(
    request: LoginRequest,
) -> LoginResult:
    try:
        validate_server_url(
            request.server_url,
        )

        openbis = Openbis(
            request.server_url,
        )

        if request.personal_access_token:
            openbis.set_token(
                request.personal_access_token,
                save_token=False,
            )

            # Make one real request so invalid or
            # expired PATs fail during login.
            openbis.get_spaces()

            return LoginResult(
                success=True,
                username=(request.username or None),
                token=openbis.token,
            )

        if not request.username or not request.password:
            return LoginResult(
                success=False,
                error=("Username and password are required."),
            )

        openbis.login(
            request.username,
            request.password,
            save_token=False,
        )

        return LoginResult(
            success=True,
            username=request.username,
            token=openbis.token,
        )

    except Exception as exc:
        error = openbis_error_message(
            exc,
            fallback=("Invalid username/password or personal access token."),
        )

        return LoginResult(
            success=False,
            error=error,
        )


def get_spaces(
    request: AuthRequest,
) -> SpacesResult:
    try:
        openbis = get_authenticated_openbis(
            request,
        )

        spaces = [space.code for space in openbis.get_spaces()]

        return SpacesResult(
            success=True,
            spaces=spaces,
        )

    except Exception as exc:
        return SpacesResult(
            success=False,
            error=openbis_error_message(
                exc,
                fallback=("Could not retrieve spaces from openBIS."),
            ),
        )


def get_projects(
    request: ProjectsRequest,
) -> ProjectsResult:
    try:
        openbis = get_authenticated_openbis(
            request,
        )

        projects = [
            project.code
            for project in openbis.get_projects(
                space=request.space,
            )
        ]

        return ProjectsResult(
            success=True,
            projects=projects,
        )

    except Exception as exc:
        return ProjectsResult(
            success=False,
            error=openbis_error_message(
                exc,
                fallback=("Could not retrieve projects from openBIS."),
            ),
        )


def get_collections(
    request: CollectionsRequest,
) -> CollectionsResult:
    try:
        openbis = get_authenticated_openbis(
            request,
        )

        projects = openbis.get_projects(
            space=request.space,
            code=request.project,
        )

        if not projects:
            return CollectionsResult(
                success=True,
                collections=[],
            )

        project = projects[0]

        collections = [collection.code for collection in project.get_collections()]

        return CollectionsResult(
            success=True,
            collections=collections,
        )

    except Exception as exc:
        return CollectionsResult(
            success=False,
            error=openbis_error_message(
                exc,
                fallback=("Could not retrieve collections from openBIS."),
            ),
        )
