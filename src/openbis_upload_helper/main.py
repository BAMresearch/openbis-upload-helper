import argparse
import json
import sys

from openbis_upload_helper.client.openbis import (
    AuthRequest,
    CollectionsRequest,
    LoginRequest,
    ProjectsRequest,
    get_collections,
    get_projects,
    get_spaces,
    login,
)
from openbis_upload_helper.parsers.processing_logger import (
    create_processing_logger,
)
from openbis_upload_helper.parsers.registry import (
    list_parsers,
)
from openbis_upload_helper.parsers.runner import (
    ProcessRequest,
    run_parsers,
)


def read_payload(input_file: str | None) -> str:
    if input_file:
        with open(input_file, encoding="utf-8") as file:
            return file.read()

    return sys.stdin.read()


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input-file",
        default=None,
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser("hello")
    subparsers.add_parser("login")
    subparsers.add_parser("spaces")
    subparsers.add_parser("projects")
    subparsers.add_parser("collections")
    subparsers.add_parser("parsers")
    subparsers.add_parser("process")

    args = parser.parse_args()

    if args.command == "hello":
        print('{"message":"Hello from Python"}')
        return

    if args.command == "login":
        # input is a JSON payload with the login request, e.g.:
        # {
        #   "server_url": "https://local.openbis.ch/openbis",
        #   "username": "admin",
        #   "password": "test",
        #   "personal_access_token": ""
        # }
        payload = read_payload(args.input_file)

        # output is a JSON payload with the login result, e.g.:
        # {
        #   "success": true,
        #   "username": "admin",
        #   "error": null
        # }
        request = LoginRequest.model_validate_json(payload)
        result = login(request)

        print(result.model_dump_json())
        return

    if args.command == "spaces":
        payload = read_payload(args.input_file)

        request = AuthRequest.model_validate_json(payload)
        result = get_spaces(request)

        print(result.model_dump_json())
        return

    if args.command == "projects":
        payload = read_payload(args.input_file)

        request = ProjectsRequest.model_validate_json(payload)
        result = get_projects(request)

        print(result.model_dump_json())
        return

    if args.command == "collections":
        payload = read_payload(args.input_file)

        request = CollectionsRequest.model_validate_json(payload)
        result = get_collections(request)

        print(result.model_dump_json())
        return

    if args.command == "parsers":
        result = list_parsers()

        print(result.model_dump_json())
        return

    if args.command == "process":
        payload = read_payload(
            args.input_file,
        )

        request = ProcessRequest.model_validate_json(
            payload,
        )

        logger = create_processing_logger()

        logger.info(
            "Processing operation started.",
            kind="stage",
            stage="started",
            files=sum(len(job.paths) for job in request.jobs),
            jobs=len(request.jobs),
        )

        result = run_parsers(
            request,
            logger=logger,
        )

        print(
            json.dumps(
                {
                    "kind": "result",
                    "result": result.model_dump(),
                },
            ),
            flush=True,
        )

        return


if __name__ == "__main__":
    main()
