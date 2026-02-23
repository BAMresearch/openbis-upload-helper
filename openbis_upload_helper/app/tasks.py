from bam_masterdata.cli.cli import run_parser
from bam_masterdata.logger import logger
from celery import shared_task
from django.core.cache import cache
from pybis import Openbis

from openbis_upload_helper.uploader.entry_points import get_entry_point_parsers

from .utils import FileRemover


@shared_task(bind=True)
def process_uploaded_files(
    self, parsed_files, project_name, collection_name, space_name, openbis_session_id
):
    """
    Celery task to process uploaded files asynchronously.

    This task handles the parsing and uploading of files to OpenBIS.
    It's designed to be run in the background to allow multiple users
    to upload files concurrently without blocking the main application.

    Args:
        parsed_files (dict): Dictionary mapping parser names to lists of file paths
                            e.g. {"MasterdataParser": ["file1.csv", "file2.csv"]}
        project_name (str): Name of the OpenBIS project
        collection_name (str): Name of the OpenBIS collection/experiment
        space_name (str): Name of the OpenBIS space
        openbis_session_id (str): Session ID to retrieve the cached OpenBIS connection

    Returns:
        dict: Status of the task execution
    """
    try:
        # Update task state to indicate progress
        self.update_state(
            state="PROGRESS",
            meta={"current": 0, "total": 100, "status": "Initializing..."},
        )

        # Retrieve cached Openbis connection using session ID
        o = cache.get(openbis_session_id)
        if not o:
            logger.error(
                f"Failed to retrieve OpenBIS connection for session {openbis_session_id}"
            )
            raise RuntimeError("OpenBIS session not found. Please login again.")

        logger.info(
            f"Starting file processing task for space: {space_name}, project: {project_name}"
        )
        self.update_state(
            state="PROGRESS",
            meta={"current": 20, "total": 100, "status": "Processing files..."},
        )

        # Reconstruct files_parser dictionary from parsed_files and available parsers
        # parsed_files has parser names as keys, but run_parser expects parser class instances
        available_parsers = get_entry_point_parsers()
        files_parser = {}

        for parser_name, file_paths in parsed_files.items():
            # Find the parser class for this parser name
            for parser_config in available_parsers.values():
                if parser_config.get("name") == parser_name:
                    # Create a new instance of the parser class
                    parser_instance = parser_config["parser_class"]()
                    files_parser[parser_instance] = file_paths
                    logger.info(
                        f"Assigned {len(file_paths)} files to parser {parser_name}"
                    )
                    break

        # Run the parser for each parser class and its associated files
        run_parser(
            openbis=o,
            files_parser=files_parser,
            project_name=project_name,
            collection_name=collection_name,
            space_name=space_name,
        )

        logger.info(f"Successfully completed file processing for space: {space_name}")
        self.update_state(
            state="PROGRESS",
            meta={"current": 100, "total": 100, "status": "Processing complete"},
        )

        return {
            "status": "success",
            "message": "Files processed successfully",
            "space": space_name,
            "project": project_name,
            "collection": collection_name,
        }

    except Exception as e:
        logger.exception(f"Error in process_uploaded_files task: {e}")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@shared_task(bind=True)
def cleanup_temporary_files(self, uploaded_files):
    """
    Celery task to clean up temporary files asynchronously.

    This task removes temporary directories created during file upload
    processing. Running this in the background prevents blocking the
    main application thread.

    Args:
        uploaded_files (list): List of tuples (file_name, file_path) representing uploaded files

    Returns:
        dict: Status of the cleanup operation
    """
    try:
        logger.info(f"Starting cleanup of {len(uploaded_files)} uploaded files")
        self.update_state(
            state="PROGRESS",
            meta={"current": 0, "total": 100, "status": "Cleaning up..."},
        )

        file_remover = FileRemover(uploaded_files)
        file_remover.cleanup()

        logger.info("Temporary files cleanup completed successfully")
        self.update_state(
            state="PROGRESS",
            meta={"current": 100, "total": 100, "status": "Cleanup complete"},
        )

        return {
            "status": "success",
            "message": "Temporary files cleaned up successfully",
            "files_cleaned": len(uploaded_files),
        }

    except Exception as e:
        logger.exception(f"Error in cleanup_temporary_files task: {e}")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise
