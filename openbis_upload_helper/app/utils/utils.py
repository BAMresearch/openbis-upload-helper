import datetime
import os
import re
import shutil
import tarfile
import tempfile
import time
import uuid
import zipfile

from bam_masterdata.logger import log_storage, logger
from cryptography.fernet import Fernet, InvalidToken
from decouple import config as environ
from django.conf import settings
from django.core.cache import cache
from pybis import Openbis

from openbis_upload_helper.uploader.entry_points import get_entry_point_parsers

# Instantiate the Fernet class with the secret key
cipher_suite = Fernet(settings.SECRET_ENCRYPTION_KEY)


# Encrypt the password
def encrypt_password(plain_text_password):
    encrypted_password = cipher_suite.encrypt(plain_text_password.encode("utf-8"))
    return encrypted_password.decode("utf-8")  # Return as a string


def decrypt_password(encrypted_password):
    try:
        # Remove the manual padding correction, Fernet handles it automatically
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode("utf-8"))
        return decrypted_password.decode("utf-8")
    except InvalidToken as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise InvalidToken("Decryption failed due to an invalid token.")
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise e


def get_openbis_from_cache(request):
    session_id = request.session.get("openbis_session_id")
    if session_id:
        o = cache.get(session_id)
        if o:
            return o

    # If cache expired or object missing, force relogin:
    username = request.session.get("openbis_username")
    encrypted_password = request.session.get("openbis_password")
    if username and encrypted_password:
        password = decrypt_password(encrypted_password)
        o = Openbis(settings.OPENBIS_URL)
        o.login(username, password, save_token=True)

        # Cache again
        session_id = str(uuid.uuid4())
        request.session["openbis_session_id"] = session_id
        cache.set(session_id, o, timeout=60 * 60)
        return o

    return None


def preload_context_request(request, context):
    """Preload context for the homepage view.

    Args:
        request (_type_): Request object containing session data and other information.
        context (_type_): context dictionary to be populated with session data.

    Returns:
        Dict: Avalable Parsers for the homepage view.
        List: Parser names for the homepage view.
    """
    available_parsers = get_entry_point_parsers()
    parser_choices = [
        entrypoint.get("name", "Unknown") for entrypoint in available_parsers.values()
    ]
    request.session["parser_choices"] = parser_choices
    return available_parsers, parser_choices


class FileLoader:
    def __init__(self, uploaded_files, selected_files):
        self.uploaded_files = uploaded_files
        self.selected_files = selected_files
        self.saved_file_names = []
        self.temp_dirs = []  # List to keep track of temporary directories
        self.size_limit = environ("UPLOAD_SIZE_LIMIT", default=None)
        # timeout in seconds (default 300)

    def load_files(self):
        if not self.uploaded_files:
            raise ValueError("No files uploaded.")
        # start countdown
        self.start_time = time.time()

        file_sizes = 0
        for uploaded_file in self.uploaded_files:
            file_sizes += uploaded_file.size
            if self.size_limit and file_sizes > int(float(self.size_limit)):
                raise ValueError(
                    f"Uploaded files exceed the size limit of {int(float(self.size_limit))} bytes."
                )

        for uploaded_file in self.uploaded_files:
            if uploaded_file.name.endswith(".zip"):
                self._process_zip(uploaded_file)
            elif uploaded_file.name.endswith((".tar", ".tar.gz", ".tar.z")):
                self._process_tar(uploaded_file)
            else:
                self._process_regular_file(uploaded_file)

        if not self.saved_file_names:
            raise ValueError("No files were saved. Processing may have failed.")
        return self.saved_file_names

    def _process_zip(self, uploaded_file):
        tmp_dir = tempfile.mkdtemp()
        self.temp_dirs.append(tmp_dir)
        zip_path = os.path.join(tmp_dir, uploaded_file.name)
        with open(zip_path, "wb") as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for zip_info in zip_ref.infolist():
                if not zip_info.is_dir():
                    target_path = os.path.join(tmp_dir, zip_info.filename)
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    # read zip member in chunks to allow timeout checks
                    with (
                        zip_ref.open(zip_info) as src,
                        open(target_path, "wb") as out_file,
                    ):
                        while True:
                            chunk = src.read(8192)
                            if not chunk:
                                break
                            out_file.write(chunk)
                    if zip_info.filename in self.selected_files:
                        self.saved_file_names.append((zip_info.filename, target_path))

    def _process_tar(self, uploaded_file):
        suffix = os.path.splitext(uploaded_file.name)[1]
        tmp_tar_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_tar:
                for chunk in uploaded_file.chunks():
                    tmp_tar.write(chunk)
                tmp_tar_path = tmp_tar.name

            tmp_dir = tempfile.mkdtemp()
            self.temp_dirs.append(tmp_dir)
            with tarfile.open(tmp_tar_path, "r:*") as tar_ref:
                for member in tar_ref.getmembers():
                    if member.isfile():
                        if extracted_file := tar_ref.extractfile(member):
                            target_path = os.path.join(tmp_dir, member.name)
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            with open(target_path, "wb") as out_file:
                                while True:
                                    chunk = extracted_file.read(8192)
                                    if not chunk:
                                        break
                                    out_file.write(chunk)
                            if member.name in self.selected_files:
                                self.saved_file_names.append((member.name, target_path))

        finally:
            if tmp_tar_path and os.path.exists(tmp_tar_path):
                os.remove(tmp_tar_path)

    def _process_regular_file(self, uploaded_file):
        tmp_dir = tempfile.mkdtemp()
        self.temp_dirs.append(tmp_dir)
        target_path = os.path.join(tmp_dir, uploaded_file.name)
        with open(target_path, "wb") as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
        if uploaded_file.name in self.selected_files:
            self.saved_file_names.append((uploaded_file.name, target_path))

    def antivirus_scan(self):
        # Placeholder for antivirus scanning logic
        pass


class FilesParser:
    def __init__(self, uploaded_files, available_parsers, o):
        self.uploaded_files = uploaded_files
        self.available_parsers = available_parsers
        self.files_parser = {}
        self.parsed_files = {}
        self.o = o
        self.parser_instances = {}

    def assign_parsers(self, request):
        for idx, (file_name, file_path) in enumerate(self.uploaded_files):
            parser_name = request.POST.get(f"parser_type_{idx}")
            if not parser_name:
                raise ValueError(f"No parser selected for file {file_name}")

            if parser_name not in self.parser_instances:
                for parser in self.available_parsers.values():
                    if parser_name == parser["name"]:
                        self.parser_instances[parser_name] = parser["parser_class"]()
                        break

            parsed_class = self.parser_instances[parser_name]
            self.files_parser.setdefault(parsed_class, []).append(file_path)

            self.parsed_files.setdefault(parser_name, []).append(file_name)
        return self.parsed_files, self.files_parser


class FileRemover:
    def __init__(self, uploaded_files):
        self.uploaded_files = uploaded_files

    def cleanup(self):
        for _, temp_file in self.uploaded_files:
            temp_dir = os.path.dirname(temp_file)
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        self.uploaded_files.clear()


def log_results(request, parsed_files={}, context={}):
    log_storage.clear()
    for parser, paths in parsed_files.items():
        for path in paths:
            log_storage.append(
                {
                    "event": f"[{parser}] Parsed: {os.path.basename(path)}",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "level": "info",
                }
            )
    # format logs
    context_logs = []
    for log in log_storage:
        if log.get("level") == "debug":
            continue
        log["timestamp"] = datetime.datetime.fromisoformat(
            log["timestamp"].replace("Z", "+00:00")
        ).strftime("%H:%M:%S, %d.%m.%Y")
        context_logs.append(
            {
                "event": log["event"],
                "timestamp": log["timestamp"],
                "level": "danger" if log["level"] == "error" else log["level"],
            }
        )
    context["logs"] = context_logs
    request.session["checker_logs"] = context_logs
    return context_logs


def extract_name(obj):
    if isinstance(obj, dict):
        return obj.get("code") or obj.get("identifier") or obj.get("name") or str(obj)
    return (
        getattr(obj, "code", None)
        or getattr(obj, "identifier", None)
        or getattr(obj, "name", None)
        or str(obj)
    )


def reorganize_spaces(spaces: list[str]) -> list[str]:
    """
    Reorganizes a list of space names so that:
    - BAM_* spaces appear first
    - VP.x_* and VP.xx_* spaces follow (case-insensitive)
    - all other spaces come last
    Pattern examples:
      VP.1_NAME, Vp.01_TEST, vp.12_ABC
    """

    # 1. BAM_* spaces (case-sensitive as original)
    bam_spaces = sorted([s for s in spaces if s.startswith("BAM_")])

    # 2. VP.x_* spaces, case-insensitive
    vp_pattern = re.compile(r"(?i)(VP\.(\d{1,2}))_", re.IGNORECASE)

    vp_groups: dict[str, list[str]] = {}

    for s in spaces:
        match = vp_pattern.match(s)
        if match:
            vp_key = match.group(1).upper()  # normalize e.g. VP.1 → VP.1, vp.01 → VP.01
            vp_groups.setdefault(vp_key, []).append(s)

    # Sort by numeric value, not lexicographically (VP.2 < VP.10)
    def vp_sort_key(vp_key: str) -> int:
        n = int(vp_key.split(".")[1])
        return n

    vp_spaces: list[str] = []
    for vp_key in sorted(vp_groups.keys(), key=vp_sort_key):
        vp_spaces.extend(sorted(vp_groups[vp_key]))

    # 3. Others (not BAM and not VP)
    others = sorted(
        [s for s in spaces if not s.startswith("BAM_") and not vp_pattern.match(s)]
    )

    return bam_spaces + vp_spaces + others
