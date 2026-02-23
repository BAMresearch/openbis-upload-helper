set positional-arguments := true

default:
    @just --list

# --- Python / uv ---

sync:
    uv sync

# --- Django ---

manage +args:
    uv run python manage.py {{args}}

runserver port="8000":
    uv run python manage.py runserver_plus 0.0.0.0:{{port}}

migrate *args:
    uv run python manage.py migrate {{args}}

makemigrations *args:
    uv run python manage.py makemigrations {{args}}

createsuperuser:
    uv run python manage.py createsuperuser

collectstatic:
    uv run python manage.py collectstatic --noinput

shell:
    uv run python manage.py shell_plus

show-urls:
    uv run python manage.py show_urls

# --- Testing ---

test *args:
    uv run pytest {{args}}

test-cov:
    uv run pytest --cov --cov-report=html
    @echo "Coverage report: htmlcov/index.html"

# --- Code quality ---

lint:
    uv run pre-commit run --all-files

fmt:
    uv run ruff format .
    uv run ruff check --fix .

mypy:
    uv run mypy .

# --- Celery (optional - only needed when CELERY_TASK_ALWAYS_EAGER=False) ---

celery-worker *args:
    CELERY_TASK_ALWAYS_EAGER=False uv run celery -A config.celery_app worker -l info {{args}}

celery-beat:
    CELERY_TASK_ALWAYS_EAGER=False uv run celery -A config.celery_app beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

celery-flower:
    uv run celery -A config.celery_app flower

# --- Database ---

reset-db:
    rm -f db.sqlite3
    just migrate
    @echo "Database reset. Run 'just createsuperuser' to create an admin user."

# --- Docs ---

docs:
    cd docs && uv run make html

docs-serve:
    cd docs && uv run python -m http.server --directory _build/html

# --- Initial setup ---

setup:
    @echo "Setting up project..."
    uv sync
    uv run pre-commit install
    uv run python manage.py migrate
    @echo ""
    @echo "Setup complete! Run 'just runserver' to start developing."
    @echo "Run 'just createsuperuser' to create an admin account."
```