"""
Database migration script - uses Alembic.

Run from the backend directory:
    python migrate.py          # upgrade to latest
    python migrate.py downgrade   # downgrade one step

Or use Alembic directly from the project root:
    python -m alembic upgrade head
    python -m alembic revision --autogenerate -m "description"
    python -m alembic downgrade -1
"""
import sys
import subprocess
import os

def run_migrations():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)

    args = sys.argv[1:] if len(sys.argv) > 1 else ["upgrade", "head"]

    subprocess.run(["python", "-m", "alembic"] + args, check=True)

if __name__ == "__main__":
    run_migrations()
