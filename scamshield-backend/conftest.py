import os
import tempfile
import pytest

# Ensure automated test suite runs against an isolated temporary database
# to prevent tests from inserting mock data into the production/live database.
test_db = tempfile.NamedTemporaryFile(suffix="_test_scamshield.db", delete=False)
test_db.close()
os.environ["SCAMSHIELD_DB_PATH"] = test_db.name

from database import init_db
init_db()

@pytest.fixture(scope="session", autouse=True)
def teardown_test_database():
    yield
    try:
        if os.path.exists(test_db.name):
            os.remove(test_db.name)
    except Exception:
        pass
