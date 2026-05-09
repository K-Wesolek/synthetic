import pytest
import duckdb
from backend.db import init_db


@pytest.fixture
def db():
    con = duckdb.connect(":memory:")
    init_db(con)
    yield con
    con.close()
