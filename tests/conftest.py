from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.policy import load_policy

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SAMPLE_TRIVY_PATH = DATA_DIR / "sample_trivy_report.json"
SAMPLE_CSV_PATH = DATA_DIR / "sample_cves.csv"
SAMPLE_EPSS_PATH = DATA_DIR / "epss_scores.csv"
SAMPLE_KEV_PATH = DATA_DIR / "kev_catalog.json"
SAMPLE_ASSET_CRITICALITY_PATH = DATA_DIR / "asset_criticality.yaml"


@pytest.fixture()
def policy():
    return load_policy()


@pytest.fixture()
def test_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def client(test_engine):
    session_factory = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    def _override_get_session():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override_get_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
