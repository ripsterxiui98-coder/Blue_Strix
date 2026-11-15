"""Integration: chained audit events via repository + alert helpers."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from bluestrix.core import repository as repo
from bluestrix.core.alerting import evaluate_and_alert_chain
from bluestrix.core.audit_chain import verify_chain
from bluestrix.core.database import Base, create_db_engine
import bluestrix.core.models_db  # noqa: F401


class CaptureNotifier:
    def __init__(self) -> None:
        self.count = 0

    def send(self, title: str, body: str, severity: str = "INFO") -> bool:
        self.count += 1
        return True


@pytest.fixture()
def db():
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = Session()
    yield s
    s.close()
    engine.dispose()


def test_repository_audit_chain(db):
    repo.create_audit_event(
        db, actor="sys", action="login_success", target="u", decision="ALLOWED", reason="ok"
    )
    repo.create_audit_event(
        db, actor="sys", action="logout", target="u", decision="ALLOWED", reason="bye"
    )
    chain = repo.list_audit_events_for_chain(db)
    assert len(chain) == 2
    assert verify_chain(chain).valid
    n = CaptureNotifier()
    r = evaluate_and_alert_chain(chain, notifiers=[n])
    assert r.skipped
    # tamper
    chain[1]["reason"] = "mutated"
    r2 = evaluate_and_alert_chain(chain, notifiers=[n])
    assert r2.sent == 1
