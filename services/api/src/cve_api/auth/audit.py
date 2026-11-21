"""Fixed event vocabulary; safe metadata in existing immutable audit and outbox."""

from uuid import UUID, uuid4

from cve_common.events.contracts import EventEnvelope
from cve_common.events.outbox import Outbox
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload
from cve_common.logging.correlation import correlation_id
from sqlalchemy.ext.asyncio import AsyncSession

from .repository import execute


class SecurityEvent(Payload):
    action: str
    outcome: str
    user_id: UUID | None = None


def registry() -> EventRegistry:
    value = EventRegistry()
    value.register(EventDefinition("auth.security", 1, "cve-api", SecurityEvent))
    return value


async def record(
    session: AsyncSession, action: str, user: UUID | None = None, *, success: bool = True
) -> None:
    cid = correlation_id.get()
    try:
        request_id = UUID(cid) if cid else uuid4()
    except ValueError:
        request_id = uuid4()
    outcome = "success" if success else "failure"
    await execute(
        session,
        (
            "INSERT INTO security.audit_log(actor_user_id,action,obj"
            "ect_type,object_id,request_id,outcome,auth_runtime) VAL"
            "UES(:u,:a,'authentication',:object,:cid,:o,true)"
        ),
        u=user,
        a="auth." + action,
        object=str(user) if user else None,
        cid=request_id,
        o=outcome,
    )
    if action.startswith(("login", "mfa_failure", "rate_limited")):
        await execute(
            session,
            (
                "INSERT INTO security.login_events(user_id,outcome,reaso"
                "n_code,request_id,auth_runtime) VALUES(:u,:o,:a,:cid,tr"
                "ue)"
            ),
            u=user,
            o=outcome,
            a=action,
            cid=request_id,
        )
    if user is not None:
        await execute(
            session,
            (
                "INSERT INTO security.user_events(user_id,actor_user_id,"
                "event_type,auth_runtime) VALUES(:u,:u,:a,true)"
            ),
            u=user,
            a="auth." + action,
        )
    if action in {"login_success", "login_failure", "mfa_failure", "rate_limited"}:
        await execute(
            session, "UPDATE security.auth_counters SET n=n+1 WHERE name=:name", name=action
        )
    await Outbox(registry()).emit(
        session,
        EventEnvelope(
            event_type="auth.security",
            schema_version=1,
            source="cve-api",
            aggregate_type="authentication",
            aggregate_id=str(user or request_id),
            aggregate_version=1,
            payload={"action": action, "outcome": outcome, "user_id": str(user) if user else None},
            idempotency_key=str(uuid4()),
            correlation_id=request_id,
        ),
    )
