"""Versioned job/outbox runtime; legacy rows retained outside the managed scheduler."""

from alembic import op

revision = "00013_automation_runtime"
down_revision = "00012_original_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
ALTER TABLE automation.job_types ADD max_attempts integer NOT NULL DEFAULT 3 CHECK(max_attempts BETWEEN 1 AND 100),
 ADD payload_version integer NOT NULL DEFAULT 1 CHECK(payload_version>0),
 ADD runtime_seconds integer NOT NULL DEFAULT 300 CHECK(runtime_seconds BETWEEN 1 AND 3600),
 ADD retry_base double precision NOT NULL DEFAULT 5 CHECK(retry_base>=0.1 AND retry_base<=3600),
 ADD retry_cap double precision NOT NULL DEFAULT 3600 CHECK(retry_cap>=retry_base AND retry_cap<=86400);
ALTER TABLE automation.jobs ADD runtime_version integer NOT NULL DEFAULT 0 CHECK(runtime_version IN (0,1)),
 ADD payload_version integer NOT NULL DEFAULT 1 CHECK(payload_version>0), ADD creator_role name,
 ADD request_fingerprint bytea, ADD correlation_id uuid, ADD lease_token uuid,
 ADD heartbeat_at timestamptz, ADD deadline timestamptz, ADD execution_deadline timestamptz,
 ADD cancel_requested boolean NOT NULL DEFAULT false, ADD replay_of uuid REFERENCES automation.jobs(id),
 ADD updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 ADD CHECK(runtime_version=0 OR (creator_role IS NOT NULL AND correlation_id IS NOT NULL AND octet_length(request_fingerprint)=32)),
 ADD CHECK(runtime_version=0 OR ((status='running')=(lease_token IS NOT NULL)));
ALTER TABLE automation.job_attempts DROP CONSTRAINT job_attempts_outcome_check;
ALTER TABLE automation.job_attempts ADD CHECK(outcome IN ('succeeded','failed','timed_out','cancelled','lease_lost')),
 ADD lease_token uuid, ADD duration_ms double precision;
CREATE INDEX jobs_runtime_due ON automation.jobs(job_type,scheduled_at,priority DESC,id)
 WHERE runtime_version=1 AND status IN ('queued','retry_pending');
CREATE INDEX jobs_runtime_leases ON automation.jobs(lease_until,id) WHERE runtime_version=1 AND status='running';
CREATE INDEX jobs_runtime_owner ON automation.jobs(lease_owner) WHERE status='running';
CREATE INDEX jobs_runtime_deadletters ON automation.jobs(finished_at,id) WHERE runtime_version=1 AND status IN ('failed','timed_out');
CREATE FUNCTION automation.safe_payload(value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT
 SET search_path=pg_catalog AS $$ SELECT jsonb_typeof(value)='object' AND octet_length(value::text)<=16384
 AND system.safe_metadata(value) AND NOT system.has_reserved_key(value,
 ARRAY['url','target_url','callback_url','module','class','command','shell','python','transport','smtp_password','mfa_secret']) $$;
CREATE FUNCTION automation.managed_write_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ((TG_OP<>'DELETE' AND NEW.runtime_version=1) OR (TG_OP<>'INSERT' AND OLD.runtime_version=1))
 AND current_user<>'postgres_owner' THEN RAISE EXCEPTION 'managed runtime operation required' USING ERRCODE='42501'; END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER jobs_managed BEFORE INSERT OR UPDATE OR DELETE ON automation.jobs
 FOR EACH ROW EXECUTE FUNCTION automation.managed_write_guard();
CREATE FUNCTION automation.attempt_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF current_user<>'postgres_owner' AND EXISTS(SELECT 1 FROM automation.jobs WHERE id=NEW.job_id AND runtime_version=1)
 THEN RAISE EXCEPTION 'managed attempt operation required' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER attempts_managed BEFORE INSERT OR UPDATE ON automation.job_attempts FOR EACH ROW EXECUTE FUNCTION automation.attempt_guard();

CREATE FUNCTION automation.enqueue_job(p_type text,p_version integer,p_payload jsonb,p_key text,p_correlation uuid,
 p_priority integer DEFAULT 0,p_scheduled timestamptz DEFAULT NULL,p_deadline timestamptz DEFAULT NULL,
 p_max integer DEFAULT 3,p_scope text DEFAULT 'system',p_pending boolean DEFAULT false,p_replay uuid DEFAULT NULL)
 RETURNS automation.jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; t automation.job_types; fingerprint bytea; actor text; ts timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO t FROM automation.job_types WHERE code=p_type;
 IF t.code IS NULL OR NOT session_user=ANY(t.producer_roles) THEN RAISE EXCEPTION 'unauthorized job type' USING ERRCODE='42501'; END IF;
 IF p_version<>t.payload_version OR NOT automation.safe_payload(p_payload) OR p_key IS NULL OR length(p_key) NOT BETWEEN 1 AND 128
 OR p_scope IS NULL OR length(p_scope)>128 OR p_correlation IS NULL OR p_priority NOT BETWEEN -100 AND 100 OR p_max NOT BETWEEN 1 AND t.max_attempts
 OR (p_deadline IS NOT NULL AND p_deadline<=ts) THEN RAISE EXCEPTION 'invalid job contract' USING ERRCODE='22023'; END IF;
 actor:=session_user||':'||p_scope;
 fingerprint:=sha256(convert_to(jsonb_build_object('payload',p_payload,'version',p_version,'priority',p_priority,
 'scheduled',p_scheduled,'deadline',p_deadline,'max',p_max,'pending',p_pending)::text,'UTF8'));
 INSERT INTO automation.jobs(job_type,payload_version,payload,idempotency_key,actor_reference,creator_role,
 runtime_version,request_fingerprint,correlation_id,priority,scheduled_at,deadline,max_attempts,status,replay_of)
 VALUES(p_type,p_version,p_payload,p_key,actor,session_user,1,fingerprint,p_correlation,p_priority,
 greatest(p_scheduled,ts),p_deadline,p_max,CASE WHEN p_pending THEN 'pending' ELSE 'queued' END,p_replay)
 ON CONFLICT(job_type,actor_reference,idempotency_key) DO NOTHING RETURNING * INTO j;
 IF j.id IS NULL THEN
  SELECT * INTO j FROM automation.jobs WHERE job_type=p_type AND actor_reference=actor AND idempotency_key=p_key;
  IF j.request_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='23505'; END IF;
 END IF;
 RETURN j;
END $$;
CREATE FUNCTION automation.claim_job(p_types text[],p_worker uuid,p_lease double precision) RETURNS SETOF automation.jobs
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; ts timestamptz:=clock_timestamp(); seconds integer;
BEGIN
 IF p_worker IS NULL OR p_lease NOT BETWEEN 0.2 AND 300 OR cardinality(p_types) NOT BETWEEN 1 AND 32 THEN
 RAISE EXCEPTION 'invalid claim' USING ERRCODE='22023'; END IF;
 SELECT q.* INTO j FROM automation.jobs q JOIN automation.job_types jt ON jt.code=q.job_type
 WHERE q.runtime_version=1 AND q.job_type=ANY(p_types) AND jt.handler_role=session_user
 AND q.status IN ('queued','retry_pending') AND q.scheduled_at<=ts AND q.attempts<q.max_attempts
 AND (q.deadline IS NULL OR q.deadline>ts)
 ORDER BY CASE WHEN q.scheduled_at<ts-interval '60 seconds' THEN 0 ELSE 1 END,
 CASE WHEN q.scheduled_at<ts-interval '60 seconds' THEN q.scheduled_at END,
 q.priority DESC,q.scheduled_at,q.id FOR UPDATE OF q SKIP LOCKED LIMIT 1;
 IF j.id IS NULL THEN RETURN; END IF;
 SELECT runtime_seconds INTO seconds FROM automation.job_types WHERE code=j.job_type;
 UPDATE automation.jobs SET status='running',attempts=attempts+1,fencing_token=fencing_token+1,
 lease_owner=p_worker,lease_token=gen_random_uuid(),execution_deadline=least(ts+make_interval(secs=>seconds),deadline),
 lease_until=least(ts+make_interval(secs=>p_lease),ts+make_interval(secs=>seconds),deadline),
 heartbeat_at=ts,started_at=ts,finished_at=NULL,error_code=NULL,updated_at=ts WHERE id=j.id RETURNING * INTO j;
 INSERT INTO automation.job_attempts(job_id,attempt,fencing_token,worker_id,lease_token,started_at)
 VALUES(j.id,j.attempts,j.fencing_token,p_worker,j.lease_token,ts);
 RETURN NEXT j;
END $$;
CREATE FUNCTION automation.heartbeat_job(p_id uuid,p_worker uuid,p_token uuid,p_epoch bigint,p_lease double precision)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer; ts timestamptz:=clock_timestamp();
BEGIN
 IF p_lease NOT BETWEEN 0.2 AND 300 THEN RETURN false; END IF;
 UPDATE automation.jobs j SET lease_until=least(ts+make_interval(secs=>p_lease),execution_deadline,deadline),
 heartbeat_at=ts,updated_at=ts FROM automation.job_types jt WHERE jt.code=j.job_type AND jt.handler_role=session_user
 AND j.id=p_id AND j.runtime_version=1 AND j.status='running' AND j.lease_owner=p_worker AND j.lease_token=p_token
 AND j.fencing_token=p_epoch AND j.lease_until>ts AND j.execution_deadline>ts AND NOT j.cancel_requested;
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;
CREATE FUNCTION automation.finish_job(p_id uuid,p_worker uuid,p_token uuid,p_epoch bigint,p_outcome text,
 p_error text DEFAULT NULL,p_result uuid DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; ts timestamptz:=clock_timestamp(); new_status text; delay double precision; t automation.job_types;
BEGIN
 SELECT q.* INTO j FROM automation.jobs q JOIN automation.job_types jt ON jt.code=q.job_type
 WHERE q.id=p_id AND q.runtime_version=1 AND jt.handler_role=session_user FOR UPDATE OF q;
 IF j.id IS NULL OR j.status<>'running' OR j.lease_owner IS DISTINCT FROM p_worker OR j.lease_token IS DISTINCT FROM p_token
 OR j.fencing_token<>p_epoch OR j.lease_until<=ts THEN RETURN false; END IF;
 IF p_outcome NOT IN ('succeeded','failed','retry','timed_out','cancelled') OR
 (p_error IS NOT NULL AND p_error NOT IN ('TEMPORARY','NETWORK','DATABASE','TIMEOUT','RATE_LIMIT','UNAVAILABLE',
 'INVALID_PAYLOAD','UNKNOWN_JOB','FORBIDDEN','PERMANENT','LEASE_LOST','CANCELLED','RETRY_EXHAUSTED','SHUTDOWN')) THEN
 RAISE EXCEPTION 'invalid outcome' USING ERRCODE='22023'; END IF;
 SELECT * INTO t FROM automation.job_types WHERE code=j.job_type;
 new_status:=CASE WHEN j.cancel_requested THEN 'cancelled'
 WHEN j.execution_deadline<=ts OR j.deadline<=ts THEN 'timed_out'
 WHEN p_outcome='retry' AND j.attempts<j.max_attempts THEN 'retry_pending'
 WHEN p_outcome='retry' AND p_error='TIMEOUT' THEN 'timed_out'
 WHEN p_outcome='retry' THEN 'failed' ELSE p_outcome END;
 delay:=least(t.retry_cap,t.retry_base*power(2.0,least(j.attempts-1,20)))*(0.8+random()*0.2);
 UPDATE automation.jobs SET status=new_status,lease_owner=NULL,lease_token=NULL,lease_until=NULL,
 error_code=CASE WHEN new_status='cancelled' THEN 'CANCELLED' ELSE p_error END,result_reference=p_result,
 scheduled_at=CASE WHEN new_status='retry_pending' THEN ts+make_interval(secs=>delay) ELSE scheduled_at END,
 finished_at=CASE WHEN new_status='retry_pending' THEN NULL ELSE ts END,updated_at=ts WHERE id=j.id;
 UPDATE automation.job_attempts SET finished_at=ts,
 outcome=CASE WHEN new_status='retry_pending' THEN 'failed' ELSE new_status END,
 error_code=CASE WHEN new_status='cancelled' THEN 'CANCELLED' ELSE p_error END,
 duration_ms=extract(epoch FROM ts-started_at)*1000 WHERE job_id=j.id AND fencing_token=p_epoch;
 RETURN true;
END $$;
CREATE FUNCTION automation.recover_jobs(p_limit integer DEFAULT 50) RETURNS integer
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; ts timestamptz:=clock_timestamp(); n integer:=0; final text; delay double precision; t automation.job_types;
BEGIN
 IF p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid recovery limit'; END IF;
 FOR j IN SELECT q.* FROM automation.jobs q JOIN automation.job_types jt ON jt.code=q.job_type
 WHERE q.runtime_version=1 AND jt.handler_role=session_user AND
 ((q.status='running' AND q.lease_until<=ts) OR
 (q.status IN ('pending','queued','retry_pending') AND q.deadline<=ts))
 ORDER BY q.lease_until NULLS LAST,q.id FOR UPDATE OF q SKIP LOCKED LIMIT p_limit LOOP
  SELECT * INTO t FROM automation.job_types WHERE code=j.job_type;
  final:=CASE WHEN j.cancel_requested THEN 'cancelled' WHEN j.deadline<=ts OR j.execution_deadline<=ts THEN 'timed_out'
  WHEN j.attempts>=j.max_attempts THEN 'failed' ELSE 'retry_pending' END;
  delay:=least(t.retry_cap,t.retry_base*power(2.0,least(greatest(j.attempts-1,0),20)))*(0.8+random()*0.2);
  UPDATE automation.job_attempts SET finished_at=ts,outcome=CASE WHEN final='retry_pending' THEN 'lease_lost' ELSE final END,
  error_code='LEASE_LOST',duration_ms=extract(epoch FROM ts-started_at)*1000 WHERE job_id=j.id AND finished_at IS NULL;
  UPDATE automation.jobs SET status=final,lease_owner=NULL,lease_token=NULL,lease_until=NULL,error_code='LEASE_LOST',
  scheduled_at=CASE WHEN final='retry_pending' THEN ts+make_interval(secs=>delay) ELSE scheduled_at END,
  finished_at=CASE WHEN final='retry_pending' THEN NULL ELSE ts END,updated_at=ts WHERE id=j.id;
  n:=n+1;
 END LOOP;
 RETURN n;
END $$;
CREATE FUNCTION automation.control_job(p_id uuid,p_action text) RETURNS uuid
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; new_id uuid;
BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'job administration denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO j FROM automation.jobs WHERE id=p_id AND runtime_version=1 FOR UPDATE;
 IF j.id IS NULL THEN RAISE EXCEPTION 'job unavailable'; END IF;
 IF p_action='release' AND j.status='pending' THEN
 UPDATE automation.jobs SET status='queued',scheduled_at=greatest(scheduled_at,clock_timestamp()),updated_at=clock_timestamp() WHERE id=j.id; RETURN j.id;
 ELSIF p_action='cancel' AND j.status IN ('pending','queued','retry_pending','running') THEN
 UPDATE automation.jobs SET cancel_requested=true,status=CASE WHEN status='running' THEN status ELSE 'cancelled' END,
 finished_at=CASE WHEN status='running' THEN NULL ELSE clock_timestamp() END,updated_at=clock_timestamp() WHERE id=j.id; RETURN j.id;
 ELSIF p_action='replay' AND j.status IN ('failed','timed_out','cancelled') THEN
 IF NOT EXISTS(SELECT 1 FROM automation.job_types jt WHERE jt.code=j.job_type AND session_user=ANY(jt.producer_roles))
 THEN RAISE EXCEPTION 'replay producer denied' USING ERRCODE='42501'; END IF;
 SELECT id INTO new_id FROM automation.enqueue_job(j.job_type,j.payload_version,j.payload,gen_random_uuid()::text,
 j.correlation_id,j.priority,NULL,NULL,j.max_attempts,'replay',false,j.id); RETURN new_id;
 END IF;
 RAISE EXCEPTION 'invalid administrative transition' USING ERRCODE='22023';
END $$;
"""

DDL += r"""
ALTER TABLE automation.event_types ADD schema_version integer NOT NULL DEFAULT 1 CHECK(schema_version>0),
 ADD requires_order boolean NOT NULL DEFAULT false;
ALTER TABLE automation.event_outbox ADD runtime_version integer NOT NULL DEFAULT 0 CHECK(runtime_version IN (0,1)),
 ADD schema_version integer NOT NULL DEFAULT 1 CHECK(schema_version>0), ADD aggregate_version bigint CHECK(aggregate_version>0),
 ADD request_fingerprint bytea, ADD CHECK(runtime_version=0 OR (aggregate_version IS NOT NULL AND correlation_id IS NOT NULL AND octet_length(request_fingerprint)=32));
CREATE INDEX outbox_runtime_aggregate ON automation.event_outbox(source,aggregate_type,aggregate_id,aggregate_version) WHERE runtime_version=1;
CREATE TABLE automation.delivery_targets (
 id text PRIMARY KEY CHECK(id ~ '^[a-z][a-z0-9_-]{0,47}$'), enabled boolean NOT NULL DEFAULT false,
 max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 100),
 retry_base double precision NOT NULL DEFAULT 5 CHECK(retry_base BETWEEN 0.1 AND 3600),
 retry_cap double precision NOT NULL DEFAULT 3600 CHECK(retry_cap>=retry_base AND retry_cap<=86400)
);
CREATE TABLE automation.event_routes (
 event_type text NOT NULL REFERENCES automation.event_types(code), destination text NOT NULL REFERENCES automation.delivery_targets(id),
 PRIMARY KEY(event_type,destination)
);
ALTER TABLE automation.event_deliveries ADD runtime_version integer NOT NULL DEFAULT 0 CHECK(runtime_version IN (0,1)),
 ADD lease_token uuid, ADD heartbeat_at timestamptz, ADD execution_deadline timestamptz,
 ADD ordered boolean NOT NULL DEFAULT false, ADD max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 100),
 ADD finished_at timestamptz, ADD CHECK(runtime_version=0 OR ((status='running')=(lease_token IS NOT NULL)));
CREATE TRIGGER deliveries_managed BEFORE INSERT OR UPDATE OR DELETE ON automation.event_deliveries
 FOR EACH ROW EXECUTE FUNCTION automation.managed_write_guard();
CREATE TABLE automation.delivery_attempts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_id uuid NOT NULL, destination text NOT NULL,
 attempt integer NOT NULL CHECK(attempt>0), worker_id uuid NOT NULL, lease_token uuid NOT NULL,
 fencing_token bigint NOT NULL CHECK(fencing_token>0), started_at timestamptz NOT NULL,
 finished_at timestamptz, outcome text CHECK(outcome IN ('delivered','retry','failed','lease_lost')),
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z_]{1,48}$'), duration_ms double precision,
 FOREIGN KEY(event_id,destination) REFERENCES automation.event_deliveries(event_id,destination),
 UNIQUE(event_id,destination,attempt), UNIQUE(event_id,destination,fencing_token)
);
CREATE INDEX deliveries_runtime_due ON automation.event_deliveries(next_attempt_at,event_id,destination)
 WHERE runtime_version=1 AND status IN ('pending','retry_pending');
CREATE INDEX deliveries_runtime_lease ON automation.event_deliveries(lease_until,event_id) WHERE runtime_version=1 AND status='running';
CREATE TABLE automation.event_consumers (
 id text PRIMARY KEY CHECK(id ~ '^[a-z][a-z0-9_-]{0,47}$'), consumer_role name NOT NULL, event_types text[] NOT NULL
);
CREATE TABLE automation.processed_events (
 consumer text NOT NULL REFERENCES automation.event_consumers(id), event_id uuid NOT NULL REFERENCES automation.event_outbox(id),
 processed_at timestamptz NOT NULL DEFAULT clock_timestamp(), fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(consumer,event_id)
);
CREATE TRIGGER processed_events_immutable BEFORE UPDATE OR DELETE ON automation.processed_events
 FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE FUNCTION automation.emit_event(p_id uuid,p_type text,p_version integer,p_source text,p_aggregate_type text,
 p_aggregate_id text,p_aggregate_version bigint,p_payload jsonb,p_key text,p_correlation uuid)
 RETURNS automation.event_outbox LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e automation.event_outbox; t automation.event_types; fingerprint bytea; latest bigint;
BEGIN
 SELECT * INTO t FROM automation.event_types WHERE code=p_type;
 IF t.code IS NULL OR t.producer_role<>session_user OR t.source<>p_source THEN
 RAISE EXCEPTION 'unauthorized event producer' USING ERRCODE='42501'; END IF;
 IF p_id IS NULL OR p_correlation IS NULL OR p_version<>t.schema_version OR p_aggregate_version<1
 OR length(p_aggregate_type) NOT BETWEEN 1 AND 64 OR length(p_aggregate_id) NOT BETWEEN 1 AND 128
 OR length(p_key) NOT BETWEEN 1 AND 128 OR NOT automation.safe_payload(p_payload) THEN
 RAISE EXCEPTION 'invalid event contract' USING ERRCODE='22023'; END IF;
 fingerprint:=sha256(convert_to(jsonb_build_object('type',p_type,'version',p_version,'source',p_source,
 'aggregate_type',p_aggregate_type,'aggregate_id',p_aggregate_id,'aggregate_version',p_aggregate_version,'payload',p_payload)::text,'UTF8'));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_source||'/'||p_aggregate_type||'/'||p_aggregate_id,7));
 SELECT * INTO e FROM automation.event_outbox WHERE source=p_source AND idempotency_key=p_key;
 IF e.id IS NOT NULL THEN
 IF e.request_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'event idempotency conflict' USING ERRCODE='23505'; END IF;
 RETURN e; END IF;
 IF t.requires_order THEN
 SELECT max(aggregate_version) INTO latest FROM automation.event_outbox WHERE runtime_version=1 AND source=p_source
 AND aggregate_type=p_aggregate_type AND aggregate_id=p_aggregate_id;
 IF p_aggregate_version<=latest THEN RAISE EXCEPTION 'aggregate version must increase' USING ERRCODE='22023'; END IF;
 END IF;
 INSERT INTO automation.event_outbox(id,event_type,schema_version,source,aggregate_type,aggregate_id,aggregate_version,
 payload,idempotency_key,correlation_id,runtime_version,request_fingerprint)
 VALUES(p_id,p_type,p_version,p_source,p_aggregate_type,p_aggregate_id,p_aggregate_version,p_payload,p_key,p_correlation,1,fingerprint)
 RETURNING * INTO e;
 INSERT INTO automation.event_deliveries(event_id,destination,runtime_version,ordered,max_attempts)
 SELECT e.id,r.destination,1,t.requires_order,d.max_attempts FROM automation.event_routes r
 JOIN automation.delivery_targets d ON d.id=r.destination WHERE r.event_type=e.event_type AND d.enabled;
 RETURN e;
END $$;
CREATE FUNCTION automation.claim_delivery(p_targets text[],p_worker uuid,p_lease double precision)
 RETURNS SETOF automation.event_deliveries LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d automation.event_deliveries; ts timestamptz:=clock_timestamp();
BEGIN
 IF session_user<>'event_dispatcher' THEN RAISE EXCEPTION 'dispatcher required' USING ERRCODE='42501'; END IF;
 IF p_worker IS NULL OR p_lease NOT BETWEEN 0.2 AND 300 OR cardinality(p_targets)>32 THEN RAISE EXCEPTION 'invalid claim'; END IF;
 SELECT q.* INTO d FROM automation.event_deliveries q JOIN automation.event_outbox e ON e.id=q.event_id
 JOIN automation.delivery_targets t ON t.id=q.destination
 WHERE q.runtime_version=1 AND q.destination=ANY(p_targets) AND t.enabled AND q.status IN ('pending','retry_pending')
 AND q.next_attempt_at<=ts AND q.attempts<q.max_attempts AND (NOT q.ordered OR NOT EXISTS(
 SELECT 1 FROM automation.event_deliveries prev JOIN automation.event_outbox pe ON pe.id=prev.event_id
 WHERE prev.destination=q.destination AND prev.runtime_version=1 AND prev.status<>'delivered'
 AND pe.source=e.source AND pe.aggregate_type=e.aggregate_type AND pe.aggregate_id=e.aggregate_id
 AND pe.aggregate_version<e.aggregate_version))
 ORDER BY q.next_attempt_at,e.occurred_at,q.event_id FOR UPDATE OF q SKIP LOCKED LIMIT 1;
 IF d.event_id IS NULL THEN RETURN; END IF;
 UPDATE automation.event_deliveries SET status='running',attempts=attempts+1,lease_owner=p_worker,lease_token=gen_random_uuid(),
 fencing_token=fencing_token+1,lease_until=ts+make_interval(secs=>p_lease),heartbeat_at=ts,
 execution_deadline=ts+interval '60 seconds' WHERE event_id=d.event_id AND destination=d.destination RETURNING * INTO d;
 INSERT INTO automation.delivery_attempts(event_id,destination,attempt,worker_id,lease_token,fencing_token,started_at)
 VALUES(d.event_id,d.destination,d.attempts,p_worker,d.lease_token,d.fencing_token,ts);
 RETURN NEXT d;
END $$;
CREATE FUNCTION automation.heartbeat_delivery(p_id uuid,p_destination text,p_worker uuid,p_token uuid,p_epoch bigint,p_lease double precision)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer; ts timestamptz:=clock_timestamp();
BEGIN
 IF session_user<>'event_dispatcher' OR p_lease NOT BETWEEN 0.2 AND 300 THEN RETURN false; END IF;
 UPDATE automation.event_deliveries SET lease_until=least(ts+make_interval(secs=>p_lease),execution_deadline),heartbeat_at=ts
 WHERE event_id=p_id AND destination=p_destination AND runtime_version=1 AND status='running' AND lease_owner=p_worker
 AND lease_token=p_token AND fencing_token=p_epoch AND lease_until>ts AND execution_deadline>ts;
 GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
END $$;
CREATE FUNCTION automation.finish_delivery(p_id uuid,p_destination text,p_worker uuid,p_token uuid,p_epoch bigint,
 p_outcome text,p_error text DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d automation.event_deliveries; t automation.delivery_targets; ts timestamptz:=clock_timestamp(); final text; delay double precision;
BEGIN
 IF session_user<>'event_dispatcher' THEN RAISE EXCEPTION 'dispatcher required' USING ERRCODE='42501'; END IF;
 SELECT * INTO d FROM automation.event_deliveries WHERE event_id=p_id AND destination=p_destination AND runtime_version=1 FOR UPDATE;
 IF d.event_id IS NULL OR d.status<>'running' OR d.lease_owner IS DISTINCT FROM p_worker OR d.lease_token IS DISTINCT FROM p_token
 OR d.fencing_token<>p_epoch OR d.lease_until<=ts THEN RETURN false; END IF;
 IF p_outcome NOT IN ('delivered','retry','failed') OR (p_error IS NOT NULL AND p_error NOT IN
 ('TEMPORARY','NETWORK','DATABASE','TIMEOUT','RATE_LIMIT','UNAVAILABLE','INVALID_PAYLOAD','FORBIDDEN','PERMANENT','LEASE_LOST','SHUTDOWN')) THEN
 RAISE EXCEPTION 'invalid delivery outcome'; END IF;
 SELECT * INTO t FROM automation.delivery_targets WHERE id=p_destination;
 final:=CASE WHEN p_outcome='retry' AND d.attempts<d.max_attempts THEN 'retry_pending' WHEN p_outcome='retry' THEN 'failed' ELSE p_outcome END;
 delay:=least(t.retry_cap,t.retry_base*power(2.0,least(d.attempts-1,20)))*(0.8+random()*0.2);
 UPDATE automation.event_deliveries SET status=final,lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code=p_error,
 next_attempt_at=CASE WHEN final='retry_pending' THEN ts+make_interval(secs=>delay) ELSE next_attempt_at END,
 delivered_at=CASE WHEN final='delivered' THEN ts ELSE NULL END,finished_at=CASE WHEN final='retry_pending' THEN NULL ELSE ts END
 WHERE event_id=p_id AND destination=p_destination;
 UPDATE automation.delivery_attempts SET finished_at=ts,outcome=p_outcome,error_code=p_error,
 duration_ms=extract(epoch FROM ts-started_at)*1000 WHERE event_id=p_id AND destination=p_destination AND fencing_token=p_epoch;
 RETURN true;
END $$;
CREATE FUNCTION automation.recover_deliveries(p_limit integer DEFAULT 50) RETURNS integer
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d automation.event_deliveries; ts timestamptz:=clock_timestamp(); n integer:=0; final text; t automation.delivery_targets;
BEGIN
 IF session_user<>'event_dispatcher' OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'recovery denied'; END IF;
 FOR d IN SELECT * FROM automation.event_deliveries WHERE runtime_version=1 AND status='running' AND lease_until<=ts
 ORDER BY lease_until,event_id FOR UPDATE SKIP LOCKED LIMIT p_limit LOOP
 SELECT * INTO t FROM automation.delivery_targets WHERE id=d.destination;
 final:=CASE WHEN d.attempts>=d.max_attempts THEN 'failed' ELSE 'retry_pending' END;
 UPDATE automation.event_deliveries SET status=final,lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code='LEASE_LOST',
 next_attempt_at=ts+make_interval(secs=>least(t.retry_cap,t.retry_base*power(2.0,least(d.attempts-1,20)))*(0.8+random()*0.2)),
 finished_at=CASE WHEN final='failed' THEN ts ELSE NULL END WHERE event_id=d.event_id AND destination=d.destination;
 UPDATE automation.delivery_attempts SET finished_at=ts,outcome='lease_lost',error_code='LEASE_LOST',
 duration_ms=extract(epoch FROM ts-started_at)*1000 WHERE event_id=d.event_id AND destination=d.destination AND finished_at IS NULL;
 n:=n+1;
 END LOOP; RETURN n;
END $$;
CREATE FUNCTION automation.consume_event(p_consumer text,p_event uuid,p_fingerprint bytea) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e automation.event_outbox; c automation.event_consumers; previous bytea; n integer;
BEGIN
 SELECT * INTO c FROM automation.event_consumers WHERE id=p_consumer;
 SELECT * INTO e FROM automation.event_outbox WHERE id=p_event AND runtime_version=1;
 IF c.id IS NULL OR e.id IS NULL OR c.consumer_role<>session_user OR NOT e.event_type=ANY(c.event_types) THEN
 RAISE EXCEPTION 'consumer denied' USING ERRCODE='42501'; END IF;
 IF p_fingerprint IS NOT NULL AND p_fingerprint IS DISTINCT FROM e.request_fingerprint THEN RAISE EXCEPTION 'event fingerprint mismatch' USING ERRCODE='22023'; END IF;
 INSERT INTO automation.processed_events(consumer,event_id,fingerprint) VALUES(p_consumer,p_event,coalesce(p_fingerprint,e.request_fingerprint)) ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n=0 THEN SELECT fingerprint INTO previous FROM automation.processed_events WHERE consumer=p_consumer AND event_id=p_event;
 IF previous IS DISTINCT FROM coalesce(p_fingerprint,e.request_fingerprint) THEN RAISE EXCEPTION 'consumer conflict' USING ERRCODE='23505'; END IF; END IF;
 RETURN n=1;
END $$;
CREATE FUNCTION automation.runtime_metrics() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE jobs jsonb; deliveries jsonb; extra jsonb;
BEGIN
 IF session_user NOT IN ('event_dispatcher','api_security','reporter','status_probe') THEN RAISE EXCEPTION 'metrics denied' USING ERRCODE='42501'; END IF;
 SELECT coalesce(jsonb_object_agg(status,n),'{}') INTO jobs FROM (SELECT status,count(*) n FROM automation.jobs WHERE runtime_version=1 GROUP BY status) q;
 SELECT coalesce(jsonb_object_agg(status,n),'{}') INTO deliveries FROM (SELECT status,count(*) n FROM automation.event_deliveries WHERE runtime_version=1 GROUP BY status) q;
 SELECT jsonb_build_object('oldest_job_seconds',coalesce(max(extract(epoch FROM clock_timestamp()-created_at)) FILTER(WHERE status IN ('queued','retry_pending')),0),
 'expired_leases',count(*) FILTER(WHERE status='running' AND lease_until<clock_timestamp()),
 'average_duration_ms',(SELECT coalesce(avg(duration_ms),0) FROM automation.job_attempts WHERE finished_at IS NOT NULL),
 'error_rate',(SELECT coalesce(avg((outcome NOT IN ('succeeded'))::int),0) FROM automation.job_attempts WHERE finished_at IS NOT NULL),
 'retry_rate',coalesce(avg((attempts>1)::int),0),
 'legacy_jobs',(SELECT count(*) FROM automation.jobs WHERE runtime_version=0 AND status IN ('pending','queued','running','retry_pending')),
 'legacy_events',(SELECT count(*) FROM automation.event_outbox WHERE runtime_version=0),
 'outbox_backlog',(SELECT count(*) FROM automation.event_deliveries WHERE runtime_version=1 AND status IN ('pending','running','retry_pending')),
 'oldest_event_seconds',(SELECT coalesce(max(extract(epoch FROM clock_timestamp()-e.occurred_at)),0)
 FROM automation.event_deliveries d JOIN automation.event_outbox e ON e.id=d.event_id WHERE d.runtime_version=1 AND d.status IN ('pending','running','retry_pending')),
 'delivery_error_rate',(SELECT coalesce(avg((outcome<>'delivered')::int),0) FROM automation.delivery_attempts WHERE finished_at IS NOT NULL))
 INTO extra FROM automation.jobs WHERE runtime_version=1;
 RETURN jsonb_build_object('jobs',jobs,'deliveries',deliveries)||extra;
END $$;
CREATE FUNCTION automation.inspect_runtime(p_kind text,p_limit integer DEFAULT 50) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user NOT IN ('api_security','reporter') OR p_limit NOT BETWEEN 1 AND 100 OR p_kind NOT IN ('jobs','outbox') THEN
 RAISE EXCEPTION 'inspection denied' USING ERRCODE='42501'; END IF;
 IF p_kind='jobs' THEN RETURN coalesce((SELECT jsonb_agg(x) FROM (SELECT id,job_type,status,attempts,max_attempts,
 lease_until,fencing_token,error_code,created_at,finished_at,correlation_id FROM automation.jobs WHERE runtime_version=1
 ORDER BY created_at DESC,id LIMIT p_limit) x),'[]'); END IF;
 RETURN coalesce((SELECT jsonb_agg(x) FROM (SELECT event_id,destination,status,attempts,last_error_code,lease_until,fencing_token
 FROM automation.event_deliveries WHERE runtime_version=1 ORDER BY next_attempt_at,event_id LIMIT p_limit) x),'[]');
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA automation FROM PUBLIC;
DO $$ DECLARE r text; signature text; BEGIN
 FOR r IN SELECT unnest(ARRAY['api_ingest','api_security','dashboard_admin','inventory_processor','importer','enricher','matcher','findings_writer','reporter','event_dispatcher','notification']) LOOP
 FOR signature IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='automation' AND p.proname IN ('enqueue_job','emit_event','consume_event') LOOP
 EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',signature,r); END LOOP; END LOOP;
 FOR r IN SELECT unnest(ARRAY['inventory_processor','importer','enricher','matcher','findings_writer','reporter','notification']) LOOP
 FOR signature IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='automation' AND p.proname IN ('claim_job','heartbeat_job','finish_job','recover_jobs') LOOP
 EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',signature,r); END LOOP; END LOOP;
 FOR signature IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='automation' AND p.proname IN ('claim_delivery','heartbeat_delivery','finish_delivery','recover_deliveries') LOOP
 EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO event_dispatcher',signature); END LOOP;
 FOR signature IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='automation' AND p.proname IN ('runtime_metrics','inspect_runtime','control_job') LOOP
 IF signature LIKE '%control_job(%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO api_security',signature);
 ELSIF signature LIKE '%inspect_runtime(%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO api_security,reporter',signature);
 ELSE EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO api_security,reporter,status_probe,event_dispatcher',signature); END IF;
 END LOOP;
END $$;
"""

DDL += r"""
GRANT USAGE ON SCHEMA automation TO status_probe;
GRANT SELECT ON automation.delivery_attempts TO event_dispatcher,reporter;
CREATE FUNCTION automation.check_job_fence(p_id uuid,p_worker uuid,p_token uuid,p_epoch bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs;
BEGIN
 SELECT q.* INTO j FROM automation.jobs q JOIN automation.job_types jt ON jt.code=q.job_type
 WHERE q.id=p_id AND q.runtime_version=1 AND jt.handler_role=session_user FOR UPDATE OF q;
 IF j.id IS NULL OR j.status<>'running' OR j.lease_owner IS DISTINCT FROM p_worker OR j.lease_token IS DISTINCT FROM p_token
 OR j.fencing_token<>p_epoch OR j.lease_until<=clock_timestamp() OR j.execution_deadline<=clock_timestamp() OR j.cancel_requested THEN RETURN false; END IF;
 RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION automation.check_job_fence(uuid,uuid,uuid,bigint)
 TO inventory_processor,importer,enricher,matcher,findings_writer,reporter,notification;
"""

DDL += r"""
CREATE TRIGGER outbox_managed BEFORE INSERT ON automation.event_outbox
 FOR EACH ROW EXECUTE FUNCTION automation.managed_write_guard();
"""

DDL += r"""
ALTER TABLE automation.jobs ADD error_summary text GENERATED ALWAYS AS
 (CASE WHEN runtime_version<>1 OR error_code IS NULL THEN NULL
 WHEN error_code='LEASE_LOST' THEN 'Execution lease no longer owned'
 WHEN error_code='TIMEOUT' THEN 'Execution time limit exceeded'
 WHEN error_code='CANCELLED' THEN 'Execution cancelled'
 WHEN error_code IN ('TEMPORARY','NETWORK','DATABASE','RATE_LIMIT','UNAVAILABLE','SHUTDOWN') THEN 'Temporary processing failure'
 ELSE 'Permanent processing failure' END) STORED;
"""

DDL += r"""
CREATE TABLE automation.runtime_actions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 actor_role name NOT NULL, event_id uuid REFERENCES automation.event_outbox(id), destination text NOT NULL,
 operation text NOT NULL CHECK(operation='delivery_retry'), previous_limit integer NOT NULL, new_limit integer NOT NULL
);
CREATE TRIGGER runtime_actions_immutable BEFORE UPDATE OR DELETE ON automation.runtime_actions
 FOR EACH ROW EXECUTE FUNCTION system.append_only();
GRANT SELECT ON automation.runtime_actions TO reporter;
CREATE FUNCTION automation.retry_delivery(p_event uuid,p_destination text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d automation.event_deliveries; t automation.delivery_targets; new_limit integer;
BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'delivery recovery denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO d FROM automation.event_deliveries WHERE event_id=p_event AND destination=p_destination AND runtime_version=1 FOR UPDATE;
 SELECT * INTO t FROM automation.delivery_targets WHERE id=p_destination;
 IF d.event_id IS NULL OR d.status<>'failed' OR d.max_attempts>=100 OR NOT t.enabled THEN
 RAISE EXCEPTION 'delivery not eligible for controlled retry' USING ERRCODE='22023'; END IF;
 new_limit:=least(100,d.max_attempts+t.max_attempts);
 UPDATE automation.event_deliveries SET status='retry_pending',max_attempts=new_limit,next_attempt_at=clock_timestamp(),
 finished_at=NULL WHERE event_id=p_event AND destination=p_destination;
 INSERT INTO automation.runtime_actions(actor_role,event_id,destination,operation,previous_limit,new_limit)
 VALUES(session_user,p_event,p_destination,'delivery_retry',d.max_attempts,new_limit);
 RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION automation.retry_delivery(uuid,text) TO api_security;
"""
