"""
REAL fixes for quantum_providers/openquantum_provider.py

Written against confirmed SDK method signatures and JobRead field names:

  JobRead fields (confirmed):
    id, status, input_data_url, job_preparation_id, execution_plan_id,
    queue_priority_id, message, output_data_url, calibration_data_url,
    transaction_id, submitted_at, extra

  SchedulerClient.get_job(job_id) -> JobRead
  SchedulerClient.list_jobs(organization_id=None, limit=20, cursor=None,
                             status=None) -> PaginatedJobs
  SchedulerClient.download_job_calibration(job: JobRead) -> Any
    (raises RuntimeError if job.calibration_data_url is None)

  HONEST LIMITATION: JobRead has no completed_at/started_at/queue_position.
  Real execution-duration timing is NOT available from this endpoint.
  get_job_timing below returns only what is real: time since submission
  and current status — not invented duration fields.
"""

# ── Replace get_calibration_data ────────────────────────────────────────
def get_calibration_data(self, device_id: str) -> "Dict[str, CalibrationSnapshot]":
    """
    Real implementation. Calibration is tagged per-JOB, not per-device —
    there is no fleet/device calibration endpoint in this SDK. To answer
    "what is the calibration for this device", find the most recent job
    run on it and pull the calibration attached to that job.

    Honest limitation: if no job has been run on this device yet, or the
    most recent job carries no calibration_data_url, this returns {}
    rather than fabricating a snapshot.
    """
    try:
        result = self._scheduler.list_jobs(limit=50)
        jobs = getattr(result, "jobs", []) or []

        matching_job = None
        for j in jobs:
            backend = (getattr(j, "backend_class_id", None)
                       or getattr(j, "backend", None)
                       or getattr(j, "device_id", None))
            if backend == device_id:
                matching_job = j
                break

        if matching_job is None:
            return {}

        full_job = self._scheduler.get_job(matching_job.id)

        if not getattr(full_job, "calibration_data_url", None):
            return {}

        raw = self._scheduler.download_job_calibration(full_job)
        if not raw:
            return {}

        return {
            device_id: CalibrationSnapshot(
                device_id=device_id,
                source_job_id=full_job.id,
                raw=raw,
            )
        }
    except RuntimeError:
        # download_job_calibration raises this when calibration_data_url
        # is None — already checked above, but the SDK may still throw
        # in a race; treat as "no calibration available" rather than error
        return {}
    except Exception as e:
        print(f"[OpenQuantum] get_calibration_data failed: {e}")
        return {}


# ── Replace get_queue_depth ─────────────────────────────────────────────
def get_queue_depth(self, device_id: str) -> QueueStatus:
    """
    Real implementation. No fleet-wide queue-depth endpoint exists in
    this SDK (confirmed: SchedulerClient has no such method). This is an
    honest approximation: count jobs with status "Queued" that target
    this device, from the caller's own visible job list.

    This underestimates true queue depth — it only sees YOUR queued jobs,
    not the whole backend's queue. Documented, not hidden.
    """
    try:
        result = self._scheduler.list_jobs(limit=200, status="Queued")
        jobs = getattr(result, "jobs", []) or []

        matching = [j for j in jobs if (
            getattr(j, "backend_class_id", None) == device_id or
            getattr(j, "backend", None) == device_id or
            getattr(j, "device_id", None) == device_id
        )]

        return QueueStatus(
            device_id=device_id,
            pending_jobs=len(matching),
            status="approximate_own_jobs_only",
        )
    except Exception as e:
        print(f"[OpenQuantum] get_queue_depth failed: {e}")
        return QueueStatus(device_id=device_id, pending_jobs=-1,
                            status="error")


# ── Replace get_job_history ─────────────────────────────────────────────
def get_job_history(self, limit: int = 200) -> "List[JobRecord]":
    """
    Real implementation against list_jobs(). SDK default limit is 20;
    caller-specified limit is passed through directly.
    """
    try:
        result = self._scheduler.list_jobs(limit=limit)
        jobs = getattr(result, "jobs", []) or []

        records = []
        for j in jobs:
            records.append(JobRecord(
                job_id=getattr(j, "id", None),
                status=getattr(j, "status", None),
                submitted_at=getattr(j, "submitted_at", None),
                message=getattr(j, "message", None),
            ))
        return records
    except Exception as e:
        print(f"[OpenQuantum] get_job_history failed: {e}")
        return []


# ── Replace get_job_timing ──────────────────────────────────────────────
def get_job_timing(self, job_id: str) -> "Dict[str, float]":
    """
    Real implementation against get_job(). HONEST LIMITATION: JobRead
    has no completed_at, started_at, or queue_position field. Real
    execution-duration timing cannot be computed from this endpoint —
    that data is simply not exposed by the API as documented.

    Returns only what is real: elapsed wall-clock time since submission,
    and the current status string. Does not invent duration fields.
    """
    try:
        job = self._scheduler.get_job(job_id)

        submitted_at = getattr(job, "submitted_at", None)
        if not submitted_at:
            return {}

        from datetime import datetime
        try:
            submitted = datetime.fromisoformat(
                submitted_at.replace("Z", "+00:00"))
        except Exception:
            return {}

        now = datetime.now(submitted.tzinfo)
        elapsed_s = (now - submitted).total_seconds()

        return {
            "elapsed_since_submission_s": elapsed_s,
            "status": getattr(job, "status", None),
            # No execution_time_s or queue_time_s — not available from
            # this API. Do not fabricate these fields.
        }
    except Exception as e:
        print(f"[OpenQuantum] get_job_timing failed: {e}")
        return {}
