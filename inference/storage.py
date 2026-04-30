# storage.py - SQLite flow persistence

# One row per completed alert. Scalar fields are indexed columns. Structured
# data (attribution) is stored as JSON text, too nested to query inside, just
# needs to round trip integrally

# WAL mode allows the FastAPI thread to read concurrently while the inference
# worker thread writes. A threading.Lock guards the single write path

import contextlib
import datetime
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Generator

log = logging.getLogger(__name__)

DB_PATH = Path("/app/data/flows.db")

_conn: sqlite3.Connection | None = None
_write_lock = threading.Lock()

@contextlib.contextmanager
def _read_conn() -> Generator[sqlite3.Connection, None, None]:
    # short lived read connection in WAL mode
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()

def init_db() -> None:
    # Open or create the database and apply the schema
    global _conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    
    # WAL allows concurrent read from the FastAPI thread while the inference
    # worker writes. NORMAL sync is safe with WAL and avoids an fsync per commit
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    
    _conn.executescript("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
                flow_id TEXT NOT NULL,
                ts REAL NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                proto TEXT NOT NULL,
                duration REAL NOT NULL,
                fwd_pkts INTEGER NOT NULL,
                label TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                score_fast REAL,
                score_medium REAL,
                score_slow REAL,
                score_comp REAL,
                score_oor REAL,
                attribution TEXT,
                features TEXT,
                t_enqueue_ns INTEGER,
                t_socket_ns INTEGER,
                t_dequeue_ns INTEGER,
                t_scored_ns INTEGER
            );
            CREATE TABLE IF NOT EXISTS phases (
                id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL,
                scenario TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('baseline', 'attack', 'benign', 'recovery')),
                t_start REAL NOT NULL,
                t_end REAL,
                attacker_ip TEXT
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                flow_id TEXT NOT NULL,
                ts REAL NOT NULL,
                corrected_label TEXT,
                dismiss INTEGER NOT NULL DEFAULT 0,
                reason TEXT,
                analyst_text TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_phases_run ON phases(run_id);
            CREATE INDEX IF NOT EXISTS idx_phases_t ON phases(t_start, t_end);
            CREATE INDEX IF NOT EXISTS idx_ts ON flows(ts);
            CREATE INDEX IF NOT EXISTS idx_src_ip ON flows(src_ip);
            CREATE INDEX IF NOT EXISTS idx_proto ON flows(proto);
            CREATE INDEX IF NOT EXISTS idx_label ON flows(label);
            CREATE INDEX IF NOT EXISTS idx_feedback_flow_id ON feedback(flow_id);
    """)
    _conn.commit()
    log.info("SQLite DB ready at %s", DB_PATH)
    
def insert_flow(alert: dict) -> None:
    if _conn is None:
        return
    
    v = alert.get("verdict", {})
    s = alert.get("scores", {})
    t = alert.get("_timing", {})
    
    with _write_lock:
        try:
            _conn.execute("""
                INSERT INTO flows
                    (flow_id, ts, src_ip, dst_ip, src_port, dst_port,
                     proto, duration, fwd_pkts,
                     label, severity, confidence,
                     score_fast, score_medium, score_slow, score_comp, score_oor,
                     attribution, features,
                     t_enqueue_ns, t_socket_ns, t_dequeue_ns, t_scored_ns)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                alert["flow_id"], alert["ts"],
                alert["src_ip"], alert["dst_ip"],
                alert["src_port"], alert["dst_port"],
                alert["proto"], alert["duration"], alert["fwd_pkts"],
                v.get("label", ""), v.get("severity", ""), v.get("confidence", 0.0),
                s.get("fast"), s.get("medium"), s.get("slow"), s.get("composite"),
                s.get("oor"),
                json.dumps(alert.get("attribution", [])),
                json.dumps(alert.get("features", {})),
                t.get("t_enqueue_ns"), t.get("t_socket_ns"),
                t.get("t_dequeue_ns"), t.get("t_scored_ns")
            ))
            _conn.commit()
        except Exception:
            log.warning("Failed to insert flow %s", alert.get("flow_id"), exc_info=True)
            
def clear_flows() -> int:
    if _conn is None:
        return 0
    with _write_lock:
        cur = _conn.execute("DELETE FROM flows")
        _conn.commit()
        return cur.rowcount
    
def write_phase(run_id: str, scenario: str, phase: str,
                t_start: float, attacker_ip: str | None = None) -> int | None:
    if _conn is None:
        return -1
    with _write_lock:
        cur = _conn.execute(
            "INSERT INTO phases (run_id, scenario, phase, t_start, attacker_ip) "
            "VALUES (?,?,?,?,?)",
            (run_id, scenario, phase, t_start, attacker_ip)
        )
        _conn.commit()
        return cur.lastrowid
    
def close_phase(phase_id: int, t_end: float) -> None:
    if _conn is None or phase_id < 0:
        return
    with _write_lock:
        _conn.execute("UPDATE phases SET t_end=? WHERE id=?", (t_end, phase_id))
        _conn.commit()
        
def query_phases(run_id: str | None = None) -> list[dict]:
    if _conn is None:
        return []
    sql = "SELECT id, run_id, scenario, phase, t_start, t_end, attacker_ip FROM phases"
    params: list = []
    if run_id:
        sql += " WHERE run_id=?"
        params.append(run_id)
    sql += " ORDER BY t_start"
    with _read_conn() as rc:
        rows = rc.execute(sql, params).fetchall()
    keys = ("id", "run_id", "scenario", "phase", "t_start", "t_end", "attacker_ip")
    return [dict(zip(keys, r)) for r in rows]

def query_flows(
    limit: int = 200,
    proto: str | None = None,
    label: str | None = None,
    src_ip: str | None = None,
    ts_from: float | None = None,
    ts_to: float | None = None
) -> list[dict]:
    """
        Return flows as alert dicts, newest first
        
        All filter params are optional and can be combined. ts_from/ts_to are Unix
        timestamps. Use them in the scenario runner to bound the query to the attack
        window so the limit doesn't cut off early flows
    """
    if _conn is None:
        return []
    
    clauses: list[str] = []
    params: list[Any] = []
    
    if proto:
        clauses.append("proto = ?")
        params.append(proto.upper())
    if label:
        clauses.append("label = ?")
        params.append(label)
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if ts_from is not None:
        clauses.append("ts >= ?")
        params.append(ts_from)
    if ts_to is not None:
        clauses.append("ts <= ?")
        params.append(ts_to)
        
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    
    with _read_conn() as rc:
        rows = rc.execute(f"""
            SELECT flow_id, ts, src_ip, dst_ip, src_port, dst_port,
                   proto, duration, fwd_pkts,
                   label, severity, confidence,
                   score_fast, score_medium, score_slow, score_comp, score_oor,
                   attribution,
                   t_enqueue_ns, t_socket_ns, t_dequeue_ns, t_scored_ns
            FROM flows
            {where}
            ORDER BY ts DESC
            LIMIT ?
            """,
            params
        ).fetchall()
        
    return [_row_to_alert(r) for r in rows]

def get_flow_features(flow_id: str) -> tuple[str, dict] | None:
    """
        Return (proto, feature_dict) for a stored flow, or None if not found
        
        Used by the FP feedback loop to retrieve the OIF feature vector so
        reinforce_normal() can be called without recomputing it from the raw flow
    """
    if _conn is None:
        return None
    with _read_conn() as rc:
        row = rc.execute(
            "SELECT proto, features FROM flows WHERE flow_id=? LIMIT 1",
            (flow_id,)
        ).fetchone()
    if row is None or not row[1]:
        return None
    return row[0], json.loads(row[1])

def upsert_feedback(
    flow_id: str,
    ts: float,
    corrected_label: str | None,
    dismiss: bool,
    reason: str,
    analyst_text: str | None = None
) -> None:
    if _conn is None:
        return
    with _write_lock:
        try:
            _conn.execute(
                """
                    INSERT OR REPLACE INTO feedback
                        (flow_id, ts, corrected_label, dismiss, reason, analyst_text)
                    VALUES (?,?,?,?,?,?)
                """,
                (flow_id, ts, corrected_label, int(dismiss), reason, analyst_text)
            )
            _conn.commit()
        except Exception:
            log.warning("Failed to upsert feedback for flow %s", flow_id, exc_info=True)
            
def upsert_feedback_bulk(
    flow_ids: list[str],
    dismiss: bool = True,
    corrected_label: str | None = None,
    reason: str = "Bulk dismissed as false positive",
) -> int:
    # Persist feedback for multiple flows in a single transation
    
    if _conn is None or not flow_ids:
        return 0
    now = time.time()
    with _write_lock:
        try:
            _conn.executemany(
                """
                    INSERT OR REPLACE INTO feedback
                        (flow_id, ts, corrected_label, dismiss, reason, analyst_text)
                    VALUES (?,?,?,?,?,?)
                """,
                [(fid, now, corrected_label, int(dismiss), reason, None) for fid in flow_ids]
            )
            _conn.commit()
            return len(flow_ids)
        except Exception:
            log.warning("Failed to upsert bulk feedback", exc_info=True)
            return 0
        
def query_feedback(flow_id: str | None = None) -> list[dict]:
    if _conn is None:
        return []
    with _read_conn() as rc:
        if flow_id:
            rows = rc.execute(
                "SELECT flow_id, ts, corrected_label, dismiss, reason, analyst_text "
                "FROM feedback WHERE flow_id = ? ORDER BY ts DESC",
                (flow_id,)
            ).fetchall()
        else:
            rows = rc.execute(
                "SELECT flow_id, ts, corrected_label, dismiss, reason, analyst_text "
                "FROM feedback ORDER BY ts DESC LIMIT 200"
            ).fetchall()
    return [
        {
            "flow_id": r[0],
            "ts": r[1],
            "corrected_label": r[2],
            "dismiss": bool(r[3]),
            "reason": r[4] or "",
            "analyst_text": r[5]
        } for r in rows
    ]
    
def iter_flows_ndjson():
    """
        Generator that yields one NDJSON line per flow, ordered by timestamp
        
        Opens its own read connection so it can be iterated lazily by a
        StreamingResponse without holding the write lock or loading everything
        into memory. Suitable for arbitrarily large databases
    """
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        cursor = conn.execute(
            """
                SELECT flow_id, ts, proto, src_ip, dst_ip, src_port, dst_port,
                   duration, fwd_pkts,
                   label, severity, confidence,
                   score_fast, score_medium, score_slow, score_comp, score_oor,
                   attribution,
                   t_enqueue_ns, t_socket_ns, t_dequeue_ns, t_scored_ns
                FROM flows
                ORDER BY ts
            """
        )
        for row in cursor:
            obj = {
                "flow_id": row[0], "ts": row[1], "proto": row[2],
                "src_ip": row[3], "dst_ip": row[4],
                "src_port": row[5], "dst_port": row[6],
                "duration": row[7], "fwd_pkts": row[8],
                "label": row[9], "severity": row[10], "confidence": row[11],
                "score_fast": row[12], "score_medium": row[13],
                "score_slow": row[14], "score_comp": row[15],
                "score_oor": row[16],
                "attribution": json.loads(row[17] or "[]"),
                "t_enqueue_ns": row[18], "t_socket_ns": row[19],
                "t_dequeue_ns": row[20], "t_scored_ns": row[21]
            }
            yield json.dumps(obj) + '\n'
    finally:
        conn.close()
        
def query_hourly_summary() -> list[dict]:
    """
        Return hourly aggregate stats for the summary CSV export
        
        One row per (hour, proto)
    """
    if _conn is None:
        return []
    with _read_conn() as rc:
        rows = rc.execute(
            """
                SELECT
                    CAST(ts / 3600 AS INTEGER) * 3600 AS hour_ts,
                    proto,
                    COUNT(*) AS total,
                    SUM(severity = 'CRITICAL') AS critical,
                    SUM(severity = 'HIGH') AS high,
                    SUM(severity = 'INFO') AS info,
                    AVG(confidence) AS mean_score,
                    MAX(confidence) AS max_score,
                    AVG(
                    CASE WHEN t_scored_ns IS NOT NULL
                              AND t_dequeue_ns IS NOT NULL
                         THEN (t_scored_ns - t_dequeue_ns) / 1e6
                         ELSE NULL END
                ) AS mean_oif_ms
                FROM flows
                GROUP BY hour_ts, proto
                ORDER BY hour_ts, proto
            """
        ).fetchall()
        return [{
            "hour_ts": r[0],
            "hour": datetime.datetime.utcfromtimestamp(r[0]).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "proto": r[1],
            "total": r[2],
            "critical": r[3] or 0,
            "high": r[4] or 0,
            "info": r[5] or 0,
            "mean_score": round(r[6] or 0.0, 6),
            "max_score": round(r[7] or 0.0, 6),
            "mean_oif_ms": round(r[8], 4) if r[8] is not None else None
        } for r in rows]
        
def query_window_history(
    proto: str,
    since: float,
    bucket_sec: int = 300
) -> list[dict]:
    """
        Return time bucketed average per-window scores for one protocol
        
        Groups flows into bucket_sec-wide buckets and averages the three OIF
        window scores. Used by the dashboard heatmap ribbon to show score trends
        over the last 24h without requiring a separate write path
    """
    if _conn is None:
        return []
    with _read_conn() as rc:
        rows = rc.execute(
            """
                SELECT
                    CAST(ts / ? AS INTEGER) * ? AS bucket_ts,
                    AVG(score_fast) AS fast,
                    AVG(score_medium) AS medium,
                    AVG(score_slow) AS slow,
                    MAX(score_comp) AS peak
                FROM flows
                WHERE proto = ? AND ts >= ? AND score_fast IS NOT NULL
                GROUP BY bucket_ts
                ORDER BY bucket_ts
            """,
            (bucket_sec, bucket_sec, proto.upper(), since)
        ).fetchall()
    return [{
        "ts":     r[0],
            "fast":   r[1] or 0.0,
            "medium": r[2] or 0.0,
            "slow":   r[3] or 0.0,
            "peak":   r[4] or 0.0
    } for r in rows]
    
def _row_to_alert(row: tuple) -> dict:
    (flow_id, ts, src_ip, dst_ip, src_port, dst_port,
     proto, duration, fwd_pkts,
     label, severity, confidence,
     fast, medium, slow, comp, oor,
     attribution_json,
     t_enqueue_ns, t_socket_ns, t_dequeue_ns, t_scored_ns) = row
    
    return {
        "flow_id": flow_id,
        "ts": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "duration": duration,
        "fwd_pkts": fwd_pkts,
        "verdict": {
            "label": label,
            "severity": severity,
            "confidence": confidence,
        },
        "scores": {
            "fast": fast,
            "medium": medium,
            "slow": slow,
            "composite": comp,
            "oor": oor,
        },
        # Flat alias so scenarios and evaluation can use composite score
        # without navigating the nested dict
        "score_comp": comp,
        "attribution": json.loads(attribution_json or "[]"),
        "timing": {
            "t_enqueue_ns": t_enqueue_ns,
            "t_socket_ns": t_socket_ns,
            "t_dequeue_ns": t_dequeue_ns,
            "t_scored_ns": t_scored_ns,
        }
    }