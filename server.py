"""
Distributed password-cracking server.

- Workers connect and REGISTER.
- Server assigns disjoint integer ranges [start, end).
- Workers send CHECKPOINTs and DONE with attempts.
- Watchdog detects lost workers and requeues only the remaining portion of their ranges.
- Once any worker sends FOUND, server stops handing out new work and prints the password.
"""

#!/usr/bin/env python3
import argparse
import socket
import sys
import threading
import time
import csv
import os
from collections import deque
from datetime import datetime
from typing import Tuple, Optional, Dict, Any, List


# =========================
#       CSV RUN LOGGER
# =========================
class RunLogger:
    """Thread-safe CSV logger for server-side runs (one file per run)."""
    def __init__(self, log_dir: str = "logs"):
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = os.path.join(log_dir, f"run_{ts}.csv")
        self.lock = threading.Lock()

        with open(self.path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "ts_iso", "event",
                "node_id",
                "range_start", "range_end",
                "cursor",
                "attempts", "total",
                "password",
                "note"
            ])

    def log(
        self,
        event: str,
        node_id: Optional[int] = None,
        range_start: Optional[int] = None,
        range_end: Optional[int] = None,
        cursor: Optional[int] = None,
        attempts: Optional[int] = None,
        total: Optional[int] = None,
        password: Optional[str] = None,
        note: Optional[str] = None,
    ):
        row = [
            datetime.now().isoformat(timespec="seconds"),
            event,
            node_id if node_id is not None else "",
            range_start if range_start is not None else "",
            range_end if range_end is not None else "",
            cursor if cursor is not None else "",
            attempts if attempts is not None else "",
            total if total is not None else "",
            password if password is not None else "",
            note if note is not None else "",
        ]
        with self.lock:
            with open(self.path, "a", newline="") as f:
                csv.writer(f).writerow(row)


# =========================
#       NODE REGISTRY
# =========================

class NodeRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._nodes: Dict[int, Dict[str, Any]] = {}
        self._next_id = 1

    def add_node(self, ip: str, port: int) -> int:
        with self._lock:
            node_id = self._next_id
            self._next_id += 1
            self._nodes[node_id] = {
                "ip": ip,
                "port": port,
                "status": "idle",          # idle / working / done / lost
                "current_range": None,     # (start, end)
                "last_checkpoint": None,   # {"cursor":..., "attempts":..., "total":...}
                "last_seen_ts": time.time(),
                "note": "",
                "note_until_ts": 0.0,
            }
            return node_id

    def get(self, node_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            n = self._nodes.get(node_id)
            return dict(n) if n else None  # copy for safe reads

    def items(self):
        with self._lock:
            return [(nid, dict(info)) for nid, info in self._nodes.items()]

    def touch(self, node_id: int):
        with self._lock:
            n = self._nodes.get(node_id)
            if n:
                n["last_seen_ts"] = time.time()

    def set_range(self, node_id: int, start: int, end: int):
        with self._lock:
            n = self._nodes[node_id]
            n["current_range"] = (start, end)
            n["status"] = "working"
            n["last_checkpoint"] = None
            n["last_seen_ts"] = time.time()

    def set_checkpoint(self, node_id: int, cursor: int, attempts: int, total: int):
        # Keep checkpoints monotonic by attempts to prevent regressions.
        with self._lock:
            n = self._nodes[node_id]
            prev = n.get("last_checkpoint")
            if prev is None or attempts >= int(prev.get("attempts", -1)):
                n["last_checkpoint"] = {"cursor": cursor, "attempts": attempts, "total": total}
            n["last_seen_ts"] = time.time()

    def mark_done(self, node_id: int):
        with self._lock:
            n = self._nodes.get(node_id)
            if n:
                n["status"] = "done"
                n["last_seen_ts"] = time.time()

    def mark_lost(self, node_id: int):
        with self._lock:
            n = self._nodes.get(node_id)
            if n:
                n["status"] = "lost"
                n["last_seen_ts"] = time.time()

    def set_note(self, node_id: int, note: str, seconds: float = 2.5):
        with self._lock:
            n = self._nodes.get(node_id)
            if n:
                n["note"] = note
                n["note_until_ts"] = time.time() + seconds

    def note_for_ui(self, node_id: int) -> str:
        with self._lock:
            n = self._nodes.get(node_id)
            if not n:
                return ""
            if time.time() > n.get("note_until_ts", 0.0):
                return ""
            return n.get("note", "")

    def try_claim_loss(self, node_id: int) -> Tuple[bool, Optional[Tuple[int, int]]]:
        """
        Atomically mark node as lost *only if* it is currently working.
        Returns (claimed, current_range). Prevents double requeue.
        """
        with self._lock:
            n = self._nodes.get(node_id)
            if not n:
                return False, None
            if n["status"] != "working":
                return False, n.get("current_range")
            n["status"] = "lost"
            n["last_seen_ts"] = time.time()
            return True, n.get("current_range")


# =========================
#      RANGE MANAGER
# =========================

# Requeue only [resume_start, end); already-tested part of the range is not redone
class RangeManager:
    """
    Owns pending + inflight ranges so we never hand out duplicates.
    Requeues ONLY the remaining part based on checkpoint.
    """
    def __init__(self, chunk_size: int):
        self.chunk_size = chunk_size
        self.lock = threading.Lock()
        self.next_start = 0

        self.pending = deque()              # deque[(start,end)]
        self.pending_set = set()            # set[(start,end)]
        self.inflight_by_node = {}          # node_id -> (start,end)

    def claim_next(self, node_id: int) -> Tuple[int, int]:
        with self.lock:
            if node_id in self.inflight_by_node:
                raise RuntimeError(f"Node {node_id} already has inflight work.")

            if self.pending:
                rng = self.pending.popleft()
                self.pending_set.discard(rng)
            else:
                start = self.next_start
                end = start + self.chunk_size
                self.next_start = end
                rng = (start, end)

            self.inflight_by_node[node_id] = rng
            return rng

    def complete(self, node_id: int) -> Optional[Tuple[int, int]]:
        with self.lock:
            return self.inflight_by_node.pop(node_id, None)

    def requeue_node_partial(self, node_id: int, resume_start: int) -> Optional[Tuple[int, int]]:
        """
        Pop inflight range for node_id and requeue only [resume_start, end).
        """
        with self.lock:
            rng = self.inflight_by_node.pop(node_id, None)
            if not rng:
                return None

            start, end = rng
            rs = max(start, min(int(resume_start), end))
            if rs >= end:
                return None

            rem = (rs, end)
            if rem not in self.pending_set:
                self.pending.appendleft(rem)
                self.pending_set.add(rem)
            return rem

    def snapshot_pending(self, max_show: int = 6) -> Tuple[int, List[Tuple[int, int]]]:
        with self.lock:
            q = list(self.pending)
        return len(q), q[:max_show]


# =========================
#     PROTOCOL HELPERS
# =========================

def read_line(f) -> str:
    line = f.readline()
    if not line:
        return ""
    return line.decode("utf-8", errors="replace").strip()

def parse_kv_line(line: str) -> dict:
    parts = line.split()
    kv = {}
    for part in parts[1:]:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        kv[k] = v
    return kv


# =========================
#       LIVE VIEW UI
# =========================
STATUS_EMOJI = {
    "idle": "💤 idle",
    "working": "🛠️ work",
    "done": "✅ done",
    "lost": "❌ lost",
}

def format_queue(range_mgr: RangeManager) -> str:
    n, shown = range_mgr.snapshot_pending()
    if n == 0:
        return "0"
    s = ", ".join([f"[{a}-{b}]" for a, b in shown])
    if n > len(shown):
        s += f", … (+{n-len(shown)} more)"
    return f"{n} → {s}"

def live_view_loop(registry: NodeRegistry, range_mgr: RangeManager, found_event: threading.Event, found_box: dict):
    while True:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        found_str = "yes ✅" if found_event.is_set() else "no ❌"
        pw = found_box.get("password")

        print("=== Distributed Cracker Server (live view) ===")
        print(now_str)
        print(f"Password found: {found_str}" + (f"  →  {pw}" if found_event.is_set() and pw else ""))
        print(f"Pending ranges queued: {format_queue(range_mgr)}\n")

        header = (
            f"{'Node':<5} {'Address':<22} {'Status':<12} {'Range':<18} "
            f"{'Progress':<22} {'Note':<22} {'LastSeen(s)':<10}"
        )
        print(header)
        print("-" * len(header))

        for node_id, info in sorted(registry.items(), key=lambda x: x[0]):
            ip = info["ip"]
            port = info["port"]
            status = STATUS_EMOJI.get(info["status"], info["status"])

            r = info.get("current_range") or ("-", "-")
            r_str = f"{r[0]}-{r[1]}" if r[0] != "-" else "-"

            cp = info.get("last_checkpoint")
            if cp:
                attempts = int(cp.get("attempts", 0))
                total = int(cp.get("total", 0))
                pct = int(attempts / total * 100) if total else 0
                prog_str = f"{attempts}/{total} ({pct}%)"
            elif info["status"] == "done":
                prog_str = "✅ 100%"
            else:
                prog_str = "-"

            note = registry.note_for_ui(node_id)

            if info["status"] == "lost":
                last_seen = ""
            else:
                last_seen = f"{(time.time()-info['last_seen_ts']):.1f}"

            print(
                f"{node_id:<5} {ip+':'+str(port):<22} {status:<12} {r_str:<18} "
                f"{prog_str:<22} {note:<22} {last_seen:<10}"
            )

        time.sleep(0.8)


# =========================
#    TIMEOUT / REQUEUE
# =========================

# resume_start = range_start + attempts, so we only requeue untested candidates
def compute_resume_start(info: Dict[str, Any]) -> Optional[int]:
    """
    Resume rule YOU asked for:
      resume_start = range_start + attempts
    """
    rng = info.get("current_range")
    cp = info.get("last_checkpoint")
    if not rng or not cp:
        return None

    start, end = rng
    try:
        attempts = int(cp.get("attempts", 0))
        total = int(cp.get("total", 0))
    except Exception:
        return None

    if total <= 0:
        return None

    attempts = max(0, min(attempts, end - start))
    return start + attempts

def requeue_lost(node_id: int, registry: NodeRegistry, range_mgr: RangeManager, logger: RunLogger, why: str):
    claimed, rng = registry.try_claim_loss(node_id)
    if not claimed:
        return

    registry.set_note(node_id, "❌ lost connection", seconds=3.0)
    logger.log("LOST", node_id=node_id, note=why)

    info = registry.get(node_id) or {}
    if not rng:
        return

    resume_start = compute_resume_start(info)
    if resume_start is None:
        # no checkpoint -> requeue whole range by resuming at range start
        resume_start = rng[0]

    requeued = range_mgr.requeue_node_partial(node_id, resume_start)
    if requeued:
        a, b = requeued
        print(f"[SERVER] Node #{node_id} lost ({why}). Requeued {a}-{b}.")
        logger.log("REQUEUE", node_id=node_id, range_start=a, range_end=b, note=f"resume_start={resume_start}")
    else:
        print(f"[SERVER] Node #{node_id} lost ({why}). Nothing left to requeue.")
        logger.log("REQUEUE", node_id=node_id, note="nothing-left")

def watchdog(registry: NodeRegistry, range_mgr: RangeManager, timeout_s: int, found_event: threading.Event, logger: RunLogger):
    while True:
        now = time.time()
        for node_id, info in registry.items():
            if info["status"] != "working":
                continue
            if found_event.is_set():
                continue
            last_seen = info.get("last_seen_ts", 0.0)
            if now - last_seen > timeout_s:
                requeue_lost(node_id, registry, range_mgr, logger, why="timeout")
        time.sleep(1.0)


# =========================
#    ASSIGN / SEND WORK
# =========================

def send_work(conn: socket.socket, node_id: int, registry: NodeRegistry, range_mgr: RangeManager,
              checkpoint_interval: int, logger: RunLogger) -> None:
    start, end = range_mgr.claim_next(node_id)
    registry.set_range(node_id, start, end)

    work_line = f"WORK start={start} end={end} checkpoint={checkpoint_interval}\n"
    conn.sendall(work_line.encode("utf-8"))

    registry.set_note(node_id, "📨 new work sent", seconds=2.5)
    print(f"[SERVER] Sent work to node #{node_id}: {start}-{end} (checkpoint={checkpoint_interval})")
    logger.log("ASSIGN", node_id=node_id, range_start=start, range_end=end, total=(end - start))


# =========================
#      CLIENT HANDLER
# =========================
def handle_client(
    conn: socket.socket,
    addr: Tuple[str, int],
    registry: NodeRegistry,
    range_mgr: RangeManager,
    checkpoint_interval: int,
    target_hash: str,
    found_event: threading.Event,
    found_box: dict,
    found_lock: threading.Lock,
    logger: RunLogger
) -> None:
    ip, client_port = addr
    node_id: Optional[int] = None
    f = conn.makefile("rb")

    try:
        msg = read_line(f)
        if msg != "REGISTER":
            return

        node_id = registry.add_node(ip, client_port)
        logger.log("REGISTER", node_id=node_id, note=f"{ip}:{client_port}")

        print(f"[SERVER] Node #{node_id} registered from {ip}:{client_port}")
        registry.set_note(node_id, "👋 connected", seconds=2.0)

        conn.sendall(f"WELCOME {node_id}\n".encode("utf-8"))
        conn.sendall(f"HASH {target_hash}\n".encode("utf-8"))

        if found_event.is_set():
            conn.sendall(b"STOP\n")
            registry.mark_done(node_id)
            logger.log("STOP_SENT", node_id=node_id, note="already found")
            return

        send_work(conn, node_id, registry, range_mgr, checkpoint_interval, logger)

        while True:
            line = read_line(f)
            if not line:
                if node_id is not None:
                    requeue_lost(node_id, registry, range_mgr, logger, why="disconnect")
                break

            if line.startswith("PING"):
                registry.touch(node_id)
                continue

            registry.touch(node_id)

            info = registry.get(node_id)
            if info and info.get("status") == "lost":
                try:
                    conn.sendall(b"STOP\n")
                except Exception:
                    pass
                logger.log("STOP_SENT", node_id=node_id, note="zombie stopped")
                break

            if line.startswith("CHECKPOINT"):
                kv = parse_kv_line(line)
                try:
                    cursor = int(kv.get("current", kv.get("cursor", "-1")))
                    attempts = int(kv.get("attempts", "0"))
                    total = int(kv.get("total", "0"))
                    registry.set_checkpoint(node_id, cursor, attempts, total)

                    r = (registry.get(node_id) or {}).get("current_range")
                    logger.log(
                        "CHECKPOINT",
                        node_id=node_id,
                        range_start=r[0] if r else None,
                        range_end=r[1] if r else None,
                        cursor=cursor,
                        attempts=attempts,
                        total=total
                    )
                    registry.set_note(node_id, f"📍 {attempts}/{total}", seconds=1.2)
                except ValueError:
                    logger.log("CHECKPOINT_BAD", node_id=node_id, note=line)
                continue

            if line.startswith("FOUND"):
                kv = parse_kv_line(line)
                password = kv.get("password")

                with found_lock:
                    if not found_event.is_set():
                        found_event.set()
                        found_box["password"] = password
                        print(f"\n[SERVER] ✅ PASSWORD FOUND by node #{node_id}: {password}\n")
                        logger.log("FOUND", node_id=node_id, password=password)
                        registry.set_note(node_id, "🏁 FOUND!", seconds=4.0)
                continue

            if line.startswith("DONE"):
                rng = range_mgr.complete(node_id)
                registry.mark_done(node_id)
                registry.set_note(node_id, "✅ done", seconds=2.5)

                kv = parse_kv_line(line)
                attempts = int(kv.get("total_attempts", "0") or 0)

                logger.log(
                    "DONE",
                    node_id=node_id,
                    range_start=rng[0] if rng else None,
                    range_end=rng[1] if rng else None,
                    attempts=attempts,
                    total=(rng[1]-rng[0]) if rng else None
                )

                if found_event.is_set():
                    conn.sendall(b"STOP\n")
                    registry.set_note(node_id, "🛑 STOP sent", seconds=3.0)
                    logger.log("STOP_SENT", node_id=node_id, note="after done")
                    break

                continue

            if line == "REQUEST":
                if found_event.is_set():
                    conn.sendall(b"STOP\n")
                    registry.set_note(node_id, "🛑 STOP sent", seconds=3.0)
                    logger.log("STOP_SENT", node_id=node_id, note="on request")
                    break

                send_work(conn, node_id, registry, range_mgr, checkpoint_interval, logger)
                continue

            logger.log("UNKNOWN", node_id=node_id, note=line)

    except (ConnectionResetError, BrokenPipeError, OSError):
        if node_id is not None:
            requeue_lost(node_id, registry, range_mgr, logger, why="socket error")
    except Exception as e:
        logger.log("ERROR", node_id=node_id, note=str(e))
        if node_id is not None:
            requeue_lost(node_id, registry, range_mgr, logger, why="exception")
    finally:
        try:
            conn.close()
        except Exception:
            pass


# =========================
#        MAIN SERVER
# =========================
def run_server(port: int, work_size: int, checkpoint_interval: int, timeout_s: int, target_hash: str, live: bool):
    if work_size <= 0:
        print("[SERVER][ERROR] --work-size must be > 0")
        sys.exit(1)
    if checkpoint_interval <= 0:
        print("[SERVER][ERROR] --checkpoint must be > 0")
        sys.exit(1)
    if checkpoint_interval > work_size:
        print("[SERVER][ERROR] --checkpoint must be <= --work-size")
        sys.exit(1)

    host = "0.0.0.0"
    registry = NodeRegistry()
    range_mgr = RangeManager(work_size)

    found_event = threading.Event()
    found_box = {"password": None}
    found_lock = threading.Lock()

    logger = RunLogger()
    print(f"[SERVER] Logging run to: {logger.path}")

    wd = threading.Thread(
        target=watchdog,
        args=(registry, range_mgr, timeout_s, found_event, logger),
        daemon=True
    )
    wd.start()

    if live:
        lv = threading.Thread(
            target=live_view_loop,
            args=(registry, range_mgr, found_event, found_box),
            daemon=True
        )
        lv.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((host, port))
        except OSError as e:
            print(f"[SERVER][ERROR] bind failed: {e}")
            sys.exit(1)

        server_sock.listen(50)
        print(f"[SERVER] Listening on {host}:{port}")
        print(f"[SERVER] work-size={work_size}, checkpoint={checkpoint_interval}, timeout={timeout_s}s")
        print(f"[SERVER] HASH={target_hash}")

        try:
            while True:
                conn, addr = server_sock.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, registry, range_mgr, checkpoint_interval, target_hash,
                          found_event, found_box, found_lock, logger),
                    daemon=True
                )
                t.start()
        except KeyboardInterrupt:
            logger.log("SERVER_STOP")
            print("\n[SERVER] Shutting down.")
            print(f"[SERVER] Run log saved to {logger.path}")


def main():
    p = argparse.ArgumentParser(description="Distributed Cracker Server (fault-tolerant, no duplicate ranges)")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--work-size", type=int, default=10000)
    p.add_argument("--checkpoint", type=int, default=10000)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--hash", required=True, help="mkpasswd-style hash (e.g., $6$...)")
    p.add_argument("--no-live", action="store_true", help="disable live view UI")
    args = p.parse_args()

    run_server(
        port=args.port,
        work_size=args.work_size,
        checkpoint_interval=args.checkpoint,
        timeout_s=args.timeout,
        target_hash=args.hash,
        live=not args.no_live
    )

if __name__ == "__main__":
    main()
