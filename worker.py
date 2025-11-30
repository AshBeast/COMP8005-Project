#!/usr/bin/env python3
import argparse
import socket
import sys
import threading
import time
import subprocess
from typing import Tuple, Optional

# ---------------- protocol helpers ----------------

def read_line(f) -> str:
    line = f.readline()
    if not line:
        return ""
    return line.decode("utf-8", errors="replace").strip()

def parse_work_line(line: str) -> Tuple[int, int, int]:
    parts = line.split()
    if len(parts) < 2 or parts[0] != "WORK":
        raise ValueError(f"Not a WORK line: {line!r}")

    params = {}
    for part in parts[1:]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        params[key] = int(value)

    return params["start"], params["end"], params["checkpoint"]

def safe_send(sock: socket.socket, data: str, send_lock: threading.Lock) -> bool:
    try:
        with send_lock:
            sock.sendall(data.encode("utf-8"))
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False


# ---------------- hash verify ----------------
# Prefer stdlib `crypt` if available (fast, no subprocess). Fallback to openssl.

try:
    import crypt  # type: ignore
except Exception:
    crypt = None

def verify_candidate(candidate: str, target_hash: str) -> bool:
    if crypt is not None:
        try:
            return crypt.crypt(candidate, target_hash) == target_hash
        except Exception:
            pass
    return openssl_verify(candidate, target_hash)

def openssl_verify(candidate: str, full_hash: str) -> bool:
    computed = openssl_crypt(candidate, full_hash)
    return computed == full_hash

def openssl_crypt(candidate: str, full_hash: str) -> Optional[str]:
    """
    Compute mkpasswd-style $1/$5/$6 crypt using openssl.
    Tries both '-rounds X' and embedding rounds in salt.
    """
    if not full_hash.startswith("$"):
        return None

    parts = full_hash.split("$")
    if len(parts) < 3:
        return None

    algo = parts[1]       # "1" md5, "5" sha256, "6" sha512
    salt = parts[2]
    rounds = None

    if salt.startswith("rounds="):
        rounds = salt.split("=", 1)[1]
        if len(parts) >= 4:
            salt = parts[3]

    flag = f"-{algo}"
    base_cmd = ["openssl", "passwd", flag, "-salt", salt]

    if rounds is not None:
        try_cmd = base_cmd + ["-rounds", rounds, candidate]
        try:
            out = subprocess.check_output(try_cmd, stderr=subprocess.DEVNULL)
            return out.decode().strip()
        except Exception:
            pass

        embedded_salt = f"rounds={rounds}${salt}"
        try_cmd2 = ["openssl", "passwd", flag, "-salt", embedded_salt, candidate]
        try:
            out = subprocess.check_output(try_cmd2, stderr=subprocess.DEVNULL)
            return out.decode().strip()
        except Exception:
            return None

    try:
        out = subprocess.check_output(base_cmd + [candidate], stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return None


# ---------------- bruteforce ----------------

UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
SYMBOLS = "@#%^&*()_+-=.,:;?"

CHARSET = UPPER + LOWER + DIGITS + SYMBOLS  # 79 chars
MIN_LEN = 1
MAX_LEN = 30

def total_space_size() -> int:
    base = len(CHARSET)
    total = 0
    for L in range(MIN_LEN, MAX_LEN + 1):
        total += base ** L
    return total

def index_to_word(idx: int) -> Optional[str]:
    """
    Map 0..(total_space-1) into strings over CHARSET.
    Ordering: all length=1 then length=2 then length=3 and so on until we find the password.
    """
    base = len(CHARSET)
    for L in range(MIN_LEN, MAX_LEN + 1):
        count = base ** L
        if idx < count:
            chars = []
            x = idx
            for _ in range(L):
                chars.append(CHARSET[x % base])
                x //= base
            return "".join(reversed(chars))
        idx -= count
    return None


# ---------------- threaded cracking ----------------

# initial CHECKPOINT (attempts=0) so the server sees activity even when checkpoint == work_size
def crack_range_threaded(
    sock: socket.socket,
    node_id: int,
    start: int,
    end: int,
    checkpoint: int,
    target_hash: str,
    num_threads: int,
    send_lock: threading.Lock,
) -> Tuple[int, Optional[str]]:
    """
    Returns (attempts_done, found_password).
    Sends:
      - CHECKPOINT at start of chunk (attempts=0) so checkpoint==worksize still shows activity.
      - CHECKPOINT every N attempts (best-effort).
      - FOUND when discovered.
    """
    keyspace_total = total_space_size()
    total_assigned = end - start
    if total_assigned <= 0:
        return 0, None

    stop_event = threading.Event()
    found_box = {"password": None}

    attempts_lock = threading.Lock()
    attempts = 0
    next_checkpoint = checkpoint if checkpoint > 0 else None

    # initial checkpoint (Darcy's "checkpoint==worksize" edge case)
    safe_send(
        sock,
        f"CHECKPOINT node={node_id} current={start-1} attempts=0 total={total_assigned}\n",
        send_lock,
    )

    def maybe_checkpoint(current_idx: int):
        nonlocal next_checkpoint
        if checkpoint <= 0 or next_checkpoint is None:
            return
        if attempts >= next_checkpoint and not stop_event.is_set():
            safe_send(
                sock,
                f"CHECKPOINT node={node_id} current={current_idx} attempts={attempts} total={total_assigned}\n",
                send_lock,
            )
            next_checkpoint += checkpoint

    def worker_thread(sub_start: int, sub_end: int):
        nonlocal attempts
        for current_idx in range(sub_start, sub_end):
            if stop_event.is_set():
                return
            if current_idx >= keyspace_total:
                return

            candidate = index_to_word(current_idx)
            if candidate is None:
                return

            if verify_candidate(candidate, target_hash):
                found_box["password"] = candidate
                stop_event.set()
                safe_send(sock, f"FOUND node={node_id} password={candidate}\n", send_lock)
                return

            with attempts_lock:
                attempts += 1
                maybe_checkpoint(current_idx)

    # split [start, end) into contiguous parts (no overlaps)
    total = end - start
    if num_threads < 1:
        num_threads = 1
    span = (total + num_threads - 1) // num_threads  # ceil
    threads = []
    for i in range(num_threads):
        a = start + i * span
        b = min(end, a + span)
        if a >= b:
            break
        t = threading.Thread(target=worker_thread, args=(a, b), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return attempts, found_box["password"]


# ---------------- main worker loop ----------------

def run_worker(server_ip: str, port: int, num_threads: int, ping_interval: float):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[WORKER] Connecting to {server_ip}:{port} ...")
        try:
            sock.connect((server_ip, port))
        except OSError as e:
            print(f"[WORKER][ERROR] Could not connect to server: {e}")
            sys.exit(1)

        f = sock.makefile("rb")
        send_lock = threading.Lock()

        safe_send(sock, "REGISTER\n", send_lock)

        welcome = read_line(f)
        if not welcome.startswith("WELCOME "):
            print(f"[WORKER][ERROR] Expected WELCOME, got: {welcome}")
            return
        node_id = int(welcome.split()[1])
        print(f"[WORKER] {welcome}")

        hash_line = read_line(f)
        if not hash_line.startswith("HASH "):
            print(f"[WORKER][ERROR] Expected HASH, got: {hash_line}")
            return
        target_hash = hash_line.split(" ", 1)[1]

        print(f"[WORKER] Target hash received.")
        print(f"[WORKER] Bruteforce lengths {MIN_LEN}..{MAX_LEN}, charset={len(CHARSET)}, keyspace={total_space_size()}")

        # Heartbeat: periodic PING so the server watchdog doesn't mark this worker LOST
        hb_stop = threading.Event()
        def heartbeat():
            while not hb_stop.is_set():
                safe_send(sock, f"PING node={node_id}\n", send_lock)
                time.sleep(ping_interval)

        hb = threading.Thread(target=heartbeat, daemon=True)
        hb.start()

        while True:
            line = read_line(f)
            if not line:
                print("[WORKER] Server closed connection. Exiting.")
                hb_stop.set()
                return

            if line == "STOP":
                print("[WORKER] STOP received. Exiting.")
                hb_stop.set()
                return

            if not line.startswith("WORK"):
                print(f"[WORKER][ERROR] Expected WORK/STOP, got: {line}")
                hb_stop.set()
                return

            start, end, checkpoint = parse_work_line(line)
            total = end - start
            print(f"[WORKER] {line}  (threads={num_threads}, guesses={total})")

            if start >= total_space_size():
                safe_send(sock, f"DONE node={node_id} total_attempts=0 range={start}-{end}\n", send_lock)
                print("[WORKER] Start beyond keyspace. Nothing to do.")
                hb_stop.set()
                return

            t0 = time.time()
            attempts_done, found_pw = crack_range_threaded(
                sock, node_id, start, end, checkpoint, target_hash, num_threads, send_lock
            )
            dt = time.time() - t0
            rate = attempts_done / dt if dt > 0 else 0.0
            print(f"[WORKER] done chunk: attempts={attempts_done} rate={rate:.1f}/s")

            safe_send(sock, f"DONE node={node_id} total_attempts={attempts_done} range={start}-{end}\n", send_lock)

            if found_pw is not None:
                print("[WORKER] Found password; waiting for STOP...")
                continue

            if not safe_send(sock, "REQUEST\n", send_lock):
                print("[WORKER] Server closed while requesting. Exiting.")
                hb_stop.set()
                return


def main():
    parser = argparse.ArgumentParser(description="Distributed Cracker Worker (79-char charset)")
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--ping-interval", type=float, default=1.0)
    args = parser.parse_args()

    run_worker(args.server, args.port, args.threads, args.ping_interval)

if __name__ == "__main__":
    main()
