#Reads server CSV log and prints summary + plots throughput / per-node progress.
#!/usr/bin/env python3
import csv
import sys
from collections import defaultdict
from datetime import datetime

import matplotlib.pyplot as plt


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def main(path: str):
    # --- aggregated info ---
    nodes_seen = set()
    first_ts = None
    first_assign_ts = None
    found_ts = None
    found_by = None
    found_pw = None

    # per-node progress series from CHECKPOINT (percentage)
    node_progress = defaultdict(list)  # node -> [(t, pct)]

    # attempts accounting:
    # - DONE attempts are best for global completed work
    total_done_attempts = 0
    done_step_t = []      # timestamps for step plot
    done_step_y = []      # cumulative attempts

    # per-node totals (from DONE)
    node_done_attempts = defaultdict(int)
    node_done_events = defaultdict(int)

    # record ASSIGN events for optional insight
    assign_events = []  # [(t, node, start, end, total)]
    # record LOST/REQUEUE (optional debug)
    lost_events = []
    requeue_events = []

    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            t = parse_ts(row["ts_iso"])
            event = row.get("event", "")

            if first_ts is None or t < first_ts:
                first_ts = t

            # node id may be blank in some events
            node_id = row.get("node_id", "")
            node = int(node_id) if node_id.strip() else None
            if node is not None:
                nodes_seen.add(node)

            if event == "ASSIGN":
                if first_assign_ts is None:
                    first_assign_ts = t
                # may be blank depending on your logger
                rs = row.get("range_start", "")
                re = row.get("range_end", "")
                tot = row.get("total", "")
                try:
                    rs_i = int(rs) if rs else None
                    re_i = int(re) if re else None
                    tot_i = int(tot) if tot else (re_i - rs_i if rs_i is not None and re_i is not None else None)
                except ValueError:
                    rs_i = re_i = tot_i = None
                assign_events.append((t, node, rs_i, re_i, tot_i))

            if event == "CHECKPOINT" and node is not None:
                attempts = row.get("attempts", "")
                total = row.get("total", "")
                try:
                    a = int(attempts) if attempts else 0
                    tot = int(total) if total else 0
                    pct = (a / tot * 100.0) if tot else 0.0
                    node_progress[node].append((t, pct))
                except ValueError:
                    pass

            if event == "DONE" and node is not None:
                # DONE attempts are per-chunk attempts_done from worker
                attempts = row.get("attempts", "")
                try:
                    a = int(attempts) if attempts else 0
                except ValueError:
                    a = 0

                total_done_attempts += a
                node_done_attempts[node] += a
                node_done_events[node] += 1

                done_step_t.append(t)
                done_step_y.append(total_done_attempts)

            if event == "FOUND":
                if found_ts is None:  # keep the first FOUND
                    found_ts = t
                    found_by = node
                    found_pw = row.get("password", "") or None

            if event == "LOST":
                lost_events.append((t, node, row.get("note", "")))

            if event == "REQUEUE":
                requeue_events.append((t, node, row.get("range_start", ""), row.get("range_end", ""), row.get("note", "")))

    # If no ASSIGN logged, fall back
    start_ts = first_assign_ts or first_ts
    end_ts = found_ts or (done_step_t[-1] if done_step_t else first_ts)

    duration_s = (end_ts - start_ts).total_seconds() if (start_ts and end_ts) else 0.0
    avg_rate = (total_done_attempts / duration_s) if duration_s > 0 else 0.0

    # --- Print summary ---
    print("=== Run Summary ===")
    print(f"Log: {path}")
    print(f"Start time: {start_ts.isoformat(timespec='seconds') if start_ts else 'N/A'}")
    if found_ts:
        print(f"Found time: {found_ts.isoformat(timespec='seconds')}")
        print(f"Found by:   Node {found_by}" if found_by is not None else "Found by:   (unknown)")
        print(f"Password:   {found_pw}" if found_pw else "Password:   (not logged)")
    else:
        print("Found time: (not found in log)")
    print(f"Duration:   {duration_s:.2f} s")
    print(f"Nodes seen: {sorted(nodes_seen) if nodes_seen else 'N/A'}")
    print(f"Total attempts (sum of DONE): {total_done_attempts}")
    print(f"Avg guesses/sec: {avg_rate:.2f}")

    if lost_events:
        print(f"Lost events: {len(lost_events)}")
    if requeue_events:
        print(f"Requeue events: {len(requeue_events)}")

    print("\n=== Per-node totals (from DONE) ===")
    if node_done_attempts:
        for n in sorted(node_done_attempts):
            attempts = node_done_attempts[n]
            chunks = node_done_events[n]
            # Per-node “rate” is rough unless all nodes ran for full duration;
            # still useful as a simple metric for report.
            node_rate = (attempts / duration_s) if duration_s > 0 else 0.0
            print(f"Node {n}: attempts={attempts}, chunks_done={chunks}, approx_rate={node_rate:.2f}/s")
    else:
        print("(No DONE events found — did the run finish or are you logging DONE?)")

    # --- Plot 1: per-node progress (%) over time ---
    if node_progress:
        plt.figure()
        for node, series in sorted(node_progress.items()):
            xs = [p[0] for p in series]
            ys = [p[1] for p in series]
            plt.plot(xs, ys, label=f"Node {node}")
        plt.title("Per-node progress over time (CHECKPOINT %)")
        plt.ylabel("Progress (%)")
        plt.xlabel("Time")
        plt.legend()
        plt.tight_layout()
    else:
        print("\n(No CHECKPOINT series to plot.)")

    # --- Plot 2: global cumulative attempts (DONE step series) ---
    if done_step_t:
        # sort by time in case log interleaves threads weirdly
        pairs = sorted(zip(done_step_t, done_step_y), key=lambda x: x[0])
        xs = [p[0] for p in pairs]
        ys = [p[1] for p in pairs]

        plt.figure()
        plt.step(xs, ys, where="post")
        plt.title("Global completed attempts over time (cumulative DONE)")
        plt.ylabel("Attempts completed")
        plt.xlabel("Time")
        plt.tight_layout()

        # --- Plot 3: rough throughput over time (delta DONE / delta t) ---
        if len(xs) >= 2:
            rates_t = []
            rates = []
            for i in range(1, len(xs)):
                dt = (xs[i] - xs[i-1]).total_seconds()
                da = ys[i] - ys[i-1]
                if dt > 0:
                    rates_t.append(xs[i])
                    rates.append(da / dt)
            if rates:
                plt.figure()
                plt.plot(rates_t, rates)
                plt.title("Approx throughput over time (from DONE deltas)")
                plt.ylabel("Guesses/sec")
                plt.xlabel("Time")
                plt.tight_layout()
    else:
        print("(No DONE series to plot.)")

    plt.show()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: plot_run.py logs/run_YYYYMMDD_HHMMSS.csv")
        sys.exit(1)
    main(sys.argv[1])
