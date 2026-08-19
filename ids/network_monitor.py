import psutil
import time
import threading
from datetime import datetime

class NetworkMonitor:
    def __init__(self, window_seconds=10,
                 work_start=8, work_end=17):
        self.window_seconds = window_seconds
        self.work_start = work_start   # 8 AM
        self.work_end = work_end       # 5 PM
        self.running = False
        self.lock = threading.Lock()

        self.bytes_in = 0
        self.bytes_out = 0
        self.packets_in = 0
        self.packets_out = 0

        self._last_stats = psutil.net_io_counters()

        self.thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self.thread.start()

    def _monitor_loop(self):
        self.running = True
        while self.running:
            time.sleep(1)
            try:
                current = psutil.net_io_counters()
                with self.lock:
                    self.bytes_in = (
                        current.bytes_recv -
                        self._last_stats.bytes_recv
                    )
                    self.bytes_out = (
                        current.bytes_sent -
                        self._last_stats.bytes_sent
                    )
                    self.packets_in = (
                        current.packets_recv -
                        self._last_stats.packets_recv
                    )
                    self.packets_out = (
                        current.packets_sent -
                        self._last_stats.packets_sent
                    )
                    self._last_stats = current
            except Exception as e:
                print(f"Network monitor error: {e}")

    def is_work_hours(self):
        """Check if current time is within work hours."""
        now = datetime.now()
        hour = now.hour
        return self.work_start <= hour < self.work_end

    def check_login_time(self):
        """
        Returns:
        - allowed: bool
        - message: str
        - hour: int
        """
        now = datetime.now()
        hour = now.hour
        minute = now.minute
        time_str = now.strftime("%I:%M %p")

        if self.is_work_hours():
            return True, f"Work hours access at {time_str}", hour
        else:
            return (
                False,
                f"ALERT: After-hours access attempt at {time_str}",
                hour
            )

    def get_active_connections(self):
        # FIX: psutil.net_connections() can hang for a long time on
        # Windows (security software hooks, permission checks, high
        # connection counts). Run it on a side thread with a hard
        # timeout so extract_features() never blocks the IDS check
        # indefinitely. If it doesn't finish in time, we fall back to
        # safe empty defaults instead of freezing the whole login flow.
        result = {"value": (set(), set(), 0, 0)}

        def worker():
            try:
                connections = psutil.net_connections(kind='inet')
                ports = set()
                ips = set()
                failed = 0
                syn_count = 0

                for conn in connections:
                    if conn.raddr:
                        ports.add(conn.raddr.port)
                        ips.add(conn.raddr.ip)
                    if conn.status == 'SYN_SENT':
                        syn_count += 1
                    if conn.status in ('CLOSE_WAIT', 'TIME_WAIT'):
                        failed += 1

                result["value"] = (ports, ips, syn_count, failed)
            except Exception:
                pass  # keep the default empty result

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=2.0)  # give it 2 seconds max; abandon it otherwise

        return result["value"]

    def extract_features(self):
        """Extract 7 network features including time."""
        with self.lock:
            packets_per_sec = self.packets_in + self.packets_out
            bytes_per_sec = self.bytes_in + self.bytes_out

        ports, ips, syn_count, failed = self.get_active_connections()

        if self.bytes_in > 0:
            ratio = self.bytes_out / self.bytes_in
        else:
            ratio = 0.0

        # Login time feature
        allowed, message, hour = self.check_login_time()
        after_hours = 0 if allowed else 1

        features = [
            float(packets_per_sec),    # F11: packets/sec
            float(bytes_per_sec),      # F12: bytes/sec
            float(len(ports)),         # F13: unique ports
            float(syn_count),          # F14: SYN count
            float(failed),             # F15: failed connections
            float(min(ratio, 10.0)),   # F16: traffic ratio
            float(after_hours)         # F17: after-hours flag
        ]
        return features, allowed, message

    def stop(self):
        self.running = False