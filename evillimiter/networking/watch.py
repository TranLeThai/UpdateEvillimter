import time
import threading
import logging
from typing import List, Optional

from .host import Host

logger = logging.getLogger(__name__)

class HostWatcher:
    def __init__(self, host_scanner, reconnection_callback):
        self._scanner = host_scanner
        self._reconnection_callback = reconnection_callback
        
        self._hosts = set()
        self._hosts_lock = threading.Lock()

        self._interval = 45.0
        self._iprange = None
        self._settings_lock = threading.Lock()

        self._log_list = []
        self._log_list_lock = threading.Lock()

        # Improved stopping mechanism
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def interval(self) -> float:
        with self._settings_lock:
            return self._interval

    @interval.setter
    def interval(self, value: float):
        with self._settings_lock:
            self._interval = float(value)

    @property
    def iprange(self):
        with self._settings_lock:
            return self._iprange

    @iprange.setter
    def iprange(self, value):
        with self._settings_lock:
            self._iprange = value

    @property
    def hosts(self):
        with self._hosts_lock:
            return self._hosts.copy()

    @property
    def log_list(self):
        with self._log_list_lock:
            return list(self._log_list)

    def add(self, host: Host) -> None:
        with self._hosts_lock:
            self._hosts.add(host)
        host.watched = True
        logger.debug(f"Watching host {host.ip}")

    def remove(self, host: Host) -> None:
        with self._hosts_lock:
            self._hosts.discard(host)
        host.watched = False
        logger.debug(f"Stopped watching host {host.ip}")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
            
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._watch_loop, daemon=True, name="HostWatcherThread")
        self._thread.start()
        logger.info("Host Watcher started.")

    def stop(self) -> None:
        self._stop_event.set()
        # Wait mechanism is smart now, so join is fast
        if self._thread:
            self._thread.join(timeout=1.0)
        logger.info("Host Watcher stopped.")

    def _watch_loop(self) -> None:
        while not self._stop_event.is_set():
            # Copy hosts safely
            with self._hosts_lock:
                current_hosts = list(self._hosts)

            if current_hosts:
                logger.debug("Scanning for reconnects...")
                reconnected_hosts = self._scanner.scan_for_reconnects(current_hosts, self.iprange)
                
                for old_host, new_host in reconnected_hosts.items():
                    logger.info(f"Reconnection detected: {old_host.ip} -> {new_host.ip}")
                    
                    # Call the callback
                    if self._reconnection_callback:
                        self._reconnection_callback(old_host, new_host)
                    
                    # Add to log
                    with self._log_list_lock:
                        self._log_list.append({
                            'old': old_host,
                            'new': new_host,
                            'time': time.strftime('%Y-%m-%d %H:%M %p')
                        })

            # Wait for interval OR stop signal
            # This makes stop() work immediately instead of waiting for 45s
            self._stop_event.wait(self.interval)