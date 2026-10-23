"""Event-driven FIFO with a single timer for actual retry deadlines."""
from collections import OrderedDict
import threading
import time


class TransferQueue:
    def __init__(self, wake, *, lock=None, clock=time.monotonic, timer_factory=threading.Timer):
        self.wake, self.clock, self.timer_factory = wake, clock, timer_factory
        self.lock = lock or threading.RLock()
        self.ready, self.delayed = OrderedDict(), {}
        self.timer = None
        self.timer_due = None
        self.generation = 0
        self.closed = False

    def enqueue(self, key):
        with self.lock:
            if self.closed or key in self.ready:
                return False
            self.delayed.pop(key, None)
            self.ready[key] = None
            self._arm()
            return True

    def retry(self, key, delay):
        with self.lock:
            if self.closed:
                return
            self.ready.pop(key, None)
            self.delayed[key] = self.clock() + max(.05, delay)
            self._arm()

    def discard(self, key):
        with self.lock:
            self.ready.pop(key, None)
            self.delayed.pop(key, None)
            self._arm()

    def take(self):
        with self.lock:
            now = self.clock()
            for key, due in sorted(self.delayed.items(), key=lambda row: row[1]):
                if due > now:
                    break
                self.delayed.pop(key)
                self.ready.setdefault(key, None)
            self._arm()
            return self.ready.popitem(last=False)[0] if self.ready else None

    def _arm(self):
        due = min(self.delayed.values(), default=None) if not self.closed else None
        if self.timer_due == due:
            return
        self.generation += 1
        generation = self.generation
        if self.timer is not None:
            self.timer.cancel()
        self.timer, self.timer_due = None, due
        if due is None:
            return
        def fired():
            with self.lock:
                if self.closed or generation != self.generation:
                    return
                self.timer, self.timer_due = None, None
                self.take_due()
            self.wake()
        self.timer = self.timer_factory(max(.001, due-self.clock()), fired)
        self.timer.daemon = True
        self.timer.start()

    def take_due(self):
        with self.lock:
            now = self.clock()
            for key, due in sorted(self.delayed.items(), key=lambda row: row[1]):
                if due <= now:
                    self.delayed.pop(key)
                    self.ready.setdefault(key, None)
            self._arm()

    def close(self):
        with self.lock:
            self.closed = True
            self.ready.clear()
            self.delayed.clear()
            self._arm()
