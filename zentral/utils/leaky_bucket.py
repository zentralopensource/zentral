import threading
import time


class LeakyBucket:
    def __init__(self, capacity, rate):
        self.capacity = capacity
        self.rate = rate
        self._lock = threading.Lock()
        self._state = (time.monotonic(), self.capacity)

    # multiprocessing fix

    def __getstate__(self):
        state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._lock = threading.Lock()

    # end multiprocessing fix

    def _unsafe_update_state(self):
        last_updated_at, last_volume = self._state
        updated_at = time.monotonic()
        elapsed_time = updated_at - last_updated_at
        volume = max(0, min(self.capacity, last_volume + self.rate * elapsed_time))
        self._state = (updated_at, volume)
        return volume

    def _unsafe_take_one(self):
        updated_at, volume = self._state
        assert volume >= 1
        self._state = (updated_at, volume - 1)

    def _take_one(self):
        with self._lock:
            volume = self._unsafe_update_state()
            if volume >= 1:
                self._unsafe_take_one()
                return 0
        return (1 - volume) / self.rate

    def consume(self, wait=True):
        while True:
            delay = self._take_one()
            if delay == 0:
                return True
            if wait:
                time.sleep(delay)
            else:
                return False
