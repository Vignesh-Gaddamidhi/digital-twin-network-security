from typing import Optional
from datetime import datetime, timezone

class SimulationClock:
    """Discrete, virtualized simulation clock decoupled from real wall-clock time."""

    def __init__(self, tick_step: float = 1.0):
        self._tick_step = tick_step
        self._current_time: float = 0.0
        self._is_running: bool = False
        self._start_wall_time: Optional[str] = None
        self._last_tick_wall_time: Optional[str] = None

    @property
    def currentTime(self) -> float:
        return round(self._current_time, 3)

    @property
    def isRunning(self) -> bool:
        return self._is_running

    def start(self):
        self._is_running = True
        if self._start_wall_time is None:
            self._start_wall_time = datetime.now(timezone.utc).isoformat()
        self._last_tick_wall_time = datetime.now(timezone.utc).isoformat()

    def pause(self):
        self._is_running = False

    def resume(self):
        self._is_running = True
        self._last_tick_wall_time = datetime.now(timezone.utc).isoformat()

    def tick(self, step: Optional[float] = None) -> float:
        """Advances virtual clock by one step if running. Returns new virtual time."""
        if not self._is_running:
            return self.currentTime

        delta = step if step is not None else self._tick_step
        self._current_time += delta
        self._last_tick_wall_time = datetime.now(timezone.utc).isoformat()
        return self.currentTime

    def step(self, delta: float = 1.0) -> float:
        """Forces clock forward by delta seconds regardless of pause status (for step debugging)."""
        self._current_time += delta
        self._last_tick_wall_time = datetime.now(timezone.utc).isoformat()
        return self.currentTime

    def reset(self):
        self._current_time = 0.0
        self._is_running = False
        self._start_wall_time = None
        self._last_tick_wall_time = None