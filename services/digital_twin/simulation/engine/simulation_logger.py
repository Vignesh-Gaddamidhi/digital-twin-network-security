import json
from pathlib import Path
from typing import List, Optional
from packages.shared_types.src.reproducible_simulation import ReproducibleSimulationEvent

class SimulationLogger:
    """Manages append-only JSONL persistence for reproducible simulation event streams."""

    def __init__(self, log_path: Optional[str] = None):
        if log_path:
            self.file_path = Path(log_path)
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
            self.file_path = base_dir / "data" / "simulation" / "simulation-events.jsonl"

        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def appendEvent(self, event: ReproducibleSimulationEvent):
        line = json.dumps(event.model_dump()) + "\n"
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(line)

    def readEvents(self, run_id: Optional[str] = None) -> List[ReproducibleSimulationEvent]:
        if not self.file_path.exists():
            return []

        events = []
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                data = json.loads(stripped)
                if run_id is None or data.get("runId") == run_id:
                    events.append(ReproducibleSimulationEvent(**data))
        return events

    def clear(self):
        if self.file_path.exists():
            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write("")

simulation_logger = SimulationLogger()