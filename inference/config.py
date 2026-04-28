# config.py - runtime configuration with persistence

# Settings are loaded from /app/config.json on startup. If the file is absent
# (first run) defaults are used. The analyst can update settings via the dashboard
# settings panel. Changes are written atomically and take effect immediately
# without a restart

# Only analyst-facing parameters live here. Internal OIF parameters
# (n_trees, window sizes, max_leaf_samples) are not exposed. They are
# algorithm design choices (not yet operable, the algorithm is somewhat
# stable with the current configuration).

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_CONFIG_PATH = Path("/app/config.json")

@dataclass
class AppConfig:
    # Alert severity thresholds - OIF composite score (0-1)
    # Raise to reduce false positives, lower to catch more marginal anomalies
    threshold_high: float = 0.6
    threshold_critical: float = 0.8
    
    # FLows required before detection activates per protocol
    # TCP can tolerate the larger value because HTTP/SSH traffic is
    # continuous. UDP is sparse so the medium window (1024) is the practical limit
    baseline_tcp: int = 4096
    baseline_udp: int = 1024
    
    # Minimum TCP packet count before a flow is passed to the OIF
    # Default 4 prevents micro flows (port scans, SYN floods) from
    # reaching the detector and poisoning the baseline (issue encountered
    # while testing). Lower to 2-3 in developer mode to observe how the
    # OIF scores these flows. Value of 1 floods the inference queue during
    # port scans
    min_tcp_pkts: int = 4
    
    # When True, flows where either endpoint is the Docker bridge gateway
    # (172.20.0.1 testbed network) are silently dropped before OIF scoring and
    # storage. Useful during eval runs to suppress host management
    # traffic (API polls, dashboard WebSocket) that is structurally out-of-distribution
    # but benign
    filter_gateway: bool = False
    
def _load(path: Path) -> AppConfig:
    if not path.exists():
        return AppConfig()
    try:
        data = json.loads(path.read_text())
        fields = AppConfig.__dataclass_fields__
        return AppConfig(**{k: v for k, v in data.items() if k in fields})
    except Exception:
        log.warning("Could not load config from %s - using defaults", path, exc_info=True)
        return AppConfig()
    
def save(cfg: "AppConfig", path: Path = _CONFIG_PATH) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(cfg), indent=2))
        tmp.replace(path)
        log.debug("Config saved to %s", path)
    except Exception:
        log.warning("Could not save config to %s", path, exc_info=True)
        
# Module level singleton - imported by other modules
cfg: AppConfig = _load(_CONFIG_PATH)

def update(new_cfg: AppConfig) -> None:
    # Replace the runtime config and persist to disk
    global cfg
    cfg = new_cfg
    save(cfg)