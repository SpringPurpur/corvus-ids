# classifier.py - inference entry point

# online_detector.process_flow() - MultiWindowOIF anomaly detection
# for both TCP and UDP

import logging
import pickle
import time
import uuid
from pathlib import Path
from typing import Any

import numpy as np

from online_detector import process_flow as _oif_process_flow, tcp_detector, udp_detector

log = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent / "models"

class Classifier:
    def predict(self, flow: dict) -> dict | None:
        """
            Run inference on a completed flow dict
            
            Returns a baselining status dict during the warmup period, a full
            alert dict once detection is active, or None for unsupported protocols
        """
        result = _oif_process_flow(flow)
        if result is None:
            return None
        
        # During baselining, return a lightweight status update for the dashboard
        if result["baselining"]:
            return {
                "type": "baselining",
                "protocol": result["protocol"],
                "progress": result["progress"]
            }
        
        t_scored_ns = time.time_ns() # OIF complete - post scoring stamp
        
        return {
            "flow_id": str(uuid.uuid4()),
            "ts": flow["first_pkt_ns"] / 1e9,
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "proto": result["protocol"],
            "duration": flow["flow_duration_s"],
            "fwd_pkts": flow["tot_fwd_pkts"],
            "verdict": {
                "label": result["verdict"],
                "severity": result["verdict"],
                "confidence": result["scores"]["composite"],
            },
            "scores": result["scores"],
            "attribution": result["attribution"],
            "features": result.get("features", {}),
            # Pipeline latency timestamps (ns, CLOCK_REALTIME)
            # t_enqueue_ns: when C ipc_writer_enqueue() copied flow to ring buffer
            # t_socket_ns: when Python ctypes-decoded the flow from the socket
            # t_dequeue_ns: when the protocol worker dequeued the flow
            # t_scored_ns: when OIF scoring completed
            
            # Derived latencies:
            # ipc_ms = (t_socket_ns - t_enqueue_ns) / 1e6 - true IPC wire + decode
            # queue_ms = (t_dequeue_ns - t_socket_ns) / 1e6 - Python asyncio queue wait
            # oif_ms = (t_scored_ns - t_dequeue_ns) / 1e6 - OIF scoring time
            "_timing": {
                "t_enqueue_ns": flow.get("t_enqueue_ns", 0),
                "t_socket_ns": flow.get("t_socket_ns", 0),
                "t_dequeue_ns": flow.get("_t_dequeue_ns", 0),
                "t_scored_ns": t_scored_ns
            }
        }