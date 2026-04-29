# online_detector.py - multi-window streaming anomaly detection for TCP and UDP

# Implements Online Isolation Forest (Leveni et al.) natively in Python
# The algorithm maintains adaptive histogram trees that grow and collapse as data
# arrives and departs the sliding window. No batch retraining and no Java dependency
# (like in CapyMOA package implementation)

# Three models per protocol at different window sizes (256/1024/4096) weighted
# 20%/30%/50%. Slower windows resist poisoning, a flood must outlast 4096 flows
# to materially shift the slow window's definition of normal (and even this is
# partially prevented by witholding flows)

# Explainability through path-depth attribution over OIF trees. Splits are data-adaptive
# (chosen from actual observed ranges), so the feature at each split node is the
# one that most effectively partitioned the data around this point. More meaningful
# than HalfSpaceTrees' random half-space cuts

# Tree implementation: flat numpy arrays instead of linked Python objects.
# Nodes are stored in parallel pre-allocated arrays indexed by an integer ID.
# The scoring hot path is a tight while loop over integer array indices. No
# dict lookups, no Python object attribute access, and no recursion overhead.
# This makes the per flow cost around 5 to 10 times lower than the linked node
# implementation and is structured for straightforward Cython compilation (all array
# accesses are bounded, types are statically known)

# Thread model: one dedicated thread per protocol (TCP, UDP). Each thread owns
# its detector exclusively. No locking required within MultiWindowOIF.

import logging
import math
import pickle
import random
from collections import deque
from pathlib import Path
from typing import NamedTuple

import numpy as np
from sklearn.preprocessing import RobustScaler

import config as _cfg_module

log = logging.getLogger(__name__)

# Cython hot-path import
# Compiled at container build time via: python setup_ext.py build_ext --inplace
# Falls back to pure-Python implementations in _ArrayTree if absent
try:
    from _array_tree import score_one_cy as _cy_score, attribute_path_cy as _cy_attr
    _CY = True
    log.info("Cython _array_tree extension loaded - using compiled hot paths")
except ImportError:
    _CY = False
    log.info("Cython _array_tree not found - using pure-Python hot paths")
    
# feature definition

# Selected on three principles from the network measurement literature
# 1. Temporal regularity
# 2. Traffic assymetry
# 3. Multi-dimensional anomaly signatures

# Ratios (syn_flag_ratio, fwd_act_data_ratio, down_up_ratio) are bounded [0,1]
# and duration independent, per RFC 7011 flow record conventions

TCP_OIF_FEATURES: list[tuple[str, callable]] = [
    ("fwd_pkts_per_sec", lambda r: r["fwd_pkts_per_sec"]),
    ("bwd_pkts_per_sec", lambda r: r["bwd_pkts_per_sec"]),
    ("pkt_len_mean", lambda r: r["pkt_len_mean"]),
    ("pkt_len_std", lambda r: r["pkt_len_std"]),
    ("flow_duration_s", lambda r: r["flow_duration_s"]),
    ("flow_iat_mean", lambda r: r["flow_iat_mean"] / 1_000_000.0), #ns -> s
    ("fwd_iat_std", lambda r: r["fwd_iat_std"]/ 1_000_000.0),
    ("init_fwd_win_bytes", lambda r: float(r["init_fwd_win_bytes"])),
    ("syn_flag_ratio", lambda r: r["syn_flag_ratio"]),
    ("fwd_act_data_ratio", lambda r: r["fwd_act_data_pkts"] / max(r["tot_fwd_pkts"], 1))
]

UDP_OIF_FEATURES: list[tuple[str, callable]] = [
    ("fwd_pkts_per_sec", lambda r: r["fwd_pkts_per_sec"]),
    ("bwd_pkts_per_sec", lambda r: r["bwd_pkts_per_sec"]),
    ("pkt_len_mean", lambda r: r["pkt_len_mean"]),
    ("pkt_len_std", lambda r: r["pkt_len_Std"]),
    ("flow_duration_s", lambda r: r["Flow_duration_s"]),
    ("flow_iat_mean", lambda r: r["flow_iat_mean"] / 1_000_000.0), #ns -> s
    ("flow_iat_std", lambda r: r["flow_iat_std"]/ 1_000_000.0),
    ("down_up_ratio", lambda r: r["tot_bwd_bytes"] / max(r["tot_fwd_bytes"], 1)),
    ("bwd_pkt_len_max", lambda r: float(r["bwd_pkt_len_max"]))
]

TCP_OIF_FEATURE_NAMES = [name for name, _ in TCP_OIF_FEATURES]
UDP_OIF_FEATURE_NAMES = [name for name, _ in UDP_OIF_FEATURES]

# IPs suppressed when cfg.filter_gateway=True (developer mode toggle)
# 172.20.0.1 is the Docker bridge gateway. All host side API calls,
# dashboard WebSocket connections, and eval script polls originate here
MANAGEMENT_IPS: frozenset[str] = frozenset({"172.20.0.1"})

def _extract(flow: dict, features: list[tuple[str, callable]]) -> np.ndarray:
    return np.array([fn(flow) for _, fn in features], dtype=np.float64)

# array based Online Isolation Tree

class _ArrayTree:
    """
    Online Isolation Tree with flat numpy array storage
    
    Nodes are stored in pre-allocated parallel int/float arrays
    Internal nodes have feat_idx[i] >= 0 (feature index for the split)
    Leaf nodes have feat_idx[i] == -1
    
    The scoring hot path is a tight while loop over array indices:
        while feat_idx[node] >= 0:
            node = left[node] if x[fi] < threshold[node] else right[node]
    
    This structure maps directly to a Cython 'cdef' or C struct array
    if future compilation is desired
    """
    
    _INITIAL_CAP = 256
    
    def __init__(
        self,
        n_features: int,
        max_leaf_samples: int,
        rng: random.Random
    ) -> None:
        self.n_features = n_features
        self.max_leaf_samples = max_leaf_samples
        self._rng = rng
        
        cap = self._INITIAL_CAP
        self._cap = cap
        self._root = -1 # -1 = empty tree
        self._n_alloc = 0 # next slot index
        self._free: list[int] = []
        
        # node arrays - all parallel, indexed by node ID
        self._feat_idx = np.full(cap, -1, dtype=np.int32) # split feature; -1 = leaf
        self._threshold = np.zeros(cap, dtype=np.float64) # split threshold
        self._left = np.zeros(cap, dtype=np.int32) # left child index
        self._right = np.zeros(cap, dtype=np.int32) # right child index
        self._h = np.zeros(cap, dtype=np.int32) #point count in node
        self._depth = np.zeros(cap, dtype=np.int32) # depth (root = 0)
        self._min_val = np.zeros((cap, n_features), dtype=np.float64)
        self._max_val = np.zeros((cap, n_features), dtype=np.float64)
        
    # allocation
        
    def _alloc(self) -> int:
        if self._free:
            return self._free.pop()
        idx = self._n_alloc
        if idx >= self._cap:
            self._expand()
        self._n_alloc += 1
        return idx
        
    def _expand(self) -> None:
        # double all arrays when capacity is exhausted
        old = self._cap
        self._cap = old * 2
        self._feat_idx = np.concatenate([self._feat_idx, np.full(old, -1, np.int32)])
        self._threshold = np.concatenate([self._threshold, np.zeros(old)])
        self._left = np.concatenate([self._left, np.zeros(old, np.int32)])
        self._right = np.concatenate([self._right, np.zeros(old, np.int32)])
        self._h = np.concatenate([self._h, np.zeros(old, np.int32)])
        self._depth = np.concatenate([self._depth, np.zeros(old, np.int32)])
        self._min_val = np.vstack([self._min_val, np.zeros((old, self.n_features))])
        self._max_val = np.vstack([self._max_val, np.zeros((old, self.n_features))])
            
    # split threshold
    def _split_threshold(self, depth: int) -> int:
        # Adaptive criterion from Leveni et al.
        return self.max_leaf_samples * (1 << depth)
        
    def _leaf_correction(self, h: int) -> float:
        if h <= self.max_leaf_samples:
            return 0.0
        return math.log2(h / self.max_leaf_samples)
        
    # split
        
    def _split(self, node: int) -> None:
        min_v = self._min_val[node]
        max_v = self._max_val[node]
        range_v = max_v - min_v
        cands = np.nonzero(range_v > 0)[0]
        if len(cands) == 0:
            return
            
        q = int(self._rng.choice(cands.tolist()))
        p = self._rng.uniform(float(min_v[q]), float(max_v[q]))
            
        frac_l = (p - float(min_v[q])) / float(range_v[q])
        h_tot = int(self._h[node])
        h_left = max(round(h_tot * frac_l), 1)
        h_right = max(h_tot - h_left, 1)
        d = int(self._depth[node])
            
        l = self._alloc()
        r = self._alloc()
            
        # Left child: box = [min, max] with max[q] = p
        self._feat_idx[l] = -1
        self._h[l] = h_left
        self._depth[l] = d + 1
        self._min_val[l] = min_v.copy()
        self._max_val[l] = max_v.copy()
        self._max_val[l, q] = p
            
        # Right child: box = [min, max] with min[q] = p
        self._feat_idx[r] = -1
        self._h[r] = h_right
        self._depth[r] = d + 1
        self._min_val[r] = min_v.copy()
        self._max_val[r] = max_v.copy()
        self._min_val[r, q] = p
            
        self._feat_idx[node] = q
        self._threshold[node] = p
        self._left[node] = l
        self._right[node] = r
        
    def learn_one(self, x: np.ndarray, max_depth: int) -> None:
        if self._root < 0:
            idx = self._alloc()
            self._root = idx
            self._feat_idx[idx] = -1
            self._h[idx] = 1
            self._depth[idx] = 0
            self._min_val[idx] = x
            self._max_val[idx] = x
            return
            
        node = self._root
        while self._feat_idx[node] >= 0: # internal
            self._h[node] += 1
            np.minimum(self._min_val[node], x, out=self._min_val[node])
            np.maximum(self._max_val[node], x, out=self._max_val[node])
            fi = int(self._feat_idx[node])
            node = int(self._left[node]) if x[fi] < self._threshold[node] \
                else int(self._right[node])
                    
        # leaf
        self._h[node] += 1
        np.minimum(self._min_val[node], x, out=self._min_val[node])
        np.maximum(self._max_val[node], x, out=self._max_val[node])
            
        depth = int(self._depth[node])
        if self._h[node] >= self._split_threshold(depth) and depth < max_depth:
            self._split(node)
                
    # unlearn
        
    def unlearn_one(self, x: np.ndarray) -> None:
        if self._root < 0:
            return
            
        # Phase 1: walk down, decrement h, check for collapse top-down
        # Collapsing at a node avoids going further. Same semantics as
        # the original recursive implementation
        node = self._root
        path : list[int] = [] # internal nodes visited before the leaf
            
        while self._feat_idx[node] >= 0: # internal
            self._h[node] -= 1
            depth = int(self._depth[node])
            if self._h[node] < self._split_threshold(depth):
                self._collapse(node)
                # Update ancestors above the collapsed node bottom-up
                for p in reversed(path):
                    if self._feat_idx[p] < 0:
                        break # p itself was collapsed
                    l = int(self._left[p])
                    r = int(self._right[p])
                    np.minimum(self._min_val[l], self._min_val[r], out=self._min_val[p])
                    np.maximum(self._max_val[l], self._max_val[r], out=self._max_val[p])
                if self._h[self._root] <= 0:
                    self._free_subtree(self._root)
                    self._root = -1
                return
            path.append(node)
            fi = int(self._feat_idx[node])
            node = int(self._left[node]) if x[fi] < self._threshold[node] \
                    else int(self._right[node])
                       
        # Phase 2: reached the leaf - decrement h and tighten box using tree constraints
        leaf = node
        self._h[leaf] -= 1
            
        # Tighten the leaf's bounding box using structural path constraints.
        # Each ancestor split (feature q, threshold thr) is a hard constraint on
        # the leaf's data range - samples are always routed deterministically, so
        # the left subtree can only contain values x[q] < thr (max[q] <= thr) and
        # the right subtree can only contain values x[q] > thr (min[q] >= thr).
        # Without storing the full sample set we cannot compute the exact new
        # min/max after an unlearn, but we can apply these structural bounds.
        # This prevents extreme unlearned samples from permanently widening the
        # leaf box and degrading future _split() threshold sampling
        for p in path:
            q = int(self._feat_idx[p])
            thr = float(self._threshold[p])
            if x[q] < thr:
                if self._max_val[leaf, q] > thr:
                        self._max_val[leaf, q] = thr
            else:
                if self._min_val[leaf, q] < thr:
                    self._min_val[leaf, q] = thr
            
        for p in reversed(path):
            l = int(self._left[p])
            r = int(self._right[p])
            np.minimum(self._min_val[l], self._max_val[r], out=self._min_val[p])
            np.maximum(self._min_val[l], self._max_val[r], out=self._max_val[p])
            
        if self._root >= 0 and self._h[self._root] <= 0:
            self._free_subtree(self._root)
            self._root = -1
                
    def _collapse(self, node: int) -> None:
        # Merge both child subtrees into this node, making it a leaf
        l = int(self._left[node])
        r = int(self._right[node])
        np.minimum(self._min_val[l], self._min_val[r], out=self._min_val[node])
        np.maximum(self._max_val[l], self._max_val[r], out=self._max_val[node])
        self._free_subtree(l)
        self._free_subtree(r)
        self._feat_idx[node] = -1
            
    def _free_subtree(self, node: int) -> None:
        # Return all nodes in the subtree to the free list (iterative)
        stack = [node]
        while stack:
            nd = stack.pop()
            if self._feat_idx[nd] >= 0:
                stack.append(int(self._left[nd]))
                stack.append(int(self._right[nd]))
                self._feat_idx[nd] = -1
            self._free.append(nd)
        
    # score
        
    def score_one(self, x: np.ndarray) -> float:
        # Path depth + leaf correction. Hot path, tight array index loop
        if self._root < 0:
            return 0.0
        if _CY:
            return _cy_score(
                self._feat_idx, self._threshold, self._left, self._right,
                self._h, self._root, x, self.max_leaf_samples
            )
        node = self._root
        depth = 0
        while self._feat_idx[node] >= 0:
            fi = int(self._feat_idx[node])
            node = int(self._left[node]) if x[fi] < self._threshold[node] \
                else int(self._right[node])
            depth += 1
        return depth + self._leaf_correction(int(self._h[node]))
        
    # attribution
        
    def attribute_path(
        self,
        x: np.ndarray,
        model_weight: float,
        feat_scores: np.ndarray # shape (n_features,) accumulated inplace
    ) -> None:
        # Depth weighted attribution: features at shallower depth get higher weight
        if self._root < 0:
            return
        if _CY:
            _cy_attr(
                self._feat_idx, self._threshold, self._left, self._right,
                self._root, x, model_weight, feat_scores,
            )
            return
        node = self._root
        depth = 0
        while self._feat_idx[node] >= 0:
            fi = int(self._feat_idx[node])
            feat_scores[fi] += model_weight / (depth + 1)
            node = int(self._left[node]) if x[fi] < self._threshold[node] \
                    else int(self._right[node])
            depth += 1
                
# Online Isolation Forest

class OnlineIsolationForest:
    # Ensemble of _ArrayTrees with a sliding window
    
    # All internal APIs take np.ndarray (not dict). The caller is responsible
    # for converting the flow feature vector to a numpy array before calling
    
    # Anomaly score = 2^(-E[depth] / c(omega, eta)) = log2(omega/eta)
    # Score between (0,1), higher is more anomalous
    
    def __init__(
        self,
        feature_names: list[str],
        n_trees: int = 32,
        window_size: int = 2048,
        max_leaf_samples: int = 32,
        subsample: float = 1.0,
        seed: int = 42
    ) -> None:
        self.feature_names = feature_names
        self.n_features = len(feature_names)
        self.window_size = window_size
        self.max_leaf_samples = max_leaf_samples
        self.subsample = subsample
        self.max_depth = max(1, int(math.log2(window_size / max_leaf_samples)))
        self._norm = float(self.max_depth)
        self._rng = random.Random(seed)
        self._trees = [
            _ArrayTree(self.n_features, max_leaf_samples, random.Random(seed + i))
            for i in range(n_trees)
        ]
        self._window: deque[np.ndarray] = deque()
        
    def learn_one(self, x: np.ndarray) -> None:
        if len(self._window) >= self.window_size:
            old = self._window.popleft()
            for tree in self._trees:
                tree.unlearn_one(old)
        self._window.append(x)
        for tree in self._trees:
            if self.subsample < 1.0 and self._rng.random() >= self.subsample:
                continue
            tree.learn_one(x, self.max_depth)
    
    def score_one(self, x: np.ndarray) -> float:
        if not self._window:
            return 0.5
        depths = [t.score_one(x) for t in self._trees]
        mean_depth = sum(depths) / len(depths)
        return 2.0 ** (-mean_depth / (self._norm + 1e-10))
    
    def attribute(
        self,
        x: np.ndarray,
        model_weight: float,
        feat_scores: np.ndarray
    ) -> None:
        # Accumulate depth weighted attribution across all trees
        for tree in self._trees:
            tree.attribute_path(x, model_weight, feat_scores)
            
# Multi-window result types

class WindowScores(NamedTuple):
    fast: float
    medium: float
    slow: float
    composite: float
    
# Multi-window OIF detector

class MultiWindowOIF:
    """
        Three OnlineIsolationForest models at window sizes 256/1024/4096
        
        Weighted composite score (20%/30%/50%) gives the slow model majority
        influence, resisting poisoning by sustained floods. All three models
        share the same feature set and are kept in sync (learn_one selective
        training applied identically)
        
        Thread safety: each MultiWindowOIF instance must be accessed from
        exactly one thread. The caller ensures this via the protocol-split
        worker layout: tcp_detector owned by tcp_worker, udp_detector by
        udp_worker
    """
    
    _WINDOWS = (256, 1024, 4096)
    _WEIGHTS = (0.2, 0.3, 0.5)
    
    # Tree storage format version. Bump when the internal tree structure
    # changes so that stale pickles are rejected and a fresh baseline is
    # started. v1 = linked _OIFNode objects, v2 = flat _ArrayTree arrays
    # (current)
    _TREE_VERSION = 2
    
    # Flows scoring at or above this threshold are witheld from trainings
    # prevents attack traffic from shifting the model's definition of normal
    TRAIN_THRESHOLD = 0.8
    
    # OOR augmentation: oor_score = 1 - exp(-deviation/OOR_SCALE), where
    # deviation = max(x_scaled[i]) (L infinity norm in RobustScaler space,
    # unit = IQR)
    OOR_SCALE = 25.0
    
    # After a rejection, withold the next COOLDOWN_FLOWS from training
    COOLDOWN_FLOWS = 25
    
    # Save to disk every N trained flows
    _SAVE_INTERVAL = 200
    
    def __init__(
        self,
        feature_names: list[str],
        protocol: str,
        baseline_flows: int | None = None,
        save_path: str | Path | None = None
    ) -> None:
        self.feature_names = feature_names
        self.protocol = protocol
        self._save_path = Path(save_path) if save_path else None
        
        self._models: list[OnlineIsolationForest] = [
            OnlineIsolationForest(
                feature_names = feature_names,
                n_trees = 32,
                window_size = w,
                max_leaf_samples = 8,
                seed = 42 + i
            )
            for i, w in enumerate(self._WINDOWS)
        ]
        
        self._scaler = RobustScaler()
        self._scaler_fitted = False
        
        self._baseline_buffer: list[np.ndarray] = []
        self._baseline_complete = False
        self.BASELINE_FLOWS = baseline_flows if baseline_flows is not None \
                              else self._WINDOWS[2]
                              
        self._n_trained = 0
        self._n_seen = 0
        self._n_rejected = 0
        self._n_frozen = 0
        self._cooldown = 0
        self._score_buf: deque[float] = deque(maxlen=500)
    
    # baselining
    
    @property
    def is_ready(self) -> bool:
        return self._baseline_complete
    
    @property
    def baseline_progress(self) -> float:
        if self._baseline_complete:
            return 1.0
        return min(len(self._baseline_buffer) / self.BASELINE_FLOWS, 1.0)
    
    def _complete_baseline(self) -> None:
        X = np.array(self._baseline_buffer)
        self._scaler.fit(X)
        self._scaler_fitted = True
        
        # IQR floor estimates prevents zero IQR collapse
        _FLOORS: dict[str, float] = {
            "fwd_pkts_per_sec": 5.0,
            "bwd_pkts_per_sec": 5.0,
            "pkt_len_mean": 100.0,
            "pkt_len_std": 100.0,
            "flow_duration_s": 5.0,
            "flow_iat_mean": 10.0,
            "fwd_iat_std": 5.0,
            "init_fwd_win_bytes": 8192.0, # TCP window varies by OS/kernel
            "syn_flag_ratio": 0.02,
            "fwd_act_data_ratio": 0.02,
            "down_up_ratio": 0.02,
            "bwd_pkt_len_max": 50.0
        }
        for i, name in enumerate(self.feature_names):
            floor = _FLOORS.get(name, 1.0)
            if self._scaler.scale_[i] < floor:
                log.info("[%s OIF] scale floor applied: %s %.4g -> %.4g",
                         self.protocol, name, self._scaler.scale_[i], floor)
                self._scaler.scale_[i] = floor
        
        # Seed each model on the tail of the baseline corpus
        X_scaled = self._scaler.transform(X)
        for model, window_size in zip(self._models, self._WINDOWS):
            tail = X_scaled[-window_size:]
            for row in tail:
                model.learn_one(row)
                
        self._baseline_complete = True
        self._baseline_buffer.clear()
        log.info("[%s OIF] Baseline complete on %d flows - detection active",
                 self.protocol, self.BASELINE_FLOWS)
        self.save()
        
        # persistence
        
    def save(self) -> None:
        if self._save_path is None:
            return
        try:
            self._save_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._save_path.with_suffix(".pkl.tmp")
            with open(tmp, "wb") as f:
                pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)
            tmp.replace(self._save_path)
            log.debug("[%s OIF] Saved to %s (%d trained)",
                      self.protocol, self._save_path, self._n_trained)
        except Exception:
            log.warning("[%s OIF] Failed to save model", self.protocol, exc_info=True)
    
    def __setstate__(self, state: dict) -> None:
        # Restore from pickle. Fills in defaults for attributes added later
        self.__dict__.update(state)
        if "_n_frozen" not in state: self._n_frozen = 0
        if "_cooldown" not in state: self._cooldown = 0
    
    @classmethod
    def load(cls, path: str | Path) -> "MultiWindowOIF":
        with open(path, "rb") as f:
            obj = pickle.load(f)
        if not isinstance(obj, cls):
            raise TypeError(f"Expected MultiWindowOIF, got {type(obj)}")
        return obj
    
    def _compatible_with(self, feature_names: list[str]) -> bool:
        # Check feature set and tree format version before trusting a loaded pkl
        version_ok = getattr(self, "_TREE_VERSION", 1) == MultiWindowOIF._TREE_VERSION
        return self.feature_names == feature_names and version_ok
    
    # inference
    @property
    def _cooldown_active(self) -> bool:
        return self._cooldown > 0
    
    def process(self, raw: np.ndarray) -> tuple[WindowScores, list[dict], float] | None:
        # Score a flow, returns None during baselining
        
        # After baselining: returns (WindowScores, top 3 attribution list, oor_score)
        # Flows scoring below TRAIN_THRESHOLD are trained on. High score flows are
        # witheld to prevent poisonong
        
        if not self._baseline_complete:
            self._baseline_buffer.append(raw)
            if len(self._baseline_buffer) >= self.BASELINE_FLOWS:
                self._complete_baseline()
            return None
        
        x_scaled = self._scaler.transform(raw.reshape(1, -1))[0]
        max_deviation = float(np.max(np.abs(x_scaled)))
        oor_score = 1.0 - math.exp(-max_deviation / self.OOR_SCALE)
        
        if oor_score >= 0.55 or log.isEnabledFor(logging.DEBUG):
            worst_i = int(np.argmax(np.abs(x_scaled)))
            worst_dev = float(np.abs(x_scaled[worst_i]))
            log.debug("[%s OIF] oor=%.3f worst=%s dev=%.1f IQR",
                      self.protocol, oor_score,
                      self.feature_names[worst_i], worst_dev)
            
        if oor_score >= self.TRAIN_THRESHOLD:
            # fast path: extreme outlier skips 96 tree traversals entirely
            # Points this far outside the training bounding box are marked CRITICAL
            # regardless of the OIF path length. Attribution names the worst feature
            composite = oor_score
            worst_feat = self.feature_names[int(np.argmax(np.abs(x_scaled)))]
            window_scores = WindowScores(fast=oor_score, medium=oor_score,
                                         slow=oor_score, composite=oor_score)
            attribution = [{
                "feature": worst_feat,
                "score": 1.0,
                "value": float(raw[self.feature_names.index(worst_feat)]),
                "baseline": self.baseline_stats().get(worst_feat, {})
            }]
        else:
            # Normal path: full OIF scoring + path depth attribution
            scores = tuple(m.score_one(x_scaled) for m in self._models)
            composite = max(sum(w * s for w, s in zip(self._WEIGHTS, scores)), oor_score)
            window_scores = WindowScores(
                fast=scores[0], medium=scores[1], slow=scores[2],
                composite=composite
            )
            attribution = self._attribute(x_scaled, raw)
        
        self._n_seen += 1
        self._score_buf.append(composite)
        
        if composite >= self.TRAIN_THRESHOLD:
            self._n_rejected += 1
            self._cooldown = self.COOLDOWN_FLOWS
        elif self._cooldown_active:
            self._cooldown -= 1
            self._n_frozen += 1
        else:
            # x_scaled defined, only reachable via the normal path
            for model in self._models:
                model.learn_one(x_scaled)
            self._n_trained += 1
            if self._n_trained % self._SAVE_INTERVAL == 0:
                self.save()
                
        return window_scores, attribution, oor_score
    
    # false positive feedback
    
    def reinforce_normal(self, raw: np.ndarray) -> None:
        """
            Force-learn a flow as normal, bypassing the anomaly score threshold.
            
            Called when an analyst marks a flow as a false positive. Passes the
            feature vector directly to learn_one() on all window models so the trees
            shift to treat similar flows as less anomalous.
        """
        if not self._baseline_complete or not self._scaler_fitted:
            log.warning("[%s OIF] reinforce_normal called before baseline, ignoring",
                        self.protocol)
            return
        x_scaled = self._scaler.transform(raw.reshape(1, -1))[0]
        for model in self._models:
            model.learn_one(x_scaled)
        self._n_trained += 1
        log.info("[%s OIF] FP reinforced as normal (scaled_max=%.2f, n_trained=%d)",
                 self.protocol, float(np.max(np.abs(x_scaled))), self._n_trained)
        if self._n_trained % self._SAVE_INTERVAL == 0:
            self.save()
            
    # path depth attribution
    
    def _attribute(
        self,
        x_scaled: np.ndarray,
        x_raw: np.ndarray
    ) -> list[dict]:
        """
            Depth weighted attribution over all trees and all window models
            
            feat_scores is a numpy array accumulated inplace across all trees.
        """
        feat_scores = np.zeros(len(self.feature_names), dtype=np.float64)
        for model, weight in zip(self._models, self._WEIGHTS):
            model.attribute(x_scaled, weight, feat_scores)
        total = float(feat_scores.sum()) or 1.0
        top3_idx = np.argsort(feat_scores)[::-1][:3]
        stats = self.baseline_stats()
        return [{
            "feature": self.feature_names[i],
            "score": float(feat_scores[i] / total),
            "value": float(x_raw[i]),
            "baseline": stats.get(self.feature_names[i], {})
        } for i in top3_idx]
        
    # health metrics
    
    def metrics(self) -> dict:
        buf = list(self._score_buf)
        arr = np.array(buf) if buf else np.array([0, 0])
        return {
            "n_seen": self._n_seen,
            "n_trained": self._n_trained,
            "n_rejected": self._n_rejected,
            "n_frozen": self._n_frozen,
            "rejection_rate": self._n_rejected / max(self._n_seen, 1),
            "cooldown_remaining": self._cooldown,
            "score_p50": float(np.percentile(arr, 50)),
            "score_p95": float(np.percentile(arr, 95)),
            "score_recent": buf[-20:],
            "n_baseline": len(self._baseline_buffer),
            "n_baseline_target": self.BASELINE_FLOWS
        }
        
    # baseline statistics for dashboard context
    
    def baseline_stats(self) -> dict[str, dict[str, float]]:
        # Median and IQR per feature from the fitted RobustScaler
        if not self._scaler_fitted:
            return {}
        return {
            name: {
                "median": float(self._scaler.center_[i]),
                "iqr": float(self._scaler.scale_[i])
            }
            for i, name in enumerate(self.feature_names)
        }
    
# Module level detector instances

# One per protocol. On startup, try to load a previously saved model. Fall back
# to a fresh instance if absent, corrupt, wrong featue set, or wrong version.
# Each detector is accessed from exactly one dedicated worker thread

_MODEL_DIR = Path("/app/models")

def _load_or_create(
    feature_names: list[str],
    protocol: str,
    filename: str,
    baseline_flows: int | None = None
) -> "MultiWindowOIF":
    path = _MODEL_DIR / filename
    if path.exists():
        try:
            detector = MultiWindowOIF.load(path)
            if detector._compatible_with(feature_names):
                detector._save_path = path
                log.info("[%s OIF] Loaded saved model from %s (%d trained, baseline=%s)",
                         protocol, path, detector._n_trained,
                         "complete" if detector.is_ready else "incomplete")
                return detector
            log.warning("[%s OIF] Incompativle saved model (feature set or variable mismatch)"
                        " - starting fresh", protocol)
        except Exception:
            log.warning("[%s OIF] Could not load %s, starting fresh",
                        protocol, path, exc_info=True)
    
    return MultiWindowOIF(feature_names=feature_names, protocol=protocol,
                          baseline_flows=baseline_flows, save_path=path)
    
tcp_detector = _load_or_create(TCP_OIF_FEATURE_NAMES, "TCP", "tcp_oif.pkl")
udp_detector = _load_or_create(UDP_OIF_FEATURE_NAMES, "UDP", "udp_oif.pkl",
                               baseline_flows=_cfg_module.cfg.baseline_udp)

def reset_detector(protocol: str) -> None:
    # Discard a trained detector and start fresh
    global tcp_detector, udp_detector
    cfg = _cfg_module.cfg
    
    if protocol in ("TCP", "all"):
        pkl = _MODEL_DIR / "tcp_oif.pkl"
        if pkl.exists():
            pkl.unlink()
        tcp_detector = MultiWindowOIF(
            TCP_OIF_FEATURE_NAMES, protocol="TCP",
            baseline_flows=cfg.baseline_tcp, save_path=pkl
        )
        log.info("[TCP OIF] Baseline reset - rebaselining on %d flows", cfg.baseline_tcp)
    
    if protocol in ("UDP", "all"):
        pkl = _MODEL_DIR / "udp_oif.pkl"
        if pkl.exists():
            pkl.unlink()
        udp_detector = MultiWindowOIF(
            UDP_OIF_FEATURE_NAMES, protocol="UDP",
            baseline_flows=cfg.baseline_udp, save_path=pkl
        )
        log.info("[UDP OIF] Baseline reset - rebaselining on %d flows", cfg.baseline_udp)
        
def process_flow(flow: dict) -> dict | None:
    # Entry point: extract features, run MultiWindowOIF, return result dict
    
    # Returns a baselining status dict during warmup, a full result dict
    # during detection, or None for unsupported protocols or bad flows
    
    cfg = _cfg_module.cfg
    proto = flow["protocol"]
    
    if proto == 6:
        detector = tcp_detector
        features = TCP_OIF_FEATURES
    elif proto == 17:
        detector = udp_detector
        features = UDP_OIF_FEATURES
    else:
        log.debug("Unsupported protocol %d - skipping", proto)
        return None
    
    if cfg.filter_gateway:
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        if src in MANAGEMENT_IPS or dst in MANAGEMENT_IPS:
            return None
    
    if proto == 6 and flow.get("tot_pkts", 0) < cfg.min_tcp_pkts:
        return None
    if proto == 17 and flow.get("flow_duration_s", 0.0) < 1e-4:
        return None
    
    raw = _extract(flow, features)
    result = detector.process(raw)
    
    proto_str = "TCP" if proto == 6 else "UDP"
    
    if result is None:
        return {
            "baselining": True,
            "progress": detector.baseline_progress,
            "protocol": proto_str
        }
    
    scores, attribution, oor_score = result
    
    if scores.composite >= cfg.threshold_critical:
        severity = "CRITICAL"
    elif scores.composite >= cfg.threshold_high:
        severity = "HIGH"
    else:
        severity = "INFO"
        
    # all feature values keyed by name, included in alert dict for LLM context
    # can receive the full feature vector as optional context
    
    feature_values = {name: float(fn(flow)) for name, fn in features}
    
    return {
        "baselining": False,
        "protocol": proto_str,
        "scores": {
            "fast": scores.fast,
            "medium": scores.medium,
            "slow": scores.slow,
            "composite": scores.composite,
            "oor": oor_score
        },
        "verdict": severity,
        "attribution": attribution,
        "features": feature_values
    }

# TODO - feedback reinforce