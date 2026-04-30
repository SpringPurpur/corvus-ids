# cython: boundscheck=False, wraparound=False, cdivision=True, language_level=3
"""
    _array_tree.pyx - compiled hot paths for _ArrayTree

    Two functions exported:
    score_one_cy - path depth traversal for anomaly scoring
    attribute_path_cy - depth weighted feature attribution

    Both replace the equivalent while loops in _ArrayTree.score_one /
    _ArrayTree.attribute_path in online_detector.py

    The Python class structure and pickling stay in online_detector.py
    These are pure C-level helpers - no Python objects are allocated in
    the hot paths. Both functions release the GIL during the traversal
    loop, allowing the TCP and UDP workers to run their tree traversals
    concurrently at the C layer.

    The original Python loops call int() on each numpy scalar index
    (around 400-500 ns per conversion, ~1250 ns total per node). Typed
    Cython memoryviews replace all Python object creation with direct C
    pointer arithmetic.
"""

import numpy as np
cimport numpy as cnp
from libc.math cimport log2

cnp.import_array()

def score_one_cy(
    cnp.int32_t[::1] feat_idx,
    cnp.float64_t[::1] threshold,
    cnp.int32_t[::1] left_ch,
    cnp.int32_t[::1] right_ch,
    cnp.int32_t[::1] h,
    int root,
    cnp.float64_t[:] x,
    int max_leaf_samples
) -> double:
    """
        Traverse one isolation tree and return path depth + leaf correction

        Parameter mirror _ArrayTree's node arrays plus the root index and
        the input vector X (RobustScaler transformed, shape (n_features,))

        X is declared as non-contiguous (double[:], not double[::1]) because
        sklearn's transform()[0] may return a non-contiguous row view
    """
    cdef int node = root
    cdef int fi
    cdef int depth = 0
    cdef int leaf_h

    if root < 0:
        return <double>0.0
    
    with nogil:
        while feat_idx[node] >= 0:
            fi = feat_idx[node]
            if x[fi] < threshold[node]:
                node = left_ch[node]
            else:
                node = right_ch[node]
            depth += 1
        leaf_h = h[node]
    
    if leaf_h <= max_leaf_samples:
        return <double>depth
    return <double>depth + log2(<double>leaf_h / <double>max_leaf_samples)

def attribute_path_cy(
    cnp.int32_t[::1] feat_idx,
    cnp.float64_t[::1] threshold,
    cnp.int32_t[::1] left_ch,
    cnp.int32_t right_ch,
    int root,
    cnp.float64_t[:] x,
    double model_weight,
    cnp.float64_t[::1] feat_scores
) -> None:
    """
        Accumulate depth-weighted attribution into feat_scores (inplace)

        feat_scores must be a C-contiguous float64 array of shape (n_features,)
        Caller zeros it before iterating over trees
    """
    cdef int node = root
    cdef int fi
    cdef int depth = 0

    if root < 0:
        return
    
    with nogil:
        while feat_idx[node] >= 0:
            fi = feat_idx[node]
            feat_scores[fi] += model_weight / (depth + 1)
            if x[fi] < threshold[node]:
                node = left_ch[node]
            else:
                node = right_ch[node]
            depth += 1