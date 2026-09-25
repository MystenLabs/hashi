// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
// Frozen: fastcrypto e59b4a4 fastcrypto-tbls/src/knapsack_weight_reduction.rs, documented there,
// with a local error type; plus hashi c5fdcd8b2 build_reduced_nodes' pre-reduction arithmetic.
// Never edit.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReductionError {
    InvalidThreshold { threshold: u32, max_faulty: u32 },
    BelowLowerBound { total_weight: u16, lower_bound: u16 },
    InvalidInput,
    Violated(&'static str),
}

type ReducerResult<T> = Result<T, ReductionError>;

const MAX_PARTIES: usize = 1000;
const MAX_WEIGHT: u16 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReducedWeights {
    pub weights: Vec<u16>,
    pub t: u16,
    pub f: u16,
}

pub(crate) fn reduce_weights(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    total_weight_lower_bound: u16,
) -> ReducerResult<ReducedWeights> {
    if weights.is_empty() || weights.len() > MAX_PARTIES || weights.iter().any(|&w| w > MAX_WEIGHT)
    {
        return Err(ReductionError::InvalidInput);
    }
    let total_weight = weights.iter().map(|&w| w as u32).sum::<u32>();
    if total_weight == 0 || total_weight > u16::MAX as u32 {
        return Err(ReductionError::InvalidInput);
    }
    let w_total = total_weight as u16;
    if t == 0
        || f == 0
        || t > w_total
        || f >= t
        || (t as u32) + 2 * (f as u32) > total_weight
        || (t as u32) + (f as u32) + (delta as u32) > total_weight
    {
        return Err(ReductionError::InvalidInput);
    }
    if total_weight_lower_bound == 0 || total_weight_lower_bound > w_total {
        return Err(ReductionError::InvalidInput);
    }

    let rank = |c: &ReducedWeights| (c.weights.iter().map(|&w| w as u32).sum::<u32>(), c.t);

    let mut best = ReducedWeights {
        weights: weights.to_vec(),
        t,
        f,
    };
    for offset in (0..100).step_by(10) {
        let best_total = rank(&best).0;
        if let Some(candidate) = sweep(
            weights,
            w_total,
            t,
            f,
            delta,
            total_weight_lower_bound,
            offset,
            best_total,
        ) {
            if rank(&candidate) < rank(&best) {
                best = candidate;
            }
        }
    }
    Ok(best)
}

#[allow(clippy::too_many_arguments)]
fn sweep(
    weights: &[u16],
    w_total: u16,
    t: u16,
    f: u16,
    delta: u16,
    lower_bound: u16,
    offset: u64,
    best_total: u32,
) -> Option<ReducedWeights> {
    let max_weight = *weights.iter().max().expect("non-empty") as u64;

    let mut d_candidate = (10_000 * max_weight / (100 - offset)) as u32;

    while d_candidate > 100 {
        let reduced = weights
            .iter()
            .map(|&w| reduce_weight(w, d_candidate, offset))
            .collect::<Vec<_>>();
        let reduced_total = reduced.iter().map(|&w| w as u32).sum::<u32>();
        if reduced_total > best_total {
            return None;
        }
        if reduced_total >= lower_bound as u32
            && !greedy_reject(weights, &reduced, w_total, t, f, delta, reduced_total)
        {
            if let Ok((tp, fp)) = check_candidate(weights, w_total, t, f, delta, &reduced) {
                return Some(ReducedWeights {
                    weights: reduced,
                    t: tp,
                    f: fp,
                });
            }
        }

        let next = weights
            .iter()
            .zip(reduced.iter())
            .map(|(&w, &q)| (10_000 * (w as u64) / (100 * (q as u64 + 1) - offset)) as u32)
            .max()
            .expect("non-empty");
        d_candidate = next.min(d_candidate - 1);
    }
    None
}

fn reduce_weight(w: u16, d: u32, offset: u64) -> u16 {
    ((10_000 * (w as u64) + offset * (d as u64)) / (100 * (d as u64))) as u16
}

fn knapsack_min_original(weights: &[u16], reduced: &[u16], reduced_total: u32) -> Vec<u32> {
    let mut min_original_weight = vec![u32::MAX; reduced_total as usize + 1];
    min_original_weight[0] = 0;
    for (&w, &q) in weights.iter().zip(reduced.iter()) {
        let (w, q) = (w as u32, q as usize);
        if q == 0 {
            continue;
        }
        for v in (q..min_original_weight.len()).rev() {
            if min_original_weight[v - q] != u32::MAX {
                min_original_weight[v] = min_original_weight[v].min(min_original_weight[v - q] + w);
            }
        }
    }
    min_original_weight
}

fn max_reduced_weight(min_original_weight: &[u32], weight: u32) -> u32 {
    min_original_weight
        .iter()
        .rposition(|&x| x <= weight)
        .expect("min_original_weight[0] = 0 always qualifies") as u32
}

fn greedy_reject(
    weights: &[u16],
    reduced: &[u16],
    w_total: u16,
    t: u16,
    f: u16,
    delta: u16,
    reduced_total: u32,
) -> bool {
    let mut by_density = (0..weights.len())
        .filter(|&i| reduced[i] > 0)
        .collect::<Vec<_>>();
    by_density.sort_by(|&a, &b| {
        ((reduced[b] as u32) * (weights[a] as u32))
            .cmp(&((reduced[a] as u32) * (weights[b] as u32)))
    });

    let g_lower = |weight: u32| {
        let (mut remaining_weight, mut reduced_weight) = (weight, 0u32);
        for &i in &by_density {
            let w = weights[i] as u32;
            if w <= remaining_weight {
                remaining_weight -= w;
                reduced_weight += reduced[i] as u32;
            }
        }
        reduced_weight
    };

    if g_lower((t - 1) as u32) + g_lower(w_total as u32 - t as u32 - delta as u32) >= reduced_total
    {
        return true;
    }
    g_lower((t - 1) as u32)
        + g_lower(f as u32)
        + g_lower(w_total as u32 - t as u32 - f as u32 - delta as u32)
        >= reduced_total
}

fn check_candidate(
    weights: &[u16],
    w_total: u16,
    t: u16,
    f: u16,
    delta: u16,
    reduced: &[u16],
) -> ReducerResult<(u16, u16)> {
    let reduced_total = reduced.iter().map(|&w| w as u32).sum::<u32>();
    let min_original_weight_map = knapsack_min_original(weights, reduced, reduced_total);

    let tp = max_reduced_weight(&min_original_weight_map, (t - 1) as u32) + 1;

    let fp = max_reduced_weight(&min_original_weight_map, f as u32);
    if fp == 0 {
        return Err(ReductionError::Violated("f' == 0"));
    }

    let b1 = (w_total as u32) - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < tp {
        return Err(ReductionError::Violated("L3 violated"));
    }

    let b2 = (w_total as u32) - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2) < tp + fp {
        return Err(ReductionError::Violated("L1 violated"));
    }

    Ok((tp as u16, fp as u16))
}

pub(crate) fn verify_reduction(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    reduction: &ReducedWeights,
) -> ReducerResult<()> {
    let w_total = weights.iter().map(|&w| w as u32).sum::<u32>();
    let reduced_total = reduction.weights.iter().map(|&w| w as u32).sum::<u32>();
    if weights.len() != reduction.weights.len()
        || weights.len() > MAX_PARTIES
        || t == 0
        || f == 0
        || (t as u32) > w_total
        || w_total > u16::MAX as u32
        || reduced_total > u16::MAX as u32
        || reduction.t == 0
        || reduction.f == 0
    {
        return Err(ReductionError::InvalidInput);
    }
    if f >= t
        || reduction.f >= reduction.t
        || (t as u32) + 2 * (f as u32) > w_total
        || (t as u32) + (f as u32) + (delta as u32) > w_total
    {
        return Err(ReductionError::InvalidInput);
    }
    let min_original_weight_map = knapsack_min_original(weights, &reduction.weights, reduced_total);

    if max_reduced_weight(&min_original_weight_map, (t - 1) as u32) > (reduction.t - 1) as u32 {
        return Err(ReductionError::Violated("P violated"));
    }

    if max_reduced_weight(&min_original_weight_map, f as u32) > reduction.f as u32 {
        return Err(ReductionError::Violated("L2 violated"));
    }

    let b1 = w_total - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < reduction.t as u32 {
        return Err(ReductionError::Violated("L3 violated"));
    }

    let b2 = w_total - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2)
        < reduction.t as u32 + reduction.f as u32
    {
        return Err(ReductionError::Violated("L1 violated"));
    }
    Ok(())
}

const MAX_BASIS_POINTS: u32 = 10000;
const MIN_TOTAL_WEIGHT_AFTER_REDUCTION: u16 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reduction {
    pub weights: Vec<u16>,
    pub threshold: u16,
    pub max_faulty: u16,
    pub pre_reduction_threshold: u16,
    pub pre_reduction_max_faulty: u16,
    pub allowed_delta: u16,
    pub lower_bound: u16,
}

pub fn reduce(
    weights: &[u16],
    max_faulty_in_basis_points: u16,
    allowed_delta_in_basis_points: u16,
    is_production: bool,
) -> ReducerResult<Reduction> {
    let total_weight: u16 = weights.iter().sum();
    let max_faulty =
        (total_weight as u32 * max_faulty_in_basis_points as u32 / MAX_BASIS_POINTS).max(1);
    let threshold = (total_weight as u32).saturating_sub(2 * max_faulty);
    if threshold <= max_faulty {
        return Err(ReductionError::InvalidThreshold {
            threshold,
            max_faulty,
        });
    }
    let delta = (total_weight as u32 * allowed_delta_in_basis_points as u32 / MAX_BASIS_POINTS)
        .min(total_weight as u32) as u16;
    let (threshold, max_faulty) = (threshold as u16, max_faulty as u16);
    let lower_bound = if is_production {
        MIN_TOTAL_WEIGHT_AFTER_REDUCTION
    } else {
        MIN_TOTAL_WEIGHT_AFTER_REDUCTION.min(total_weight)
    };
    if total_weight < lower_bound {
        return Err(ReductionError::BelowLowerBound {
            total_weight,
            lower_bound,
        });
    }
    let reduction = reduce_weights(weights, threshold, max_faulty, delta, lower_bound)?;
    verify_reduction(weights, threshold, max_faulty, delta, &reduction)?;
    Ok(Reduction {
        weights: reduction.weights,
        threshold: reduction.t,
        max_faulty: reduction.f,
        pre_reduction_threshold: threshold,
        pre_reduction_max_faulty: max_faulty,
        allowed_delta: delta,
        lower_bound,
    })
}
