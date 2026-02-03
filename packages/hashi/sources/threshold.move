module hashi::threshold;

// TODO: Make threshold configurable.
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

public(package) fun certificate_threshold(total_weight: u16): u16 {
    (((total_weight as u64) * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR) as u16)
}
