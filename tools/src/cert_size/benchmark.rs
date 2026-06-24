// Licensed under the Apache-2.0 license

use std::fmt::{self, Display};

use anyhow::{anyhow, Result};
use caliptra_dpe::MAX_HANDLES;

use super::{measure_cert_csr, Algorithm};

/// Linear Approximation/Linearization derived from a single measurement series (cert or CSR).
///
/// Models certificate size as `base + per_handle * n` where `n` is the
/// number of TCI nodes (handles). `per_handle` is the delta between the
/// first two sample points (the maximum observed rate, since DER length
/// encoding causes slightly higher growth at small `n`).
struct LinearApprox {
    per_handle: usize,
    base: usize,
    /// Whether `base + per_handle * n >= actual` for every sample point.
    covers_all: bool,
    /// Worst-case under-estimation in bytes (0 when `covers_all` is true).
    worst_deficit: usize,
    /// `(n, predicted, actual)` at the last sample point.
    last_check: (usize, usize, usize),
}

impl LinearApprox {
    /// Derive a linear upper-bound approximation from measured `(n, size)` pairs.
    fn from_sizes(sizes: &[(usize, usize)]) -> Option<Self> {
        if sizes.len() < 2 {
            return None;
        }
        let (x1, y1) = sizes[0];
        let (x2, y2) = sizes[1];

        // violates monotonic, linear growth which we assume is the case for
        // increasing ASN.1 certificates.
        if x2 <= x1 || y2 <= y1 {
            return None;
        }

        let per_handle = (y2 - y1) / (x2 - x1);
        let base = y1.saturating_sub(per_handle * x1);

        let worst_deficit = sizes
            .iter()
            .filter_map(|&(n, s)| {
                let predicted = base + per_handle * n;
                (predicted < s).then(|| s - predicted)
            })
            .max()
            .unwrap_or(0);

        let &(x_n, y_n) = sizes.last().unwrap();
        let predicted_last = base + per_handle * x_n;

        Some(Self {
            per_handle,
            base,
            covers_all: worst_deficit == 0,
            worst_deficit,
            last_check: (x_n, predicted_last, y_n),
        })
    }
}

impl Display for LinearApprox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "per_handle={:<5} base={:<7}", self.per_handle, self.base)?;
        let (n, predicted, actual) = self.last_check;
        if self.covers_all {
            let overshoot = if actual > 0 {
                ((predicted as f64 - actual as f64) / actual as f64) * 100.0
            } else {
                0.0
            };
            write!(
                f,
                "  n={n}: predicted={predicted} actual={actual} (+{overshoot:.1}%)"
            )
        } else {
            write!(
                f,
                "  WARNING: under-estimates by up to {} bytes!",
                self.worst_deficit
            )
        }
    }
}

struct BenchmarkResults {
    algo_name: &'static str,
    max_handles: usize,
    handle_counts: Vec<usize>,
    cert_sizes: Vec<(usize, usize)>,
    csr_sizes: Vec<(usize, usize)>,
}

impl BenchmarkResults {
    fn approx(&self) -> Option<(usize, usize)> {
        let cert_approx = LinearApprox::from_sizes(&self.cert_sizes)?;
        let csr_approx = LinearApprox::from_sizes(&self.csr_sizes)?;

        let per_handle = cert_approx.per_handle.max(csr_approx.per_handle);
        let (x1, y1) = self.csr_sizes[0];
        let base = y1.saturating_sub(per_handle * x1);
        Some((base, per_handle))
    }

    /// Check that `(base, per_handle)` covers every sample in both series to ensure
    /// there will be enough space for the Cert/CSR.
    fn verify(&self, base: usize, per_handle: usize) -> bool {
        self.cert_sizes
            .iter()
            .chain(self.csr_sizes.iter())
            .all(|&(n, s)| base + per_handle * n >= s)
    }
}

impl Display for BenchmarkResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Benchmark: {} (MAX_HANDLES={})\n",
            self.algo_name, self.max_handles
        )?;

        write!(f, "{:>6}", "n")?;
        for n in &self.handle_counts {
            write!(f, "{n:>8}")?;
        }
        writeln!(f)?;
        write!(f, "{:->6}", "")?;
        for _ in &self.handle_counts {
            write!(f, "{:->8}", "")?;
        }
        writeln!(f)?;

        for (label, sizes) in [("cert", &self.cert_sizes), ("csr", &self.csr_sizes)] {
            write!(f, "{label:>6}")?;
            for (_, size) in sizes {
                write!(f, "{size:>8}")?;
            }
            writeln!(f)?;
        }

        for (label, sizes) in [("cert", &self.cert_sizes), ("csr", &self.csr_sizes)] {
            if let Some(approx) = LinearApprox::from_sizes(sizes) {
                writeln!(f, "  {label:>4}:  {approx}")?;
            }
        }

        if let Some((base, per_handle)) = self.approx() {
            let verified = self.verify(base, per_handle);
            writeln!(
                f,
                "\nUse base={base}, per_handle={per_handle} for dpe/build.rs constants"
            )?;
            if verified {
                write!(f, "Verified as upper bound at all sample points.")?;
            } else {
                write!(f, "ERR: Approximation failed for some sample points")?;
            }
        }

        Ok(())
    }
}

pub(crate) fn run(algorithm: Algorithm) -> Result<()> {
    let handle_counts: Vec<usize> = [1, 2, 4, 8, 16, 24, 32, 48, 64]
        .into_iter()
        .filter(|&n| n <= MAX_HANDLES)
        .collect();

    if handle_counts.len() < 2 {
        return Err(anyhow!(
            "MAX_HANDLES={MAX_HANDLES} is too small for benchmark (need at least 2)"
        ));
    }

    let algo_name: &'static str = match algorithm {
        #[cfg(feature = "p256")]
        Algorithm::Ec => "P256",
        #[cfg(feature = "p384")]
        Algorithm::Ec => "P384",
        #[cfg(feature = "ml-dsa")]
        Algorithm::Mldsa => "ML-DSA-87",
        #[allow(unreachable_patterns)]
        _ => "unknown",
    };

    let mut cert_sizes = Vec::new();
    let mut csr_sizes = Vec::new();

    for &n in &handle_counts {
        for (is_cert, sizes) in [(true, &mut cert_sizes), (false, &mut csr_sizes)] {
            let sz = measure_cert_csr(algorithm, n, is_cert)?;
            sizes.push((n, sz.size()));
        }
    }

    let results = BenchmarkResults {
        algo_name,
        max_handles: MAX_HANDLES,
        handle_counts,
        cert_sizes,
        csr_sizes,
    };

    println!("{results}");
    Ok(())
}
