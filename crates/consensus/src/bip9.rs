use crate::ConsensusError;

/// Versionbits deployment parameters for a BIP9 deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// Bit number signalled in the block version.
    pub bit: u8,
    /// Median-time-past at which signalling starts.
    pub start_time: u32,
    /// Median-time-past at which signalling times out.
    pub timeout: u32,
}

/// Checks that a block version signals an active BIP9 deployment when required.
pub fn check_bip9(
    version: i32,
    median_time_past: u32,
    deployment: Deployment,
) -> Result<(), ConsensusError> {
    if median_time_past < deployment.start_time || median_time_past >= deployment.timeout {
        return Ok(());
    }
    let bit = u32::from(deployment.bit);
    let Some(mask) = 1u32.checked_shl(bit) else {
        return Err(ConsensusError::Bip {
            bip: "BIP9",
            reason: format!("deployment bit {} is out of range", deployment.bit),
        });
    };
    let version = u32::from_ne_bytes(version.to_ne_bytes());
    if version & mask == 0 {
        return Err(ConsensusError::Bip {
            bip: "BIP9",
            reason: format!("version does not signal bit {}", deployment.bit),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Deployment, check_bip9};

    #[test]
    fn active_deployment_accepts_signalled_version() {
        let deployment = Deployment {
            bit: 1,
            start_time: 100,
            timeout: 200,
        };
        assert_eq!(check_bip9(2, 150, deployment), Ok(()));
    }

    #[test]
    fn active_deployment_rejects_missing_signal() {
        let deployment = Deployment {
            bit: 1,
            start_time: 100,
            timeout: 200,
        };
        assert!(check_bip9(0, 150, deployment).is_err());
    }
}
