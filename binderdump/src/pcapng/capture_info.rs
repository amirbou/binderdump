use std::{fs::File, io::Read, time::Duration};

use android_system_properties::AndroidSystemProperties;
use anyhow::{Context, Result};
use nix;

#[derive(Debug)]
pub struct CaptureInfo {
    model: String,
    os: String,
    fingerprint: String,
    kernel_version: String,
    capture_app: &'static str,
    timeshift: Duration,
}

impl CaptureInfo {
    pub fn new() -> Result<Self> {
        let properties = AndroidSystemProperties::new();

        let model = properties
            .get("ro.product.model")
            .context("Failed to getprop model name")?;
        let version = properties
            .get("ro.build.version.release")
            .context("Failed to getprop Android version")?;

        let os = format!("Android {}", version);
        let fingerprint = properties
            .get("ro.build.fingerprint")
            .context("Failed to getprop device fingerprint")?;

        let mut kernel_version = String::new();
        File::open("/proc/version")
            .context("Failed to open /proc/version")?
            .read_to_string(&mut kernel_version)?;

        let capture_app = concat!("binderdump (version ", env!("CARGO_PKG_VERSION"), ")");

        let real_clock = nix::time::clock_gettime(nix::time::ClockId::CLOCK_REALTIME)
            .context("failed to get CLOCK_REALTIME")?;
        let boot_clock = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
            .context("failed to get CLOCK_BOOTTIME")?;

        let timeshift = real_clock - boot_clock;

        Ok(Self {
            model,
            os,
            fingerprint,
            kernel_version,
            capture_app,
            timeshift: timeshift.into(),
        })
    }

    pub fn get_model(&self) -> &str {
        &self.model
    }

    pub fn get_os(&self) -> &str {
        &self.os
    }

    pub fn get_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn get_kernel_version(&self) -> &str {
        &self.kernel_version
    }

    pub fn get_capture_app(&self) -> &'static str {
        self.capture_app
    }

    pub fn get_timeshift(&self) -> &Duration {
        &self.timeshift
    }
}