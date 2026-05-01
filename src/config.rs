use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub sampling: SamplingConfig,
    pub thresholds: ThresholdConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    pub cpu_sample_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub high_cpu_percent: f32,
    pub very_high_cpu_percent: f32,
    pub high_mem_percent: f32,
    pub very_high_mem_percent: f32,
    pub low_cpu_percent: f32,
    pub low_mem_percent: f32,
    pub busy_fd_count: u32,
    pub busy_thread_count: u32,
    pub idle_min_elapsed_seconds: u64,
    pub supervisor_children_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub default_limit: usize,
    pub graph_default_depth: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            sampling: SamplingConfig { cpu_sample_ms: 700 },
            thresholds: ThresholdConfig {
                high_cpu_percent: 65.0,
                very_high_cpu_percent: 90.0,
                high_mem_percent: 8.0,
                very_high_mem_percent: 16.0,
                low_cpu_percent: 1.0,
                low_mem_percent: 0.3,
                busy_fd_count: 128,
                busy_thread_count: 64,
                idle_min_elapsed_seconds: 300,
                supervisor_children_count: 4,
            },
            output: OutputConfig {
                default_limit: 10,
                graph_default_depth: 3,
            },
        }
    }
}

impl AppConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => {
                let raw = fs::read_to_string(path)
                    .with_context(|| format!("failed to read config at {}", path.display()))?;
                let cfg = toml::from_str::<AppConfig>(&raw)
                    .with_context(|| format!("failed to parse config at {}", path.display()))?;
                Ok(cfg)
            }
            None => Ok(Self::default()),
        }
    }
}
