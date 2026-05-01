use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub state: String,
    pub start_ticks: u64,
    pub elapsed_seconds: u64,
    pub cpu_percent: f32,
    pub mem_bytes: u64,
    pub mem_percent: f32,
    pub thread_count: u32,
    pub fd_count: u32,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub has_tty: bool,
    pub listen_sockets: Vec<String>,
    pub connected_sockets: Vec<String>,
    pub listen_ports: Vec<u16>,
    pub connected_remote_ports: Vec<u16>,
    pub cgroup: Option<String>,
    pub children: Vec<i32>,
    pub parent_chain: Vec<i32>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorDescription {
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyInsight {
    pub direct_parent: Option<i32>,
    pub direct_children: Vec<i32>,
    pub cgroup_peers: Vec<i32>,
    pub depends_on: Vec<String>,
    pub depended_on_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StopImpactInsight {
    pub impact_level: String,
    pub suggestion: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorAssessment {
    pub status: String,
    pub summary: Vec<String>,
    pub technical_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessExplanation {
    pub snapshot: ProcessSnapshot,
    pub why_this_matters: Vec<String>,
    pub snapshot_caveat: String,
    pub behavior_descriptions: Vec<BehaviorDescription>,
    pub dependency: DependencyInsight,
    pub stop_impact: StopImpactInsight,
    pub behavior_assessment: BehaviorAssessment,
    pub notable_observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessStore {
    pub processes: HashMap<i32, ProcessSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopEntry {
    pub pid: i32,
    pub name: String,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub activity_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub pid: i32,
    pub relation: String,
    pub name: String,
}
