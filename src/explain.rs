use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::config::AppConfig;
use crate::model::{
    BehaviorAssessment, BehaviorDescription, DependencyInsight, GraphNode, ProcessExplanation,
    ProcessSnapshot, ProcessStore, StopImpactInsight, TopEntry,
};

pub fn explain_process(
    store: &ProcessStore,
    pid: i32,
    config: &AppConfig,
) -> Option<ProcessExplanation> {
    let snapshot = store.processes.get(&pid)?.clone();
    let dependency = dependency_insight(store, &snapshot);
    let behavior_descriptions = behavior_descriptions(store, &snapshot, config);
    let behavior_assessment = behavior_assessment(&snapshot, config);
    let stop_impact = stop_impact_insight(&snapshot, &dependency, &behavior_assessment);
    let why_this_matters = why_this_matters(&snapshot, &dependency, &stop_impact, config);
    let notable_observations = notable_observations(&snapshot);

    Some(ProcessExplanation {
        snapshot,
        why_this_matters,
        snapshot_caveat: "This analysis is snapshot-based; short-lived activity may not appear."
            .to_string(),
        behavior_descriptions,
        dependency,
        stop_impact,
        behavior_assessment,
        notable_observations,
    })
}

pub fn top_by_cpu(store: &ProcessStore, limit: usize) -> Vec<TopEntry> {
    top_entries(store, limit, SortMode::Cpu)
}

pub fn top_by_mem(store: &ProcessStore, limit: usize) -> Vec<TopEntry> {
    top_entries(store, limit, SortMode::Mem)
}

pub fn graph_view(store: &ProcessStore, pid: i32, depth: usize) -> Option<Vec<GraphNode>> {
    let root = store.processes.get(&pid)?;
    let mut nodes = Vec::new();
    nodes.push(GraphNode {
        pid: root.pid,
        relation: "self".to_string(),
        name: root.name.clone(),
    });

    let mut visited = HashSet::new();
    visited.insert(root.pid);

    let mut queue = VecDeque::new();
    queue.push_back((root.pid, 0_usize));

    while let Some((current, level)) = queue.pop_front() {
        if level >= depth {
            continue;
        }
        let Some(current_snapshot) = store.processes.get(&current) else {
            continue;
        };

        if current_snapshot.ppid > 0 && visited.insert(current_snapshot.ppid) {
            if let Some(parent) = store.processes.get(&current_snapshot.ppid) {
                nodes.push(GraphNode {
                    pid: parent.pid,
                    relation: "parent".to_string(),
                    name: parent.name.clone(),
                });
                queue.push_back((parent.pid, level + 1));
            }
        }

        for child_pid in &current_snapshot.children {
            if visited.insert(*child_pid) {
                if let Some(child) = store.processes.get(child_pid) {
                    nodes.push(GraphNode {
                        pid: child.pid,
                        relation: "child".to_string(),
                        name: child.name.clone(),
                    });
                    queue.push_back((child.pid, level + 1));
                }
            }
        }
    }

    Some(nodes)
}

#[derive(Debug, Clone, Copy)]
enum SortMode {
    Cpu,
    Mem,
}

fn top_entries(store: &ProcessStore, limit: usize, sort_mode: SortMode) -> Vec<TopEntry> {
    let mut entries: Vec<TopEntry> = store
        .processes
        .values()
        .map(|snapshot| TopEntry {
            pid: snapshot.pid,
            name: snapshot.name.clone(),
            cpu_percent: snapshot.cpu_percent,
            mem_percent: snapshot.mem_percent,
            activity_hint: activity_hint(snapshot),
        })
        .collect();

    entries.sort_by(|a, b| match sort_mode {
        SortMode::Cpu => b
            .cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(Ordering::Equal),
        SortMode::Mem => b
            .mem_percent
            .partial_cmp(&a.mem_percent)
            .unwrap_or(Ordering::Equal),
    });
    entries.truncate(limit);
    entries
}

fn activity_hint(snapshot: &ProcessSnapshot) -> String {
    if !snapshot.listen_ports.is_empty() {
        return format!("listening on ports {:?}", snapshot.listen_ports);
    }
    if !snapshot.connected_sockets.is_empty() {
        return format!(
            "{} active network connections",
            snapshot.connected_sockets.len()
        );
    }
    if !snapshot.children.is_empty() {
        return format!("manages {} child processes", snapshot.children.len());
    }
    if snapshot.cpu_percent > 2.0 {
        return format!("currently using {:.1}% cpu", snapshot.cpu_percent);
    }
    "no strong active signals at this snapshot".to_string()
}

fn dependency_insight(store: &ProcessStore, snapshot: &ProcessSnapshot) -> DependencyInsight {
    let mut cgroup_peers = Vec::new();
    if let Some(cgroup) = &snapshot.cgroup {
        for proc_item in store.processes.values() {
            if proc_item.pid != snapshot.pid && proc_item.cgroup.as_ref() == Some(cgroup) {
                cgroup_peers.push(proc_item.pid);
            }
        }
        cgroup_peers.sort_unstable();
    }

    let listener_map = listener_port_map(store);
    let mut depends_on = Vec::new();
    let mut depended_on_by = Vec::new();

    if snapshot.ppid > 0 {
        depends_on.push(format!("parent pid {}", snapshot.ppid));
    }
    if !snapshot.connected_remote_ports.is_empty() {
        for port in &snapshot.connected_remote_ports {
            if let Some(pids) = listener_map.get(port) {
                depends_on.push(format!(
                    "connected to local service on port {} via pids {:?}",
                    port, pids
                ));
            } else {
                depends_on.push(format!("connected to remote port {}", port));
            }
        }
    }

    if !snapshot.children.is_empty() {
        depended_on_by.push(format!(
            "{} direct child process(es)",
            snapshot.children.len()
        ));
    }
    if !snapshot.listen_ports.is_empty() {
        for port in &snapshot.listen_ports {
            let mut clients = Vec::new();
            for proc_item in store.processes.values() {
                if proc_item.pid == snapshot.pid {
                    continue;
                }
                if proc_item.connected_remote_ports.contains(port) {
                    clients.push(proc_item.pid);
                }
            }
            if !clients.is_empty() {
                clients.sort_unstable();
                depended_on_by.push(format!("listening port {} used by {:?}", port, clients));
            } else {
                depended_on_by.push(format!("listening port {} (no observed clients)", port));
            }
        }
    }

    DependencyInsight {
        direct_parent: if snapshot.ppid > 0 {
            Some(snapshot.ppid)
        } else {
            None
        },
        direct_children: snapshot.children.clone(),
        cgroup_peers,
        depends_on,
        depended_on_by,
    }
}

fn listener_port_map(store: &ProcessStore) -> HashMap<u16, Vec<i32>> {
    let mut map: HashMap<u16, Vec<i32>> = HashMap::new();
    for proc_item in store.processes.values() {
        for port in &proc_item.listen_ports {
            map.entry(*port).or_default().push(proc_item.pid);
        }
    }
    for pids in map.values_mut() {
        pids.sort_unstable();
        pids.dedup();
    }
    map
}

fn behavior_descriptions(
    store: &ProcessStore,
    snapshot: &ProcessSnapshot,
    config: &AppConfig,
) -> Vec<BehaviorDescription> {
    let mut descriptions = Vec::new();
    descriptions.push(lifecycle_description(snapshot, config));
    descriptions.push(process_graph_description(snapshot));
    descriptions.push(network_description(snapshot));
    descriptions.extend(resource_descriptions(store, snapshot, config));
    descriptions.push(session_description(snapshot));
    descriptions
}

fn lifecycle_description(snapshot: &ProcessSnapshot, config: &AppConfig) -> BehaviorDescription {
    let summary = if snapshot.elapsed_seconds >= config.thresholds.idle_min_elapsed_seconds {
        format!(
            "Long-running (~{} minutes uptime)",
            snapshot.elapsed_seconds / 60
        )
    } else {
        format!(
            "Recently started (~{} seconds uptime)",
            snapshot.elapsed_seconds
        )
    };

    let mut evidence = Vec::new();
    evidence.push(format!("state is {}", snapshot.state));
    evidence.push(format!("elapsed time {} seconds", snapshot.elapsed_seconds));
    if let Some(exe) = &snapshot.exe {
        evidence.push(format!("executable path {}", exe));
    }

    BehaviorDescription { summary, evidence }
}

fn process_graph_description(snapshot: &ProcessSnapshot) -> BehaviorDescription {
    let summary = if snapshot.children.is_empty() {
        "No child processes observed in this snapshot".to_string()
    } else {
        format!(
            "Acts as a parent process with {} children",
            snapshot.children.len()
        )
    };

    let mut evidence = Vec::new();
    evidence.push(format!("parent pid is {}", snapshot.ppid));
    evidence.push(format!("children pids: {:?}", snapshot.children));
    if !snapshot.parent_chain.is_empty() {
        evidence.push(format!("parent chain: {:?}", snapshot.parent_chain));
    }

    BehaviorDescription { summary, evidence }
}

fn network_description(snapshot: &ProcessSnapshot) -> BehaviorDescription {
    let summary = if !snapshot.listen_ports.is_empty() {
        format!("Listening on local ports {:?}", snapshot.listen_ports)
    } else if !snapshot.connected_sockets.is_empty() {
        format!(
            "Has {} active network connection(s)",
            snapshot.connected_sockets.len()
        )
    } else {
        "No active network sockets observed in this snapshot (may vary over time).".to_string()
    };

    let mut evidence = Vec::new();
    if !snapshot.listen_sockets.is_empty() {
        evidence.push(format!(
            "listening sockets: {}",
            snapshot.listen_sockets.join(" | ")
        ));
    }
    if !snapshot.connected_sockets.is_empty() {
        evidence.push(format!(
            "connected sockets: {}",
            snapshot.connected_sockets.join(" | ")
        ));
    }
    if evidence.is_empty() {
        evidence.push("no tcp socket descriptors matched process fds".to_string());
    }

    BehaviorDescription { summary, evidence }
}

fn resource_descriptions(
    store: &ProcessStore,
    snapshot: &ProcessSnapshot,
    config: &AppConfig,
) -> Vec<BehaviorDescription> {
    let (median_threads, median_fds) = population_medians(store);
    let mut descriptions = Vec::new();

    let cpu_summary = if snapshot.cpu_percent <= config.thresholds.low_cpu_percent {
        format!("Currently low CPU usage (~{:.1}%)", snapshot.cpu_percent)
    } else if snapshot.cpu_percent >= config.thresholds.very_high_cpu_percent {
        format!(
            "Currently very high CPU usage (~{:.1}%)",
            snapshot.cpu_percent
        )
    } else if snapshot.cpu_percent >= config.thresholds.high_cpu_percent {
        format!("Currently high CPU usage (~{:.1}%)", snapshot.cpu_percent)
    } else {
        format!(
            "Currently moderate CPU usage (~{:.1}%)",
            snapshot.cpu_percent
        )
    };
    descriptions.push(BehaviorDescription {
        summary: cpu_summary,
        evidence: vec!["cpu measured from sampled process jiffies".to_string()],
    });

    let mem_mib = snapshot.mem_bytes as f64 / (1024.0 * 1024.0);
    let mem_summary = if snapshot.mem_percent <= config.thresholds.low_mem_percent {
        format!("Low memory usage (~{:.1} MiB)", mem_mib)
    } else if snapshot.mem_percent >= config.thresholds.very_high_mem_percent {
        format!("Very high memory usage (~{:.1} MiB)", mem_mib)
    } else if snapshot.mem_percent >= config.thresholds.high_mem_percent {
        format!("High memory usage (~{:.1} MiB)", mem_mib)
    } else {
        format!("Moderate memory usage (~{:.1} MiB)", mem_mib)
    };
    descriptions.push(BehaviorDescription {
        summary: mem_summary,
        evidence: vec![format!(
            "memory share {:.2}% of total RAM",
            snapshot.mem_percent
        )],
    });

    if snapshot.fd_count >= config.thresholds.busy_fd_count {
        descriptions.push(BehaviorDescription {
            summary: format!(
                "High file descriptor count ({}), indicating active resource usage",
                snapshot.fd_count
            ),
            evidence: vec![format!("host median fd count is {:.1}", median_fds)],
        });
    } else {
        descriptions.push(BehaviorDescription {
            summary: format!("Open file descriptor count is {}", snapshot.fd_count),
            evidence: vec![format!("host median fd count is {:.1}", median_fds)],
        });
    }

    if snapshot.thread_count >= config.thresholds.busy_thread_count {
        descriptions.push(BehaviorDescription {
            summary: format!(
                "High thread count ({}) suggests concurrent task handling",
                snapshot.thread_count
            ),
            evidence: vec![format!("host median thread count is {:.1}", median_threads)],
        });
    }

    descriptions
}

fn session_description(snapshot: &ProcessSnapshot) -> BehaviorDescription {
    let summary = if snapshot.has_tty {
        "Has a controlling terminal (interactive-style process)".to_string()
    } else {
        "No controlling terminal (background-style process)".to_string()
    };

    let mut evidence = Vec::new();
    evidence.push(format!("has tty: {}", snapshot.has_tty));
    if let Some(cgroup) = &snapshot.cgroup {
        evidence.push(format!("cgroup path: {}", cgroup));
    }

    BehaviorDescription { summary, evidence }
}

fn behavior_assessment(snapshot: &ProcessSnapshot, config: &AppConfig) -> BehaviorAssessment {
    let mut technical_notes = Vec::new();
    let mut caution_signals = 0_u8;

    if snapshot.state == "D" || snapshot.state == "Z" {
        caution_signals += 2;
        technical_notes.push(format!(
            "process state {} can indicate a problem",
            snapshot.state
        ));
    }
    if snapshot.cpu_percent >= config.thresholds.very_high_cpu_percent {
        caution_signals += 1;
        technical_notes.push(format!("cpu is very high at {:.1}%", snapshot.cpu_percent));
    }
    if snapshot.mem_percent >= config.thresholds.very_high_mem_percent {
        caution_signals += 1;
        technical_notes.push(format!(
            "memory is very high at {:.2}%",
            snapshot.mem_percent
        ));
    }

    technical_notes.push(format!(
        "cpu is {:.1}% at this snapshot",
        snapshot.cpu_percent
    ));
    technical_notes.push(format!(
        "memory is {:.2}% at this snapshot",
        snapshot.mem_percent
    ));

    if snapshot.fd_count >= config.thresholds.busy_fd_count
        || snapshot.thread_count >= config.thresholds.busy_thread_count
    {
        technical_notes.push(
            "higher descriptor/thread counts can still be normal for complex applications"
                .to_string(),
        );
    }

    let (status, summary) = if caution_signals >= 2 {
        (
            "needs-attention".to_string(),
            vec![
                "Needs attention due to unusual process or resource signals.".to_string(),
                "Re-check soon or inspect logs before restarting or killing this process."
                    .to_string(),
            ],
        )
    } else if caution_signals == 1 {
        (
            "watch".to_string(),
            vec![
                "Mostly healthy, but one signal deserves monitoring.".to_string(),
                "No immediate failure signs in this snapshot.".to_string(),
            ],
        )
    } else {
        (
            "appears-normal".to_string(),
            vec![
                if snapshot.has_tty {
                    "Appears normal for an interactive application process.".to_string()
                } else {
                    "Appears normal for a background application.".to_string()
                },
                "No conflicting or abnormal signals observed in this snapshot.".to_string(),
            ],
        )
    };

    BehaviorAssessment {
        status,
        summary,
        technical_notes,
    }
}

fn stop_impact_insight(
    snapshot: &ProcessSnapshot,
    dependency: &DependencyInsight,
    behavior_assessment: &BehaviorAssessment,
) -> StopImpactInsight {
    let mut reasons = Vec::new();
    let mut suggestion = Vec::new();

    if !snapshot.children.is_empty() {
        reasons.push(format!("has {} child process(es)", snapshot.children.len()));
    }
    if !snapshot.listen_ports.is_empty() {
        reasons.push(format!(
            "listens on local ports {:?}",
            snapshot.listen_ports
        ));
    }
    if !dependency.cgroup_peers.is_empty() {
        reasons.push(format!(
            "shares runtime group with {} peer process(es)",
            dependency.cgroup_peers.len()
        ));
    }
    if !snapshot.connected_sockets.is_empty() {
        reasons.push(format!(
            "has {} active network connection(s)",
            snapshot.connected_sockets.len()
        ));
    }

    let impact_level = if !snapshot.listen_ports.is_empty() || snapshot.children.len() >= 2 {
        "high"
    } else if !dependency.cgroup_peers.is_empty()
        || !snapshot.connected_sockets.is_empty()
        || !snapshot.children.is_empty()
    {
        "medium"
    } else {
        "low"
    }
    .to_string();

    if impact_level == "high" {
        if !snapshot.children.is_empty() {
            suggestion.push(format!(
                "Likely to disrupt {} child process(es) and related tasks.",
                snapshot.children.len()
            ));
        }
        if !snapshot.listen_ports.is_empty() {
            suggestion.push(
                "Provides listening sockets, so dependent local clients may fail temporarily."
                    .to_string(),
            );
        }
        if suggestion.is_empty() {
            suggestion
                .push("Likely to cause visible interruption in current workload.".to_string());
        }
    } else if impact_level == "medium" {
        if !snapshot.children.is_empty() {
            suggestion.push(format!(
                "May disrupt {} child process(es) or related subtasks.",
                snapshot.children.len()
            ));
        } else if !snapshot.listen_ports.is_empty() {
            suggestion.push("May interrupt local clients connected to this process.".to_string());
        } else {
            suggestion
                .push("May interrupt related workflows that depend on this process.".to_string());
        }
    } else {
        suggestion
            .push("Impact is likely limited based on current dependency signals.".to_string());
    }

    if behavior_assessment.status == "needs-attention" {
        suggestion.push(
            "Inspect logs before stopping, because current health signals look unusual."
                .to_string(),
        );
    }

    StopImpactInsight {
        impact_level,
        suggestion,
        reasons,
    }
}

fn why_this_matters(
    snapshot: &ProcessSnapshot,
    dependency: &DependencyInsight,
    stop_impact: &StopImpactInsight,
    config: &AppConfig,
) -> Vec<String> {
    let mut out = Vec::new();

    if stop_impact.impact_level == "high" {
        out.push(
            "Stopping this process is likely to have visible impact on your current session."
                .to_string(),
        );
    } else if stop_impact.impact_level == "medium" {
        out.push("Stopping this process may interrupt part of your current workflow.".to_string());
    } else {
        out.push(
            "This process currently looks more isolated, so stop impact appears lower.".to_string(),
        );
    }

    if !snapshot.listen_ports.is_empty() {
        out.push(
            "It exposes local service endpoints, which usually means other components may rely on it."
                .to_string(),
        );
    } else if !dependency.cgroup_peers.is_empty() {
        out.push(
            "It is part of an active runtime group, likely tied to a larger runtime environment."
                .to_string(),
        );
    } else if !snapshot.children.is_empty() {
        out.push("It coordinates child processes as part of its current workload.".to_string());
    }

    if resources_are_stable(snapshot, config) {
        out.push("Resource usage is currently moderate and does not appear unusual.".to_string());
    } else {
        out.push("Resource usage is elevated, so monitor it before taking action.".to_string());
    }

    out
}

fn resources_are_stable(snapshot: &ProcessSnapshot, config: &AppConfig) -> bool {
    snapshot.cpu_percent < config.thresholds.high_cpu_percent
        && snapshot.mem_percent < config.thresholds.high_mem_percent
        && snapshot.state != "D"
        && snapshot.state != "Z"
}

fn notable_observations(snapshot: &ProcessSnapshot) -> Vec<String> {
    let mut notes = Vec::new();

    if let Some(exe) = &snapshot.exe {
        if exe.starts_with("/tmp/") {
            notes.push(format!(
                "Executable runs from a temporary mount path ({}), common for bundled apps but worth verifying if unexpected.",
                exe
            ));
        }
        if exe.contains(" (deleted)") {
            notes.push(
                "Executable path points to a deleted file, which can happen after updates or unusual process lifecycles."
                    .to_string(),
            );
        }
    } else {
        notes.push(
            "Executable path is unavailable for this process (kernel-managed or permission-limited context)."
                .to_string(),
        );
    }

    if snapshot.state == "Z" {
        notes.push(
            "Process is in zombie state; parent process cleanup may be required.".to_string(),
        );
    }
    if snapshot.state == "D" {
        notes.push(
            "Process is in uninterruptible sleep; investigate IO waits if this persists."
                .to_string(),
        );
    }
    if snapshot.parent_chain.len() >= 8 {
        notes.push(
            "Process has a deep parent chain, which may reflect layered launch/orchestration."
                .to_string(),
        );
    }

    notes
}

fn population_medians(store: &ProcessStore) -> (f32, f32) {
    let mut thread_values: Vec<u32> = store
        .processes
        .values()
        .map(|p| p.thread_count)
        .filter(|v| *v > 0)
        .collect();
    let mut fd_values: Vec<u32> = store
        .processes
        .values()
        .map(|p| p.fd_count)
        .filter(|v| *v > 0)
        .collect();

    if thread_values.is_empty() || fd_values.is_empty() {
        return (1.0, 1.0);
    }

    thread_values.sort_unstable();
    fd_values.sort_unstable();

    let thread_mid = thread_values.len() / 2;
    let fd_mid = fd_values.len() / 2;

    (thread_values[thread_mid] as f32, fd_values[fd_mid] as f32)
}
