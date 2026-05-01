use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::model::{ProcessSnapshot, ProcessStore};

#[derive(Debug, Clone)]
struct StatInfo {
    name: String,
    ppid: i32,
    state: char,
    tty_nr: i32,
    utime: u64,
    stime: u64,
    start_ticks: u64,
}

#[derive(Debug, Clone)]
struct SocketEntry {
    state: String,
    local_repr: String,
    remote_repr: String,
    local_port: u16,
    remote_port: u16,
}

pub fn collect_store(config: &AppConfig) -> Result<ProcessStore> {
    let proc_root = Path::new("/proc");
    let pids = read_pids(proc_root)?;
    let mem_total = read_mem_total_bytes(proc_root).unwrap_or(1);
    let uptime_seconds = read_uptime_seconds(proc_root).unwrap_or(0);
    let clock_ticks = read_sysconf(libc::_SC_CLK_TCK, 100) as u64;
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get() as f32)
        .unwrap_or(1.0);

    let total_jiffies_a = read_total_jiffies(proc_root).unwrap_or(0);
    let mut per_pid_a: HashMap<i32, u64> = HashMap::new();
    for pid in &pids {
        if let Ok(stat) = read_stat(proc_root, *pid) {
            per_pid_a.insert(*pid, stat.utime + stat.stime);
        }
    }

    thread::sleep(Duration::from_millis(config.sampling.cpu_sample_ms));

    let total_jiffies_b = read_total_jiffies(proc_root).unwrap_or(total_jiffies_a);
    let mut per_pid_b: HashMap<i32, u64> = HashMap::new();
    for pid in &pids {
        if let Ok(stat) = read_stat(proc_root, *pid) {
            per_pid_b.insert(*pid, stat.utime + stat.stime);
        }
    }

    let socket_map = read_socket_map(proc_root);

    let mut processes: HashMap<i32, ProcessSnapshot> = HashMap::new();
    let dt_total = total_jiffies_b.saturating_sub(total_jiffies_a);

    for pid in pids {
        let stat = match read_stat(proc_root, pid) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let cmdline = read_cmdline(proc_root, pid).unwrap_or_default();
        let exe = read_exe(proc_root, pid).ok();
        let exe_identity = read_exe_identity(proc_root, pid).ok();
        let uid = read_uid(proc_root, pid).unwrap_or(0);
        let mem_bytes = read_vmrss_bytes(proc_root, pid).unwrap_or(0);
        let mem_percent = if mem_total == 0 {
            0.0
        } else {
            (mem_bytes as f32 / mem_total as f32) * 100.0
        };
        let io = read_io_bytes(proc_root, pid).unwrap_or((0, 0));
        let cgroup = read_cgroup(proc_root, pid).ok();
        let (fd_count, socket_inodes) =
            read_fd_count_and_socket_inodes(proc_root, pid).unwrap_or((0, HashSet::new()));

        let mut listen_sockets = Vec::new();
        let mut connected_sockets = Vec::new();
        let mut listen_ports = Vec::new();
        let mut connected_remote_ports = Vec::new();

        for inode in socket_inodes {
            if let Some(entry) = socket_map.get(&inode) {
                let descriptor = format!(
                    "{}:{} -> {}:{} ({})",
                    entry.local_repr,
                    entry.local_port,
                    entry.remote_repr,
                    entry.remote_port,
                    entry.state
                );
                if entry.state == "LISTEN" {
                    listen_ports.push(entry.local_port);
                    listen_sockets.push(descriptor);
                } else {
                    if entry.remote_port > 0 {
                        connected_remote_ports.push(entry.remote_port);
                    }
                    connected_sockets.push(descriptor);
                }
            }
        }

        listen_ports.sort_unstable();
        listen_ports.dedup();
        connected_remote_ports.sort_unstable();
        connected_remote_ports.dedup();

        let cpu_percent = if dt_total == 0 {
            0.0
        } else {
            let a = per_pid_a.get(&pid).copied().unwrap_or(0);
            let b = per_pid_b.get(&pid).copied().unwrap_or(a);
            let dt_proc = b.saturating_sub(a);
            (dt_proc as f32 / dt_total as f32) * 100.0 * cpu_count
        };

        let elapsed_seconds = uptime_seconds.saturating_sub(stat.start_ticks / clock_ticks);
        let fingerprint =
            build_fingerprint(&exe, exe_identity.as_deref(), &cmdline, cgroup.as_deref());

        processes.insert(
            pid,
            ProcessSnapshot {
                pid,
                ppid: stat.ppid,
                uid,
                name: stat.name,
                exe,
                cmdline,
                state: stat.state.to_string(),
                start_ticks: stat.start_ticks,
                elapsed_seconds,
                cpu_percent,
                mem_bytes,
                mem_percent,
                thread_count: read_threads(proc_root, pid).unwrap_or(0),
                fd_count,
                io_read_bytes: io.0,
                io_write_bytes: io.1,
                has_tty: stat.tty_nr != 0,
                listen_sockets,
                connected_sockets,
                listen_ports,
                connected_remote_ports,
                cgroup,
                children: Vec::new(),
                parent_chain: Vec::new(),
                fingerprint,
            },
        );
    }

    let parent_links: Vec<(i32, i32)> = processes
        .iter()
        .map(|(pid, proc_item)| (*pid, proc_item.ppid))
        .collect();

    for (pid, ppid) in &parent_links {
        if let Some(parent) = processes.get_mut(ppid) {
            parent.children.push(*pid);
        }
    }

    for process in processes.values_mut() {
        process.children.sort_unstable();
    }

    let mut parent_chains: HashMap<i32, Vec<i32>> = HashMap::new();
    for pid in processes.keys() {
        let chain = build_parent_chain(*pid, &processes, 16);
        parent_chains.insert(*pid, chain);
    }

    for (pid, chain) in parent_chains {
        if let Some(process) = processes.get_mut(&pid) {
            process.parent_chain = chain;
        }
    }

    Ok(ProcessStore { processes })
}

fn build_parent_chain(
    pid: i32,
    processes: &HashMap<i32, ProcessSnapshot>,
    max_depth: usize,
) -> Vec<i32> {
    let mut out = Vec::new();
    let mut current = pid;
    let mut seen = HashSet::new();
    for _ in 0..max_depth {
        let Some(proc_item) = processes.get(&current) else {
            break;
        };
        let ppid = proc_item.ppid;
        if ppid <= 0 || !seen.insert(ppid) {
            break;
        }
        out.push(ppid);
        current = ppid;
    }
    out
}

fn build_fingerprint(
    exe: &Option<String>,
    exe_identity: Option<&str>,
    cmdline: &[String],
    cgroup: Option<&str>,
) -> String {
    let exe_part = exe
        .as_deref()
        .map(normalize_path)
        .unwrap_or_else(|| "unknown-exe".to_string());
    let exe_meta_part = exe_identity.unwrap_or("unknown-meta").to_string();
    let cmd_part = if cmdline.is_empty() {
        "no-cmd".to_string()
    } else {
        normalize_cmdline(cmdline)
    };
    let cgroup_part = cgroup
        .map(normalize_cgroup_path)
        .unwrap_or_else(|| "no-cgroup".to_string());
    format!(
        "{}|{}|{}|{}",
        exe_part, exe_meta_part, cmd_part, cgroup_part
    )
}

fn normalize_path(path: &str) -> String {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(normalize_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_cgroup_path(path: &str) -> String {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(normalize_cgroup_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_cmdline(cmdline: &[String]) -> String {
    cmdline
        .iter()
        .take(3)
        .map(|arg| normalize_cmd_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_cmd_arg(arg: &str) -> String {
    if arg.chars().all(|c| c.is_ascii_digit()) {
        return "{num}".to_string();
    }
    if arg.starts_with("/tmp/") || arg.starts_with("/run/user/") {
        return "{runtime-path}".to_string();
    }
    arg.chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect::<String>()
}

fn normalize_path_segment(segment: &str) -> String {
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return "{num}".to_string();
    }
    if segment.starts_with(".mount_") {
        return "{mount}".to_string();
    }
    if segment.starts_with(".tmp") {
        return "{tmp}".to_string();
    }
    if looks_ephemeral_token(segment) {
        return "{id}".to_string();
    }
    segment.to_string()
}

fn normalize_cgroup_segment(segment: &str) -> String {
    if segment.ends_with(".scope") {
        let trimmed = segment.trim_end_matches(".scope");
        let normalized = trimmed
            .split('-')
            .map(|part| {
                if part.chars().all(|c| c.is_ascii_digit()) || looks_ephemeral_token(part) {
                    "{id}".to_string()
                } else {
                    part.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("-");
        return format!("{}.scope", normalized);
    }
    normalize_path_segment(segment)
}

fn looks_ephemeral_token(text: &str) -> bool {
    if text.len() < 8 {
        return false;
    }
    let mut has_alpha = false;
    let mut has_digit = false;
    let mut alpha_num_count = 0_usize;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            has_alpha = true;
            alpha_num_count += 1;
        } else if ch.is_ascii_digit() {
            has_digit = true;
            alpha_num_count += 1;
        }
    }
    let mostly_alnum = alpha_num_count.saturating_mul(100) / text.len() >= 80;
    has_alpha && has_digit && mostly_alnum
}

fn read_pids(proc_root: &Path) -> Result<Vec<i32>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(proc_root).context("failed to read /proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if let Ok(pid) = text.parse::<i32>() {
            out.push(pid);
        }
    }
    out.sort_unstable();
    Ok(out)
}

fn read_total_jiffies(proc_root: &Path) -> Result<u64> {
    let text = fs::read_to_string(proc_root.join("stat")).context("failed to read /proc/stat")?;
    let line = text.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let _cpu = parts.next();
    let total = parts
        .filter_map(|part| part.parse::<u64>().ok())
        .fold(0_u64, |acc, item| acc.saturating_add(item));
    Ok(total)
}

fn read_mem_total_bytes(proc_root: &Path) -> Result<u64> {
    let text =
        fs::read_to_string(proc_root.join("meminfo")).context("failed to read /proc/meminfo")?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0);
            return Ok(kb.saturating_mul(1024));
        }
    }
    Ok(0)
}

fn read_uptime_seconds(proc_root: &Path) -> Result<u64> {
    let text =
        fs::read_to_string(proc_root.join("uptime")).context("failed to read /proc/uptime")?;
    let value = text
        .split_whitespace()
        .next()
        .unwrap_or("0")
        .parse::<f64>()
        .unwrap_or(0.0);
    Ok(value.max(0.0) as u64)
}

fn read_stat(proc_root: &Path, pid: i32) -> Result<StatInfo> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("stat"))
        .with_context(|| format!("failed to read /proc/{pid}/stat"))?;

    let lparen = text.find('(').context("bad stat format: missing (")?;
    let rparen = text.rfind(')').context("bad stat format: missing )")?;
    let name = text[lparen + 1..rparen].to_string();
    let rest = text[rparen + 1..].trim();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        anyhow::bail!("bad stat format: not enough fields");
    }

    let state = fields[0].chars().next().unwrap_or('?');
    let ppid = fields[1].parse::<i32>().unwrap_or(0);
    let tty_nr = fields[4].parse::<i32>().unwrap_or(0);
    let utime = fields[11].parse::<u64>().unwrap_or(0);
    let stime = fields[12].parse::<u64>().unwrap_or(0);
    let start_ticks = fields[19].parse::<u64>().unwrap_or(0);

    Ok(StatInfo {
        name,
        ppid,
        state,
        tty_nr,
        utime,
        stime,
        start_ticks,
    })
}

fn read_cmdline(proc_root: &Path, pid: i32) -> Result<Vec<String>> {
    let data = fs::read(proc_root.join(pid.to_string()).join("cmdline"))
        .with_context(|| format!("failed to read /proc/{pid}/cmdline"))?;
    let out = data
        .split(|byte| *byte == 0)
        .filter(|piece| !piece.is_empty())
        .map(|piece| String::from_utf8_lossy(piece).to_string())
        .collect();
    Ok(out)
}

fn read_exe(proc_root: &Path, pid: i32) -> Result<String> {
    let path = fs::read_link(proc_root.join(pid.to_string()).join("exe"))
        .with_context(|| format!("failed to read /proc/{pid}/exe"))?;
    Ok(path.to_string_lossy().to_string())
}

fn read_exe_identity(proc_root: &Path, pid: i32) -> Result<String> {
    let meta = fs::metadata(proc_root.join(pid.to_string()).join("exe"))
        .with_context(|| format!("failed to stat /proc/{pid}/exe"))?;
    Ok(format!("dev{}-ino{}", meta.dev(), meta.ino()))
}

fn read_uid(proc_root: &Path, pid: i32) -> Result<u32> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("status"))
        .with_context(|| format!("failed to read /proc/{pid}/status"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap_or(0);
            return Ok(uid);
        }
    }
    Ok(0)
}

fn read_threads(proc_root: &Path, pid: i32) -> Result<u32> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("status"))
        .with_context(|| format!("failed to read /proc/{pid}/status"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            let count = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap_or(0);
            return Ok(count);
        }
    }
    Ok(0)
}

fn read_vmrss_bytes(proc_root: &Path, pid: i32) -> Result<u64> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("status"))
        .with_context(|| format!("failed to read /proc/{pid}/status"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0);
            return Ok(kb.saturating_mul(1024));
        }
    }
    Ok(0)
}

fn read_io_bytes(proc_root: &Path, pid: i32) -> Result<(u64, u64)> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("io"))
        .with_context(|| format!("failed to read /proc/{pid}/io"))?;
    let mut read_bytes = 0_u64;
    let mut write_bytes = 0_u64;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("read_bytes:") {
            read_bytes = rest.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("write_bytes:") {
            write_bytes = rest.trim().parse::<u64>().unwrap_or(0);
        }
    }

    Ok((read_bytes, write_bytes))
}

fn read_cgroup(proc_root: &Path, pid: i32) -> Result<String> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup"))
        .with_context(|| format!("failed to read /proc/{pid}/cgroup"))?;
    let mut best = String::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, ':');
        let _id = parts.next();
        let _controllers = parts.next();
        let path = parts.next().unwrap_or("").trim();
        if path.len() > best.len() {
            best = path.to_string();
        }
    }
    Ok(best)
}

fn read_fd_count_and_socket_inodes(proc_root: &Path, pid: i32) -> Result<(u32, HashSet<u64>)> {
    let fd_path = proc_root.join(pid.to_string()).join("fd");
    let mut count = 0_u32;
    let mut socket_inodes = HashSet::new();
    for entry in
        fs::read_dir(&fd_path).with_context(|| format!("failed to read {}", fd_path.display()))?
    {
        let entry = entry?;
        count = count.saturating_add(1);
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_text = target.to_string_lossy();
            if let Some(inode) = parse_socket_inode(&target_text) {
                socket_inodes.insert(inode);
            }
        }
    }
    Ok((count, socket_inodes))
}

fn parse_socket_inode(target: &str) -> Option<u64> {
    let prefix = "socket:[";
    if let Some(rest) = target.strip_prefix(prefix) {
        let trimmed = rest.strip_suffix(']')?;
        return trimmed.parse::<u64>().ok();
    }
    None
}

fn read_socket_map(proc_root: &Path) -> HashMap<u64, SocketEntry> {
    let mut out = HashMap::new();
    for (file, is_ipv6) in [("tcp", false), ("tcp6", true)] {
        let path = proc_root.join("net").join(file);
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 10 {
                    continue;
                }
                let local = cols[1];
                let remote = cols[2];
                let state_hex = cols[3];
                let inode = cols[9].parse::<u64>().unwrap_or(0);
                if inode == 0 {
                    continue;
                }

                let (local_repr, local_port) = parse_address_and_port(local, is_ipv6);
                let (remote_repr, remote_port) = parse_address_and_port(remote, is_ipv6);

                out.insert(
                    inode,
                    SocketEntry {
                        state: tcp_state_name(state_hex).to_string(),
                        local_repr,
                        remote_repr,
                        local_port,
                        remote_port,
                    },
                );
            }
        }
    }
    out
}

fn parse_address_and_port(text: &str, is_ipv6: bool) -> (String, u16) {
    let mut parts = text.split(':');
    let addr_hex = parts.next().unwrap_or("");
    let port_hex = parts.next().unwrap_or("0");
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    let addr = if is_ipv6 {
        decode_ipv6(addr_hex)
    } else {
        decode_ipv4(addr_hex)
    };
    (addr, port)
}

fn decode_ipv4(hex: &str) -> String {
    if hex.len() != 8 {
        return hex.to_string();
    }
    let mut octets = Vec::new();
    for i in (0..8).step_by(2) {
        if let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) {
            octets.push(byte);
        }
    }
    if octets.len() != 4 {
        return hex.to_string();
    }
    octets.reverse();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn decode_ipv6(hex: &str) -> String {
    if hex.len() != 32 {
        return hex.to_string();
    }
    let mut parts = Vec::new();
    for i in (0..32).step_by(4) {
        parts.push(&hex[i..i + 4]);
    }
    parts.join(":")
}

fn tcp_state_name(state_hex: &str) -> &'static str {
    match state_hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn read_sysconf(key: libc::c_int, fallback: i64) -> i64 {
    let value = unsafe { libc::sysconf(key) };
    if value <= 0 { fallback } else { value }
}
