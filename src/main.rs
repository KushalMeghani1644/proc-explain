use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use proc_explain::collector;
use proc_explain::config::AppConfig;
use proc_explain::explain;

#[derive(Debug, Parser)]
#[command(name = "proc-explain")]
#[command(version = "0.3.0")]
#[command(about = "Explain what a process is doing in plain English")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, value_enum, default_value_t = ExplainDetail::Default, global = true)]
    explain_detail: ExplainDetail,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Inspect {
        pid: i32,
    },
    Top {
        #[arg(long, value_enum, default_value_t = TopSort::Cpu)]
        by: TopSort,
        #[arg(long)]
        limit: Option<usize>,
    },
    Graph {
        pid: i32,
        #[arg(long)]
        depth: Option<usize>,
    },
    PrintConfig,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TopSort {
    Cpu,
    Mem,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExplainDetail {
    Default,
    Full,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Inspect { pid } => {
            let store =
                collector::collect_store(&config).context("failed to collect process data")?;
            let explanation = explain::explain_process(&store, pid, &config)
                .with_context(|| format!("pid {} was not found", pid))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&explanation)?);
            } else {
                print_explanation(&explanation, cli.explain_detail);
            }
        }
        Commands::Top { by, limit } => {
            let store =
                collector::collect_store(&config).context("failed to collect process data")?;
            let limit = limit.unwrap_or(config.output.default_limit);
            let entries = match by {
                TopSort::Cpu => explain::top_by_cpu(&store, limit),
                TopSort::Mem => explain::top_by_mem(&store, limit),
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                print_top_entries(&entries, by);
            }
        }
        Commands::Graph { pid, depth } => {
            let store =
                collector::collect_store(&config).context("failed to collect process data")?;
            let depth = depth.unwrap_or(config.output.graph_default_depth);
            let graph = explain::graph_view(&store, pid, depth)
                .with_context(|| format!("pid {} was not found", pid))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&graph)?);
            } else {
                print_graph(&graph, depth);
            }
        }
        Commands::PrintConfig => {
            println!("{}", toml::to_string_pretty(&config)?);
        }
    }

    Ok(())
}

fn print_explanation(explanation: &proc_explain::model::ProcessExplanation, detail: ExplainDetail) {
    let snapshot = &explanation.snapshot;
    println!("Process {} ({})", snapshot.pid, snapshot.name);
    println!("- exe: {}", snapshot.exe.as_deref().unwrap_or("<unknown>"));
    println!(
        "- ppid: {} | uid: {} | state: {}",
        snapshot.ppid, snapshot.uid, snapshot.state
    );
    println!(
        "- cpu: {:.1}% | mem: {:.2}% ({:.1} MiB) | threads: {} | fds: {}",
        snapshot.cpu_percent,
        snapshot.mem_percent,
        snapshot.mem_bytes as f64 / (1024.0 * 1024.0),
        snapshot.thread_count,
        snapshot.fd_count
    );
    println!("- fingerprint: {}", snapshot.fingerprint);

    println!("\nWhy this matters:");
    for item in &explanation.why_this_matters {
        println!("- {}", item);
    }

    println!("\nBehavior now:");
    for behavior in &explanation.behavior_descriptions {
        println!("- {}", behavior.summary);
        if matches!(detail, ExplainDetail::Full) && !behavior.evidence.is_empty() {
            println!("  evidence: {}", behavior.evidence.join("; "));
        }
    }

    println!("\nDependency risk:");
    if let Some(parent) = explanation.dependency.direct_parent {
        println!("- parent: {}", parent);
    }
    println!("- children: {:?}", explanation.dependency.direct_children);
    println!("- cgroup peers: {:?}", explanation.dependency.cgroup_peers);
    if !explanation.dependency.depends_on.is_empty() {
        println!(
            "- depends on: {}",
            explanation.dependency.depends_on.join(" | ")
        );
    }
    if !explanation.dependency.depended_on_by.is_empty() {
        println!(
            "- depended on by: {}",
            explanation.dependency.depended_on_by.join(" | ")
        );
    }

    println!("\nHealth:");
    if !matches!(
        explanation.behavior_assessment.status.as_str(),
        "appears-normal"
    ) {
        println!(
            "- Status: {}",
            explanation.behavior_assessment.status.replace('-', " ")
        );
    }
    for line in &explanation.behavior_assessment.summary {
        println!("- {}", line);
    }
    if matches!(detail, ExplainDetail::Full)
        && !explanation.behavior_assessment.technical_notes.is_empty()
    {
        println!(
            "- Technical notes: {}",
            explanation.behavior_assessment.technical_notes.join("; ")
        );
    }

    if !explanation.notable_observations.is_empty() {
        println!("\nNotable observations:");
        for note in &explanation.notable_observations {
            println!("- {}", note);
        }
    }

    println!("\nIf stopped:");
    for line in &explanation.stop_impact.suggestion {
        println!("- {}", line);
    }
    if matches!(detail, ExplainDetail::Full) && !explanation.stop_impact.reasons.is_empty() {
        println!("- reasons: {}", explanation.stop_impact.reasons.join("; "));
    }

    println!("\nNote:");
    println!("- {}", explanation.snapshot_caveat);
}

fn print_top_entries(entries: &[proc_explain::model::TopEntry], by: TopSort) {
    println!("Top processes by {:?}", by);
    for entry in entries {
        println!(
            "- pid {:>6} {:<24} cpu {:>6.1}% mem {:>6.2}%",
            entry.pid,
            trim_name(&entry.name, 24),
            entry.cpu_percent,
            entry.mem_percent,
        );
        println!("  activity: {}", entry.activity_hint);
    }
}

fn print_graph(nodes: &[proc_explain::model::GraphNode], depth: usize) {
    println!("Dependency graph (depth {})", depth);
    for node in nodes {
        println!("- pid {:>6} {:<8} {}", node.pid, node.relation, node.name);
    }
}

fn trim_name(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }
    let keep = max_len.saturating_sub(3);
    let mut out = input.chars().take(keep).collect::<String>();
    out.push_str("...");
    out
}
