# proc-explain (alpha v0.3.0)

A CLI that tells you why a process is running? Should YOU care?

Ever seen a random process and had the thought:

Why is it here?
Do I need it? 
Can I kill it without breaking my current session?

## Quick-start

```bash
cargo run -- inspect <pid> 
```

For more detailed output:

```bash
cargo run -- inspect <pid> --explain-detail full 
```

## Example

```zsh
 cargo run -- inspect 10360
 
Process 10360 (helium)
- exe: /tmp/.mount_heliumPiKMPB/opt/helium/helium
- ppid: 10351 | uid: 1000 | state: S
- cpu: 0.0% | mem: 3.47% (203.2 MiB) | threads: 37 | fds: 337
- fingerprint: tmp/{mount}/opt/helium/helium|dev59-ino936|{runtime-path}|user.slice/{id}/{id}/app.slice/app-org.chromium.Chromium-{id}.scope

Why this matters:
- Stopping this process is likely to have visible impact on your current session.
- It is part of an active runtime group, likely tied to a larger runtime environment.
- Resource usage is currently moderate and does not appear unusual.

Behavior now:
- Long-running (~156 minutes uptime)
- Acts as a parent process with 4 children
- No active network sockets observed in this snapshot (may vary over time).
- Currently low CPU usage (~0.0%)
- Moderate memory usage (~203.2 MiB)
- High file descriptor count (337), indicating active resource usage
- No controlling terminal (background-style process)

Dependency risk:
- parent: 10351
- children: [10368, 10369, 10430, 14137]
- cgroup peers: [14137]
- depends on: parent pid 10351
- depended on by: 4 direct child process(es)

Health:
- Appears normal for a background application.
- No conflicting or abnormal signals observed in this snapshot.

Notable observations:
- Executable runs from a temporary mount path (/tmp/.mount_heliumPiKMPB/opt/helium/helium), common for bundled apps but worth verifying if unexpected.

If stopped:
- Likely to disrupt 4 child process(es) and related tasks.

Note:
- This analysis is snapshot-based; short-lived activity may not appear.
```

## Why not just use `ps` or `htop`?

Traditional tools show raw data:
- CPU usage
- memory
- process tree

They don’t explain what it *means*.

`proc-explain` interprets those signals and answers:
- What is this process doing?
- Is this behavior normal?
- What happens if I stop it?

It focuses on **understanding**, not just visibility.

## Design goals

- Behavior-first: no hardcoded app name mappings
- Explainability: every conclusion is based on observable signals
- Safety: avoids binary “kill/don’t kill” judgments
- Configurable: thresholds and rules live in TOML, not code
- Honest: snapshot limitations are always made explicit
