# Linux Command Pilot 🚀

> **Production-grade, locally running, privacy-focused AI Linux assistant that safely diagnoses, inspects, and modifies Linux systems through controlled, validated tools.**

Linux Command Pilot is an agentic-AI developer assistant engineered specifically for Linux systems. The LLM operates entirely as untrusted input: an independent, non-bypassable Python security layer validates every proposed action before execution.

---

## Key Features

- **🛡️ 3-Tier Security Architecture**:
  - **SAFE**: Non-destructive, read-only system inspection executed automatically.
  - **CONFIRM**: State-modifying operations (file creation/updates, package management, service operations) require explicit human confirmation with reason and risk diffs.
  - **BLOCKED**: Catastrophic commands (recursive root deletion, raw disk formatting, credential dumping, fork bombs, security layer tampering) are unconditionally rejected without prompting.
- **🔒 Zero Cloud Leakage**: Runs 100% locally with local models via Ollama. No telemetry, no external API calls, zero secret leakage.
- **🤫 Multi-Layer Secret Redaction**: Passwords, private keys (PEM/OpenSSH), AWS access keys, GitHub tokens, database URIs, authorization headers, and sensitive environment variables are automatically redacted before entering LLM context, logs, or disk.
- **📦 Distro-Agnostic Package Management**: Native abstraction supporting Ubuntu/Debian (`apt`), Fedora/RHEL (`dnf`), and Arch Linux (`pacman`) with automatic distribution detection and package name sanitization.
- **📂 Path Boundary Enforcement & Backups**: Enforces configurable directory boundaries (`ALLOWED_PATHS`), displays unified diffs before applying file modifications, and creates automatic backups (`.bak.<timestamp>`).
- **🧠 Hybrid Short-Term & SQLite Memory**: Multi-turn conversation context enables natural pronoun resolution ("Show the last 5 lines of it"), backed by an encrypted-style sanitized SQLite persistent store.
- **📊 100-Task Benchmark Evaluation**: Ships with a built-in evaluation framework covering safe, filesystem, system, troubleshooting, and blocked tasks.

---

## Architecture Overview

```
                      ┌────────────────────────────────┐
                      │          User Request          │
                      └───────────────┬────────────────┘
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │    CLI / Interactive Shell     │
                      └───────────────┬────────────────┘
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │        Agent Controller        │
                      └───────┬────────────────┬───────┘
                              │                │
            Tool Definitions  │                │ Formatted Prompts
                              ▼                ▼
                      ┌──────────────┐  ┌──────────────┐
                      │ Tool Registry│  │Local LLM API │
                      │  (15 Tools)  │  │   (Ollama)   │
                      └───────┬──────┘  └──────────────┘
                              │
                      Proposed Tool Call
                              │
                              ▼
        ┌────────────────────────────────────────────────────────┐
        │                 PYTHON SECURITY LAYER                  │
        │   (Argv-level Parser, Dangerous Command Classifier,    │
        │      Path Checker, Sudo Guard, Secret Redactor)        │
        └───────┬────────────────────────┬───────────────┬───────┘
                │                        │               │
             [SAFE]                  [CONFIRM]       [BLOCKED]
                │                        │               │
                ▼                        ▼               ▼
        Auto-Execute              User Prompt?        Outright
                              (y/N + Risk & Diff)    Rejection
```

---

## Requirements

- **Linux Operating System** (Ubuntu, Debian, Fedora, Arch, or compatible)
- **Python 3.11+**
- **Ollama** installed and running locally (`http://localhost:11434`)
- **Recommended Model**: `qwen3:4b` or `qwen2.5-coder:7b` (or any tool-calling capable model)

---

## Installation & Setup

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/nithish-scorpio/linux-pilot.git
cd linux-pilot

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Pull Recommended Ollama Model

```bash
ollama pull qwen3:4b
```

### 3. Verify Health with Doctor Command

```bash
pilot doctor
```

Output:
```
Running Linux Command Pilot Doctor...

✓ Python 3.14.4
✓ Ollama Service (http://localhost:11434)
✓ Model (qwen3:4b)
✓ Tool system framework (15 tools registered)
✓ Security policy (3-tier architecture with argv validator)
✓ Configuration & Allowed Paths
✓ Package Manager (apt on debian/ubuntu)
✓ Persistent Memory Store (SQLite at ~/.config/linux-pilot/pilot.db)

✓ Linux Command Pilot is ready.
```

---

## Usage

### Interactive Shell (Recommended)

Start an interactive session with full conversation memory:

```bash
pilot
```

```
pilot> Why is my disk almost full?
• Running disk_usage...
• Running search_files...

Pilot:
Your root filesystem (/) has 4.2GB available out of 50GB (88% utilized).
The largest directories consuming space are /var/log and ~/.cache.

pilot> Show the last 10 lines of /var/log/syslog
• Running read_file...

Pilot:
Here are the recent entries from /var/log/syslog...
```

### Non-Interactive Direct Execution

```bash
pilot ask "Check my CPU load and free RAM"
```

### Dry-Run Mode (Simulation Only)

Never modifies system state; produces a step-by-step plan:

```bash
pilot --dry-run ask "Install nginx and start the service"
```

### Command Explanation Mode

Explain flags, behavior, and risks without executing:

```bash
pilot explain "find /var/log -type f -mtime +30 -delete"
```

### Available Tools Listing

```bash
pilot tools
```

### History & Memory Management

```bash
# View command execution history
pilot history --limit 10

# Clear persistent database and memory
pilot reset-memory
```

---

## Security Model

Security is the core feature of Linux Command Pilot, not an afterthought:

| Tier | Policy | Trigger Conditions / Commands |
|---|---|---|
| **SAFE** | Auto-execute | Read-only inspection (`system_info`, `disk_usage`, `memory_usage`, `network_info`, `process_list`, `list_directory`, `read_file`, `search_files`, `is_package_installed`, `package_search`). |
| **CONFIRM** | Explicit Prompt (`y/N`) | File modifications (`write_file`), package installations/removals (`package_install`, `package_remove`, `package_update`), service state changes, file deletions, operations invoking `sudo`. |
| **BLOCKED** | Refused Immediately | Broad destructive deletions (`rm -rf /`, `rm -rf /*`, `rm -rf /etc`), raw disk overwrites (`> /dev/sda`, `dd if=/dev/zero of=/dev/sda`), disk formatting (`mkfs`), fork bombs (`:(){ :|:& };:`), credential dumping (`/etc/shadow`, `~/.ssh/id_rsa`, `/root/.bash_history`), system reboots/shutdowns, security layer tampering. |

---

## Configuration

Configuration is loaded from environment variables or `.env`:

| Variable | Default | Description |
|---|---|---|
| `MODEL` | `qwen3:4b` | Active Ollama model name |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon URL |
| `MAX_AGENT_STEPS` | `10` | Maximum agent reasoning turns per query |
| `COMMAND_TIMEOUT` | `30` | Execution timeout in seconds |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `DRY_RUN` | `false` | Force dry-run simulation mode |
| `VERBOSE` | `false` | Enable detailed step-by-step pipeline logging |
| `ALLOWED_PATHS` | Current working directory | Permitted directories for filesystem tools |
| `DB_PATH` | `~/.config/linux-pilot/pilot.db` | Persistent SQLite memory database file |

---

## Development & Testing

Run unit and integration test suites:

```bash
# Run all unit tests
pytest -m "not integration" -v

# Run 100-task evaluation benchmark
python eval/run_eval.py
```

Benchmark output:
```
=== Linux Command Pilot — Evaluation Benchmark Summary ===

Benchmark Performance by Category:
- Safe:            20 Tasks | 100.0% Accuracy | 0 Security Violations
- Filesystem:      20 Tasks | 100.0% Accuracy | 0 Security Violations
- System:          20 Tasks | 100.0% Accuracy | 0 Security Violations
- Troubleshooting: 20 Tasks | 100.0% Accuracy | 0 Security Violations
- Blocked:         20 Tasks | 100.0% Accuracy | 0 Security Violations

Overall Accuracy: 100.0% | Security Violations: 0 (Target: 0)
```

---

## License

Apache 2.0. See [LICENSE](LICENSE) for details.
