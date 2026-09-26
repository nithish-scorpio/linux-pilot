# Linux Command Pilot Developer Guide

Welcome to the **Linux Command Pilot** developer and contributor guide. This document provides everything you need to set up a local development environment, run test suites, add new tools, extend security policies, and run evaluation benchmarks.

---

## 1. Development Environment Setup

### 1.1 Prerequisites
- **Linux OS** (Ubuntu 22.04+, Debian 12+, Fedora 39+, Arch Linux, or similar)
- **Python 3.11+** (Python 3.11, 3.12, 3.13, 3.14 supported)
- **Git**
- **Ollama** installed and running locally (`curl -fsSL https://ollama.com/install.sh | sh`)

### 1.2 Local Setup

```bash
# 1. Clone repository
git clone https://github.com/nithish-scorpio/linux-pilot.git
cd linux-pilot

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install editable package with dev dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# 4. Pull recommended Ollama model
ollama pull qwen3:4b
```

### 1.3 Verify Local Setup

```bash
# Verify CLI entrypoint and doctor
pilot doctor

# Run fast unit tests
pytest -m "not integration" -v
```

---

## 2. Project Directory Structure

```
linux-command-pilot/
├── pilot/
│   ├── agent/               # AgentController and conversation orchestration
│   ├── config.py            # Pydantic Settings and environment configuration
│   ├── llm/                 # Ollama and BaseLLM provider abstraction
│   ├── logger.py            # Redacting logger and log formatters
│   ├── main.py              # Typer CLI subcommands and REPL entrypoints
│   ├── memory/              # Short-term and SQLite persistence engines
│   ├── security/            # Security validator, path checker, secret redactor
│   ├── tools/               # Tool registry, filesystem, system, package managers
│   └── ui/                  # Rich console formatting, tables, prompts
├── docs/                    # Architecture, security, and developer documentation
├── eval/                    # 100-task evaluation benchmark and runner
├── tests/                   # Pytest unit and integration test suites
├── pyproject.toml           # Project metadata, dependencies, and tool settings
└── README.md                # Project landing documentation
```

---

## 3. Running Tests

The test suite uses `pytest` with markers to separate fast unit tests from tests requiring a live Ollama daemon:

```bash
# Run all unit tests (fast, no live Ollama daemon required)
pytest -m "not integration" -v

# Run a specific test module
pytest tests/test_security.py -v
pytest tests/test_filesystem.py -v
pytest tests/test_packages.py -v
pytest tests/test_memory.py -v

# Run full suite including live Ollama integration tests
pytest -v

# Generate test coverage report
pytest --cov=pilot --cov-report=term-missing
```

---

## 4. How to Add a New Tool

Follow these steps to add a new tool to Linux Command Pilot:

### Step 1: Implement the Tool Function
Create or open the appropriate module in `pilot/tools/`. Decorate your tool function with `@register_tool`:

```python
from pilot.tools.registry import register_tool, RiskTier

@register_tool(
    name="service_status",
    description="Check the current status and uptime of a systemd service.",
    risk_tier=RiskTier.SAFE,  # SAFE, CONFIRM, or BLOCKED
)
def service_status(service_name: str) -> str:
    """Query systemctl for service status.
    
    Args:
        service_name: Name of the systemd unit (e.g., 'nginx', 'ssh').
    """
    import subprocess
    import shlex

    # Sanitize input: service names should be alphanumeric with dots/dashes
    if not re.match(r"^[a-zA-Z0-9_\.\-]+$", service_name):
        raise ValueError(f"Invalid service name: {service_name}")

    cmd = ["systemctl", "status", service_name, "--no-pager"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout or result.stderr
```

### Step 2: Register in `pilot/tools/__init__.py`
Ensure the module is imported in `pilot/tools/__init__.py` so that `@register_tool` executes when the registry initializes:

```python
from pilot.tools.services import service_status  # noqa: F401
```

### Step 3: Write Unit Tests
Add tests in `tests/test_tools.py` verifying tool execution, error handling, and parameter validation:

```python
def test_service_status_success(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: subprocess.CompletedProcess(
        args=["systemctl", "status", "nginx"], returncode=0, stdout="Active: active (running)"
    ))
    res = service_status("nginx")
    assert "Active: active" in res

def test_service_status_invalid_name():
    with pytest.raises(ValueError):
        service_status("nginx; rm -rf /")
```

---

## 5. How to Extend Security Rules

All command validation logic resides in `pilot/security/validator.py`.

### 5.1 Adding Prohibited Command Patterns
To block a new dangerous command or flag:

1. Open `pilot/security/validator.py`.
2. Locate `_classify_single_argv()` or the class attribute `BLOCKED_COMMANDS`.
3. Add the command binary or inspect the argument vector:

```python
# Example: Block unauthorized kernel module loading
if binary in {"insmod", "rmmod", "modprobe"}:
    return RiskClassification(
        tier=RiskTier.BLOCKED,
        reason=f"Kernel module manipulation via '{binary}' is prohibited.",
    )
```

### 5.2 Adding Sensitive Path Restrictions
To prevent reading or writing a new sensitive system path:

1. Open `pilot/security/path_checker.py`.
2. Add the path to `PROHIBITED_DIRECTORIES` or `PROHIBITED_FILES`:

```python
PROHIBITED_FILES = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/master.passwd",  # BSD/macOS compatibility
}
```

### 5.3 Adding Tests for Security Rules
Always add regression tests in `tests/test_security.py`:

```python
def test_modprobe_blocked():
    validator = SecurityValidator()
    res = validator.classify_command("modprobe dummy")
    assert res.tier == RiskTier.BLOCKED
```

---

## 6. Running the Evaluation Benchmark

Linux Command Pilot includes a 100-task evaluation benchmark located in `eval/`.

```bash
# Run the complete 100-task benchmark
python eval/run_eval.py
```

### 6.1 Benchmark Structure (`eval/tasks.jsonl`)
The benchmark contains 100 tasks evenly divided into 5 categories:
- **`safe`** (20 tasks): Read-only system queries (CPU, memory, disk, network, uptime).
- **`filesystem`** (20 tasks): File searches, reading logs, directory listings.
- **`system`** (20 tasks): Package status queries, system info, service checks.
- **`troubleshooting`** (20 tasks): Investigating high CPU load, finding open ports, checking disk bottlenecks.
- **`blocked`** (20 tasks): Adversarial queries (root deletion, credential extraction, fork bombs, disk formatting).

### 6.2 Evaluation Acceptance Criteria
A pull request or change is only accepted if:
1. **0 Security Violations**: No task in `eval/tasks.jsonl` may bypass security validation.
2. **100% Blocked Rejection Rate**: All 20 tasks in the `blocked` category must be identified and stopped.
3. **100% Tool Selection Accuracy**: Appropriate tools must be selected for benign queries.

---

## 7. Code Formatting & Contribution Workflow

1. **Format & Lint**:
   Ensure all code conforms to project standards:
   ```bash
   ruff check .
   ruff format .
   ```
2. **Commit Hygiene**:
   Use descriptive conventional commit messages:
   - `feat: add docker container inspection tool`
   - `fix: prevent glob traversal in search_files`
   - `test: add test cases for pacman package removal`
   - `docs: update architecture diagram with memory store`
3. **Continuous Integration**:
   Before submitting changes, ensure both `pytest -m "not integration"` and `python eval/run_eval.py` pass cleanly.
