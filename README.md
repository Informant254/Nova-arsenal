# Nova Arsenal - Autonomous AI-powered Bug Bounty Hunting Agent

Nova Arsenal is a cutting-edge, fully autonomous security research agent designed to streamline and enhance bug bounty hunting operations. It leverages advanced AI capabilities, including a local LLM, a real headless browser, and a vast arsenal of security tools, to conduct comprehensive vulnerability assessments from a single command.

## Features

Nova is engineered to perform a wide array of security tasks autonomously:

*   **Autonomous Campaign Planning and Execution**: Nova can plan and execute entire bug bounty hunts from a single, high-level command.
*   **Extensive Tool Integration**: Utilizes over 1,000 security tools, intelligently selecting the most appropriate ones for each mission.
*   **Local LLM Integration**: Employs a local Ollama LLM for reasoning, eliminating the need for paid API access.
*   **Real Headless Browser**: Operates a Playwright headless browser for effective interaction with JavaScript-heavy targets.
*   **Vulnerability Chaining**: Capable of chaining multiple vulnerabilities (e.g., SSRF to metadata, SQLi to RCE) to identify complex attack paths.
*   **Continuous Learning**: Learns from every hunt, adapting and improving its strategies over time.
*   **Self-Modification Engine**: Features a safe self-modification engine, allowing Nova to evolve its own code to enhance performance.
*   **Real-time Reporting**: Sends real-time findings and generates professional reports in HTML, Markdown, and JSON formats.
*   **Cloud Execution**: Designed to run 24/7 on GitHub's cloud Linux environment (GitHub Actions).

## Architecture

Nova's architecture is modular, allowing for robust and scalable security operations. The `nova.py` orchestrator acts as the central dispatch, interpreting natural language commands and delegating tasks to specialized modules. The core components include:

*   **Reasoning Core (`nova_reasoning_core.py`)**: The LLM-powered engine that drives Nova's decision-making, task planning, and vulnerability analysis.
*   **Toolbox (`nova_toolbox.py`)**: Manages and deploys a vast collection of security tools, dynamically selecting the best fit for specific attack vectors.
*   **Browser Agent (`nova_browser.py`)**: Utilizes Playwright for web interaction, research, and exploitation of web applications.
*   **Memory System (`nova_memory_system.py`)**: Stores persistent knowledge and learning from past hunts, enabling continuous improvement.
*   **Evolution Engine (`nova_evolution.py`)**: Facilitates safe self-modification of Nova's codebase based on learned insights.
*   **Report Generator (`nova_report.py`)**: Compiles detailed, professional reports of findings, including CVSS scores, reproduction steps, impact, and remediation advice.
*   **Vulnerability Tracker (`nova_vuln_tracker.py`)**: A SQLite-based database for tracking vulnerabilities across runs, identifying regressions and new issues.
*   **Cloud Integration (`nova_cloud.py`)**: Manages deployment and monitoring of hunts within GitHub Actions.

The following diagram illustrates the high-level architecture of the Nova Arsenal:

![Nova Arsenal Architecture](https://files.manuscdn.com/user_upload_by_module/session_file/310519663614776290/mxAdcBmzlqBHnkRP.png)

## Installation

To set up Nova Arsenal locally, follow these steps:

### 1. Clone the Repository

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
```

### 2. Run the Setup Script

Nova comes with a convenient setup script that handles dependencies and environment configuration.

```bash
chmod +x nova_setup.sh && ./nova_setup.sh
```

This script will set up a Python virtual environment and install necessary tools.

## Usage

Once installed, you can launch Nova for a bug bounty hunt. Ensure your virtual environment is activated.

### Local Hunt

```bash
source ~/nova_workspace/.venv/bin/activate
python nova.py "Launch Mythos Black on https://target.com" --autonomous
```

Replace `https://target.com` with your authorized target URL.

### Cloud Hunt (GitHub Actions)

Nova can also be run in the cloud using GitHub Actions. This requires a `GITHUB_TOKEN` to be set as a secret in your repository.

```bash
# From anywhere, using just Python + your GitHub token
export GITHUB_TOKEN=your_token # Replace with your actual GitHub token
python nova_cloud.py hunt https://target.com
python nova_cloud.py hunt https://target.com --evolve  # evolve after hunt
python nova_cloud.py watch 12345678                     # watch live
python nova_cloud.py results                            # get findings
python nova_cloud.py brain                              # see what she learned
```

## Reporting

After each hunt, Nova generates comprehensive reports in various formats:

*   `cloud_reports/nova_report_<target>_<date>.html` — Full visual report
*   `cloud_reports/nova_report_<target>_<date>.md` — Markdown (HackerOne-ready)
*   `cloud_reports/nova_report_<target>_<date>.json` — Machine-readable

Each finding includes a CVSS score, reproduction steps, impact analysis, and remediation advice.

## Legal Notice

Nova Arsenal is built for **authorised security testing only**. The default `targets.txt` contains intentionally vulnerable practice targets. **Never hunt targets without explicit written permission.** You are responsible for all use of this tool.

## Stack

*   **Languages**: Python 3.12, Go 1.21+, Node.js, Ruby, Rust/Cargo
*   **LLM**: Ollama (local LLM, no API cost)
*   **Browser Automation**: Playwright (real headless browser)
*   **Cloud Environment**: GitHub Actions (cloud Linux environment)
*   **Security Tools**: 1,000+ specialized security tools across various categories.
