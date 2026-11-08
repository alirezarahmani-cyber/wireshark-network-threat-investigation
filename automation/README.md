# Python PCAP Analyzer — Optional Automation

## Overview

This directory contains a reusable Python utility developed to support offline network traffic analysis and indicator extraction.

The tool is intended to automate selected repetitive analysis tasks and complement manual investigations performed with Wireshark.

The primary security findings in this project were established through Wireshark packet inspection and evidence correlation, rather than automated malware detection.

**Validation Status:** The revised reusable implementation has not yet been independently tested.

## Files

| File | Description |
|---|---|
| `analyzer.py` | Python PCAP analysis utility |
| `requirements.txt` | Python dependency specification |
| `README.md` | Installation and usage instructions |

## Requirements

- Python 3
- Scapy 2.8.0
- An authorized `.pcap` or `.pcapng` file

## Installation

Open a terminal in the repository root directory.

### 1. Create a Virtual Environment

```powershell
python -m venv .venv
```

### 2. Activate the Virtual Environment

For Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Alternatively, use the virtual environment's Python executable directly without activating it.

### 3. Install Dependencies

```powershell
python -m pip install -r automation/requirements.txt
```

## Usage

Run the analyzer from the repository root directory.

### Basic Execution

```powershell
python automation/analyzer.py "path\to\capture.pcap"
```

Replace `path\to\capture.pcap` with the actual location of your packet capture file.

### Specify an Output Directory

```powershell
python automation/analyzer.py "path\to\capture.pcap" --output-dir "output"
```

The `--output-dir` option allows you to select a custom directory for generated results.

### Use a Custom Indicator File

```powershell
python automation/analyzer.py "path\to\capture.pcap" --indicators "path\to\indicators.json"
```

The optional indicator file uses JSON to supply indicators for matching against selected network traffic attributes.

### Combine Optional Arguments

```powershell
python automation/analyzer.py "path\to\capture.pcap" --indicators "path\to\indicators.json" --output-dir "output"
```

## Command-Line Arguments

| Argument | Description | Required |
|---|---|---|
| `pcap` | Path to the input PCAP or PCAPNG file | Yes |
| `--indicators` | Path to a custom JSON indicator file | No |
| `--output-dir` | Directory for generated analysis results | No |

If `--output-dir` is omitted, the analyzer uses the following default structure:

```text
output/
└── <capture-name>/
```

The capture name is derived from the input filename without its extension.

## Intended Functionality

The analyzer is designed to support:

- Offline PCAP and PCAPNG processing.
- Basic network traffic summarization.
- Extraction of selected network communication details.
- Identification of frequently observed communication pairs.
- Matching selected network attributes against optional indicators.
- Exporting structured analysis results.

These functions are intended to support investigative workflows rather than replace detailed packet inspection.

## Output

The analyzer is designed to write structured analysis results to a designated output directory.

The reviewed implementation includes JSON summary generation and console output displaying traffic statistics and selected communication pairs.

Generated results should be reviewed before being used in an investigation report.

## Validation and Limitations

The original investigation included manual Wireshark analysis and supporting Python-based traffic extraction.

The analyzer was subsequently revised into a reusable utility for additional PCAP files.

**The revised implementation has not yet been independently validated through a complete execution test.**

Consequently:

- Successful execution is not guaranteed across all PCAP files.
- Extracted results may differ from Wireshark protocol statistics.
- Indicator matches do not automatically establish malicious activity.
- The tool does not independently confirm endpoint compromise.
- Automated findings require analyst verification.

The utility should be treated as an educational and investigative supporting tool, not a production-ready detection system.

## Security Considerations

- Analyze only packet captures obtained from authorized sources.
- Prefer offline or isolated analysis environments.
- Do not execute scripts or executable payloads extracted from suspicious traffic.
- Avoid uploading sensitive or confidential packet captures to public repositories.
- Review generated outputs before sharing them.
- Do not interpret unusual traffic volume or indicator matches as definitive evidence of malware.

## Relationship to the Main Investigation

This utility is an optional supporting component of the Network Traffic Security Investigation project.

The project's primary findings include suspicious script delivery, executable-format HTTP transfers, repeated HTTP requests, possible persistence reporting, and additional encrypted TLS communications.

Those findings were established through manual Wireshark analysis and documented network evidence.

The Python utility is included to demonstrate an additional approach to traffic processing and investigative automation.

For the complete investigation, refer to the main repository README and the full incident investigation report.

---

**Disclaimer:** This utility is intended for defensive cybersecurity education and authorized network traffic analysis only.