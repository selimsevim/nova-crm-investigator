# Autonomous CRM Incident Investigator (Hackathon)

**Built for the AWS & Amazon Nova Hackathon** 

An autonomous, agentic system powered by **Amazon Nova Pro v1** deployed on **Amazon Bedrock** and **Amazon Athena** that detects, traces, and diagnoses CRM data pipeline anomalies (specifically, source volume drops) in seconds.

Instead of manually debugging SQL queries, tracking down peer patterns, and attempting to rule out false positives, the **Incident Investigator** spots anomalies and independently executes a sequence of bounded data-warehouse queries (via Athena) to produce a clear, evidence-backed operational summary.

---

## Project Components

This repository contains five primary artifacts demonstrating the complete mock data-lifecycle—from generating synthetic anomalies to autonomous root-cause analysis and a hackathon presentation deck.

### 1. `generate_leads.py`
A python script that generates a highly-realistic, 500k row synthetic CRM leads dataset spanning 5 months. 
- Creates normal daily patterns with weekday/weekend seasonality and country-specific weighting across multiple sources (e.g. `web_form`, `crm_import`, `LinkedinForm_2026`, etc.).
- Explicitly injects deterministic *anomalies* into the final week of data: 
  - **Isolated drop:** `FR | LinkedinForm` goes to 0 overnight.
  - **Broader multi-country weakness:** `GB | web_form` and `DE | web_form` both experience an 85% drop.
- Outputs the mock data to a CSV (`leads_500k.csv`).

### 2. `query_creation` (Bash)
A setup script used to programmatically register **Amazon Athena Named Queries**. The LLM uses these queries as its tools. Included tools:
- `inv_prep_recent_vs_hist_volume`: Aggregates the last 28 days of data vs the last 7 days to flag candidates.
- `inv_trace_target_volume_trend`: Day-by-day 7d volume trend.
- `inv_trace_country_peer_volumes`: Evaluates if the issue is a "country-wide" pipeline failure by looking at other sources in the same country.
- `inv_trace_source_family_peers`: Evaluates if a source's anomaly is part of a "broader multi-country weakness" by looking at the same source family across other countries.
- `inv_trace_target_last_seen`: Extracts the specific timestamp the pipeline failed.
- `inv_trace_recent_target_sample`: Pulls a 25-row sample for final inspection.

### 3. `main.py`
The core Autonomous Investigator agent.
- **Bootstrapping:** Scans the target database using the preparatory `inv_prep_recent_vs_hist_volume` query to isolate any sub-group experiencing severe (>50%) recent volume drops.
- **Agentic Loop:** For each flagged anomaly, it invokes **Amazon Bedrock (`eu.amazon.nova-pro-v1:0`)** with a strict system prompt and strict evaluation rules.
- **Tool Execution:** Nova receives the anomaly and iteratively calls the Athena Named Queries to test hypotheses iteratively.
- **Session Memory:** Implements a global session memory struct `SourceSessionState` and `CountrySessionState`. If the LLM establishes a "broader multi-country same-source weakness" on the first flagged country, it skips analyzing the source-family again for the next country's iteration.
- **Output:** Returns a validated, strictly typed JSON root-cause verdict and saves it to `incident_report.txt` and `investigation_log.json`.

### 4. `presentation-v2.html`
The interactive, slick hackathon pitch deck showcasing the problem of slow debugging, highlighting the multi-agent investigation path, comparing traditional stacks with the Nova architecture, and containing a simulated terminal demo. Open it in any modern browser!

---

## How to Run the Demo

### Prerequisites
- Python 3.9+
- AWS CLI configured with active credentials
- Appropriate IAM permissions for **Amazon Bedrock** (Model access to Amazon Nova Pro v1) and **Amazon Athena/S3**.

### 1. Generate the Mock Dataset
```bash
pip install pandas faker
python generate_leads.py
```
*This generates `leads_500k_hackathon_clean.csv`. Upload this CSV to an S3 bucket connected to an Athena database table named `leads` in the `crm_monitoring_demo` database.*

### 2. Initialize Athena Named Queries
Run the bash script to map the diagnostic tools into Athena:
```bash
chmod +x query_creation
./query_creation
```

### 3. Launch the Autonomous Investigator
```bash
pip install boto3
export ATHENA_DATABASE="crm_monitoring_demo"
export ATHENA_WORKGROUP="primary"
export BEDROCK_MODEL_ID="eu.amazon.nova-pro-v1:0"

python main.py
```

Watch the terminal window as Nova Pro sequences hypothesis tests! Let it run until it delivers the final JSON verdict for all affected CRM cohorts.

---

## Key Highlights
- **Strict Guardrails:** The LLM is forced to cite hard numbers (percentages and actual rows) to confirm drops.
- **Bounded Tooling:** Instead of giving the LLM carte-blanche `text-to-SQL`, it is tightly restricted to a finite state machine of pre-vetted queries to ensure zero hallucinations and extreme cost-efficiency.
- **Stateful Memory:** Multi-anomaly deduplication via Python session memory. The LLM gets injected context of early findings to shortcut subsequent investigation routes.
