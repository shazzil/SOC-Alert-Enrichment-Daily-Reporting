# =====================================
# SOC Enrichment Workflow Using Wazuh and n8n
# =====================================

project:
  title: "SOC Enrichment Workflow (Version 2)"
  platform: "n8n"
  status: "in-progress"
  phase: "development"
  domain: "Cybersecurity / SOC Automation"
  description: >
    This workflow ingests alerts from Wazuh, checks for IOC data
    (hash or URL), enriches alerts using VirusTotal, stores results
    in PostgreSQL, and generates daily HTML email reports.

# -------------------------------------
# Embedded Diagram Preview
# -------------------------------------
diagram:
  image: "docs/workflow_architecture.png"
  note: "Exported screenshot of n8n workflow"

# -------------------------------------
# Workflow Overview
# -------------------------------------
workflow:
  name: "SOC IOC Enrichment Pipeline v2"
  triggers:
    - Webhook (real-time Wazuh alerts)
    - Schedule Trigger (daily reporting)

  summary:
    - Receive Wazuh alert
    - Check for IOC (hash/url)
    - Enrich using VirusTotal
    - Store results in PostgreSQL
    - Generate daily HTML report
    - Send report via Gmail

# -------------------------------------
# Trigger Nodes
# -------------------------------------
triggers:

  webhook_trigger:
    type: webhook
    purpose: >
      Receives real-time alerts from Wazuh manager.
    output: raw alert JSON

  schedule_trigger:
    type: schedule
    frequency: daily
    purpose: >
      Executes daily report generation.

# -------------------------------------
# Real-Time Enrichment Pipeline
# -------------------------------------
pipeline_realtime:

  - node: If
    purpose: Check if alert contains IOC (hash or URL)
    outputs:
      true: proceed to VirusTotal
      false: stop

  - node: VirusTotal HTTP Request
    type: HTTP Request
    method: GET
    endpoint_logic:
      hash: "https://www.virustotal.com/api/v3/files/{hash}"
      url: "https://www.virustotal.com/api/v3/urls/{url}"
    purpose: IOC enrichment

  - node: Code in JavaScript
    purpose: Parse VirusTotal results
    extracts:
      - ioc
      - malicious
      - suspicious
      - harmless
      - undetected
      - severity
      - vt_link

  - node: Insert rows in a table
    type: PostgreSQL
    operation: insert
    table: soc_alerts
    purpose: Store enriched alerts

# -------------------------------------
# Daily Reporting Pipeline
# -------------------------------------
pipeline_reporting:

  - node: Select rows from a table
    type: PostgreSQL
    operation: select
    table: soc_alerts
    purpose: Collect stored alerts

  - node: Code in JavaScript2
    purpose: Build HTML table rows
    outputs:
      - table_rows
      - total_alerts

  - node: HTML
    operation: generateHtmlTemplate
    purpose: Build SOC daily report

  - node: Send a message
    type: Gmail
    purpose: Send daily report email

# -------------------------------------
# Database Schema
# -------------------------------------
database:
  engine: PostgreSQL
  table: soc_alerts
  columns:
    - id
    - timestamp
    - rule_id
    - description
    - level
    - source_ip
    - mitre_id
    - mitre_tactic
    - mitre_technique
    - ioc
    - malicious
    - suspicious
    - harmless
    - undetected
    - severity
    - vt_link

# -------------------------------------
# Workflow Logic Notes
# -------------------------------------
logic:
  cache_strategy: >
    Future improvement: check PostgreSQL first for existing IOC
    before querying VirusTotal to reduce API usage.

  severity_mapping:
    low: 0-3 malicious engines
    medium: 4-9 malicious engines
    high: 10+

# -------------------------------------
# Version Changes
# -------------------------------------
version_changes:
  - Added PostgreSQL storage layer
  - Added daily report pipeline
  - Added HTML report generation
  - Added Gmail delivery
  - Improved IOC normalization

# -------------------------------------
# Future Improvements
# -------------------------------------
future:
  - IOC cache lookup before VirusTotal
  - Slack integration
  - SOC dashboard (Grafana/Kibana)
  - Automatic incident scoring
