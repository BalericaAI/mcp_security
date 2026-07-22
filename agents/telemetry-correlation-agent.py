```python
import os
import json
from collections import defaultdict
from datetime import datetime

# ==========================================
# CONFIG
# ==========================================

TELEMETRY_DIR = "/opt/ai-soc/incoming"

CORRELATED_OUTPUT = \
"/opt/ai-soc/correlated/correlated_findings.json"

# ==========================================
# RISK SCORING
# ==========================================

RISK_SCORES = {
    "critical_cve": 40,
    "shell_spawn": 35,
    "tls_failure": 15,
    "cert_expiring": 10,
    "policy_violation": 20
}

# ==========================================
# STORAGE
# ==========================================

student_findings = defaultdict(list)

# ==========================================
# LOAD EVENTS
# ==========================================

for root, dirs, files in os.walk(TELEMETRY_DIR):

    for file in files:

        if not file.endswith(".json"):
            continue

        path = os.path.join(root, file)

        try:

            with open(path, "r") as f:

                event = json.load(f)

                student_id = event.get(
                    "student_id",
                    "unknown"
                )

                student_findings[student_id].append(
                    event
                )

        except Exception as e:

            print(
                f"Failed to process {path}: {e}"
            )

# ==========================================
# CORRELATION
# ==========================================

results = []

for student_id, events in student_findings.items():

    risk_score = 0

    event_summary = []

    for event in events:

        event_type = event.get(
            "event_type",
            ""
        )

        score = RISK_SCORES.get(
            event_type,
            0
        )

        risk_score += score

        event_summary.append(event_type)

    # ======================================
    # RISK LEVEL
    # ======================================

    if risk_score >= 81:
        level = "CRITICAL"

    elif risk_score >= 51:
        level = "HIGH"

    elif risk_score >= 21:
        level = "MEDIUM"

    else:
        level = "LOW"

    result = {
        "student_id": student_id,
        "timestamp": str(datetime.utcnow()),
        "risk_score": risk_score,
        "risk_level": level,
        "events": event_summary
    }

    results.append(result)

# ==========================================
# OUTPUT RESULTS
# ==========================================

with open(CORRELATED_OUTPUT, "w") as f:

    json.dump(results, f, indent=2)

print("\n=== CORRELATED FINDINGS ===\n")

for result in results:

    print(json.dumps(result, indent=2))
```
