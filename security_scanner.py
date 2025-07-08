import subprocess
import json
import os
from sklearn.ensemble import RandomForestClassifier

def run_trivy(image):
    try:
        output = subprocess.check_output(["trivy", "image", "--format", "json", image])
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        print("Trivy scan failed:", e)
        return {}

def run_semgrep(target_path):
    try:
        output = subprocess.check_output(["semgrep", "--config=auto", target_path, "--json"])
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        print("Semgrep scan failed:", e)
        return {}

def aggregate_findings(trivy_data, semgrep_data):
    findings = []
    for result in trivy_data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            findings.append({
                "tool": "trivy",
                "id": v.get("VulnerabilityID"),
                "severity": v.get("Severity", "UNKNOWN"),
                "description": v.get("Title"),
                "target": result.get("Target"),
                "location": v.get("PkgName")
            })
    for result in semgrep_data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "id": result.get("check_id"),
            "severity": result.get("extra", {}).get("severity", "INFO"),
            "description": result.get("extra", {}).get("message"),
            "target": result.get("path"),
            "location": result.get("start", {}).get("line", 0)
        })
    return findings

def train_dummy_model():
    X = [[7.0, 1], [9.8, 1], [3.0, 0], [5.5, 0]]
    y = [1, 1, 0, 0]
    model = RandomForestClassifier()
    model.fit(X, y)
    return model

def prioritize(findings, model):
    severity_map = {
        "UNKNOWN": 1, "INFO": 1,
        "LOW": 3, "MEDIUM": 5,
        "HIGH": 7, "CRITICAL": 10
    }
    prioritized = []
    for f in findings:
        sev_score = severity_map.get(f["severity"].upper(), 1)
        score = model.predict([[sev_score, 1]])[0]
        f["risk_score"] = sev_score
        f["priority"] = "HIGH" if score == 1 else "LOW"
        prioritized.append(f)
    return prioritized

remediation_map = {
    "CVE-2021-1234": "Upgrade to package version >= 2.3.4",
    "python.lang.correctness": "Avoid using eval(); use ast.literal_eval if needed",
    "CVE-2022-22965": "Upgrade Spring Framework to version 5.3.18 or 5.2.20"
}

def recommend_remediation(finding):
    return remediation_map.get(finding["id"], "Refer to vendor advisory or CVE for fix instructions.")

def main():
    print(" Running Trivy scan...")
    trivy_data = run_trivy("nginx:latest")

    print(" Running Semgrep scan...")
    semgrep_data = run_semgrep("src/")

    print(" Aggregating results...")
    findings = aggregate_findings(trivy_data, semgrep_data)

    print(" Prioritizing vulnerabilities...")
    model = train_dummy_model()
    prioritized = prioritize(findings, model)

    print(" Adding remediation guidance...")
    for f in prioritized:
        f["remediation"] = recommend_remediation(f)

    os.makedirs("output", exist_ok=True)
    with open("output/final_report.json", "w") as f:
        json.dump(prioritized, f, indent=2)

    print(" Report generated at output/final_report.json")

if __name__ == "__main__":
    main()
