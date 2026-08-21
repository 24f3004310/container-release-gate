import re
from flask import Flask, request, jsonify

app = Flask(__name__)

HEX_40_REGEX = re.compile(r"^[0-9a-f]{40}$")

@app.route('/release-gate', methods=['POST'])
def release_gate():
    data = request.get_json() or {}
    workflow = data.get("workflow", {})
    image = data.get("image", {})
    target = data.get("target")
    event = data.get("event")
    ref = data.get("ref")

    violations = []

    # 1. Permissions
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    actual_perms = workflow.get("permissions", {})
    if actual_perms != expected_perms:
        violations.append("EXCESS_PERMISSION")

    # 2. PR Trigger
    if event == "pull_request":
        if workflow.get("trigger") == "pull_request_target":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests & Matrix
    if not (workflow.get("testsPassed") is True and 
            workflow.get("matrixComplete") is True and 
            workflow.get("failFast") is False):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning
    actions = workflow.get("actions", [])
    for act in actions:
        owner = act.get("owner")
        action_ref = act.get("ref", "")
        if owner != "actions":
            if not HEX_40_REGEX.match(action_ref):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Image Multi-Stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Root Runtime
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secret Mode
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # 8. Critical CVEs
    if image.get("criticalVulnerabilities", -1) != 0:
        violations.append("CRITICAL_CVE")

    # 9. Digest Pinned
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10. Production Checks
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"
    return jsonify({"decision": decision, "violations": violations})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)