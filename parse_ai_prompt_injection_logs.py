import re
import sys

PATTERNS = {
    "unauthorized_prompt_commit": r"COMMIT.*(prompt|template).*user=",
    "unknown_signature": r"unknown GPG key|signature verification failed",
    "prompt_injection": r"ignore previous instructions|print env|exfiltrate|reveal secret",
    "secret_output": r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|BEGIN PRIVATE KEY)",
    "artifact_hash_drift": r"hash mismatch|digest drift|signature mismatch",
    "runtime_callback": r"OUTBOUND connection.*(not in allowlist|unknown domain)",
}


def extract_signals(line):
    signals = []
    if re.search(PATTERNS["unauthorized_prompt_commit"], line, re.IGNORECASE):
        signals.append("Unauthorized prompt/template commit")
    if re.search(PATTERNS["unknown_signature"], line, re.IGNORECASE):
        signals.append("Unknown commit/signature validation")
    if re.search(PATTERNS["prompt_injection"], line, re.IGNORECASE):
        signals.append("Prompt injection content")
    if re.search(PATTERNS["secret_output"], line, re.IGNORECASE):
        signals.append("Secret-like output in CI/agent logs")
    if re.search(PATTERNS["artifact_hash_drift"], line, re.IGNORECASE):
        signals.append("Artifact hash drift")
    if re.search(PATTERNS["runtime_callback"], line, re.IGNORECASE):
        signals.append("Unauthorized runtime callback")
    return signals


def main():
    for raw in sys.stdin:
        line = raw.strip()
        found = extract_signals(line)
        if found:
            print(f"{line} | Detected: {', '.join(found)}")


if __name__ == "__main__":
    main()
