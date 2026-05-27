# Paste this logic directly over Nova's final summary reporting loop:

print("\n==================================================")
print("📊 HUNT SUMMARY")
print(f"Submission-Ready Findings: {len([f for f in findings if f['severity'] in ['MEDIUM', 'HIGH']])}")
print(f"Structural Hardening Items: {len([f for f in findings if f['severity'] == 'LOW'])} (logged, not submitted)")
print("==================================================")
print("📊 LIVE HUNT COMPLETE")
print(f"Target: {TARGET}")

print("\n💀 FINDINGS FOR HACKERONE SUBMISSION:")
submission_ready = [f for f in findings if f["severity"] in ["MEDIUM", "HIGH"]]

if not submission_ready:
    print("  [-] None. Clean high-fidelity perimeter sweep completed.")
else:
    for finding in submission_ready:
        print(f"  [{finding['severity']}] {finding['type']}: {finding['path']}")

print(f"\n📁 Log Saved To: {OUTPUT_FILE}")
