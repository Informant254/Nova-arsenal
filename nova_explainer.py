from nova_explainer import FindingExplainer
explainer = FindingExplainer(finding)
print(explainer.generate_full_explanation())
# Shows full attack chain + PoC + patch + detection rules
