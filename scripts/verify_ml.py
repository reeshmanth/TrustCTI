from ml.predictor import URLPredictor

p = URLPredictor.get_instance()
test_cases = [
    ("http://br-icloud.com.br", "Known Phishing"),
    ("https://en.wikipedia.org/wiki/Computer_security", "Legitimate Wiki"),
    ("http://signin.eby.de.zukruygxctzmmqi.civpro.co.za", "Known Phishing Subdomain"),
    ("http://adventure-nicaragua.net/index.php?option=com_mailto&tmpl=component&link=aHR0cD", "Known Malware Carrier"),
    ("http://192.168.1.100/admin/shell.php?cmd=whoami", "Webshell on IP Host")
]

print("=== ML PREDICTION & SHAP EXPLANATION VERIFICATION ===")
for url, label in test_cases:
    res = p.analyze_url(url)
    print(f"\nTarget: {url} ({label})")
    print(f"  Classification:       {res['classification']} ({res['threat_type']})")
    print(f"  Confidence:           {res['confidence'] * 100:.2f}%")
    print(f"  Threat Risk Score:    {res['threat_risk_score']}/100 [{res['threat_risk_category']}]")
    print(f"  CTI Trust Score:      {res['cti_trust_score']}/100 [{res['cti_trust_category']}]")
    print("  Top Contributing SHAP Features:")
    for f in res['shap_summary']['top_features'][:3]:
        print(f"    • {f['feature']} = {f['value']} -> SHAP: {f['shap_value']:+.4f} ({f['impact']})")

