# dataset_generator.py
"""
Generates a synthetic phishing email dataset for HunterTrace validation.
"""
import json
import random

COUNTRIES = ["US", "RU", "CN", "IN", "DE"]
OBFUSCATION_TYPES = ["vpn", "proxy", "tor", "none"]
SCENARIOS = ["vpn", "proxy", "tor", "direct"]


def generate_email(email_id, country, obfuscation, scenario):
    sender = f"{random.choice('abcdefghijklmnopqrstuvwxyz')*8}@mail.{country.lower()}.phish.com"
    ip = f"{random.randint(10, 99)}.180.183.{random.randint(40, 99)}"
    obf = obfuscation if obfuscation != "none" else "none"
    raw_email = (
        f"Message-ID: <{email_id}@huntertrace.test>\n"
        f"From: {sender}\n"
        f"To: victim@company.com\n"
        f"Subject: Test Phishing Email\n"
        f"Received: from [{ip}] (unknown [unknown]) by mx.company.com; Mon, 23 Mar 2026 10:00:00 +0000\n"
        f"X-Origin-Country: {country}\n"
        f"X-Obfuscation: {obf}\n\n"
        f"This is a synthetic phishing email for HunterTrace validation."
    )
    labels = {
        "true_origin_country": country,
        "obfuscation_types": [obf],
        "scenario": scenario,
        "ip": ip,
        "sender": sender,
        "email_id": email_id
    }
    return {"email_id": email_id, "raw_email": raw_email, "labels": labels}


def main():
    num_samples = 180
    data = []
    for i in range(num_samples):
        country = random.choice(COUNTRIES)
        scenario = random.choice(SCENARIOS)
        obfuscation = scenario if scenario != "direct" else "none"
        email_id = f"sample_{i:04d}"
        email = generate_email(email_id, country, obfuscation, scenario)
        data.append(email)
    with open("synthetic_phishing_dataset.jsonl", "w") as f:
        for email in data:
            f.write(json.dumps(email) + "\n")
    print(f"Generated {num_samples} synthetic phishing emails.")

if __name__ == "__main__":
    main()
