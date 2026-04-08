# Processing Flow Visualization — Quick Start

## 📋 What You Got

Four new files:

1. **`processing_flow_visualization.html`** (NEW UI)
   - Complete HTML/CSS/JavaScript
   - Integrated with existing Infrastructure Graph, Map, Heatmap panels
   - 4th tab: "Processing Flow"

2. **`PROCESSING_FLOW_GUIDE.md`** (complete reference)
   - Architecture, data schema, integration points
   - Colors, interactions, scalability notes

3. **`scripts/transform_to_flow.py`** (API transformer)
   - Automatic: `batch_results.json` → `flow_data.json`
   - CLI: `python transform_to_flow.py batch_results.json`

4. **`examples/flow_data_sample.json`** (test data)
   - 3 emails, 2 shared attacker IPs
   - Ready to visualize immediately

---

## 🚀 Get Running in 5 Minutes

### Step 1: Load Sample Data

```bash
# Replace __FLOW_DATA_JSON__ in HTML with sample data
cd /Users/lapac/Documents/projects/HunterTrace

# Copy sample into HTML for testing
cat examples/flow_data_sample.json | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('<script>')
print('const __FLOW_DATA_JSON__ =', json.dumps(data['flow_data_sample']), ';')
print('</script>')
" > /tmp/flow_data_inject.html
```

### Step 2: Open in Browser

```bash
# Open the HTML directly
open examples/processing_flow_visualization.html

# Or serve via HTTP
python3 -m http.server 8080
# Then visit: http://localhost:8080/examples/processing_flow_visualization.html
```

### Step 3: Test All Modes

- **All Emails** - See all 3 flows
- **Clustered** - See shared IP deduplication
- **Single Email** - Pick email #1, drill down

---

## 🔗 Connect to Your API

### Option A: Generate from /batch Endpoint

```bash
# 1. Run batch analysis
curl -X POST http://localhost:8000/batch \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      {"input_type": "email", "content": "From: attacker@domain.com\nTo: victim@company.com\nSubject: ...\n\nBody"},
      {"input_type": "email", "content": "..."}
    ]
  }' > batch_results.json

# 2. Transform to flow format
python3 scripts/transform_to_flow.py batch_results.json --output flow_data.json

# 3. Inject into HTML
python3 << 'EOF'
import json

# Load flow data
with open('flow_data.json') as f:
    flow_data = json.load(f)

# Read HTML template
with open('examples/processing_flow_visualization.html') as f:
    html = f.read()

# Replace placeholder
html = html.replace(
    '__FLOW_DATA_JSON__ = []',
    f'__FLOW_DATA_JSON__ = {json.dumps(flow_data)}'
)

# Write updated HTML
with open('processing_flow.html', 'w') as f:
    f.write(html)

print(f"✓ Generated processing_flow.html with {len(flow_data)} emails")
EOF

# 4. Open in browser
open processing_flow.html
```

### Option B: Real-time from Python

```python
from huntertrace.service.api import app
from fastapi.testclient import TestClient
from scripts.transform_to_flow import transform_batch_to_flow
import json

# Call API
client = TestClient(app)
response = client.post("/batch", json={
    "inputs": [
        {"input_type": "email", "content": "..."},
        # ...
    ]
})

# Transform
flow_data = transform_batch_to_flow(response.json())

# Save
with open('flow_data.json', 'w') as f:
    json.dump(flow_data, f, indent=2)

print(f"Generated {len(flow_data)} flow entries")
```

---

## 🎨 Visual Verification

### Layer Breakdown

When you open "Processing Flow" tab, you'll see:

```
[Input]    [Hop Chain]    [Signals]    [Correlation]    [Attribution]    [Verdict]
  Email        192.0.2.1        IP              ✓              85%         🔴
                mail.ru        ASN              ✓              high        Malicious
```

### Color Checks

✓ Red rectangles = Email (input)
✓ Gray circles = Servers/IPs (hops)
✓ Blue circles = IP signals, Green = ASN, Yellow = Timing
✓ Green diamond = Consistent, Red = Contradictions
✓ Red verdict box = Malicious

---

## 🔍 Interactive Features

### Hover
- Mouse over email path → highlights full forensic chain
- Mouse over shared hop ("2 emails") → shows all using it

### Click
- Email node → shows from/to/subject
- Hop node → shows IP, ASN, country
- Verdict node → shows status & risks

### Controls
- **Reset View** → D3 zoom back to fit
- **Toggle Labels** → Hide node text for less clutter
- **Mode selector** → Switch between All / Clustered / Single
- **Email selector** → (Single mode) pick specific email

---

## 📊 Data Flow Schema (Quick Reference)

Each email needs:

```javascript
{
  id: "email_1",
  from: "attacker@domain.com",
  to: "victim@company.com",
  subject: "...",

  hop_chain: [
    {
      index: 0,
      server: "mail.attacker.com",
      ip: "192.0.2.1",
      asn: "AS12345",
      country: "RU",
      signals: [
        {type: "ip", value: "192.0.2.1", confidence: 0.95}
      ]
    }
  ],

  correlation: {
    strength: "high",  // high | medium | low
    consistent_signals: 3,
    contradictions: 0,
    geography_consistent: true,
    timing_consistent: true
  },

  attribution: {
    confidence: 0.87,  // 0.0-1.0
    top_region: "Eastern Europe",
    regions: [
      {name: "Eastern Europe", probability: 0.45},
      {name: "Russia", probability: 0.35}
    ]
  },

  verdict: {
    status: "malicious",  // malicious | benign | suspicious
    confidence: 0.89,
    primary_reason: "infrastructure-overlap",
    risks: ["spoofing", "domain-impersonation"]
  }
}
```

---

## 🚨 Troubleshooting

### "No processing flow data available"
→ **Solution**: Check `__FLOW_DATA_JSON__` placeholder is replaced with actual array

### Nodes appear but no edges
→ **Likely**: Hop chain data missing or empty
→ **Fix**: Ensure each email has `hop_chain: [...]`

### Shared infrastructure not showing
→ **Mode**: Switch to "Clustered" mode (default is "All")
→ **Check**: Do emails share same `ip` or `server`?

### Empty visualization
→ **Debug**: Open browser console (F12), check for JS errors
→ **Verify**: Sample data loads correctly

### Performance slow with >100 emails
→ **Try**: Use "Clustered" mode to deduplicate
→ **Tip**: Filter to top 50 emails by confidence score

---

## 🔄 Integration Checklist

- [ ] HTML file integrated into app (or served separately)
- [ ] Data transformation script (`transform_to_flow.py`) tested
- [ ] Sample data visualizes correctly in browser
- [ ] Real API batch output transforms successfully
- [ ] All 4 modes working (All, Clustered, Single, Email selector)
- [ ] Hover/click interactions responsive
- [ ] Colors match forensic threat levels
- [ ] Performance acceptable for your dataset size

---

## 📚 Next Steps

### For DFIR Teams

1. **Validate forensic chain** - Click each node to verify reasoning
2. **Export for reports** - Take screenshots of key paths
3. **Share with incident team** - Use "Single Email" mode for focused analysis
4. **Compare campaigns** - Switch to "Clustered" to spot shared infrastructure

### For Development

1. **Add real-time animation** - See `@keyframes flow-dash` in CSS
2. **Export to PDF** - Use browser print or html2pdf lib
3. **3D visualization (future)** - Consider Babylon.js for 10K+ nodes
4. **Reverse lookup** - Click signal → fetch detailed IOCs

### For Research

1. **Attribution accuracy** - Does visualization help validation?
2. **UX feedback** - Which mode most intuitive?
3. **Scalability limits** - Test with actual large datasets

---

## 📞 Questions?

Refer to `PROCESSING_FLOW_GUIDE.md` for:
- Full data schema documentation
- Color semantics explanation
- Scalability notes & optimization tips
- Real-world integration examples
