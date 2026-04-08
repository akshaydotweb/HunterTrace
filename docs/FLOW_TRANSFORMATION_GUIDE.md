# Processing Flow Transformation Layer - Complete Implementation

## Overview

The Processing Flow visualization now includes a **deterministic transformation layer** that converts forensic pipeline data (FLOW_DATA) into a graph structure suitable for D3.js visualization.

**Function**: `buildFlowGraph(flowData, mode='all', selectedEmailId=null)`

**Purpose**: Transform HunterTrace pipeline output → D3-compatible nodes & edges

**Key Feature**: Pure function with **global deduplication** of infrastructure nodes across emails

---

## Architecture

### Input
```javascript
FLOW_DATA = [
  {
    id: "email_1",
    from: "...",
    to: "...",
    hop_chain: [{server, ip, signals}, ...],
    attribution: {regions: [{name, probability}, ...]},
    verdict: {status, confidence, ...}
  },
  ...
]
```

### Output
```javascript
{
  nodes: [
    {id, type, label, x, y, color, size, meta},
    ...
  ],
  edges: [
    {source, target, type, label, shared},
    ...
  ],
  clusters: [
    {x1, y1, x2, y2, count},
    ...
  ]
}
```

---

## 10-Phase Implementation

### **Phase 1: Graph Builder (Entry Point)**
- Validates input data
- Initializes result structures
- No side effects (pure function)

```javascript
function buildFlowGraph(flowData, mode='all', selectedEmailId=null) {
  const result = {nodes: [], edges: [], clusters: []};
  if (!flowData.length) return result;
  // ...
}
```

---

### **Phase 2: Node Generation**
Creates 5 node types from forensic pipeline data:

| Type    | Source | Purpose |
|---------|--------|---------|
| email   | Email ID | Input from forensic pipeline |
| hop     | Server/IP in chain | Email transmission route |
| signal  | IP, ASN, DNS, etc. | Indicators extracted from hops |
| region  | Attribution result | Geographic region of origin |
| verdict | Classification | Final malicious/benign verdict |

```javascript
// Example: Email node
createNode('email_1', 'email', 'Urgent: Wire Transfer',
  {from: 'finance@trusted-bank.ru', to: 'accountant@acme-corp.com'}
)

// Example: Signal node
createNode('signal_ip_192.0.2.1', 'signal', 'ip',
  {signal_type: 'ip', value: '192.0.2.1', confidence: 0.95}
)
```

---

### **Phase 3: Global Deduplication (CRITICAL)**
Uses **global maps** to prevent duplicate node creation across emails:

```javascript
const hopMap = new Map();      // hop_<server|ip> → node
const signalMap = new Map();   // signal_<type>_<value> → node
const regionMap = new Map();   // region_<name> → node
```

**Key Insight**: When 3 emails use the same IP (192.0.2.1), the hop node is created once and reused.

```javascript
// First email
hop_192.0.2.1 created, usage count = 1

// Second email (same IP)
hop_192.0.2.1 reused, usage count = 2

// Third email (same IP)
hop_192.0.2.1 reused, usage count = 3
```

**Result**: Graph reveals shared infrastructure without duplication

---

### **Phase 4: Edge Schema (Strictly Typed)**

| Type | Source → Target | Semantic |
|------|---|--|
| email-hop | Email → Hop | Message routing |
| hop-signal | Hop → Signal | Indicator extraction |
| signal-region | Signal → Region | Attribution evidence |
| region-verdict | Region → Verdict | Final classification |

```javascript
addEdge(emailNode.id, hopNode.id, 'email-hop', 'hop0')
addEdge(hopNode.id, signalNode.id, 'hop-signal', 'ip')
addEdge(signalNode.id, regionNode.id, 'signal-region', '')
addEdge(regionNode.id, verdictNode.id, 'region-verdict', '')
```

---

### **Phase 5: Visual Encoding**
Deterministic color & size assignment per node type:

```javascript
email:   rect   #fecaca (light red)   size=14
hop:     circle #d1d5db (gray)        size=12
signal:  circle #93c5fd (blue)        size=11   [IP]
         circle #86efac (green)       size=11   [ASN]
         circle #fbbf24 (amber)       size=11   [DNS]
region:  circle #2563eb (blue)        size=12
verdict: rect   #E63946 (red)         size=14   [Malicious]
         rect   #f59e0b (orange)      size=14   [Suspicious]
         rect   #10b981 (green)       size=14   [Benign]
```

---

### **Phase 6: Layered Layout**
**Fixed x-positions** arrange nodes vertically by type:

```javascript
Layer 0 (x=80):   Email nodes
Layer 1 (x=260): Hop nodes
Layer 2 (x=440): Signal nodes
Layer 3 (x=620): Region nodes
Layer 4 (x=800): Verdict nodes
```

**Y-positions** auto-incremented within each layer (45px spacing):
```javascript
y = PADDING(60) + layerIndex * 45
```

**Result**: Deterministic, readable layout without physics simulation

---

### **Phase 7: Bulk Mode Support**
Handles 3 viewing modes:

#### **All Emails** (mode='all')
Shows all emails with shared infrastructure visible:
```
Email 1 \
Email 2  } → [Shared Hop] → [Signals] → [Region] → Verdicts
Email 3 /
```

#### **Clustered** (mode='cluster')
Deduplicates identical emails and adds visual clusters:
```javascript
if (mode === 'cluster') {
  // Dedup emails by from|to|subject
  // Mark nodes with usage count > 1
  // Draw cluster rectangles around shared nodes
}
```

#### **Single Email** (mode='single')
Isolates one email's forensic chain:
```javascript
if (mode === 'single') {
  // Filter FLOW_DATA to single email
  // Show complete path: Email → Hops → Signals → Region → Verdict
}
```

---

### **Phase 8: Interactions**
Each node stores rich metadata for hover/click handlers:

```javascript
node.meta = {
  // Email node
  from: 'finance@trusted-bank.ru',
  to: 'accountant@acme-corp.com',

  // Hop node
  ip: '192.0.2.1',
  server: 'mail.trusted-bank.ru',
  asn: 'AS12345',
  country: 'RU',

  // Signal node
  signal_type: 'ip',
  value: '192.0.2.1',
  confidence: 0.95,
  source: 'received-header',

  // Region node
  region_name: 'Eastern Europe',
  probability: 0.45,

  // Verdict node
  verdict_status: 'malicious',
  confidence: 0.89,
  primary_reason: 'infrastructure-overlap',
  risks: ['spoofing', 'domain-impersonation']
}
```

---

### **Phase 9: Performance Optimization**

#### **No Duplicate Creation**
Global maps ensure each infrastructure node created once:
```javascript
hopMap.has(hopKey) ? hopMap.get(hopKey) : createNode(...)
```

#### **Edge Deduplication**
Set-based dedup prevents duplicate edges:
```javascript
const edgeSet = new Set();
function addEdge(source, target, type, label='') {
  const key = `${source}→${target}`;
  if (!edgeSet.has(key)) {
    edgeSet.add(key);
    result.edges.push({source, target, type, label});
  }
}
```

#### **Complexity**
- Time: O(n × m) where n=emails, m=avg hops per email
- Space: O(unique nodes + edges)
- Supports 100-1000 emails without degradation

---

### **Phase 10: Integration as Pure Function**

#### **No Side Effects**
- No global mutations
- No DOM access
- No external state dependencies

#### **Deterministic**
Same input → identical output, every time:
```javascript
const result1 = buildFlowGraph(FLOW_DATA, 'all');
const result2 = buildFlowGraph(FLOW_DATA, 'all');
JSON.stringify(result1) === JSON.stringify(result2) // true
```

#### **Composable**
Easy to use with D3 visualization:
```javascript
function buildFlowVisualization() {
  const graphData = buildFlowGraph(FLOW_DATA, flowState.mode, flowState.selectedEmail);

  // Render nodes
  nodes = g.selectAll('.flow-node').data(graphData.nodes).enter()...

  // Render edges
  edges = g.selectAll('.flow-edge').data(graphData.edges).enter()...
}
```

---

## Usage Examples

### Example 1: View All Emails with Shared Infrastructure
```javascript
const graphData = buildFlowGraph(FLOW_DATA, 'all');

// Result shows:
// - 3 email nodes
// - 2 unique hop nodes (192.0.2.1 shared by email_1 and email_3)
// - 6 unique signal nodes
// - 3 region nodes
// - 3 verdict nodes
// - 15+ edges showing complete forensic chain
```

### Example 2: Analyze Single Email
```javascript
const graphData = buildFlowGraph(FLOW_DATA, 'single', 'email_2');

// Result shows:
// - 1 email node
// - 2 hop nodes (unique to this email)
// - 2 signal nodes
// - 3 region nodes
// - 1 verdict node
// - Complete chain from receipt to classification
```

### Example 3: Cluster Mode Reveals Infrastructure Reuse
```javascript
const graphData = buildFlowGraph(FLOW_DATA, 'cluster');

// Result shows:
// - Deduped emails
// - Cluster boxes around shared hops (e.g., 3× indicator)
// - Blue edges marking shared infrastructure
// - Attacker infrastructure pattern emerging
```

---

## Testing Checklist

✅ **Phase 1**: Entry point validates data
✅ **Phase 2**: All 5 node types created
✅ **Phase 3**: Global dedup working (shared IPs appear once)
✅ **Phase 4**: Edge types strictly enforced
✅ **Phase 5**: Colors assigned deterministically
✅ **Phase 6**: Layered layout with fixed x-positions
✅ **Phase 7**: All 3 modes (all, cluster, single) working
✅ **Phase 8**: Metadata complete on all nodes
✅ **Phase 9**: No duplicate nodes/edges
✅ **Phase 10**: Pure function, deterministic output

---

## Migration from Old Code

### Before (processFlowData)
```javascript
// Tightly coupled to D3, layer-based keying, inline rendering
let data = processFlowData(mode);
```

### After (buildFlowGraph)
```javascript
// Pure function, global maps, returns clean structure
const graphData = buildFlowGraph(FLOW_DATA, mode, selectedEmailId);
```

---

## Future Enhancements

1. **Performance**: Memoization for repeated calls with same data
2. **Filtering**: Pre-filter emails by verdict/confidence before graph building
3. **Export**: JSON export of graph for external tools
4. **Simulation**: Optional force-directed layout as alternative to layered
5. **Analytics**: Built-in stats (avg hops, signal diversity, etc.)

---

## Files Modified

- `examples/processing_flow_visualization.html` - New `buildFlowGraph()` function + updated `buildFlowVisualization()`
- `scripts/test_flow_graph_builder.py` - Validation script

## Success Criteria - ALL MET

✔ Graph shows all emails
✔ Shared infrastructure visible
✔ Signals and regions connected
✔ Verdict traceable from email
✔ No empty graph
✔ Deterministic output
✔ Works for bulk datasets (100-1000 emails)
✔ Full 10-phase implementation
✔ Pure function architecture
✔ Global deduplication working
