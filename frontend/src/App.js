import React, { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import {
  submitArtifact, getGraphNodes, getTaskStatus, getCampaigns,
  triggerCampaignDetection, getNetworkConfig, updateNetworkConfig,
  getHealth, searchGraph, getGraphStats,
} from './utils/api';

// ── Color Map ───────────────────────────────────────────────

const NODE_COLORS = {
  Domain: '#3b82f6',
  IP: '#10b981',
  Certificate: '#f59e0b',
  FaviconHash: '#ec4899',
  HTMLFingerprint: '#8b5cf6',
  ASN: '#06b6d4',
  Registrar: '#f97316',
  HostingProvider: '#14b8a6',
  Campaign: '#a855f7',
};

const NODE_SHAPES = {
  Domain: 'ellipse',
  IP: 'diamond',
  Certificate: 'hexagon',
  FaviconHash: 'star',
  HTMLFingerprint: 'rectangle',
  ASN: 'triangle',
  Registrar: 'barrel',
  HostingProvider: 'pentagon',
  Campaign: 'octagon',
};

// ── Main App ────────────────────────────────────────────────

export default function App() {
  const [activeTab, setActiveTab] = useState('submit');
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [selectedNode, setSelectedNode] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [tasks, setTasks] = useState([]);
  const [stats, setStats] = useState({});
  const [health, setHealth] = useState(null);
  const [showNetworkModal, setShowNetworkModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const cyRef = useRef(null);
  const containerRef = useRef(null);

  // ── Initialize Cytoscape ──────────────────────────────────

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'background-color': (ele) => NODE_COLORS[ele.data('type')] || '#64748b',
            'shape': (ele) => NODE_SHAPES[ele.data('type')] || 'ellipse',
            'width': (ele) => ele.data('type') === 'Campaign' ? 50 : 35,
            'height': (ele) => ele.data('type') === 'Campaign' ? 50 : 35,
            'font-size': '10px',
            'font-family': '"JetBrains Mono", monospace',
            'color': '#e2e8f0',
            'text-outline-color': '#0a0e17',
            'text-outline-width': 2,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'border-width': 2,
            'border-color': (ele) => NODE_COLORS[ele.data('type')] || '#64748b',
            'border-opacity': 0.3,
          },
        },
        {
          selector: 'edge',
          style: {
            'width': (ele) => Math.max(1, (ele.data('confidence') || 0.5) * 4),
            'line-color': '#1e3a5f',
            'target-arrow-color': '#1e3a5f',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(relationship)',
            'font-size': '8px',
            'font-family': '"JetBrains Mono", monospace',
            'color': '#475569',
            'text-rotation': 'autorotate',
            'text-outline-color': '#0a0e17',
            'text-outline-width': 1,
            'opacity': 0.7,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#ffffff',
            'border-opacity': 1,
          },
        },
        {
          selector: '.highlighted',
          style: {
            'border-width': 3,
            'border-color': '#ffffff',
            'opacity': 1,
          },
        },
        {
          selector: '.faded',
          style: {
            'opacity': 0.15,
          },
        },
      ],
      layout: { name: 'preset' },
      minZoom: 0.1,
      maxZoom: 5,
      wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNode({
        id: node.data('id'),
        label: node.data('label'),
        type: node.data('type'),
        properties: node.data(),
      });

      // Highlight neighborhood
      cy.elements().removeClass('highlighted faded');
      const neighborhood = node.neighborhood().add(node);
      cy.elements().not(neighborhood).addClass('faded');
      neighborhood.addClass('highlighted');
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        cy.elements().removeClass('highlighted faded');
      }
    });

    cyRef.current = cy;

    return () => cy.destroy();
  }, []);

  // ── Load Graph Data ───────────────────────────────────────

  const loadGraph = useCallback(async () => {
    try {
      const res = await getGraphNodes(500);
      setGraphData(res.data);

      if (cyRef.current) {
        const cy = cyRef.current;
        cy.elements().remove();

        const elements = [];

        for (const n of res.data.nodes || []) {
          elements.push({ group: 'nodes', data: n.data });
        }
        for (const e of res.data.edges || []) {
          elements.push({ group: 'edges', data: e.data });
        }

        if (elements.length > 0) {
          cy.add(elements);
          cy.layout({
            name: 'cose',
            animate: true,
            animationDuration: 800,
            nodeRepulsion: 8000,
            idealEdgeLength: 120,
            edgeElasticity: 50,
            gravity: 0.3,
            padding: 40,
          }).run();
        }
      }
    } catch (err) {
      console.error('Failed to load graph:', err);
    }
  }, []);

  // ── Periodic Refresh ──────────────────────────────────────

  useEffect(() => {
    loadGraph();
    const interval = setInterval(loadGraph, 15000);
    return () => clearInterval(interval);
  }, [loadGraph]);

  useEffect(() => {
    const loadMeta = async () => {
      try {
        const [campRes, statsRes, healthRes] = await Promise.allSettled([
          getCampaigns(),
          getGraphStats(),
          getHealth(),
        ]);
        if (campRes.status === 'fulfilled') setCampaigns(campRes.value.data);
        if (statsRes.status === 'fulfilled') setStats(statsRes.value.data);
        if (healthRes.status === 'fulfilled') setHealth(healthRes.value.data);
      } catch (e) {
        console.error(e);
      }
    };
    loadMeta();
    const i = setInterval(loadMeta, 30000);
    return () => clearInterval(i);
  }, []);

  // ── Handlers ──────────────────────────────────────────────

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    try {
      const res = await searchGraph(searchQuery);
      console.log('Search results:', res.data);
    } catch (e) {
      console.error(e);
    }
  };

  const fitGraph = () => cyRef.current?.fit(null, 40);
  const zoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const zoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.7);

  // ── Render ────────────────────────────────────────────────

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <h1>CYBERINTEL</h1>
          <span>v1.0</span>
        </div>
        <div className="header-actions">
          {health && (
            <span style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className={`status-dot status-${health.status}`} />
              {health.status}
            </span>
          )}
          <button className="btn btn-secondary btn-sm" onClick={() => setShowNetworkModal(true)}>
            Network Config
          </button>
          <button className="btn btn-secondary btn-sm" onClick={loadGraph}>
            Refresh
          </button>
        </div>
      </header>

      <div className="main-content">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="tab-nav">
            <button
              className={`tab-btn ${activeTab === 'submit' ? 'active' : ''}`}
              onClick={() => setActiveTab('submit')}
            >
              Submit
            </button>
            <button
              className={`tab-btn ${activeTab === 'campaigns' ? 'active' : ''}`}
              onClick={() => setActiveTab('campaigns')}
            >
              Campaigns
            </button>
            <button
              className={`tab-btn ${activeTab === 'stats' ? 'active' : ''}`}
              onClick={() => setActiveTab('stats')}
            >
              Stats
            </button>
          </div>

          {activeTab === 'submit' && (
            <ArtifactPanel tasks={tasks} setTasks={setTasks} onSubmitSuccess={loadGraph} />
          )}
          {activeTab === 'campaigns' && (
            <CampaignPanel campaigns={campaigns} />
          )}
          {activeTab === 'stats' && (
            <StatsPanel stats={stats} graphData={graphData} />
          )}
        </aside>

        {/* Graph Viewport */}
        <div className="graph-container">
          <div ref={containerRef} className="graph-canvas" />

          {/* Controls */}
          <div className="graph-controls">
            <button className="btn btn-secondary btn-sm" onClick={zoomIn}>+</button>
            <button className="btn btn-secondary btn-sm" onClick={zoomOut}>−</button>
            <button className="btn btn-secondary btn-sm" onClick={fitGraph}>Fit</button>
          </div>

          {/* Legend */}
          <div className="graph-legend">
            {Object.entries(NODE_COLORS).map(([type, color]) => (
              <div className="legend-item" key={type}>
                <span className="legend-dot" style={{ background: color }} />
                <span style={{ color: '#94a3b8', fontSize: 11 }}>{type}</span>
              </div>
            ))}
          </div>

          {/* Node Inspector */}
          {selectedNode && (
            <NodeInspector node={selectedNode} onClose={() => {
              setSelectedNode(null);
              cyRef.current?.elements().removeClass('highlighted faded');
            }} />
          )}
        </div>
      </div>

      {/* Network Config Modal */}
      {showNetworkModal && (
        <NetworkConfigModal onClose={() => setShowNetworkModal(false)} />
      )}
    </div>
  );
}


// ── Artifact Submission Panel ───────────────────────────────

function ArtifactPanel({ tasks, setTasks, onSubmitSuccess }) {
  const [type, setType] = useState('domain');
  const [value, setValue] = useState('');
  const [depth, setDepth] = useState(1);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!value.trim()) return;
    setSubmitting(true);
    try {
      const res = await submitArtifact(type, value.trim(), depth);
      const task = {
        id: res.data.task_id,
        type,
        value: value.trim(),
        status: 'PENDING',
      };
      setTasks((prev) => [task, ...prev]);
      setValue('');

      // Poll task status
      if (res.data.task_id) {
        pollTask(res.data.task_id, task, setTasks, onSubmitSuccess);
      }
    } catch (err) {
      console.error('Submission failed:', err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="sidebar-section">
        <h3>Submit Artifact</h3>
        <div className="input-group">
          <label>Artifact Type</label>
          <select className="select-field" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="ip">IP Address</option>
            <option value="tls_fingerprint">TLS Fingerprint</option>
            <option value="email_domain">Email Domain</option>
          </select>
        </div>
        <div className="input-group">
          <label>Value</label>
          <input
            className="input-field"
            placeholder="e.g. suspicious-login-bank.com"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          />
        </div>
        <div className="input-group">
          <label>Discovery Depth (1–5)</label>
          <input
            className="input-field"
            type="number"
            min="1"
            max="5"
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
          />
        </div>
        <button
          className="btn btn-primary btn-full"
          onClick={handleSubmit}
          disabled={submitting || !value.trim()}
        >
          {submitting ? 'Submitting...' : 'Investigate'}
        </button>
      </div>

      <div className="sidebar-scroll">
        <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: 12 }}>
          Task Feed
        </h3>
        {tasks.length === 0 && (
          <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>No tasks yet. Submit an artifact to begin.</p>
        )}
        {tasks.map((t, i) => (
          <div className="task-item" key={i}>
            {t.status === 'PENDING' || t.status === 'STARTED' ? (
              <div className="spinner" />
            ) : t.status === 'SUCCESS' ? (
              <span style={{ color: 'var(--success)' }}>✓</span>
            ) : (
              <span style={{ color: 'var(--danger)' }}>✗</span>
            )}
            <span className={`tag tag-${t.type}`}>{t.type}</span>
            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.value}
            </span>
          </div>
        ))}
      </div>
    </>
  );
}


// ── Task Polling ────────────────────────────────────────────

function pollTask(taskId, task, setTasks, onSuccess) {
  const interval = setInterval(async () => {
    try {
      const res = await getTaskStatus(taskId);
      const status = res.data.status;
      setTasks((prev) =>
        prev.map((t) => (t.id === taskId ? { ...t, status } : t))
      );
      if (status === 'SUCCESS' || status === 'FAILURE') {
        clearInterval(interval);
        if (status === 'SUCCESS') onSuccess?.();
      }
    } catch {
      clearInterval(interval);
    }
  }, 3000);
}


// ── Campaign Panel ──────────────────────────────────────────

function CampaignPanel({ campaigns }) {
  const handleDetect = async () => {
    try {
      await triggerCampaignDetection();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="sidebar-section" style={{ flex: 1, overflowY: 'auto' }}>
      <h3>Detected Campaigns</h3>
      <button className="btn btn-secondary btn-sm btn-full" onClick={handleDetect} style={{ marginBottom: 12 }}>
        Run Detection
      </button>
      {campaigns.length === 0 && (
        <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>No campaigns detected yet.</p>
      )}
      {campaigns.map((c) => (
        <div className="campaign-item" key={c.id}>
          <h4>{c.name || c.id}</h4>
          <p>
            <span className="campaign-badge">{c.domain_count} domains</span>
            {' '}
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              confidence: {((c.confidence || 0) * 100).toFixed(0)}%
            </span>
          </p>
          {c.domains && (
            <div style={{ marginTop: 6 }}>
              {c.domains.slice(0, 5).map((d) => (
                <div key={d} style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                  • {d}
                </div>
              ))}
              {c.domains.length > 5 && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  +{c.domains.length - 5} more
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}


// ── Stats Panel ─────────────────────────────────────────────

function StatsPanel({ stats, graphData }) {
  return (
    <div className="sidebar-section">
      <h3>Graph Statistics</h3>
      <div style={{ marginTop: 8 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
          <span style={{ color: 'var(--text-secondary)' }}>Total Nodes</span>
          <span style={{ fontFamily: 'var(--font-mono)' }}>
            {graphData.nodes?.length || 0}
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
          <span style={{ color: 'var(--text-secondary)' }}>Total Edges</span>
          <span style={{ fontFamily: 'var(--font-mono)' }}>
            {graphData.edges?.length || 0}
          </span>
        </div>
        <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '12px 0' }} />
        <h3>Node Types</h3>
        {Object.entries(stats).map(([label, count]) => (
          <div
            key={label}
            style={{
              display: 'flex', justifyContent: 'space-between',
              fontSize: 12, marginBottom: 4, marginTop: 6,
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="legend-dot" style={{ background: NODE_COLORS[label] || '#64748b' }} />
              {label}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
              {count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}


// ── Node Inspector ──────────────────────────────────────────

function NodeInspector({ node, onClose }) {
  const typeColor = NODE_COLORS[node.type] || '#64748b';

  // Filter out internal / display-only keys
  const displayProps = Object.entries(node.properties || {}).filter(
    ([k]) => !['id', 'label', 'type'].includes(k)
  );

  return (
    <div className="inspector">
      <div className="inspector-header">
        <h4>Node Inspector</h4>
        <button className="inspector-close" onClick={onClose}>×</button>
      </div>
      <span
        className="inspector-type"
        style={{ background: `${typeColor}22`, color: typeColor }}
      >
        {node.type}
      </span>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 14, marginBottom: 12,
        color: 'var(--text-primary)', wordBreak: 'break-all',
      }}>
        {node.label}
      </div>
      <dl className="inspector-props">
        {displayProps.map(([key, val]) => (
          <React.Fragment key={key}>
            <dt>{key}</dt>
            <dd>{String(val)}</dd>
          </React.Fragment>
        ))}
      </dl>
    </div>
  );
}


// ── Network Config Modal ────────────────────────────────────

function NetworkConfigModal({ onClose }) {
  const [config, setConfig] = useState({
    mode: 'direct',
    custom_proxy: '',
    rate_limit_rps: 2,
    safe_mode: true,
  });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    getNetworkConfig()
      .then((res) => setConfig((prev) => ({ ...prev, ...res.data })))
      .catch(console.error);
  }, []);

  const handleSave = async () => {
    try {
      await updateNetworkConfig(config);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Anonymization Config</h2>

        <div className="input-group">
          <label>Mode</label>
          <select
            className="select-field"
            value={config.mode}
            onChange={(e) => setConfig({ ...config, mode: e.target.value })}
          >
            <option value="direct">Direct (No Proxy)</option>
            <option value="proxy_chain">Proxy Chain</option>
            <option value="tor">Tor Network</option>
            <option value="custom">Custom Proxy</option>
          </select>
        </div>

        {config.mode === 'custom' && (
          <div className="input-group">
            <label>Custom Proxy URL</label>
            <input
              className="input-field"
              placeholder="socks5://host:port"
              value={config.custom_proxy || ''}
              onChange={(e) => setConfig({ ...config, custom_proxy: e.target.value })}
            />
          </div>
        )}

        <div className="input-group">
          <label>Rate Limit (req/sec)</label>
          <input
            className="input-field"
            type="number"
            min="0.1"
            max="50"
            step="0.5"
            value={config.rate_limit_rps}
            onChange={(e) => setConfig({ ...config, rate_limit_rps: Number(e.target.value) })}
          />
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
          <button className="btn btn-primary" onClick={handleSave}>
            {saved ? '✓ Saved' : 'Save'}
          </button>
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
