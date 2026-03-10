import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_BASE}/api`,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

export const submitArtifact = (type, value, depth = 1) =>
  api.post('/artifact', { type, value, depth });

export const getTaskStatus = (taskId) =>
  api.get(`/task/${taskId}`);

export const getGraphNodes = (limit = 300) =>
  api.get(`/graph/nodes?limit=${limit}`);

export const getDomainGraph = (domain, depth = 2) =>
  api.get(`/graph/domain/${domain}?depth=${depth}`);

export const getRelated = (domain) =>
  api.get(`/graph/related/${domain}`);

export const searchGraph = (q) =>
  api.get(`/graph/search?q=${q}`);

export const getGraphStats = () =>
  api.get('/graph/stats');

export const getCampaigns = () =>
  api.get('/campaigns');

export const triggerCampaignDetection = () =>
  api.post('/campaigns/detect');

export const getNetworkConfig = () =>
  api.get('/network/config');

export const updateNetworkConfig = (config) =>
  api.put('/network/config', config);

export const getHealth = () =>
  api.get('/health');

export default api;
