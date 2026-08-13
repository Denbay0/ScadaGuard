export type Health = 'ok' | 'warning' | 'critical' | 'offline' | 'unknown'

export interface DashboardSummary {
  sites: { total: number; ok: number; warning: number; critical: number; offline: number }
  active_incidents: number
  recent_recoveries: number
  generated_at: string
}

export interface SiteSummary {
  id: string
  slug: string
  display_name: string
  status: Health
  agent_count: number
  online_agents: number
  active_incidents: number
  last_seen_at: string | null
}

export interface AgentSummary {
  id: string
  agent_id: string
  site_id: string
  host_id: string
  display_name: string
  enabled: boolean
  version: string | null
  last_seen_at: string | null
  current_status: Health
  configuration_hash: string | null
}

export interface DiscoveryCandidate {
  path: string
  type: string
  confidence: 'unknown' | 'low' | 'medium' | 'high' | 'confirmed'
  score: number
  evidence: string[]
  selected: boolean
  needs_confirmation?: boolean
  last_write_time?: string
  size?: number
  read_only_opened?: boolean
  wal_exists?: boolean
  shm_exists?: boolean
  objects?: SQLiteObject[]
  schema_candidates?: ArchiveSchemaCandidate[]
}

export interface SQLiteColumn {
  name: string
  declared_type: string
  not_null: boolean
  primary_key: boolean
}

export interface SQLiteIndex { name: string; unique: boolean; columns: string[] }
export interface SQLiteForeignKey { from_column: string; target_table: string; target_column: string }
export interface SQLiteObject {
  name: string
  type: string
  columns: SQLiteColumn[]
  indexes: SQLiteIndex[]
  foreign_keys: SQLiteForeignKey[]
  bounded_row_count: number | null
  row_count_limit_reached: boolean
  recent_samples: Array<Record<string, unknown>>
}
export interface ArchiveSchemaCandidate {
  table: string
  confidence: DiscoveryCandidate['confidence']
  roles: { timestamp: string | null; signal_id: string | null; value: string | null; quality: string | null }
  evidence: string[]
  needs_confirmation: boolean
  minimum_timestamp: string | null
  maximum_timestamp: string | null
}

export interface DiscoveryReport {
  scan_id: string
  scanned_at: string
  masterscada: { detected: boolean; status: string; version: string; confidence: string }
  components: DiscoveryCandidate[]
  archive_candidates: DiscoveryCandidate[]
  log_candidates: DiscoveryCandidate[]
  opcua_candidates: Array<Record<string, unknown> | string>
  warnings: string[]
  scan_limits?: { scanned_directories: number; scanned_files: number; truncated: boolean }
}

export interface AgentConfiguration {
  config_version: number
  config_hash: string
  created_at: string | null
  created_by: string | null
  configuration: {
    confirmed_archive: string | null
    archive_mapping: {
      table: string
      timestamp_column: string
      signal_id_column: string
      value_column: string
      quality_column: string | null
    } | null
    confirmed_logs: string[]
    monitored_signals: string[]
    thresholds: Record<string, { minimum?: number; maximum?: number; max_rate_per_second?: number }>
    monitoring_interval_seconds: number
    server_url: string | null
    rescan_requested_at: string | null
  }
  applied_version: number | null
  apply_status: string
  apply_message: string
}

export interface IncidentSummary {
  id: string
  severity: Health
  status: string
  source: string
  title: string
  site_name: string
  agent_name: string
  opened_at: string
  last_seen_at: string
  closed_at: string | null
  acknowledged_at: string | null
  occurrence_count: number
}

export interface SignalSummary {
  id: number
  signal_id: string
  display_name: string
  unit: string | null
  site_name: string
  agent_name: string
  value: number | null
  quality: string | null
  source_timestamp: string | null
  origin: string | null
  anomaly_flags: string[]
}

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (response.status === 401) {
    window.dispatchEvent(new Event('scadaguard:unauthorized'))
  }
  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Ошибка API: ${response.status}`)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  login: (username: string, password: string) =>
    request<{ username: string; role: string }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),
  me: () => request<{ username: string; role: string }>('/api/v1/auth/me'),
  summary: () => request<DashboardSummary>('/api/v1/dashboard/summary'),
  sites: () => request<SiteSummary[]>('/api/v1/sites'),
  agents: () => request<AgentSummary[]>('/api/v1/agents'),
  agent: (id: string) => request<AgentSummary>(`/api/v1/agents/${id}`),
  discovery: (id: string) => request<DiscoveryReport>(`/api/v1/agents/${id}/discovery`),
  configuration: (id: string) => request<AgentConfiguration>(`/api/v1/agents/${id}/configuration`),
  confirmArchive: (id: string, path: string) =>
    request<AgentConfiguration>(`/api/v1/agents/${id}/configuration/confirm-archive`, {
      method: 'POST', body: JSON.stringify({ path }),
    }),
  updateConfiguration: (id: string, configuration: AgentConfiguration['configuration']) =>
    request<AgentConfiguration>(`/api/v1/agents/${id}/configuration`, {
      method: 'PUT', body: JSON.stringify(configuration),
    }),
  requestDiscoveryRescan: (id: string) =>
    request<AgentConfiguration>(`/api/v1/agents/${id}/discovery/rescan`, { method: 'POST' }),
  incidents: (status = '') =>
    request<Page<IncidentSummary>>(`/api/v1/incidents${status ? `?status=${status}` : ''}`),
  signals: (search = '') =>
    request<Page<SignalSummary>>(`/api/v1/signals${search ? `?search=${encodeURIComponent(search)}` : ''}`),
}
