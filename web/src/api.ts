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
  summary: () => request<DashboardSummary>('/api/v1/dashboard/summary'),
  sites: () => request<SiteSummary[]>('/api/v1/sites'),
  incidents: (status = '') =>
    request<Page<IncidentSummary>>(`/api/v1/incidents${status ? `?status=${status}` : ''}`),
  signals: (search = '') =>
    request<Page<SignalSummary>>(`/api/v1/signals${search ? `?search=${encodeURIComponent(search)}` : ''}`),
}
