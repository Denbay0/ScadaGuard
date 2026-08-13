import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Clock3, Factory, RefreshCw, WifiOff } from 'lucide-react'
import { api, Health } from '../api'

const labels: Record<Health, string> = { ok: 'Норма', warning: 'Предупреждение', critical: 'Критично', offline: 'Нет связи', unknown: 'Неизвестно' }

export default function Dashboard() {
  const summary = useQuery({ queryKey: ['summary'], queryFn: api.summary, refetchInterval: 10_000 })
  const sites = useQuery({ queryKey: ['sites'], queryFn: api.sites, refetchInterval: 10_000 })
  const updated = new Date(Math.max(summary.dataUpdatedAt, sites.dataUpdatedAt)).toLocaleTimeString('ru-RU')
  if (summary.isLoading || sites.isLoading) return <div className="state-screen"><RefreshCw className="spin" />Загрузка актуального состояния…</div>
  if (summary.isError || sites.isError) return <div className="state-screen error"><WifiOff /><strong>Центральный API недоступен</strong><span>Старые данные не показаны как актуальные.</span><button onClick={() => { summary.refetch(); sites.refetch() }}>Повторить</button></div>
  const s = summary.data!
  return <><header className="page-header"><div><p className="eyebrow">Все производственные площадки</p><h1>Состояние системы</h1></div><div className="updated"><Clock3 />Последнее обновление: {updated}</div></header>
    <section className="metrics" aria-label="Сводные показатели">
      <article><Factory /><span>Объектов<strong>{s.sites.total}</strong></span></article>
      <article className="ok"><CheckCircle2 /><span>В норме<strong>{s.sites.ok}</strong></span></article>
      <article className="warning"><AlertTriangle /><span>Предупреждение<strong>{s.sites.warning}</strong></span></article>
      <article className="critical"><AlertTriangle /><span>Критично<strong>{s.sites.critical}</strong></span></article>
      <article className="offline"><WifiOff /><span>Нет связи<strong>{s.sites.offline}</strong></span></article>
    </section>
    <section className="section-heading"><div><p className="eyebrow">Оперативный контроль</p><h2>Объекты</h2></div><span>{s.active_incidents} активных инцидентов</span></section>
    <section className="site-grid">{sites.data!.map(site => <article className="site-card" key={site.id}><div className="site-top"><div><p className="eyebrow">{site.slug}</p><h3>{site.display_name}</h3></div><span className={`status ${site.status}`}>{labels[site.status]}</span></div><dl><div><dt>Агенты</dt><dd>{site.online_agents} / {site.agent_count} онлайн</dd></div><div><dt>Инциденты</dt><dd>{site.active_incidents}</dd></div><div><dt>Последняя связь</dt><dd>{site.last_seen_at ? new Date(site.last_seen_at).toLocaleTimeString('ru-RU') : 'нет данных'}</dd></div></dl></article>)}</section>
  </>
}
