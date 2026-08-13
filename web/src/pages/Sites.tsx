import { useQuery } from '@tanstack/react-query'
import { Factory, RefreshCw, WifiOff } from 'lucide-react'
import { api, Health } from '../api'

const labels: Record<Health, string> = {
  ok: 'Норма', warning: 'Предупреждение', critical: 'Критично', offline: 'Нет связи', unknown: 'Неизвестно',
}

export default function Sites() {
  const query = useQuery({ queryKey: ['sites'], queryFn: api.sites, refetchInterval: 10_000 })
  if (query.isLoading) return <div className="state-screen"><RefreshCw className="spin" />Загрузка объектов…</div>
  if (query.isError) return <div className="state-screen error"><WifiOff /><strong>Не удалось получить объекты</strong><button onClick={() => query.refetch()}>Повторить</button></div>
  return <>
    <header className="page-header"><div><p className="eyebrow">Структура мониторинга</p><h1>Объекты</h1></div><span className="updated"><Factory />Всего: {query.data!.length}</span></header>
    {query.data!.length === 0 ? <section className="empty-state"><Factory /><h2>Объекты ещё не добавлены</h2><p>Создайте площадку и зарегистрируйте агент через административный API.</p></section> :
      <section className="site-grid page-grid">{query.data!.map(site => <article className="site-card" key={site.id}><div className="site-top"><div><p className="eyebrow">{site.slug}</p><h3>{site.display_name}</h3></div><span className={`status ${site.status}`}>{labels[site.status]}</span></div><dl><div><dt>Агенты онлайн</dt><dd>{site.online_agents} / {site.agent_count}</dd></div><div><dt>Активные инциденты</dt><dd>{site.active_incidents}</dd></div><div><dt>Последний heartbeat</dt><dd>{site.last_seen_at ? new Date(site.last_seen_at).toLocaleString('ru-RU') : 'нет данных'}</dd></div></dl></article>)}</section>}
  </>
}
