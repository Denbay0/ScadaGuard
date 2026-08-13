import { useQuery } from '@tanstack/react-query'
import { Bot, RefreshCw, WifiOff } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api } from '../api'

export default function Agents() {
  const query = useQuery({ queryKey: ['agents'], queryFn: api.agents, refetchInterval: 10_000 })
  if (query.isLoading) return <div className="state-screen"><RefreshCw className="spin" />Загрузка агентов…</div>
  if (query.isError) return <div className="state-screen error"><WifiOff /><strong>Не удалось получить агентов</strong><button onClick={() => query.refetch()}>Повторить</button></div>
  return <>
    <header className="page-header"><div><p className="eyebrow">Инфраструктура</p><h1>Агенты</h1></div><span className="updated"><Bot />Всего: {query.data!.length}</span></header>
    {query.data!.length === 0 ? <section className="empty-state"><Bot /><h2>Агенты ещё не зарегистрированы</h2><p>Создайте агент через административный API и выдайте ему токен.</p></section> :
      <section className="site-grid page-grid">{query.data!.map(agent => {
        const online = agent.current_status !== 'offline' && Boolean(agent.last_seen_at) && Date.now() - new Date(agent.last_seen_at!).getTime() < 60_000
        return <Link className="site-card agent-link" to={`/agents/${agent.id}`} key={agent.id}>
        <div className="site-top"><div><p className="eyebrow">{agent.host_id}</p><h3>{agent.display_name}</h3></div><span className={`status ${agent.current_status}`}>{agent.current_status}</span></div>
        <dl><div><dt>Связь</dt><dd>{online ? 'online' : 'offline'}</dd></div><div><dt>Состояние мониторинга</dt><dd>{agent.current_status}</dd></div><div><dt>Версия</dt><dd>{agent.version ?? 'нет данных'}</dd></div><div><dt>Последний heartbeat</dt><dd>{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString('ru-RU') : 'нет данных'}</dd></div><div><dt>Конфигурация</dt><dd>{agent.configuration_hash ? 'получена' : 'не применена'}</dd></div></dl>
      </Link>})}</section>}
  </>
}
