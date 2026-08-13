import { useQuery } from '@tanstack/react-query'
import { Bell, RefreshCw, WifiOff } from 'lucide-react'
import { useState } from 'react'
import { api, Health } from '../api'

const labels: Record<Health, string> = { ok: 'Норма', warning: 'Warning', critical: 'Critical', offline: 'Offline', unknown: 'Unknown' }

export default function Incidents() {
  const [status, setStatus] = useState('open')
  const query = useQuery({ queryKey: ['incidents', status], queryFn: () => api.incidents(status), refetchInterval: 10_000 })
  return <>
    <header className="page-header"><div><p className="eyebrow">Журнал событий</p><h1>Инциденты</h1></div><label className="filter">Статус<select value={status} onChange={event => setStatus(event.target.value)}><option value="open">Открытые</option><option value="closed">Закрытые</option><option value="">Все</option></select></label></header>
    {query.isLoading && <div className="state-screen"><RefreshCw className="spin" />Загрузка инцидентов…</div>}
    {query.isError && <div className="state-screen error"><WifiOff /><strong>Не удалось получить инциденты</strong><button onClick={() => query.refetch()}>Повторить</button></div>}
    {query.data && (query.data.items.length === 0 ? <section className="empty-state"><Bell /><h2>Инцидентов нет</h2><p>Для выбранного фильтра события не найдены.</p></section> : <div className="table-wrap"><table><thead><tr><th>Важность</th><th>Объект / агент</th><th>Описание</th><th>Открыт</th><th>Повторы</th><th>Подтверждение</th></tr></thead><tbody>{query.data.items.map(item => <tr key={item.id}><td><span className={`status ${item.severity}`}>{labels[item.severity]}</span></td><td><strong>{item.site_name}</strong><small>{item.agent_name}</small></td><td><strong>{item.title}</strong><small>{item.source}</small></td><td>{new Date(item.opened_at).toLocaleString('ru-RU')}</td><td>{item.occurrence_count}</td><td>{item.acknowledged_at ? 'Подтверждён' : 'Ожидает'}</td></tr>)}</tbody></table></div>)}
  </>
}
