import { useQuery } from '@tanstack/react-query'
import { Activity, RefreshCw, Search, WifiOff } from 'lucide-react'
import { FormEvent, useState } from 'react'
import { api } from '../api'

export default function Signals() {
  const [input, setInput] = useState('')
  const [search, setSearch] = useState('')
  const query = useQuery({ queryKey: ['signals', search], queryFn: () => api.signals(search), refetchInterval: 10_000 })
  const submit = (event: FormEvent) => { event.preventDefault(); setSearch(input.trim()) }
  return <>
    <header className="page-header"><div><p className="eyebrow">Технологические данные</p><h1>Сигналы</h1></div><form className="search" onSubmit={submit}><Search /><input aria-label="Поиск сигналов" value={input} onChange={event => setInput(event.target.value)} placeholder="Название сигнала" /><button>Найти</button></form></header>
    {query.isLoading && <div className="state-screen"><RefreshCw className="spin" />Загрузка сигналов…</div>}
    {query.isError && <div className="state-screen error"><WifiOff /><strong>Не удалось получить сигналы</strong><button onClick={() => query.refetch()}>Повторить</button></div>}
    {query.data && (query.data.items.length === 0 ? <section className="empty-state"><Activity /><h2>Сигналов нет</h2><p>Агент ещё не передал значения или поиск не дал результатов.</p></section> : <div className="table-wrap"><table><thead><tr><th>Сигнал</th><th>Объект / агент</th><th>Значение</th><th>Качество</th><th>Источник</th><th>Время</th></tr></thead><tbody>{query.data.items.map(item => <tr key={item.id}><td><strong>{item.display_name}</strong><small>{item.signal_id}</small></td><td><strong>{item.site_name}</strong><small>{item.agent_name}</small></td><td className="reading">{item.value === null ? '—' : `${item.value.toLocaleString('ru-RU')} ${item.unit ?? ''}`}</td><td><span className={`quality ${item.quality?.toLowerCase() === 'good' ? 'good' : 'bad'}`}>{item.quality ?? 'нет данных'}</span></td><td>{item.origin ?? '—'}</td><td>{item.source_timestamp ? new Date(item.source_timestamp).toLocaleString('ru-RU') : '—'}</td></tr>)}</tbody></table></div>)}
  </>
}
