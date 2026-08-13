import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Database,
  FileText,
  RefreshCw,
  Search,
  Table2,
  WifiOff,
} from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type ArchiveSchemaCandidate } from '../api'

const confidenceLabel: Record<string, string> = {
  unknown: 'неизвестная',
  low: 'низкая',
  medium: 'средняя',
  high: 'высокая',
  confirmed: 'подтверждено',
}

function Step({ title, state, detail }: { title: string; state: 'ok' | 'warn' | 'wait'; detail: string }) {
  const Icon = state === 'ok' ? CheckCircle2 : state === 'warn' ? AlertTriangle : CircleDashed
  return <li className={`setup-step ${state}`}><Icon /><span><strong>{title}</strong><small>{detail}</small></span></li>
}

const sizeLabel = (bytes?: number) => bytes === undefined ? 'размер неизвестен' :
  new Intl.NumberFormat('ru-RU', { style: 'unit', unit: 'megabyte', maximumFractionDigits: 1 }).format(bytes / 1024 / 1024)

export default function AgentDiscovery() {
  const { agentId = '' } = useParams()
  const client = useQueryClient()
  const agent = useQuery({ queryKey: ['agent', agentId], queryFn: () => api.agent(agentId) })
  const me = useQuery({ queryKey: ['me'], queryFn: api.me })
  const discovery = useQuery({ queryKey: ['discovery', agentId], queryFn: () => api.discovery(agentId), retry: false })
  const configuration = useQuery({ queryKey: ['configuration', agentId], queryFn: () => api.configuration(agentId) })
  const [archive, setArchive] = useState('')
  const [mapping, setMapping] = useState<Record<string, string>>({})
  const refresh = () => { client.invalidateQueries({ queryKey: ['configuration', agentId] }); client.invalidateQueries({ queryKey: ['discovery', agentId] }) }
  const confirm = useMutation({ mutationFn: (path: string) => api.confirmArchive(agentId, path), onSuccess: refresh })
  const saveMapping = useMutation({
    mutationFn: (value: NonNullable<NonNullable<typeof configuration.data>['configuration']['archive_mapping']>) =>
      api.updateConfiguration(agentId, { ...configuration.data!.configuration, confirmed_archive: chosen, archive_mapping: value }),
    onSuccess: refresh,
  })
  const saveLogs = useMutation({ mutationFn: (logs: string[]) => api.updateConfiguration(agentId, { ...configuration.data!.configuration, confirmed_logs: logs }), onSuccess: refresh })
  const rescan = useMutation({ mutationFn: () => api.requestDiscoveryRescan(agentId), onSuccess: refresh })

  const report = discovery.data
  const configuredArchive = configuration.data?.configuration.confirmed_archive ?? ''
  const chosen = archive || configuredArchive || report?.archive_candidates[0]?.path || ''
  const selectedCandidate = report?.archive_candidates.find(item => item.path === chosen)
  const inferred = selectedCandidate?.schema_candidates?.[0]
  const savedMapping = configuration.data?.configuration.archive_mapping
  const field = (name: keyof NonNullable<typeof savedMapping>, fallback = '') => mapping[name] ?? savedMapping?.[name] ?? fallback
  const mappingReady = Boolean(field('table', inferred?.table) && field('timestamp_column', inferred?.roles.timestamp ?? '') && field('signal_id_column', inferred?.roles.signal_id ?? '') && field('value_column', inferred?.roles.value ?? ''))

  if (agent.isLoading || discovery.isLoading || configuration.isLoading) return <div className="state-screen"><RefreshCw className="spin" />Загрузка обнаружения…</div>
  if (agent.isError) return <div className="state-screen error"><WifiOff /><strong>Агент недоступен</strong><Link to="/agents">Вернуться</Link></div>
  if (discovery.isError || !report) return <><header className="page-header"><div><p className="eyebrow">{agent.data!.display_name}</p><h1>Настройка MasterSCADA</h1></div></header><section className="empty-state"><Search /><h2>Отчёт ещё не получен</h2><p>Агент отправит его после первого безопасного сканирования.</p></section></>

  const runtimeFound = report.components.some(item => item.type === 'process' || item.type === 'service')
  const agentOnline = agent.data!.current_status !== 'offline' && Boolean(agent.data!.last_seen_at) &&
    Date.now() - new Date(agent.data!.last_seen_at!).getTime() < 60_000
  const selectedLogs = configuration.data?.configuration.confirmed_logs ?? []
  const isAdmin = me.data?.role === 'admin'
  const schemaState = savedMapping ? 'ok' : inferred ? 'warn' : 'wait'
  const schemaDetail = savedMapping ? 'Схема подтверждена администратором' : inferred ? 'Найдены варианты, требуется подтверждение' : 'Схема пока не определена'
  const submitMapping = () => saveMapping.mutate({
    table: field('table', inferred?.table),
    timestamp_column: field('timestamp_column', inferred?.roles.timestamp ?? ''),
    signal_id_column: field('signal_id_column', inferred?.roles.signal_id ?? ''),
    value_column: field('value_column', inferred?.roles.value ?? ''),
    quality_column: field('quality_column', inferred?.roles.quality ?? '') || null,
  })

  return <>
    <header className="page-header"><div><p className="eyebrow"><Link to="/agents">Агенты</Link> / {agent.data!.display_name}</p><h1>Настройка MasterSCADA</h1></div><button className="primary-button" disabled={!isAdmin || rescan.isPending} onClick={() => rescan.mutate()}><RefreshCw className={rescan.isPending ? 'spin' : ''} />Пересканировать</button></header>
    <section className="discovery-summary panel">
      <div><span className={`discovery-icon ${report.masterscada.detected ? 'found' : ''}`}>{report.masterscada.detected ? <CheckCircle2 /> : <AlertTriangle />}</span><div><p className="eyebrow">MasterSCADA</p><h2>{report.masterscada.detected ? 'Найдена автоматически' : 'Не найдена'}</h2><p className="muted">Версия: {report.masterscada.version || 'не определена'} · Уверенность: {confidenceLabel[report.masterscada.confidence] ?? report.masterscada.confidence}</p></div></div>
      <dl><div><dt>Компоненты</dt><dd>{report.components.length}</dd></div><div><dt>Логи</dt><dd>{report.log_candidates.length}</dd></div><div><dt>SQLite</dt><dd>{report.archive_candidates.length}</dd></div><div><dt>Связь с агентом</dt><dd>{agentOnline ? 'online' : 'offline'}</dd></div></dl>
    </section>
    <section className="panel setup-panel"><p className="eyebrow">Первое подключение</p><h2>Готовность мониторинга</h2><ol className="setup-steps">
      <Step title="MasterSCADA" state={report.masterscada.detected ? 'ok' : 'warn'} detail={report.masterscada.detected ? `Обнаружена, версия ${report.masterscada.version || 'не определена'}` : 'Установка не найдена'} />
      <Step title="Runtime" state={runtimeFound ? 'ok' : 'wait'} detail={runtimeFound ? 'Процесс или служба обнаружены' : 'Runtime сейчас не обнаружен'} />
      <Step title="Логи" state={report.log_candidates.length ? 'ok' : 'wait'} detail={report.log_candidates.length ? `Найдено: ${report.log_candidates.length}` : 'Не найдены — допустимо для пустого проекта'} />
      <Step title="Основной архив" state={chosen ? (configuredArchive ? 'ok' : 'warn') : 'wait'} detail={chosen ? (configuredArchive ? 'SQLite подтверждён' : 'Кандидат требует подтверждения') : 'Архив ещё не создан или не найден'} />
      <Step title="Схема архива" state={schemaState} detail={schemaDetail} />
      <Step title="Сигналы" state={(configuration.data?.configuration.monitored_signals.length ?? 0) > 0 ? 'ok' : 'wait'} detail={(configuration.data?.configuration.monitored_signals.length ?? 0) > 0 ? 'Сигналы выбраны' : 'Не настроены — это не авария'} />
    </ol></section>
    {report.warnings.length > 0 && <section className="warning-box"><AlertTriangle />{report.warnings.join(' · ')}</section>}
    <div className="discovery-grid">
      <section className="panel"><div className="section-heading"><div><p className="eyebrow">Read-only SQLite</p><h2><Database /> Основной архив</h2></div></div>
        {report.archive_candidates.length === 0 ? <p className="muted">Кандидаты не найдены. Для нового пустого проекта архив может ещё не существовать.</p> : <div className="candidate-list">{report.archive_candidates.map(item => <label key={item.path}><input type="radio" name="archive" checked={chosen === item.path} onChange={() => setArchive(item.path)} /><span><strong>{item.path}</strong><small>{item.type} · {confidenceLabel[item.confidence]} · {sizeLabel(item.size)} · read-only: {item.read_only_opened ? 'OK' : 'нет'} · WAL: {item.wal_exists ? 'active' : 'нет'}</small><small>{item.evidence.join(' · ')}</small></span></label>)}</div>}
        {isAdmin && <div className="manual-path"><input aria-label="Другой путь архива" placeholder="Указать другой локальный путь" value={chosen} onChange={event => setArchive(event.target.value)} /><button disabled={!chosen || confirm.isPending} onClick={() => confirm.mutate(chosen)}>Подтвердить</button></div>}
      </section>
      <section className="panel"><div className="section-heading"><div><p className="eyebrow">Источники чтения</p><h2><FileText /> Логи</h2></div></div>
        {report.log_candidates.length === 0 ? <p className="muted">Источники логов не найдены.</p> : <div className="candidate-list">{report.log_candidates.map(item => <label key={item.path}><input type="checkbox" disabled={!isAdmin} checked={selectedLogs.includes(item.path)} onChange={event => saveLogs.mutate(event.target.checked ? [...selectedLogs, item.path] : selectedLogs.filter(path => path !== item.path))} /><span><strong>{item.path}</strong><small>{confidenceLabel[item.confidence]} · score {item.score}</small></span></label>)}</div>}
      </section>
    </div>
    {isAdmin && selectedCandidate && <section className="panel archive-inspector"><div className="section-heading"><div><p className="eyebrow">Архив → Инспектор</p><h2><Table2 /> Безопасная схема SQLite</h2></div></div>
      <p className="muted">Показаны только ограниченные метаданные и до пяти строк на таблицу. Изменения в SQLite не выполняются.</p>
      <div className="mapping-grid">
        <label>Таблица<input value={field('table', inferred?.table)} onChange={e => setMapping({ ...mapping, table: e.target.value })} /></label>
        <label>Timestamp<input value={field('timestamp_column', inferred?.roles.timestamp ?? '')} onChange={e => setMapping({ ...mapping, timestamp_column: e.target.value })} /></label>
        <label>Signal ID<input value={field('signal_id_column', inferred?.roles.signal_id ?? '')} onChange={e => setMapping({ ...mapping, signal_id_column: e.target.value })} /></label>
        <label>Value<input value={field('value_column', inferred?.roles.value ?? '')} onChange={e => setMapping({ ...mapping, value_column: e.target.value })} /></label>
        <label>Quality (необязательно)<input value={field('quality_column', inferred?.roles.quality ?? '')} onChange={e => setMapping({ ...mapping, quality_column: e.target.value })} /></label>
        <button className="primary-button" disabled={!mappingReady || saveMapping.isPending} onClick={submitMapping}>Подтвердить схему</button>
      </div>
      {inferred && <SchemaSummary value={inferred} />}
      <div className="inspector-tables">{selectedCandidate.objects?.map(object => <details key={object.name}><summary><strong>{object.name}</strong><span>{object.type} · строк: {object.bounded_row_count ?? 'не определено'}{object.row_count_limit_reached ? '+' : ''}</span></summary><p>Колонки: {object.columns.map(column => `${column.name} (${column.declared_type || 'ANY'})`).join(', ') || 'нет'}</p><p>Индексы: {object.indexes.map(index => `${index.name} [${index.columns.join(', ')}]`).join('; ') || 'нет'}</p><p>Связи: {object.foreign_keys.map(key => `${key.from_column} → ${key.target_table}.${key.target_column}`).join('; ') || 'нет'}</p>{object.recent_samples.length > 0 && <pre>{JSON.stringify(object.recent_samples, null, 2)}</pre>}</details>)}</div>
    </section>}
    <section className="configuration-strip"><span>Версия конфигурации: {configuration.data?.config_version ?? 0}</span><span>Статус применения: {configuration.data?.apply_status ?? 'не настроено'}</span><span>Сканирование: {new Date(report.scanned_at).toLocaleString('ru-RU')}</span></section>
  </>
}

function SchemaSummary({ value }: { value: ArchiveSchemaCandidate }) {
  return <div className="schema-summary"><strong>Предложение анализатора: {value.table}</strong><span>{confidenceLabel[value.confidence]} · timestamp: {value.roles.timestamp ?? '—'} · signal ID: {value.roles.signal_id ?? '—'} · value: {value.roles.value ?? '—'}</span><small>{value.minimum_timestamp || value.maximum_timestamp ? `Диапазон timestamp: ${value.minimum_timestamp ?? '—'} … ${value.maximum_timestamp ?? '—'}` : 'Диапазон timestamp не читался без подходящего индекса'}</small></div>
}
