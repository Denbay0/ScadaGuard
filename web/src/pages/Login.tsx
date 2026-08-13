import { ShieldCheck } from 'lucide-react'
import { FormEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'

export default function Login() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault(); setSubmitting(true); setError('')
    try { await api.login(username, password); navigate('/') }
    catch { setError('Не удалось войти. Проверьте логин и пароль.') }
    finally { setSubmitting(false) }
  }

  return <main className="login-page"><section className="login-card">
    <div className="login-mark"><ShieldCheck size={34} /></div><p className="eyebrow">Промышленный мониторинг</p>
    <h1>ScadaGuard</h1><p className="muted">Состояние MasterSCADA и качество данных всех объектов в одном месте.</p>
    <form onSubmit={submit}><label>Логин<input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required /></label>
      <label>Пароль<input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required /></label>
      {error && <div className="form-error" role="alert">{error}</div>}<button disabled={submitting}>{submitting ? 'Вход…' : 'Войти'}</button></form>
  </section></main>
}
