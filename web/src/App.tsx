import { Activity, Bell, Factory, Gauge, LogOut, Radio, ShieldCheck } from 'lucide-react'
import { NavLink, Navigate, Outlet, Route, Routes, useNavigate } from 'react-router-dom'
import { api } from './api'
import Dashboard from './pages/Dashboard'
import Incidents from './pages/Incidents'
import Login from './pages/Login'
import Signals from './pages/Signals'
import Sites from './pages/Sites'

function Shell() {
  const navigate = useNavigate()
  const signOut = async () => {
    await api.logout().catch(() => undefined)
    navigate('/login')
  }
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><ShieldCheck size={28} /><span>ScadaGuard<small>Центр мониторинга</small></span></div>
        <nav aria-label="Основная навигация">
          <NavLink to="/"><Gauge />Обзор</NavLink>
          <NavLink to="/sites"><Factory />Объекты</NavLink>
          <NavLink to="/incidents"><Bell />Инциденты</NavLink>
          <NavLink to="/signals"><Activity />Сигналы</NavLink>
        </nav>
        <div className="connection"><Radio size={16} /><span>Центральный сервер<small>состояние обновляется</small></span></div>
        <button className="logout" onClick={signOut}><LogOut size={17} />Выйти</button>
      </aside>
      <main className="content"><Outlet /></main>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Shell />}>
        <Route index element={<Dashboard />} />
        <Route path="sites" element={<Sites />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="signals" element={<Signals />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
