import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import Login from './Login'

vi.mock('../api', () => ({ api: { login: vi.fn().mockRejectedValue(new Error('invalid')) } }))

test('показывает понятную ошибку входа', async () => {
  render(<MemoryRouter><Login /></MemoryRouter>)
  fireEvent.change(screen.getByLabelText('Логин'), { target: { value: 'user' } })
  fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'wrong' } })
  fireEvent.click(screen.getByRole('button', { name: 'Войти' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось войти')
})
