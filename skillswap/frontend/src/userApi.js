// src/userApi.js
import api from './apiClient'

// POST /api/users/register
export async function registerUser(userData) {
  // userData: { name, email, password } or whatever your controller expects
  const res = await api.post('/users/register', userData)
  return res.data
}

// POST /api/users/login
export async function loginUser(credentials) {
  // credentials: { email, password }
  const res = await api.post('/users/login', credentials)
  return res.data
}

// GET /api/users
export async function getAllUsers() {
  const res = await api.get('/users')
  return res.data
}
