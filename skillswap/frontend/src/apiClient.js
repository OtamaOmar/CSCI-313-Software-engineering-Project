import axios from 'axios'

// baseURL is relative; the Vite proxy sends /api to the backend
const api = axios.create({
  baseURL: '/api',
})

export default api
