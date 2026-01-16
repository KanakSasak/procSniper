import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Configuration from './pages/Configuration'
import History from './pages/History'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/config" element={<Configuration />} />
        <Route path="/history" element={<History />} />
      </Routes>
    </Layout>
  )
}

export default App
