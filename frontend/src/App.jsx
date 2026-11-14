import { Navigate, Route, Routes } from 'react-router-dom'
import { getToken } from './api.js'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Projects from './pages/Projects.jsx'
import NewScan from './pages/NewScan.jsx'
import ScanProgress from './pages/ScanProgress.jsx'
import ScanReport from './pages/ScanReport.jsx'

function Protected({ children }) {
  return getToken() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Protected><Layout /></Protected>}>
        <Route path="/" element={<Navigate to="/projects" replace />} />
        <Route path="/projects" element={<Projects />} />
        <Route path="/scans/new" element={<NewScan />} />
        <Route path="/scans/:id" element={<ScanProgress />} />
        <Route path="/scans/:id/report" element={<ScanReport />} />
      </Route>
      <Route path="*" element={<Navigate to="/projects" replace />} />
    </Routes>
  )
}
