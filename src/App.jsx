import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { EvaluationProvider } from './context/EvaluationContext'
import Header from './components/Header'
import HomePage from './pages/HomePage'
import EvaluationPage from './pages/EvaluationPage'
import ReportPage from './pages/ReportPage'
import './App.css'

export default function App() {
  return (
    <EvaluationProvider>
      <BrowserRouter>
        <Header />
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/evaluacion" element={<EvaluationPage />} />
          <Route path="/reporte" element={<ReportPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </EvaluationProvider>
  )
}
