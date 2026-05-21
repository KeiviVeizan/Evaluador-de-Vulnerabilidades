import { createContext, useContext, useState, useCallback } from 'react'
import { CRITERIA } from '../data/criteria'

const EvaluationContext = createContext(null)

const initState = () => {
  const s = {}
  CRITERIA.forEach(c => { s[c.id] = null })
  return s
}

export function EvaluationProvider({ children }) {
  const [appA, setAppA] = useState(initState)
  const [appB, setAppB] = useState(initState)
  const [analysisA,        setAnalysisA]        = useState(null) // APK analysis
  const [analysisB,        setAnalysisB]        = useState(null)
  const [backendAnalysisA, setBackendAnalysisA] = useState(null) // backend analysis
  const [backendAnalysisB, setBackendAnalysisB] = useState(null)

  // Pre-fill from APK analysis
  const applyAnalysis = useCallback((appId, analysis) => {
    if (!analysis?.criteria) return
    const updates = {}
    Object.entries(analysis.criteria).forEach(([id, det]) => {
      if (det.result === 'pass' || det.result === 'fail') {
        updates[id] = det.result
      }
    })
    if (appId === 'A') {
      setAnalysisA(analysis)
      setAppA(prev => ({ ...prev, ...updates }))
    } else {
      setAnalysisB(analysis)
      setAppB(prev => ({ ...prev, ...updates }))
    }
  }, [])

  // Pre-fill from backend analysis
  const applyBackendAnalysis = useCallback((appId, analysis) => {
    if (!analysis?.criteria) return
    const updates = {}
    Object.entries(analysis.criteria).forEach(([id, det]) => {
      if (det.result === 'pass' || det.result === 'fail') {
        updates[id] = det.result
      }
    })
    if (appId === 'A') {
      setBackendAnalysisA(analysis)
      setAppA(prev => ({ ...prev, ...updates }))
    } else {
      setBackendAnalysisB(analysis)
      setAppB(prev => ({ ...prev, ...updates }))
    }
  }, [])

  const setResult = useCallback((appId, criterionId, value) => {
    if (appId === 'A') setAppA(prev => ({ ...prev, [criterionId]: value }))
    else               setAppB(prev => ({ ...prev, [criterionId]: value }))
  }, [])

  const reset = useCallback(() => {
    setAppA(initState())
    setAppB(initState())
    setAnalysisA(null)
    setAnalysisB(null)
    setBackendAnalysisA(null)
    setBackendAnalysisB(null)
  }, [])

  const getScore = useCallback((results) => {
    const passed    = Object.values(results).filter(v => v === 'pass').length
    const failed    = Object.values(results).filter(v => v === 'fail').length
    const na        = Object.values(results).filter(v => v === 'na').length
    const evaluated = passed + failed + na
    return { passed, failed, na, evaluated }
  }, [])

  const getCategoryScore = useCallback((results, domainId) => {
    const cats   = CRITERIA.filter(c => c.domainId === domainId)
    const passed = cats.filter(c => results[c.id] === 'pass').length
    const total  = cats.filter(c => results[c.id] !== null && results[c.id] !== 'na').length
    return { passed, total, count: cats.length }
  }, [])

  // Returns detection info for a given criterion (APK takes priority over backend)
  const getDetection = useCallback((appId, criterionId) => {
    const apk = appId === 'A' ? analysisA        : analysisB
    const bk  = appId === 'A' ? backendAnalysisA : backendAnalysisB
    return apk?.criteria?.[criterionId] ?? bk?.criteria?.[criterionId] ?? null
  }, [analysisA, analysisB, backendAnalysisA, backendAnalysisB])

  return (
    <EvaluationContext.Provider value={{
      appA, appB,
      analysisA, analysisB,
      backendAnalysisA, backendAnalysisB,
      setResult, applyAnalysis, applyBackendAnalysis, reset,
      getScore, getCategoryScore, getDetection,
    }}>
      {children}
    </EvaluationContext.Provider>
  )
}

export const useEvaluation = () => useContext(EvaluationContext)
