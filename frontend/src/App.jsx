
import { useState } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import {
  Shield, ShieldCheck, LayoutDashboard, Link2,
  Mail, QrCode, FileSearch, Share2, Activity,
  Zap, ArrowRight, CheckCircle2, AlertTriangle,
  Target, Layers, LoaderCircle, ChevronRight
} from 'lucide-react'

import EmailAnalyzer from './EmailAnalyzer'
import QRAnalyzer from './QRAnalyzer'
import './App.css'

const modules = [
  { name: 'Dashboard', Icon: LayoutDashboard },
  { name: 'URL Analyzer', Icon: Link2 },
  { name: 'Email Analyzer', Icon: Mail },
  { name: 'QR Code Analyzer', Icon: QrCode },
  { name: 'File Analyzer', Icon: FileSearch },
  { name: 'Social Media Analyzer', Icon: Share2 },
]

function ThreatGlobe() {
  return (
    <div className="globe-scene" aria-hidden="true">
      <div className="globe-orbit orbit-one" />
      <div className="globe-orbit orbit-two" />
      <div className="globe-core">
        <div className="globe-meridian" />
        <div className="globe-equator" />
        <div className="globe-shine" />
      </div>
      <div className="globe-satellite" />
      <div className="globe-caption">
        <span className="live-dot" />
        THREAT MONITOR
      </div>
    </div>
  )
}

function WaveBackground() {
  return (
    <div className="wave-background" aria-hidden="true">
      <svg viewBox="0 0 900 210" preserveAspectRatio="none">
        {Array.from({ length: 18 }, (_, i) => {
          const y = 100 + i * 3
          return (
            <path
              key={i}
              d={`M 0 ${y} C 200 ${y - 95} 340 ${y + 110} 540 ${y - 20} S 760 ${y - 90} 900 ${y - 25}`}
              fill="none"
              stroke={i % 2 ? '#a83dff' : '#00e5ff'}
              strokeWidth=".8"
              opacity={0.12 + i * 0.013}
            />
          )
        })}
      </svg>
    </div>
  )
}

function RiskGauge({ score }) {
  const safeScore = Math.max(
    0,
    Math.min(100, Number(score) || 0)
  )

  return (
    <div
      className="risk-gauge"
      role="img"
      aria-label={`Risk score ${safeScore} out of 100`}
      style={{ '--risk': `${safeScore}%` }}
    >
      <div className="gauge-center">
        <strong>
          {safeScore}
          <small>/100</small>
        </strong>
        <span>Risk Score</span>
      </div>
    </div>
  )
}

function URLAnalyzer() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)

  async function analyze(event) {
    event.preventDefault()
    const target = url.trim()

    if (!target) {
      setError('Please enter a URL.')
      return
    }

    setLoading(true)
    setResult(null)
    setError('')

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/api/analyze/url',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url: target }),
        }
      )

      if (!response.ok) {
        throw new Error(
          `Analysis failed: HTTP ${response.status}`
        )
      }

      const data = await response.json()

      if (data.error) {
        throw new Error(data.error)
      }

      setResult(data)
    } catch (err) {
      setError(
        err.message || 'Could not reach the API.'
      )
    } finally {
      setLoading(false)
    }
  }

  async function downloadReport() {
    if (!result?.target || downloading) {
      return
    }

    setDownloading(true)
    setError('')

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/api/report/url',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            url: result.target,
          }),
        }
      )

      if (!response.ok) {
        throw new Error(
          `PDF generation failed (HTTP ${response.status})`
        )
      }

      const pdfBlob = await response.blob()
      const fileUrl = URL.createObjectURL(pdfBlob)

      const downloadLink = document.createElement('a')
      downloadLink.href = fileUrl
      downloadLink.download = 'PhishGuard_URL_Report.pdf'

      document.body.appendChild(downloadLink)
      downloadLink.click()
      downloadLink.remove()

      setTimeout(() => {
        URL.revokeObjectURL(fileUrl)
      }, 1000)

    } catch (err) {
      setError(
        err.message || 'Unable to download the report.'
      )
    } finally {
      setDownloading(false)
    }
  }

  const verdict = String(
    result?.verdict || ''
  ).replaceAll('_', ' ')

  const score = Number(result?.score) || 0
  const safe = score < 30

  const confidence = Math.round(
    (Number(result?.confidence) || 0) * 100
  )

  return (
    <motion.div
      className="analyzer-view"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <div className="hero">
        <WaveBackground />

        <div className="hero-title-row">
          <div className="hero-icon">
            <Link2 size={30} />
          </div>

          <div>
            <h1>
              URL <em>Analyzer</em>
            </h1>
            <p>
              Investigate suspicious URLs using the
              PhishGuard detection engine.
            </p>
          </div>
        </div>

        <div className="hero-chips">
          <span>
            <Zap size={15} /> Phishing Detection
          </span>
          <span>
            <Shield size={15} /> Passive URL Analysis
          </span>
          <span>
            <Target size={15} /> Risk Assessment
          </span>
        </div>
      </div>

      <form
        className="scan-panel glass-panel"
        onSubmit={analyze}
      >
        <label htmlFor="target-url">
          Website URL
        </label>

        <div className="scan-row">
          <div className="scan-input-wrap">
            <Link2 size={20} />

            <input
              id="target-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              maxLength={2048}
              required
              spellCheck={false}
            />

            {url && (
              <button
                type="button"
                className="clear-button"
                onClick={() => setUrl('')}
                aria-label="Clear URL"
              >
                ×
              </button>
            )}
          </div>

          <button
            className="scan-button"
            type="submit"
            disabled={loading}
          >
            {loading ? (
              <LoaderCircle
                className="spin"
                size={19}
              />
            ) : (
              <Zap size={19} />
            )}

            {loading ? 'Analyzing...' : 'Analyze URL'}
          </button>
        </div>

        <p className="scan-note">
          Passive checks only — no page fetching or
          external threat-intelligence lookups.
        </p>
      </form>

      {error && (
        <div
          className="error-panel"
          role="alert"
        >
          <AlertTriangle size={20} />
          {error}
        </div>
      )}

      <AnimatePresence mode="wait">
        {result && (
          <motion.section
            key={result.target}
            className="report-panel glass-panel"
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.55 }}
          >
            <div className="report-heading">
              <div>
                <span className="section-kicker">
                  INVESTIGATION REPORT
                </span>

                <h2>Analysis Results</h2>

                <p className="report-target">
                  Target: {result.target}
                </p>
              </div>

              <span className="completed">
                <CheckCircle2 size={16} />
                Completed
              </span>
            </div>

            <div className="report-metrics">
              <div className="gauge-card">
                <RiskGauge score={score} />
              </div>

              <div
                className={`metric-card ${
                  safe ? 'verdict-safe' : 'verdict-warning'
                }`}
              >
                {safe ? (
                  <ShieldCheck size={25} />
                ) : (
                  <AlertTriangle size={25} />
                )}

                <span>Verdict</span>
                <strong>{verdict}</strong>
                <small>
                  Automated risk assessment
                </small>
              </div>

              <div className="metric-card metric-blue">
                <Target size={25} />
                <span>Confidence</span>
                <strong>{confidence}%</strong>

                <div className="confidence-track">
                  <div
                    style={{
                      width: `${confidence}%`,
                    }}
                  />
                </div>
              </div>

              <div className="metric-card metric-blue">
                <Layers size={25} />
                <span>Indicators</span>
                <strong>
                  {result.signals?.length ?? 0}
                </strong>
                <small>Signals returned</small>
              </div>
            </div>

            <div className="report-details">
              <div className="detail-card">
                <h3>
                  <FileSearch size={21} />
                  Investigation Summary
                </h3>

                <p>{result.summary}</p>
              </div>

              <div className="detail-card">
                <h3>
                  <Activity size={21} />
                  Detected Signals
                </h3>

                {result.signals?.length ? (
                  <ul>
                    {result.signals.map(
                      (signal, i) => (
                        <li key={i}>
                          {signal.description ||
                            signal.title ||
                            signal.name ||
                            signal.code ||
                            JSON.stringify(signal)}
                        </li>
                      )
                    )}
                  </ul>
                ) : (
                  <p>No signals returned.</p>
                )}
              </div>
            </div>

            <div className="recommendations">
              <h3>
                <ShieldCheck size={21} />
                Security Recommendations
              </h3>

              <ul>
                {result.recommendations?.length ? (
                  result.recommendations.map(
                    (item, i) => (
                      <li key={i}>
                        <CheckCircle2 size={17} />
                        {item}
                      </li>
                    )
                  )
                ) : (
                  <li>
                    No recommendations returned.
                  </li>
                )}
              </ul>
            </div>

            <p className="report-disclaimer">
              A low score does not guarantee a URL is safe.
              Review the context before acting.
            </p>

            <div className="report-actions">
              <button
                type="button"
                className="download-report-button"
                onClick={downloadReport}
                disabled={downloading}
              >
                {downloading
                  ? 'Generating PDF...'
                  : '↓ Download PDF Report'}
              </button>
            </div>
          </motion.section>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

function Dashboard({ navigate }) {
  return (
    <motion.div
      className="dashboard-view"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="hero">
        <WaveBackground />

        <div className="hero-title-row">
          <div className="hero-icon">
            <Shield size={30} />
          </div>

          <div>
            <h1>
              Threat <em>Command Center</em>
            </h1>
            <p>
              Analyze suspicious content across five
              security investigation modules.
            </p>
          </div>
        </div>
      </div>

      <div className="dashboard-metrics">
        <div className="metric-card metric-blue">
          <Layers size={26} />
          <span>AVAILABLE ANALYZERS</span>
          <strong>05</strong>
          <small>Investigation modules</small>
        </div>

        <div className="metric-card verdict-safe">
          <Activity size={26} />
          <span>PLATFORM STATUS</span>
          <strong>Local</strong>
          <small>Development environment</small>
        </div>

        <div className="metric-card metric-blue">
          <ShieldCheck size={26} />
          <span>CONNECTED ANALYZERS</span>
          <strong>03</strong>
          <small>URL, Email and QR APIs</small>
        </div>
      </div>

      <h2 className="modules-title">
        Analysis Workspace
      </h2>

      <div className="module-grid">
        {modules.slice(1).map(({ name, Icon }) => {
          const connected = [
        'URL Analyzer',
        'Email Analyzer',
        'QR Code Analyzer',
        ].includes(name)

          return (
            <motion.button
              key={name}
              type="button"
              className="module-tile glass-panel"
              onClick={() => navigate(name)}
              whileHover={{
                y: -6,
                scale: 1.015,
              }}
              transition={{ duration: 0.2 }}
            >
              <span className="module-tile-icon">
                <Icon size={27} />
              </span>

              <strong>{name}</strong>

              <small>
                {connected
                  ? 'FastAPI integration'
                  : 'Integration pending'}
              </small>

              <ArrowRight
                className="tile-arrow"
                size={19}
              />
            </motion.button>
          )
        })}
      </div>
    </motion.div>
  )
}

function App() {
  const [activePage, setActivePage] = useState(
    'Dashboard'
  )

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={28} />
          </div>

          <div>
            <h2>
              Phish<span>Guard</span>
            </h2>
            <small>
              THREAT INTELLIGENCE PLATFORM
            </small>
          </div>
        </div>

        <div className="sidebar-label">
          WORKSPACE
        </div>

        <nav aria-label="Main navigation">
          {modules.map(({ name, Icon }) => (
            <button
              key={name}
              type="button"
              className={`nav-link ${
                activePage === name
                  ? 'selected'
                  : ''
              }`}
              onClick={() => setActivePage(name)}
            >
              <Icon size={20} />
              <span>{name}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <ThreatGlobe />

          <div className="system-card">
            <span className="live-dot" />
            <strong>System Interface</strong>
            <small>
              Local Development • v0.1
            </small>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="top-header">
          <div className="breadcrumb">
            <ChevronRight size={17} />
            <span>workspace</span>

            <span className="breadcrumb-muted">
              / {activePage
                .toLowerCase()
                .replaceAll(' ', '-')}
            </span>
          </div>

          <div className="header-right">
            <Activity size={23} />
            <Shield size={23} />
          </div>
        </header>

        <div className="page-container">
  {activePage === 'Dashboard' ? (
    <Dashboard navigate={setActivePage} />
  ) : activePage === 'URL Analyzer' ? (
    <URLAnalyzer />
  ) : activePage === 'Email Analyzer' ? (
    <EmailAnalyzer />
  ) : activePage === 'QR Code Analyzer' ? (
    <QRAnalyzer />
  ) : (
    <motion.div
              className="placeholder-view glass-panel"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <Shield size={44} />

              <h1>{activePage}</h1>

              <p>
                This module's React integration
                is under development.
                The existing Python analyzer
                remains unchanged.
              </p>

              <span className="pending-tag">
                Integration pending
              </span>
            </motion.div>
          )}
        </div>
      </main>
    </div>
  )
}

export default App
