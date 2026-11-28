
import { useState } from 'react'
import { motion } from 'motion/react'
import {
  Mail,
  UploadCloud,
  ShieldCheck,
  AlertTriangle,
  LoaderCircle,
  FileSearch,
  CheckCircle2,
  Download
} from 'lucide-react'

const MAX_EMAIL_SIZE = 10 * 1024 * 1024

export default function EmailAnalyzer() {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState('')

  // -----------------------------------------
  // SELECT EMAIL FILE
  // -----------------------------------------

  function selectFile(event) {
    const selected = event.target.files?.[0]

    setResult(null)
    setError('')
    setFile(null)

    if (!selected) return

    if (!selected.name.toLowerCase().endsWith('.eml')) {
      setError('Please select a valid .eml file.')
      event.target.value = ''
      return
    }

    if (selected.size > MAX_EMAIL_SIZE) {
      setError('File must be 10 MiB or smaller.')
      event.target.value = ''
      return
    }

    setFile(selected)
  }

  // -----------------------------------------
  // ANALYZE EMAIL
  // -----------------------------------------

  async function analyzeEmail(event) {
    event.preventDefault()

    if (!file || loading) return

    setLoading(true)
    setResult(null)
    setError('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(
        'http://127.0.0.1:8000/api/analyze/email',
        {
          method: 'POST',
          body: formData,
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string'
            ? data.detail
            : `Email analysis failed (HTTP ${response.status})`
        )
      }

      if (data.error) {
        throw new Error(data.error)
      }

      setResult(data)

    } catch (err) {
      setError(
        err.message || 'Could not analyze email.'
      )
    } finally {
      setLoading(false)
    }
  }

  // -----------------------------------------
  // DOWNLOAD EMAIL PDF REPORT
  // -----------------------------------------

  async function downloadEmailReport() {
    if (!file || !result || downloading) return

    setDownloading(true)
    setError('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(
        'http://127.0.0.1:8000/api/report/email',
        {
          method: 'POST',
          body: formData,
        }
      )

      if (!response.ok) {
        let message = `PDF download failed (HTTP ${response.status})`

        try {
          const data = await response.json()

          if (typeof data.detail === 'string') {
            message = data.detail
          }
        } catch {
          // Keep the HTTP error message.
        }

        throw new Error(message)
      }

      const pdfBlob = await response.blob()

      if (pdfBlob.size === 0) {
        throw new Error('The generated PDF is empty.')
      }

      const fileUrl = URL.createObjectURL(pdfBlob)

      const downloadLink = document.createElement('a')

      downloadLink.href = fileUrl
      downloadLink.download = 'PhishGuard_Email_Report.pdf'

      document.body.appendChild(downloadLink)
      downloadLink.click()
      downloadLink.remove()

      setTimeout(() => {
        URL.revokeObjectURL(fileUrl)
      }, 1000)

    } catch (err) {
      setError(
        err.message || 'Unable to download PDF report.'
      )
    } finally {
      setDownloading(false)
    }
  }

  // -----------------------------------------
  // ANALYSIS RESULTS
  // -----------------------------------------

  const score = Math.max(
    0,
    Math.min(100, Number(result?.score) || 0)
  )

  const signals = result?.signals || []
  const recommendations = result?.recommendations || []
  const metadata = result?.metadata || {}

  const verdict = String(
    result?.verdict || 'Unknown'
  ).replaceAll('_', ' ')

  const safe = score < 30

  return (
    <motion.div
      className="analyzer-view"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >

      {/* -----------------------------------
          EMAIL ANALYZER HEADER
      ----------------------------------- */}

      <div className="hero">
        <div className="hero-title-row">

          <div className="hero-icon">
            <Mail size={30} />
          </div>

          <div>
            <h1>
              Email <em>Analyzer</em>
            </h1>

            <p>
              Investigate suspicious email files using
              the PhishGuard detection engine.
            </p>
          </div>
        </div>

        <div className="hero-chips">
          <span>
            <ShieldCheck size={15} />
            Static Analysis
          </span>

          <span>
            <Mail size={15} />
            Email Headers
          </span>

          <span>
            <FileSearch size={15} />
            Threat Detection
          </span>
        </div>
      </div>

      {/* -----------------------------------
          EMAIL UPLOAD FORM
      ----------------------------------- */}

      <form
        className="scan-panel glass-panel"
        onSubmit={analyzeEmail}
      >

        <label htmlFor="email-file">
          Upload Email (.eml)
        </label>

        <div className="email-upload-zone">

          <UploadCloud size={32} />

          <input
            id="email-file"
            type="file"
            accept=".eml,message/rfc822"
            onChange={selectFile}
            disabled={loading || downloading}
          />

          <p>
            {file
              ? file.name
              : 'Choose a suspicious .eml file'}
          </p>

          <small>
            Maximum upload size: 10 MiB
          </small>

        </div>

        <button
          className="scan-button"
          type="submit"
          disabled={!file || loading || downloading}
        >

          {loading ? (
            <LoaderCircle
              className="spin"
              size={19}
            />
          ) : (
            <ShieldCheck size={19} />
          )}

          {loading
            ? 'Analyzing...'
            : 'Analyze Email'}

        </button>

        <p className="scan-note">
          Passive local analysis. Do not upload confidential
          emails without authorization.
        </p>

      </form>

      {/* -----------------------------------
          ERROR MESSAGE
      ----------------------------------- */}

      {error && (
        <div
          className="error-panel"
          role="alert"
        >
          <AlertTriangle size={20} />
          {error}
        </div>
      )}

      {/* -----------------------------------
          EMAIL INVESTIGATION REPORT
      ----------------------------------- */}

      {result && (
        <motion.section
          className="report-panel glass-panel"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >

          <div className="report-heading">

            <div>
              <span className="section-kicker">
                EMAIL INVESTIGATION REPORT
              </span>

              <h2>
                Analysis Results
              </h2>

              <p className="report-target">
                File: {file?.name || result.target}
              </p>
            </div>

            <span className="completed">
              <CheckCircle2 size={16} />
              Completed
            </span>

          </div>

          {/* -----------------------------------
              RISK METRICS
          ----------------------------------- */}

          <div className="report-metrics">

            <div className="metric-card metric-blue">
              <ShieldCheck size={25} />
              <span>Risk Score</span>
              <strong>
                {score}/100
              </strong>
            </div>

            <div
              className={`metric-card ${
                safe
                  ? 'verdict-safe'
                  : 'verdict-warning'
              }`}
            >

              {safe ? (
                <ShieldCheck size={25} />
              ) : (
                <AlertTriangle size={25} />
              )}

              <span>Verdict</span>

              <strong>
                {verdict}
              </strong>

            </div>

            <div className="metric-card metric-blue">
              <Mail size={25} />
              <span>Signals</span>

              <strong>
                {signals.length}
              </strong>

            </div>

          </div>

          {/* -----------------------------------
              INVESTIGATION DETAILS
          ----------------------------------- */}

          <div className="report-details">

            <div className="detail-card">

              <h3>
                Sender Information
              </h3>

              <p>
                <strong>From:</strong>{' '}
                {metadata.from || 'Unknown'}
              </p>

              <p>
                <strong>Subject:</strong>{' '}
                {metadata.subject || 'None'}
              </p>

              <p>
                <strong>Reply-To:</strong>{' '}
                {metadata.reply_to || 'None'}
              </p>

              <p>
                <strong>Date:</strong>{' '}
                {metadata.date || 'Unknown'}
              </p>

            </div>

            <div className="detail-card">

              <h3>
                Detected Signals
              </h3>

              {signals.length ? (
                <ul>
                  {signals.map((signal, index) => (
                    <li key={signal.id || index}>
                      {signal.title ||
                        signal.description ||
                        signal.id ||
                        `Signal ${index + 1}`}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>
                  No signals returned.
                </p>
              )}

            </div>

          </div>

          {/* -----------------------------------
              SECURITY RECOMMENDATIONS
          ----------------------------------- */}

          <div className="recommendations">

            <h3>
              <ShieldCheck size={21} />
              Security Recommendations
            </h3>

            <ul>

              {recommendations.length ? (
                recommendations.map((item, index) => (
                  <li key={index}>
                    <CheckCircle2 size={17} />
                    {item}
                  </li>
                ))
              ) : (
                <li>
                  No recommendations returned.
                </li>
              )}

            </ul>

          </div>

          {/* -----------------------------------
              DISCLAIMER
          ----------------------------------- */}

          <p className="report-disclaimer">
            Automated analysis does not guarantee an email
            is safe. Verify suspicious messages independently.
          </p>

          {/* -----------------------------------
              PDF DOWNLOAD BUTTON
          ----------------------------------- */}

          <div className="report-actions">

            <button
              type="button"
              className="download-report-button"
              onClick={downloadEmailReport}
              disabled={downloading}
            >

              {downloading ? (
                <>
                  <LoaderCircle
                    className="spin"
                    size={18}
                  />
                  Generating PDF...
                </>
              ) : (
                <>
                  <Download size={18} />
                  Download PDF Report
                </>
              )}

            </button>

          </div>

        </motion.section>
      )}

    </motion.div>
  )
}
