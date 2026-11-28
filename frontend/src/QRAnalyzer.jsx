
import { useState } from 'react'
import { motion } from 'motion/react'

import {
  QrCode,
  UploadCloud,
  ShieldCheck,
  AlertTriangle,
  LoaderCircle,
  CheckCircle2,
  Download,
  Link2,
  FileSearch,
} from 'lucide-react'

const API = 'http://127.0.0.1:8000'
const MAX_SIZE = 10 * 1024 * 1024

const ALLOWED_EXTENSIONS = [
  'png',
  'jpg',
  'jpeg',
  'webp',
  'bmp',
]

export default function QRAnalyzer() {

  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState('')

  // =====================================
  // FILE VALIDATION
  // =====================================

  function selectFile(event) {

    const selected = event.target.files?.[0]

    setFile(null)
    setResult(null)
    setError('')

    if (!selected) return

    const extension = selected.name
      .split('.')
      .pop()
      .toLowerCase()

    if (!ALLOWED_EXTENSIONS.includes(extension)) {

      setError('Unsupported image format.')
      event.target.value = ''
      return

    }

    if (selected.size === 0) {

      setError('The selected image is empty.')
      event.target.value = ''
      return

    }

    if (selected.size > MAX_SIZE) {

      setError('Image must be 10 MiB or smaller.')
      event.target.value = ''
      return

    }

    setFile(selected)

  }

  // =====================================
  // QR CODE ANALYSIS
  // =====================================

  async function analyzeQR(event) {

    event.preventDefault()

    if (!file || loading || downloading) return

    setLoading(true)
    setResult(null)
    setError('')

    try {

      const formData = new FormData()

      formData.append('file', file)

      const response = await fetch(
        `${API}/api/analyze/qr`,
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
            : `Analysis failed (HTTP ${response.status})`
        )

      }

      if (data.error) {

        throw new Error(data.error)

      }

      setResult(data)

    } catch (err) {

      setError(
        err.message || 'QR code analysis failed.'
      )

    } finally {

      setLoading(false)

    }

  }

  // =====================================
  // PDF REPORT DOWNLOAD
  // =====================================

  async function downloadReport() {

    if (!file || !result || downloading || loading) return

    setDownloading(true)
    setError('')

    try {

      const formData = new FormData()

      formData.append('file', file)

      const response = await fetch(
        `${API}/api/report/qr`,
        {
          method: 'POST',
          body: formData,
        }
      )

      if (!response.ok) {

        let message = `PDF generation failed (HTTP ${response.status})`

        try {

          const data = await response.json()

          if (typeof data.detail === 'string') {
            message = data.detail
          }

        } catch {
          // Keep default error message
        }

        throw new Error(message)

      }

      const contentType =
        response.headers.get('content-type') || ''

      if (!contentType.includes('application/pdf')) {

        throw new Error('Server did not return a PDF.')

      }

      const blob = await response.blob()

      if (!blob.size) {

        throw new Error('Generated PDF is empty.')

      }

      const url = URL.createObjectURL(blob)

      const link = document.createElement('a')

      link.href = url

      link.download = 'PhishGuard_QR_Report.pdf'

      document.body.appendChild(link)

      link.click()

      link.remove()

      setTimeout(
        () => URL.revokeObjectURL(url),
        1000
      )

    } catch (err) {

      setError(
        err.message || 'Unable to download PDF.'
      )

    } finally {

      setDownloading(false)

    }

  }

  // =====================================
  // RESULT PROCESSING
  // =====================================

  const metadata = result?.metadata || {}

  const signals = result?.signals || []

  const recommendations =
    result?.recommendations || []

  const decodedValues =
    metadata.decoded_values || []

  const urlReports =
    metadata.url_reports || []

  const score = Math.max(
    0,
    Math.min(100, Number(result?.score) || 0)
  )

  const verdict = String(
    result?.verdict || 'Unknown'
  ).replaceAll('_', ' ')

  // =====================================
  // USER INTERFACE
  // =====================================

  return (

    <motion.div
      className="analyzer-view"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
    >

      {/* HERO SECTION */}

      <div className="hero">

        <div className="hero-title-row">

          <div className="hero-icon">
            <QrCode size={30} />
          </div>

          <div>

            <h1>
              QR Code <em>Analyzer</em>
            </h1>

            <p>
              Investigate suspicious QR codes and
              identify potential phishing destinations.
            </p>

          </div>

        </div>

        <div className="hero-chips">

          <span>Local QR Decoding</span>
          <span>URL Investigation</span>
          <span>Risk Assessment</span>
          <span>SOC Reporting</span>

        </div>

      </div>

      {/* UPLOAD SECTION */}

      <form
        className="scan-panel glass-panel"
        onSubmit={analyzeQR}
      >

        <label htmlFor="qr-file">
          Upload QR Code Image
        </label>

        <div className="email-upload-zone">

          <UploadCloud size={38} />

          <input
            id="qr-file"
            type="file"
            accept=".png,.jpg,.jpeg,.webp,.bmp"
            onChange={selectFile}
            disabled={loading || downloading}
          />

          <p>
            {file
              ? file.name
              : 'Choose a QR code image'}
          </p>

          <small>
            PNG, JPG, JPEG, WEBP, BMP | Maximum 10 MiB
          </small>

        </div>

        <button
          className="scan-button"
          type="submit"
          disabled={!file || loading || downloading}
        >

          {loading ? (

            <>
              <LoaderCircle
                size={20}
                className="spin"
              />
              Analyzing QR Code...
            </>

          ) : (

            <>
              <FileSearch size={20} />
              Analyze QR Code
            </>

          )}

        </button>

        <p className="scan-note">

          QR destinations are analyzed locally.
          Suspicious links are not automatically opened.

        </p>

      </form>

      {/* ERROR MESSAGE */}

      {error && (

        <div className="error-panel" role="alert">

          <AlertTriangle size={20} />

          {error}

        </div>

      )}

      {/* INVESTIGATION RESULTS */}

      {result && (

        <motion.section
          className="report-panel glass-panel"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >

          <div className="report-heading">

            <div>

              <span className="section-kicker">
                QR CODE INVESTIGATION REPORT
              </span>

              <h2>Analysis Results</h2>

              <p className="report-target">
                File: {file?.name || result.target}
              </p>

            </div>

            <span className="completed">

              <CheckCircle2 size={16} />

              Completed

            </span>

          </div>

          {/* RISK METRICS */}

          <div className="report-metrics">

            <div className="metric-card metric-blue">

              <ShieldCheck size={25} />

              <span>Risk Score</span>

              <strong>{score}/100</strong>

            </div>

            <div
              className={`metric-card ${
                score < 30
                  ? 'verdict-safe'
                  : 'verdict-warning'
              }`}
            >

              <AlertTriangle size={25} />

              <span>Verdict</span>

              <strong>{verdict}</strong>

            </div>

            <div className="metric-card metric-blue">

              <QrCode size={25} />

              <span>Decoded QR Codes</span>

              <strong>
                {metadata.decoded_count ?? 0}
              </strong>

            </div>

          </div>

          {/* DECODED CONTENT */}

          <div className="report-details">

            <div className="detail-card">

              <h3>Decoded Content</h3>

              <p>
                URLs detected: {metadata.url_count ?? 0}
              </p>

              {decodedValues.length > 0 ? (

                <ul>

                  {decodedValues.map((value, index) => (

                    <li
                      key={index}
                      style={{ overflowWrap: 'anywhere' }}
                    >

                      <Link2 size={16} />

                      {' '}{value}

                    </li>

                  ))}

                </ul>

              ) : (

                <p>No decoded content available.</p>

              )}

            </div>

            {/* DETECTION SIGNALS */}

            <div className="detail-card">

              <h3>Detected Signals</h3>

              {signals.length > 0 ? (

                <ul>

                  {signals.map((signal, index) => (

                    <li key={signal.id || index}>

                      <strong>
                        {signal.title || signal.id}
                      </strong>

                      <p>
                        Severity: {signal.severity || 'Unknown'}
                      </p>

                      <p>{signal.description}</p>

                      {signal.evidence && (

                        <small
                          style={{
                            overflowWrap: 'anywhere'
                          }}
                        >

                          Evidence: {signal.evidence}

                        </small>

                      )}

                    </li>

                  ))}

                </ul>

              ) : (

                <p>No detection signals returned.</p>

              )}

            </div>

          </div>

          {/* EMBEDDED URL REPORTS */}

          {urlReports.length > 0 && (

            <div className="detail-card">

              <h3>Embedded URL Investigations</h3>

              {urlReports.map((report, index) => (

                <div
                  key={index}
                  style={{
                    padding: '12px 0',
                    overflowWrap: 'anywhere',
                  }}
                >

                  <strong>
                    Destination #{index + 1}
                  </strong>

                  <p>{report.target}</p>

                  <p>
                    Risk Score: {report.score}/100
                  </p>

                  <p>
                    Verdict: {report.verdict}
                  </p>

                </div>

              ))}

            </div>

          )}

          {/* SECURITY RECOMMENDATIONS */}

          <div className="recommendations">

            <h3>

              <ShieldCheck size={21} />

              Security Recommendations

            </h3>

            <ul>

              {recommendations.map((item, index) => (

                <li key={index}>

                  <CheckCircle2 size={17} />

                  {item}

                </li>

              ))}

            </ul>

          </div>

          <p className="report-disclaimer">

            Automated QR analysis cannot guarantee
            that a destination is safe. Always verify
            suspicious destinations independently.

          </p>

          {/* DOWNLOAD BUTTON */}

          <div className="report-actions">

            <button
              type="button"
              className="download-report-button"
              onClick={downloadReport}
              disabled={downloading || loading}
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
