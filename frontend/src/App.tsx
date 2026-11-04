import { useMemo, useState, type FormEvent } from 'react'
import type {
  DisplayError,
  FeatureRow,
  PredictError,
  PredictResponse,
  ScanErrorDetail,
} from './types'

const EXAMPLES = [
  'https://www.wikipedia.org',
  'https://github.com',
  'http://example.com',
]

function pct(value: number) {
  return `${Math.round(value * 100)}%`
}

function signalTone(signal: FeatureRow['signal']) {
  if (signal === 'legitimate') {
    return 'bg-safe-soft text-safe'
  }
  if (signal === 'suspicious') {
    return 'bg-warn-soft text-warn'
  }
  return 'bg-danger-soft text-danger'
}

function parseScanError(detail: PredictError['detail']): DisplayError {
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const item = detail as ScanErrorDetail
    if (item.title || item.message) {
      return {
        title: item.title || 'Could not analyze this URL',
        message:
          item.message ||
          'The scanner stopped before it could extract features.',
        host: item.host,
      }
    }
  }
  if (typeof detail === 'string') {
    return { title: 'Could not analyze this URL', message: detail }
  }
  if (Array.isArray(detail)) {
    const message = detail
      .map((item) =>
        typeof item === 'object' && item && 'msg' in item
          ? String(item.msg)
          : String(item),
      )
      .join(' ')
    return { title: 'Could not analyze this URL', message }
  }
  return {
    title: 'Could not analyze this URL',
    message: 'The scanner could not finish this request.',
  }
}

function FeatureGrid({ features }: { features: FeatureRow[] }) {
  const counts = useMemo(() => {
    return features.reduce(
      (acc, row) => {
        acc[row.signal] += 1
        return acc
      },
      { legitimate: 0, suspicious: 0, phishing: 0 },
    )
  }, [features])

  return (
    <section className="mt-8">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.18em] text-muted uppercase">
            30 extracted features
          </p>
          <h2 className="font-display mt-1 text-2xl text-ink">
            What the Random Forest actually saw
          </h2>
        </div>
        <p className="text-sm text-muted">
          {counts.legitimate} legitimate · {counts.suspicious} suspicious ·{' '}
          {counts.phishing} phishing signals
        </p>
      </div>
      <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {features.map((row) => (
          <li
            key={row.key}
            className="flex items-start justify-between gap-3 rounded-xl border border-rule bg-white/70 px-3 py-3"
          >
            <div className="min-w-0">
              <p className="text-sm font-medium text-ink">{row.label}</p>
              <p className="truncate font-mono text-[11px] text-muted">{row.key}</p>
            </div>
            <span
              className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold ${signalTone(row.signal)}`}
            >
              {row.value}
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function ResultCard({ result }: { result: PredictResponse }) {
  const isSafe = result.verdict === 'legitimate'
  return (
    <section
      className={`mt-8 overflow-hidden rounded-2xl border ${
        isSafe ? 'border-safe/30 bg-safe-soft' : 'border-danger/30 bg-danger-soft'
      }`}
    >
      <div className="px-5 py-6 sm:px-7">
        <p className="text-xs font-semibold tracking-[0.18em] uppercase opacity-70">
          SVM verdict
        </p>
        <h2 className="font-display mt-2 text-3xl sm:text-4xl">
          {isSafe ? 'Looks legitimate' : 'Likely phishing'}
        </h2>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-ink/80">
          Random Forest trained on the UCI phishing-website features. Class{' '}
          <span className="font-semibold">0</span> is phishing, class{' '}
          <span className="font-semibold">1</span> is legitimate.
        </p>
        <dl className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <dt className="text-xs text-muted">Confidence</dt>
            <dd className="mt-1 text-lg font-semibold">{pct(result.confidence)}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Decision score</dt>
            <dd className="mt-1 font-mono text-lg">{result.decision_score}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Predicted class</dt>
            <dd className="mt-1 text-lg font-semibold">{result.prediction}</dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted">Normalized URL</dt>
            <dd className="mt-1 truncate font-mono text-xs sm:text-sm">
              {result.normalized_url}
            </dd>
          </div>
        </dl>
      </div>
    </section>
  )
}

export default function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<DisplayError | null>(null)
  const [result, setResult] = useState<PredictResponse | null>(null)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setResult(null)

    const trimmed = url.trim()
    if (!trimmed) {
      setError({
        title: 'No URL entered',
        message: 'Paste a URL first.',
      })
      return
    }

    setLoading(true)
    try {
      const response = await fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      })
      const payload = (await response.json()) as PredictResponse & PredictError
      if (!response.ok) {
        setError(parseScanError(payload.detail))
        return
      }
      setResult(payload)
    } catch {
      setError({
        title: 'Could not reach the prediction service',
        message: 'Make sure the Python API is running on port 43124.',
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-svh flex-col">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_top_right,#e8d7b8_0%,transparent_36%),radial-gradient(circle_at_bottom_left,#d9efe4_0%,transparent_28%)]" />
      <div className="relative mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-12 lg:py-16">
        <header className="flex flex-col gap-6 border-b border-rule pb-8 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-xs font-semibold tracking-[0.22em] text-muted uppercase">
              URL scanner
            </p>
            <h1 className="font-display mt-2 max-w-xl text-4xl leading-[1.05] text-ink sm:text-5xl">
              Check a link before you trust it.
            </h1>
            <p className="mt-4 max-w-xl text-base leading-7 text-muted">
              Paste a URL. The app extracts the 30 page and address features
              from your URL, then classifies it with the saved Random Forest.
            </p>
          </div>
          <p className="max-w-xs text-sm leading-6 text-muted">
            Feature values follow the training encoding: <strong>1</strong>{' '}
            legitimate, <strong>0</strong> suspicious, <strong>-1</strong> phishing.
          </p>
        </header>

        <form
          id="scanner"
          onSubmit={onSubmit}
          className="mt-8 rounded-2xl border border-rule bg-white/80 p-4 shadow-[0_20px_50px_-32px_rgba(28,25,20,0.45)] sm:p-6"
        >
          <label htmlFor="url" className="text-sm font-medium text-ink">
            Website URL
          </label>
          <div className="mt-2 flex flex-col gap-3 sm:flex-row">
            <input
              id="url"
              name="url"
              type="text"
              inputMode="url"
              autoComplete="url"
              placeholder="https://suspicious-login.example"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              className="h-12 w-full rounded-xl border border-rule bg-paper px-4 text-base text-ink outline-none ring-ink/20 placeholder:text-muted/70 focus:ring-2"
            />
            <button
              type="submit"
              disabled={loading}
              className="h-12 shrink-0 rounded-xl bg-ink px-6 text-sm font-semibold text-paper transition hover:bg-ink/90 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? 'Scanning…' : 'Analyze URL'}
            </button>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {EXAMPLES.map((example) => (
              <button
                key={example}
                type="button"
                onClick={() => setUrl(example)}
                className="rounded-full border border-rule bg-paper-2 px-3 py-1 text-xs font-medium text-ink hover:bg-white"
              >
                {example.replace('https://', '')}
              </button>
            ))}
          </div>
        </form>

        {loading && (
          <div className="mt-8 rounded-2xl border border-dashed border-rule bg-white/50 px-5 py-6">
            <p className="text-sm font-medium text-ink">Fetching the page and extracting features</p>
            <p className="mt-1 text-sm text-muted">
              This can take up to about 15 seconds while the backend downloads the site, checks TLS, and scores the Random Forest.
            </p>
          </div>
        )}

        {error && (
          <div className="mt-8 rounded-2xl border border-danger/30 bg-danger-soft px-5 py-5">
            <p className="text-sm font-semibold text-danger">{error.title}</p>
            {error.host && (
              <p className="mt-2 truncate rounded-lg bg-white/70 px-3 py-2 font-mono text-sm text-ink">
                {error.host}
              </p>
            )}
            <p className="mt-2 text-sm leading-6 text-ink/80">{error.message}</p>
          </div>
        )}

        {!loading && !error && !result && (
          <div className="mt-8 rounded-2xl border border-dashed border-rule px-5 py-10 text-center">
            <p className="font-display text-2xl text-ink">No scan yet</p>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
              Results appear here: a phishing or legitimate verdict, model
              confidence, and every extracted feature used by the classifier.
            </p>
          </div>
        )}

        {result && <ResultCard result={result} />}
        {result && <FeatureGrid features={result.features} />}
      </div>

      <footer className="relative mt-8 bg-ink text-paper">
        <div className="mx-auto grid max-w-6xl gap-10 px-4 py-12 sm:grid-cols-2 sm:px-6 lg:grid-cols-3">
          <div>
            <p className="font-display mt-2 text-2xl">Phishing URL Detection</p>
            <p className="mt-3 max-w-xs text-sm leading-6 text-paper/65">
              A machine learning demo that extracts 30 URL features and classifies
              a page with a Random Forest.
            </p>
          </div>
          <div>
            <p className="text-sm font-semibold">Tech stack</p>
            <ul className="mt-3 space-y-2 text-sm text-paper/65">
              <li>React frontend</li>
              <li>Python FastAPI backend</li>
              <li>scikit-learn Random Forest</li>
              <li>UCI phishing website features</li>
            </ul>
          </div>
          <div id="how-it-works">
            <p className="text-sm font-semibold">How it works</p>
            <ol className="mt-3 list-decimal space-y-2 pl-4 text-sm leading-6 text-paper/65">
              <li>Paste a public http(s) URL.</li>
              <li>The server extracts the 30 training features.</li>
              <li>The saved Random Forest returns phishing (0) or legitimate (1).</li>
            </ol>
          </div>
        </div>
        <div id="disclaimer" className="border-t border-white/10">
          <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-4 text-xs leading-5 text-paper/50 sm:flex-row sm:items-center sm:justify-between sm:px-6">
            <p>© 2026 Phishing URL Detection. Academic project.</p>
            <p>
              This is not a security product. Do not treat the score as proof a
              site is safe or malicious.
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}
