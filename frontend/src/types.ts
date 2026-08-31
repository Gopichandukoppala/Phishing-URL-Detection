export type FeatureSignal = 'legitimate' | 'suspicious' | 'phishing'

export type FeatureRow = {
  key: string
  label: string
  value: number
  signal: FeatureSignal
}

export type PredictResponse = {
  url: string
  normalized_url: string
  prediction: number
  verdict: 'phishing' | 'legitimate' | string
  decision_score: number
  confidence: number
  features: FeatureRow[]
}

export type ScanErrorDetail = {
  code?: string
  title?: string
  message?: string
  host?: string
}

export type PredictError = {
  detail?: string | ScanErrorDetail | Array<string | { msg?: string }>
}

export type DisplayError = {
  title: string
  message: string
  host?: string
}
