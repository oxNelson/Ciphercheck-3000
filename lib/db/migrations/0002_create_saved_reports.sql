-- Migration 0002: Create saved_reports table for Security Dashboard
CREATE TABLE IF NOT EXISTS saved_reports (
  id VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  redacted_url TEXT NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  registered_domain VARCHAR(255) NOT NULL,
  risk_level VARCHAR(50) NOT NULL,
  verdict_title VARCHAR(255) NOT NULL,
  verdict_summary TEXT,
  findings_count INTEGER NOT NULL DEFAULT 0,
  analysis_data JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saved_reports_user_id ON saved_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_saved_reports_created_at ON saved_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_saved_reports_risk_level ON saved_reports(risk_level);
