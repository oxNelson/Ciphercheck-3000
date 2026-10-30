-- Migration 0004: Add threat intelligence columns to saved_reports
ALTER TABLE saved_reports 
  ADD COLUMN IF NOT EXISTS threat_intel_status VARCHAR(50) DEFAULT 'unverified',
  ADD COLUMN IF NOT EXISTS threat_intel_matches INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_saved_reports_threat_intel_status ON saved_reports(threat_intel_status);
