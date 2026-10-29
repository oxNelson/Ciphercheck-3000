-- Migration: 0003_create_user_recommendations.sql
-- Description: Creates user_recommendations table to persist addressed and dismissed security recommendations per user

CREATE TABLE IF NOT EXISTS user_recommendations (
  user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  addressed_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  dismissed_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
