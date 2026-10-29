-- Migration 0001: Add nickname column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname VARCHAR(30);
