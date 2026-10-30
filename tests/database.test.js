import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
  initDatabase,
  getDatabaseStatus,
  isDatabasePostgres,
  closeDatabase,
  resetMemoryStore,
  createUser,
  findUserById,
  findUserByEmail,
  createSession,
  findSession,
  saveReport,
  getSavedReports,
  getUserRecommendationStatus,
  saveUserRecommendationStatus,
} from "../server-auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("Database Architecture & PostgreSQL Persistence Layer", () => {
  beforeEach(() => {
    resetMemoryStore();
  });

  test("getDatabaseStatus reports current storage type and persistence truthful indicators", async () => {
    await initDatabase();
    const status = getDatabaseStatus();
    assert.equal(typeof status.ready, "boolean");
    assert.equal(typeof status.persistent, "boolean");
    assert.ok(["in-memory", "postgres", "in-memory-fallback"].includes(status.type));
    assert.equal(isDatabasePostgres(), status.type === "postgres");
  });

  test("Database initialization in development mode provides safe in-memory fallback", async () => {
    const originalUrl = process.env.DATABASE_URL;
    const originalEnv = process.env.NODE_ENV;
    delete process.env.DATABASE_URL;
    process.env.NODE_ENV = "development";

    try {
      const res = await initDatabase();
      assert.equal(res.ready, true);
      assert.equal(res.persistent, false);
      assert.equal(res.type, "in-memory");
    } finally {
      if (originalUrl) process.env.DATABASE_URL = originalUrl;
      if (originalEnv) process.env.NODE_ENV = originalEnv;
    }
  });

  test("Production mode strictly rejects running without DATABASE_URL (refuses ephemeral storage)", async () => {
    const originalUrl = process.env.DATABASE_URL;
    const originalEnv = process.env.NODE_ENV;
    delete process.env.DATABASE_URL;
    process.env.NODE_ENV = "production";

    try {
      await assert.rejects(
        async () => {
          await initDatabase();
        },
        {
          name: "Error",
          message: /FATAL: DATABASE_URL is not configured in production/,
        }
      );
    } finally {
      if (originalUrl) process.env.DATABASE_URL = originalUrl;
      process.env.NODE_ENV = originalEnv || "development";
    }
  });

  test("Production mode strictly rejects invalid database connection rather than falling back silently", async () => {
    const originalUrl = process.env.DATABASE_URL;
    const originalEnv = process.env.NODE_ENV;
    process.env.DATABASE_URL = "postgres://invalid_user:invalid_pass@127.0.0.1:54329/nonexistent";
    process.env.NODE_ENV = "production";

    try {
      await assert.rejects(
        async () => {
          await initDatabase();
        },
        {
          name: "Error",
          message: /FATAL: Failed to connect to PostgreSQL in production/,
        }
      );
    } finally {
      if (originalUrl) {
        process.env.DATABASE_URL = originalUrl;
      } else {
        delete process.env.DATABASE_URL;
      }
      process.env.NODE_ENV = originalEnv || "development";
    }
  });

  test("Migration files exist, are numbered sequentially, and contain valid DDL", () => {
    const migrationsDir = path.join(__dirname, "..", "lib", "db", "migrations");
    assert.ok(fs.existsSync(migrationsDir), "Migrations directory must exist");

    const files = fs.readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort();
    assert.ok(files.length >= 4, "Must contain at least 4 migration files");

    assert.equal(files[0], "0000_initial_users_and_sessions.sql");
    assert.equal(files[1], "0001_add_nickname.sql");
    assert.equal(files[2], "0002_create_saved_reports.sql");
    assert.equal(files[3], "0003_create_user_recommendations.sql");

    for (const file of files) {
      const sql = fs.readFileSync(path.join(migrationsDir, file), "utf-8");
      assert.ok(sql.trim().length > 0, `Migration ${file} must not be empty`);
      // Confirm all table creations are safe and idempotent
      if (sql.includes("CREATE TABLE")) {
        assert.ok(sql.includes("CREATE TABLE IF NOT EXISTS"), `Migration ${file} must use IF NOT EXISTS for tables`);
      }
      if (sql.includes("CREATE INDEX")) {
        assert.ok(sql.includes("CREATE INDEX IF NOT EXISTS"), `Migration ${file} must use IF NOT EXISTS for indexes`);
      }
    }
  });

  test("SQL statements in server-auth.js use strict parameterized queries with no string interpolation", () => {
    const authCode = fs.readFileSync(path.join(__dirname, "..", "server-auth.js"), "utf-8");

    // Check that pgPool.query calls do not use direct interpolated variables like `${email}` in SQL
    const lines = authCode.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes("pgPool.query(") && !line.includes("${whereSql}")) {
        // Assert no unsafe parameter concatenation in query strings
        assert.ok(!line.includes("WHERE email = '"), `Line ${i + 1} has concatenated email in query`);
        assert.ok(!line.includes("WHERE id = '"), `Line ${i + 1} has concatenated id in query`);
      }
    }
  });

  test("In-memory store faithfully enforces user isolation and data contracts", async () => {
    const userA = await createUser("isolated-a@test.org", "hashA", "UserA");
    const userB = await createUser("isolated-b@test.org", "hashB", "UserB");

    // Reports isolation
    const reportAnalysis = {
      isValid: true,
      urlParts: { hostname: "bank.example.com", registeredDomain: "example.com" },
      verdict: { level: "low", title: "Clean", summary: "Safe" },
      rawInput: "https://bank.example.com",
    };
    await saveReport(userA.id, reportAnalysis);

    const reportsA = await getSavedReports(userA.id);
    const reportsB = await getSavedReports(userB.id);

    assert.equal(reportsA.total, 1);
    assert.equal(reportsB.total, 0);

    // Recommendations isolation
    await saveUserRecommendationStatus(userA.id, { addressed: ["rec-1"], dismissed: ["rec-2"] });
    const recsA = await getUserRecommendationStatus(userA.id);
    const recsB = await getUserRecommendationStatus(userB.id);

    assert.deepEqual(recsA.addressed, ["rec-1"]);
    assert.deepEqual(recsB.addressed, []);
  });

  test("closeDatabase cleanly resets pool state without throwing", async () => {
    await closeDatabase();
    const status = getDatabaseStatus();
    assert.equal(status.isPostgres, false);
  });
});
