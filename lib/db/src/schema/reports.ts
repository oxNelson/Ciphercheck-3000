import { pgTable, text, varchar, integer, jsonb, timestamp } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const savedReportsTable = pgTable("saved_reports", {
  id: varchar("id", { length: 255 }).primaryKey(),
  userId: varchar("user_id", { length: 255 })
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  url: text("url").notNull(),
  redactedUrl: text("redacted_url").notNull(),
  hostname: varchar("hostname", { length: 255 }).notNull(),
  registeredDomain: varchar("registered_domain", { length: 255 }).notNull(),
  riskLevel: varchar("risk_level", { length: 50 }).notNull(),
  verdictTitle: varchar("verdict_title", { length: 255 }).notNull(),
  verdictSummary: text("verdict_summary"),
  findingsCount: integer("findings_count").notNull().default(0),
  analysisData: jsonb("analysis_data").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type SavedReport = typeof savedReportsTable.$inferSelect;
export type NewSavedReport = typeof savedReportsTable.$inferInsert;
