import { pgTable, varchar, jsonb, timestamp } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const userRecommendationsTable = pgTable("user_recommendations", {
  userId: varchar("user_id", { length: 64 })
    .primaryKey()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  addressedIds: jsonb("addressed_ids").notNull().default([]),
  dismissedIds: jsonb("dismissed_ids").notNull().default([]),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type UserRecommendation = typeof userRecommendationsTable.$inferSelect;
export type NewUserRecommendation = typeof userRecommendationsTable.$inferInsert;
