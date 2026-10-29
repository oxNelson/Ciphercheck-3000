import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

let pool: pg.Pool | null = null;
let db: ReturnType<typeof drizzle> | any = null;

if (process.env.DATABASE_URL) {
  try {
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
    db = drizzle(pool, { schema });
  } catch (err) {
    console.warn("[Database] Failed to connect to DATABASE_URL, using mock fallback:", err);
  }
} else {
  console.warn("[Database] DATABASE_URL is not set. Database operations will use in-memory store.");
}

export { pool, db };
export * from "./schema";
