import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from 'ws';
import * as schema from '@shared/schema';

// Configure Neon database connection
neonConfig.webSocketConstructor = ws;

// Check for DATABASE_URL environment variable
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL environment variable not set");
  throw new Error("DATABASE_URL must be set");
}

// Create database pool and client
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const db = drizzle(pool, { schema });

// Add transaction support
export const transaction = async (callback: (tx: typeof db) => Promise<void>) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const tx = drizzle(client, { schema });
    await callback(tx);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
};