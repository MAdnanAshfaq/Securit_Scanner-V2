import { drizzle } from 'drizzle-orm/neon-http';
import { neon, neonConfig } from '@neondatabase/serverless';
import ws from 'ws';
import * as schema from '@shared/schema';

// Configure Neon database connection
neonConfig.webSocketConstructor = ws;
const sql = neon(process.env.DATABASE_URL!);
export const db = drizzle(sql, { schema });
// No transaction logic, only use db instance