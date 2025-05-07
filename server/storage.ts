import { eq, desc } from 'drizzle-orm';
import { db } from './db';
import * as schema from '@shared/schema';
import { 
  type User, 
  type InsertUser, 
  type Scan, 
  type InsertScan, 
  type Vulnerability, 
  type InsertVulnerability 
} from '@shared/schema';

// Storage interface with scan-related operations
export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Scan operations
  createScan(scan: InsertScan): Promise<Scan>;
  updateScan(scan: Scan): Promise<Scan>;
  getScanById(id: number): Promise<Scan | undefined>;
  getLatestScan(): Promise<Scan | undefined>;
  
  // Vulnerability operations
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  getVulnerabilityById(id: number): Promise<Vulnerability | undefined>;
  getVulnerabilitiesByScanId(scanId: number): Promise<Vulnerability[]>;
}

// Database storage implementation
export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(schema.users).where(eq(schema.users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(schema.users).where(eq(schema.users.username, username));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(schema.users).values(insertUser).returning();
    return user;
  }
  
  // Scan operations
  async createScan(insertScan: InsertScan): Promise<Scan> {
    // Make sure all required fields are set
    const scanData = {
      url: insertScan.url,
      status: insertScan.status || 'pending',
      startTime: insertScan.startTime || new Date(),
      endTime: null,
      serverInfo: null,
      highRiskCount: 0,
      mediumRiskCount: 0,
      lowRiskCount: 0,
      infoCount: 0
    };
    
    const [scan] = await db.insert(schema.scans).values(scanData).returning();
    return scan;
  }
  
  async updateScan(scan: Scan): Promise<Scan> {
    const [updatedScan] = await db.update(schema.scans)
      .set(scan)
      .where(eq(schema.scans.id, scan.id))
      .returning();
    return updatedScan;
  }
  
  async getScanById(id: number): Promise<Scan | undefined> {
    const [scan] = await db.select().from(schema.scans).where(eq(schema.scans.id, id));
    return scan;
  }
  
  async getLatestScan(): Promise<Scan | undefined> {
    const [scan] = await db.select().from(schema.scans).orderBy(desc(schema.scans.id)).limit(1);
    return scan;
  }
  
  // Vulnerability operations
  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    // Make sure all nullable fields are explicitly set to null if not provided
    const vulnData = {
      ...insertVulnerability,
      location: insertVulnerability.location || null,
      details: insertVulnerability.details || null,
      recommendation: insertVulnerability.recommendation || null,
      learnMoreUrl: insertVulnerability.learnMoreUrl || null,
    };
    
    const [vulnerability] = await db.insert(schema.vulnerabilities)
      .values(vulnData)
      .returning();
    return vulnerability;
  }
  
  async getVulnerabilityById(id: number): Promise<Vulnerability | undefined> {
    const [vulnerability] = await db.select()
      .from(schema.vulnerabilities)
      .where(eq(schema.vulnerabilities.id, id));
    return vulnerability;
  }
  
  async getVulnerabilitiesByScanId(scanId: number): Promise<Vulnerability[]> {
    return db.select()
      .from(schema.vulnerabilities)
      .where(eq(schema.vulnerabilities.scanId, scanId));
  }
}

// Create and export the storage instance
export const storage = new DatabaseStorage();