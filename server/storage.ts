import { users, type User, type InsertUser, Scan, InsertScan, Vulnerability, InsertVulnerability } from "@shared/schema";

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

// In-memory storage implementation
export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private scans: Map<number, Scan>;
  private vulnerabilities: Map<number, Vulnerability>;
  
  private currentUserId: number;
  private currentScanId: number;
  private currentVulnerabilityId: number;

  constructor() {
    this.users = new Map();
    this.scans = new Map();
    this.vulnerabilities = new Map();
    
    this.currentUserId = 1;
    this.currentScanId = 1;
    this.currentVulnerabilityId = 1;
  }

  // User methods
  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }
  
  // Scan methods
  async createScan(insertScan: InsertScan): Promise<Scan> {
    const id = this.currentScanId++;
    const scan: Scan = { 
      ...insertScan, 
      id,
      highRiskCount: 0,
      mediumRiskCount: 0,
      lowRiskCount: 0,
      infoCount: 0
    };
    this.scans.set(id, scan);
    return scan;
  }
  
  async updateScan(scan: Scan): Promise<Scan> {
    this.scans.set(scan.id, scan);
    return scan;
  }
  
  async getScanById(id: number): Promise<Scan | undefined> {
    return this.scans.get(id);
  }
  
  async getLatestScan(): Promise<Scan | undefined> {
    const scans = Array.from(this.scans.values());
    if (scans.length === 0) return undefined;
    
    // Sort by ID in descending order to get the latest scan
    return scans.sort((a, b) => b.id - a.id)[0];
  }
  
  // Vulnerability methods
  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    const id = this.currentVulnerabilityId++;
    const vulnerability: Vulnerability = { ...insertVulnerability, id };
    this.vulnerabilities.set(id, vulnerability);
    return vulnerability;
  }
  
  async getVulnerabilityById(id: number): Promise<Vulnerability | undefined> {
    return this.vulnerabilities.get(id);
  }
  
  async getVulnerabilitiesByScanId(scanId: number): Promise<Vulnerability[]> {
    return Array.from(this.vulnerabilities.values())
      .filter(vuln => vuln.scanId === scanId);
  }
}

// Create and export the storage instance
export const storage = new MemStorage();
