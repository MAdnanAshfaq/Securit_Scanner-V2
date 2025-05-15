import { pgTable, text, serial, integer, boolean, json, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// User schema (kept from original)
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// Scan related schemas
export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  url: text("url").notNull(),
  status: text("status").notNull().default("pending"), // pending, in-progress, completed, failed
  startTime: timestamp("start_time").notNull(),
  endTime: timestamp("end_time"),
  serverInfo: json("server_info").$type<ServerInfo>(),
  highRiskCount: integer("high_risk_count").default(0),
  mediumRiskCount: integer("medium_risk_count").default(0),
  lowRiskCount: integer("low_risk_count").default(0),
  infoCount: integer("info_count").default(0),
});

export const insertScanSchema = createInsertSchema(scans).pick({
  url: true,
  status: true,
  startTime: true,
  endTime: true,
  serverInfo: true,
  highRiskCount: true,
  mediumRiskCount: true,
  lowRiskCount: true,
  infoCount: true
});

export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;

export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").notNull(), // Reference to scan.id
  name: text("name").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(), // high, medium, low, info
  location: text("location"), // Where it was found
  details: text("details"), // Technical details of the vulnerability
  recommendation: text("recommendation"), // How to fix it
  learnMoreUrl: text("learn_more_url"), // Educational resource link
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
});

export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;

// Risk levels enum
export enum RiskLevel {
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info"
}

// Server info type
export interface ServerInfo {
  server?: string;
  ip?: string;
  location?: string;
  technologies?: string[];
}

// HTTP header info
export interface HeaderInfo {
  name: string;
  value: string;
  secure: boolean;
  description?: string;
}

// URL validation schema
export const urlSchema = z.object({
  url: z.string().url("Please enter a valid URL").min(1, "URL is required"),
});
