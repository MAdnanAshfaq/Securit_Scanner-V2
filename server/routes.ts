import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { scanWebsite } from "./scanEngine";
import { performAttack } from "./attackEngine";
import { urlSchema, RiskLevel } from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  // API endpoint to start a scan
  app.post("/api/scan", async (req, res) => {
    try {
      // Validate the URL
      const { url } = urlSchema.parse(req.body);
      
      // Start the scan process
      const scan = await scanWebsite(url);
      
      res.json(scan);
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: error.message });
      } else {
        const errorMessage = error instanceof Error ? error.message : "Unknown error";
        console.error("Scan error:", errorMessage);
        res.status(500).json({ message: "Failed to perform scan" });
      }
    }
  });

  // API endpoint to get the latest scan
  app.get("/api/scan", async (req, res) => {
    try {
      const latestScan = await storage.getLatestScan();
      if (!latestScan) {
        return res.status(404).json({ message: "No scan found" });
      }
      res.json(latestScan);
    } catch (error) {
      console.error("Get scan error:", error);
      res.status(500).json({ message: "Failed to get scan" });
    }
  });

  // API endpoint to get vulnerabilities for a scan
  app.get("/api/vulnerabilities", async (req, res) => {
    try {
      const latestScan = await storage.getLatestScan();
      if (!latestScan) {
        return res.status(404).json({ message: "No scan found" });
      }
      
      const vulnerabilities = await storage.getVulnerabilitiesByScanId(latestScan.id);
      res.json(vulnerabilities);
    } catch (error) {
      console.error("Get vulnerabilities error:", error);
      res.status(500).json({ message: "Failed to get vulnerabilities" });
    }
  });

  // API endpoint to get specific vulnerability details
  app.get("/api/vulnerabilities/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid vulnerability ID" });
      }
      
      const vulnerability = await storage.getVulnerabilityById(id);
      if (!vulnerability) {
        return res.status(404).json({ message: "Vulnerability not found" });
      }
      
      res.json(vulnerability);
    } catch (error) {
      console.error("Get vulnerability error:", error);
      res.status(500).json({ message: "Failed to get vulnerability" });
    }
  });

  // API endpoint to perform actual attacks
  app.post("/api/attack", async (req, res) => {
    try {
      // Extract parameters from request body
      const { 
        attackType, 
        target, 
        method = "GET", 
        parameter = "", 
        payload = "", 
        options = "" 
      } = req.body;
      
      // Validate required fields
      if (!attackType) {
        return res.status(400).json({ message: "Attack type is required" });
      }
      
      if (!target) {
        return res.status(400).json({ message: "Target URL is required" });
      }
      
      // Log the attack attempt
      console.log(`Attack requested: ${attackType} on ${target}`);
      
      // Display a warning that this should only be used ethically
      console.log("WARNING: This feature should only be used on websites you own or have permission to test");
      
      // Perform the actual attack
      const result = await performAttack(
        attackType,
        target,
        method,
        parameter,
        payload,
        options
      );
      
      res.json(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Attack execution error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        results: `Attack execution failed: ${errorMessage}` 
      });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
