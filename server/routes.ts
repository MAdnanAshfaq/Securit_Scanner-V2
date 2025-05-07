import express, { type Express } from "express";
import { createServer, type Server } from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { storage } from "./storage";
import { scanWebsite } from "./scanEngine";
import { performAttack } from "./attackEngine";
import { urlSchema, RiskLevel } from "@shared/schema";
import { z } from "zod";
import { aiAnalyzer } from "./aiAnalysis";
import nodemailer from "nodemailer";
import { generatePDFReport } from "./reportGenerator";
import { decodeHash, decodeQRCode, universalDecode } from "./decodingService";
import multer from "multer";

// Set up multer storage for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Get current directory equivalent to __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
  
  // API endpoint to get AI-enhanced analysis for a vulnerability
  app.get("/api/vulnerability-analysis/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid vulnerability ID" });
      }
      
      // Get the vulnerability
      const vulnerability = await storage.getVulnerabilityById(id);
      if (!vulnerability) {
        return res.status(404).json({ message: "Vulnerability not found" });
      }
      
      // Generate AI-enhanced analysis
      const analysis = await aiAnalyzer.analyzeVulnerability(vulnerability);
      
      if (!analysis) {
        return res.status(503).json({ message: "AI analysis service unavailable" });
      }
      
      res.json(analysis);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("AI analysis error:", errorMessage);
      res.status(500).json({ message: `AI analysis failed: ${errorMessage}` });
    }
  });
  
  // API endpoint to get AI-enhanced scan report
  app.get("/api/scan-report", async (req, res) => {
    try {
      const latestScan = await storage.getLatestScan();
      if (!latestScan) {
        return res.status(404).json({ message: "No scan found" });
      }
      
      const vulnerabilities = await storage.getVulnerabilitiesByScanId(latestScan.id);
      
      // Generate AI-enhanced scan report
      const report = await aiAnalyzer.generateScanReport(latestScan, vulnerabilities);
      
      if (!report) {
        return res.status(503).json({ message: "AI report generation service unavailable" });
      }
      
      res.json({ report });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("AI report generation error:", errorMessage);
      res.status(500).json({ message: `AI report generation failed: ${errorMessage}` });
    }
  });
  
  // API endpoint for contact form
  app.post("/api/contact", async (req, res) => {
    try {
      const { name, email, message, subject } = req.body;
      
      // Validate required fields
      if (!name || !email || !message) {
        return res.status(400).json({ message: "Name, email, and message are required" });
      }
      
      // Create email transporter with secure configuration
      const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true, // use SSL
        auth: {
          user: "adnan.ashfaq@genesisengr.com",
          pass: process.env.EMAIL_PASSWORD
        }
      });
      
      // Set up email data
      const mailOptions = {
        from: email,
        to: "adnan.ashfaq@genesisengr.com",
        subject: subject || `Contact Form Message from ${name}`,
        text: `
Name: ${name}
Email: ${email}
Message:
${message}
        `,
        html: `
<h2>Contact Form Submission</h2>
<p><strong>Name:</strong> ${name}</p>
<p><strong>Email:</strong> ${email}</p>
<p><strong>Message:</strong></p>
<p>${message.replace(/\n/g, '<br>')}</p>
        `
      };
      
      // Send email
      await transporter.sendMail(mailOptions);
      
      res.json({ success: true, message: "Contact form submitted successfully" });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Contact form error:", errorMessage);
      res.status(500).json({ message: `Failed to send contact form: ${errorMessage}` });
    }
  });

  // Create a directory for reports if it doesn't exist
  const reportsDir = path.join(__dirname, "..", "reports");
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  // Serve PDF reports statically
  app.use("/reports", (req, res, next) => {
    // Only allow access to PDF files
    if (!req.path.endsWith(".pdf")) {
      return res.status(404).send("Not found");
    }
    next();
  }, express.static(reportsDir));

  // API endpoint to generate PDF report for a scan
  app.get("/api/generate-report", async (req, res) => {
    try {
      const latestScan = await storage.getLatestScan();
      if (!latestScan) {
        return res.status(404).json({ message: "No scan found" });
      }
      
      // Generate the PDF report
      const reportPath = await generatePDFReport(latestScan.id);
      
      // Get the filename from the path
      const filename = path.basename(reportPath);
      
      // Return the URL to download the report
      res.json({
        success: true,
        message: "Report generated successfully",
        reportUrl: `/reports/${filename}`,
        filename: filename
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Report generation error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to generate report: ${errorMessage}` 
      });
    }
  });
  
  // API endpoint to email the PDF report
  app.post("/api/email-report", async (req, res) => {
    try {
      const { email, reportUrl, scanUrl } = req.body;
      
      // Validate required fields
      if (!email || !reportUrl) {
        return res.status(400).json({ 
          message: "Email and report URL are required" 
        });
      }
      
      // Get the full path to the report
      const reportFilename = path.basename(reportUrl);
      const reportPath = path.join(__dirname, "..", "reports", reportFilename);
      
      // Check if report exists
      if (!fs.existsSync(reportPath)) {
        return res.status(404).json({ 
          message: "Report file not found" 
        });
      }
      
      // Create email transporter with secure configuration
      const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true, // use SSL
        auth: {
          user: "adnan.ashfaq@genesisengr.com",
          pass: process.env.EMAIL_PASSWORD
        }
      });
      
      // Set up email data
      const mailOptions = {
        from: "adnan.ashfaq@genesisengr.com",
        to: email,
        subject: `Security Scan Report for ${scanUrl || 'Your Website'}`,
        text: `
Dear Security Professional,

Attached is your comprehensive security vulnerability report for ${scanUrl || 'your website'}.

This report contains detailed findings from our security scan, including:
- Executive summary of vulnerabilities found
- Detailed technical analysis of each issue
- Severity ratings and risk assessment
- Recommendations for remediation
- Visual charts and statistics

If you have any questions about this report or need assistance implementing the security recommendations, please contact our team.

Best regards,
The SecureScan Team
        `,
        html: `
<h2>Security Vulnerability Report</h2>
<p>Dear Security Professional,</p>
<p>Attached is your comprehensive security vulnerability report for <strong>${scanUrl || 'your website'}</strong>.</p>
<p>This report contains detailed findings from our security scan, including:</p>
<ul>
  <li>Executive summary of vulnerabilities found</li>
  <li>Detailed technical analysis of each issue</li>
  <li>Severity ratings and risk assessment</li>
  <li>Recommendations for remediation</li>
  <li>Visual charts and statistics</li>
</ul>
<p>If you have any questions about this report or need assistance implementing the security recommendations, please contact our team.</p>
<p>Best regards,<br>The SecureScan Team</p>
        `,
        attachments: [
          {
            filename: reportFilename,
            path: reportPath
          }
        ]
      };
      
      // Send email
      await transporter.sendMail(mailOptions);
      
      res.json({ 
        success: true, 
        message: "Report has been emailed successfully" 
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Email report error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to email report: ${errorMessage}` 
      });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}