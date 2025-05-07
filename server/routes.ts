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
import { emailPhishingService } from "./emailPhishingService";
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
      
      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ message: "Please provide a valid email address" });
      }
      
      // Check for EMAIL_PASSWORD environment variable
      if (!process.env.EMAIL_PASSWORD) {
        log("EMAIL_PASSWORD environment variable not set", "email");
        return res.status(500).json({ message: "Server email configuration error" });
      }
      
      log(`Sending contact form email from ${email} with subject: ${subject || 'Contact Form'}`, "email");
      
      // Create email transporter with secure configuration and proper error handling
      const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true, // use SSL
        auth: {
          user: "adnan.ashfaq@genesisengr.com",
          pass: process.env.EMAIL_PASSWORD
        },
        tls: {
          rejectUnauthorized: false // Allow self-signed certificates
        },
        debug: true, // Enable debug
        logger: true  // Log to console
      });
      
      // Set up email data with sender name in the from field
      const mailOptions = {
        from: `"${name}" <${email}>`,
        to: "adnan.ashfaq@genesisengr.com",
        replyTo: email, // Make replies go back to the sender
        subject: subject || `Contact Form Message from ${name}`,
        text: `
Name: ${name}
Email: ${email}
Message:
${message}

--
This message was sent via the Security Scanner contact form.
        `,
        html: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
  <h2 style="color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px;">Contact Form Submission</h2>
  <p><strong>Name:</strong> ${name}</p>
  <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
  <p><strong>Message:</strong></p>
  <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px;">
    <p>${message.replace(/\n/g, '<br>')}</p>
  </div>
  <p style="font-size: 12px; color: #777; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px;">
    This message was sent via the Security Scanner contact form.
  </p>
</div>
        `
      };
      
      // Send email with timeout
      const sendPromise = transporter.sendMail(mailOptions);
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Email sending timeout after 30 seconds')), 30000);
      });
      
      await Promise.race([sendPromise, timeoutPromise]);
      
      log("Contact form email sent successfully", "email");
      res.json({ success: true, message: "Contact form submitted successfully" });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      log(`Contact form error: ${errorMessage}`, "email");
      
      // Provide a user-friendly error message
      if (errorMessage.includes("Invalid login") || errorMessage.includes("authentication failed")) {
        return res.status(500).json({ message: "Email server authentication failed. Please try again later." });
      } else if (errorMessage.includes("timeout")) {
        return res.status(500).json({ message: "Email sending timed out. Please try again later." });
      }
      
      res.status(500).json({ message: "Failed to send your message. Please try again later." });
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
          success: false,
          message: "Email and report URL are required" 
        });
      }
      
      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ 
          success: false,
          message: "Please provide a valid email address" 
        });
      }
      
      // Check for EMAIL_PASSWORD environment variable
      if (!process.env.EMAIL_PASSWORD) {
        log("EMAIL_PASSWORD environment variable not set", "email");
        return res.status(500).json({ 
          success: false,
          message: "Server email configuration error" 
        });
      }
      
      // Get the full path to the report
      const reportFilename = path.basename(reportUrl);
      const reportPath = path.join(__dirname, "..", "reports", reportFilename);
      
      // Check if report exists
      if (!fs.existsSync(reportPath)) {
        return res.status(404).json({ 
          success: false,
          message: "Report file not found" 
        });
      }
      
      log(`Sending security report to ${email} for website: ${scanUrl || 'Unknown'}`, "email");
      
      // Create email transporter with secure configuration and proper error handling
      const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true, // use SSL
        auth: {
          user: "adnan.ashfaq@genesisengr.com",
          pass: process.env.EMAIL_PASSWORD
        },
        tls: {
          rejectUnauthorized: false // Allow self-signed certificates
        },
        debug: true, // Enable debug
        logger: true  // Log to console
      });
      
      // Set up email data with professional formatting
      const mailOptions = {
        from: '"Security Scanner" <adnan.ashfaq@genesisengr.com>',
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
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
  <h2 style="color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px;">Security Vulnerability Report</h2>
  <p>Dear Security Professional,</p>
  <p>Attached is your comprehensive security vulnerability report for <strong>${scanUrl || 'your website'}</strong>.</p>
  <p>This report contains detailed findings from our security scan, including:</p>
  <ul style="margin-bottom: 20px;">
    <li>Executive summary of vulnerabilities found</li>
    <li>Detailed technical analysis of each issue</li>
    <li>Severity ratings and risk assessment</li>
    <li>Recommendations for remediation</li>
    <li>Visual charts and statistics</li>
  </ul>
  <p>If you have any questions about this report or need assistance implementing the security recommendations, please contact our team.</p>
  <p style="margin-top: 30px; padding-top: 10px; border-top: 1px solid #eee;">Best regards,<br>The SecureScan Team</p>
</div>
        `,
        attachments: [
          {
            filename: reportFilename,
            path: reportPath
          }
        ]
      };
      
      // Send email with timeout
      const sendPromise = transporter.sendMail(mailOptions);
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Email sending timeout after 30 seconds')), 30000);
      });
      
      await Promise.race([sendPromise, timeoutPromise]);
      
      log("Security report email sent successfully", "email");
      res.json({ 
        success: true, 
        message: "Report has been emailed successfully" 
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      log(`Email report error: ${errorMessage}`, "email");
      
      // Provide a user-friendly error message
      if (errorMessage.includes("Invalid login") || errorMessage.includes("authentication failed")) {
        return res.status(500).json({ 
          success: false,
          message: "Email server authentication failed. Please try again later." 
        });
      } else if (errorMessage.includes("timeout")) {
        return res.status(500).json({ 
          success: false,
          message: "Email sending timed out. Please try again later." 
        });
      }
      
      res.status(500).json({ 
        success: false, 
        message: "Failed to email report. Please try again later." 
      });
    }
  });

  // API endpoint for hash decoding
  app.post("/api/decode-hash", async (req, res) => {
    try {
      const { hash } = req.body;
      
      // Validate required fields
      if (!hash) {
        return res.status(400).json({ 
          success: false, 
          message: "Hash string is required" 
        });
      }
      
      // Perform hash decoding
      const result = await decodeHash(hash);
      
      res.json({
        success: true,
        result
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Hash decoding error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to decode hash: ${errorMessage}` 
      });
    }
  });
  
  // API endpoint for universal decoding (handles any type of encoding/encryption)
  app.post("/api/universal-decode", async (req, res) => {
    try {
      const { data } = req.body;
      
      // Validate required fields
      if (!data) {
        return res.status(400).json({ 
          success: false, 
          message: "Encoded data string is required" 
        });
      }
      
      // Perform universal decoding
      const result = await universalDecode(data);
      
      res.json({
        success: true,
        result
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Universal decoding error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to decode data: ${errorMessage}` 
      });
    }
  });
  
  // API endpoint for QR code decoding
  app.post("/api/decode-qr", upload.single('image'), async (req, res) => {
    try {
      // Check if file was uploaded
      if (!req.file) {
        return res.status(400).json({ 
          success: false, 
          message: "No image file provided" 
        });
      }
      
      // Get image buffer from the uploaded file
      const imageBuffer = req.file.buffer;
      
      // Perform QR code decoding
      const result = await decodeQRCode(imageBuffer);
      
      res.json({
        success: true,
        result
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("QR decoding error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to decode QR code: ${errorMessage}` 
      });
    }
  });

  // API endpoint for analyzing emails for phishing
  app.post("/api/analyze-phishing", async (req, res) => {
    try {
      const { subject, content, sender, recipient, suspiciousUrls } = req.body;
      
      // Validate required fields
      if (!content) {
        return res.status(400).json({ 
          success: false, 
          message: "Email content is required" 
        });
      }
      
      // Analyze the email for phishing
      const analysis = await emailPhishingService.analyzeEmail({
        subject: subject || "",
        content,
        sender: sender || "",
        recipient: recipient || "",
        suspiciousUrls: suspiciousUrls || []
      });
      
      res.json(analysis);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Email phishing analysis error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to analyze email: ${errorMessage}` 
      });
    }
  });
  
  // API endpoint for storing email credentials
  app.post("/api/email-credentials", async (req, res) => {
    try {
      const { 
        email, 
        password, 
        provider, 
        server, 
        port, 
        useTLS, 
        autoScan, 
        scanFrequency 
      } = req.body;
      
      // Validate required fields
      if (!email || !password || !provider) {
        return res.status(400).json({ 
          success: false, 
          message: "Email, password, and provider are required" 
        });
      }
      
      // Check if Google Gemini API key is available for enhanced scanning
      if (!process.env.GOOGLE_GEMINI_API_KEY) {
        console.warn("No Google Gemini API key provided, AI-enhanced scanning will be limited");
      }
      
      // Store the credentials securely
      const result = await emailPhishingService.storeEmailCredentials({
        email,
        password,
        provider,
        server,
        port,
        useTLS: useTLS !== false, // Default to true if not specified
        autoScan: autoScan === true,
        scanFrequency: scanFrequency || "daily"
      });
      
      res.json({
        success: true,
        message: "Email credentials stored successfully",
        credentialId: result.credentialId
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Email credentials storage error:", errorMessage);
      res.status(500).json({ 
        success: false,
        message: `Failed to store email credentials: ${errorMessage}` 
      });
    }
  });
  
  // API endpoint to fetch emails from user's account
  app.get("/api/emails/:credentialId", async (req, res) => {
    try {
      const { credentialId } = req.params;
      const folder = req.query.folder as string || 'INBOX';
      const limit = parseInt(req.query.limit as string || '20');
      
      if (!credentialId) {
        return res.status(400).json({ 
          success: false, 
          message: "Credential ID is required" 
        });
      }
      
      // Fetch emails from the account
      const result = await emailPhishingService.fetchEmails(credentialId, folder, limit);
      
      res.json(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Email fetching error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to fetch emails: ${errorMessage}` 
      });
    }
  });
  
  // API endpoint to analyze a specific email
  app.get("/api/analyze-email/:credentialId/:messageId", async (req, res) => {
    try {
      const { credentialId, messageId } = req.params;
      const folder = req.query.folder as string || 'INBOX';
      
      if (!credentialId || !messageId) {
        return res.status(400).json({ 
          success: false, 
          message: "Credential ID and message ID are required" 
        });
      }
      
      // Analyze the specific email
      const result = await emailPhishingService.analyzeEmailById(credentialId, parseInt(messageId), folder);
      
      res.json(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("Email analysis error:", errorMessage);
      res.status(500).json({ 
        success: false, 
        message: `Failed to analyze email: ${errorMessage}` 
      });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}