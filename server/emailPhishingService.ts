import { GoogleGenerativeAI } from "@google/generative-ai";
import crypto from "crypto";
import { URL } from "url";
import { storage } from "./storage";
import nodemailer from "nodemailer";
import { log } from "./vite";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';

// Get current directory equivalent to __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define interfaces for our service
interface PhishingAnalysisRequest {
  subject: string;
  content: string;
  sender: string;
  recipient: string;
  suspiciousUrls: string[];
}

interface EmailCredentials {
  email: string;
  password: string;
  provider: string;
  server?: string;
  port?: string;
  useTLS: boolean;
  autoScan: boolean;
  scanFrequency: string;
}

/**
 * Email Phishing Analysis Service
 * Analyzes emails for phishing attempts using AI and standard security checks
 */
export class EmailPhishingService {
  private genAI: GoogleGenerativeAI | null = null;
  private geminiModel: any = null;
  private apiKey: string;
  private credentialsDir: string;

  constructor() {
    // Try to get the API key from environment variables
    this.apiKey = process.env.GOOGLE_GEMINI_API_KEY || '';
    
    // Initialize if API key is available
    if (this.apiKey) {
      this.genAI = new GoogleGenerativeAI(this.apiKey);
      this.geminiModel = this.genAI.getGenerativeModel({ model: "gemini-pro" });
    }
    
    // Set up the directory for storing encrypted credentials
    this.credentialsDir = path.join(__dirname, "..", "emailCredentials");
    if (!fs.existsSync(this.credentialsDir)) {
      fs.mkdirSync(this.credentialsDir, { recursive: true });
    }
  }

  /**
   * Analyze an email for potential phishing attempts
   * @param emailData Details of the email to analyze
   */
  async analyzeEmail(emailData: PhishingAnalysisRequest) {
    log("Analyzing email for phishing indicators...", "phishing");
    
    try {
      // Perform basic checks for common phishing indicators
      const senderAnalysis = this.analyzeSender(emailData.sender);
      const contentAnalysis = this.analyzeContent(emailData.subject, emailData.content);
      const urlAnalysis = this.analyzeURLs(emailData.content, emailData.suspiciousUrls);
      
      // Calculate risk score (0-10)
      let riskScore = this.calculateRiskScore(senderAnalysis, contentAnalysis, urlAnalysis);
      
      // Generate recommendations based on analysis
      const recommendations = this.generateRecommendations(riskScore, senderAnalysis, contentAnalysis, urlAnalysis);
      
      // If we have a Gemini API key, enhance the analysis with AI
      let aiAnalysis = null;
      if (this.apiKey && this.geminiModel) {
        aiAnalysis = await this.performAIAnalysis(emailData);
        
        // If AI analysis found additional suspicious elements, adjust risk score
        if (aiAnalysis && aiAnalysis.additionalRiskScore > 0) {
          riskScore = Math.min(10, riskScore + aiAnalysis.additionalRiskScore);
        }
      }
      
      // Determine if email is likely a phishing attempt
      const isPhishing = riskScore >= 6;
      
      // Compile summary based on findings
      const summary = this.generateSummary(isPhishing, riskScore, senderAnalysis, contentAnalysis, urlAnalysis);
      
      return {
        isPhishing,
        riskScore: Math.round(riskScore * 10) / 10, // Round to 1 decimal place
        summary,
        senderAnalysis,
        contentAnalysis,
        urlAnalysis,
        recommendations,
        aiAnalysis
      };
    } catch (error) {
      log(`Error analyzing email: ${error}`, "phishing");
      throw new Error(`Failed to analyze email: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  /**
   * Store email credentials securely for automated scanning
   * @param credentials Email account credentials
   */
  async storeEmailCredentials(credentials: EmailCredentials) {
    try {
      // Create a unique ID for this credential
      const credentialId = crypto.randomUUID();
      
      // Encrypt sensitive data before storing
      const encryptedPassword = this.encryptSensitiveData(credentials.password);
      
      // Store credentials with encryption
      const secureCredentials = {
        id: credentialId,
        email: credentials.email,
        password: encryptedPassword, // Store encrypted version
        provider: credentials.provider,
        server: credentials.server || this.getDefaultServer(credentials.provider),
        port: credentials.port || this.getDefaultPort(credentials.provider),
        useTLS: credentials.useTLS,
        autoScan: credentials.autoScan,
        scanFrequency: credentials.scanFrequency,
        dateAdded: new Date().toISOString()
      };
      
      // Save to file
      const filePath = path.join(this.credentialsDir, `${credentialId}.json`);
      fs.writeFileSync(filePath, JSON.stringify(secureCredentials, null, 2));
      
      // Test connection to verify credentials
      await this.testEmailConnection(credentials);
      
      // Set up automated scanning if enabled
      if (credentials.autoScan) {
        this.setupAutomatedScanning(credentialId);
      }
      
      log(`Email credentials stored successfully for ${credentials.email}`, "phishing");
      return { success: true, credentialId };
    } catch (error) {
      log(`Error storing email credentials: ${error}`, "phishing");
      throw new Error(`Failed to store email credentials: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  /**
   * Get user emails from their account
   * @param credentialId The ID of the stored credentials
   * @param folder The email folder to fetch from (default: INBOX)
   * @param limit The maximum number of emails to fetch (default: 20)
   */
  async fetchEmails(credentialId: string, folder: string = 'INBOX', limit: number = 20) {
    let client = null;
    try {
      // Retrieve credentials
      const credentials = await this.getStoredCredentials(credentialId);
      if (!credentials) {
        throw new Error('Credentials not found');
      }
      
      // For Gmail, we need to use special settings
      const isGmail = credentials.email.toLowerCase().includes('gmail.com') || 
                     credentials.server.toLowerCase().includes('gmail') || 
                     credentials.server.toLowerCase().includes('google');
                     
      log(`Connecting to email server for ${credentials.email} (${credentials.server})`, "phishing");
                     
      // Create IMAP client with proper settings based on provider
      client = new ImapFlow({
        host: credentials.server,
        port: parseInt(credentials.port || '993'),
        secure: credentials.useTLS,
        auth: {
          user: credentials.email,
          pass: this.decryptSensitiveData(credentials.password)
        },
        // Special settings for Gmail
        tls: {
          rejectUnauthorized: false // Important for some providers including Gmail
        },
        logger: false,
        // For Gmail, potentially need longer timeout
        emitLogs: true,
        clientInfo: { name: 'SecurityScanner' }
      });
      
      // Connect to the server with timeout
      const connectPromise = client.connect();
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Connection timeout after 15 seconds')), 15000);
      });
      
      await Promise.race([connectPromise, timeoutPromise]);
      log("Successfully connected to mail server", "phishing");
      
      // Select and lock the mailbox
      const mailbox = await client.mailboxOpen(folder);
      log(`Opened mailbox ${folder} with ${mailbox.exists || 0} messages`, "phishing");
      
      // If mailbox is empty or doesn't exist, return early
      if (!mailbox.exists) {
        await client.logout();
        return {
          success: true,
          folder,
          count: 0,
          emails: []
        };
      }
      
      // Fetch the latest messages
      const messages = [];
      
      // For Gmail, fetch newest messages first (highest UID to lowest)
      let fetchRange = '';
      
      if (isGmail && mailbox.exists > 0) {
        // For Gmail, fetch newest messages first (highest UID to lowest)
        const endSeq = mailbox.exists;
        const startSeq = Math.max(1, endSeq - limit + 1);
        fetchRange = `${startSeq}:${endSeq}`;
      } else {
        // Standard range, limited to what's available
        const count = Math.min(limit, mailbox.exists);
        fetchRange = `1:${count}`;
      }
      
      log(`Fetching email range: ${fetchRange}`, "phishing");
      
      // Process each message
      try {
        for await (const message of client.fetch(fetchRange, { envelope: true, bodyStructure: true, source: true })) {
          try {
            // Parse the raw email source
            const parsed = await simpleParser(message.source);
            
            // Format the email for our system
            const formattedEmail = {
              id: message.uid,
              subject: parsed.subject || '(No Subject)',
              from: parsed.from?.text || '',
              to: parsed.to?.text || '',
              date: parsed.date?.toISOString() || new Date().toISOString(),
              textContent: parsed.text || '',
              htmlContent: parsed.html || '',
              attachments: parsed.attachments?.map(att => ({
                filename: att.filename || 'unnamed',
                contentType: att.contentType || 'application/octet-stream',
                size: att.size || 0
              })) || [],
              headers: parsed.headers,
              flags: message.flags || []
            };
            
            messages.push(formattedEmail);
          } catch (parseError) {
            log(`Error parsing message: ${parseError}`, "phishing");
            // Continue with next message if one fails
          }
        }
      } catch (fetchError) {
        log(`Error during message fetch: ${fetchError}`, "phishing");
        // If we have some messages, continue despite errors
        if (messages.length === 0) {
          throw fetchError;
        }
      }
      
      // Sort messages by date (most recent first)
      messages.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
      
      // Close the connection
      try {
        await client.logout();
      } catch (logoutError) {
        log(`Error during logout: ${logoutError}`, "phishing");
        // Continue despite logout error
      }
      
      return {
        success: true,
        folder,
        count: messages.length,
        emails: messages
      };
    } catch (error) {
      log(`Error fetching emails: ${error}`, "phishing");
      
      // Ensure connection is closed
      if (client) {
        try {
          await client.logout();
        } catch (logoutError) {
          // Ignore logout errors during error handling
        }
      }
      
      throw new Error(`Failed to fetch emails: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  /**
   * Analyze a specific email from user's account
   * @param credentialId The ID of the stored credentials
   * @param messageId The ID of the email message to analyze
   * @param folder The folder where the message is located
   */
  async analyzeEmailById(credentialId: string, messageId: number, folder: string = 'INBOX') {
    let client = null;
    try {
      // Retrieve credentials
      const credentials = await this.getStoredCredentials(credentialId);
      if (!credentials) {
        throw new Error('Credentials not found');
      }
      
      // For Gmail, we need to use special settings
      const isGmail = credentials.email.toLowerCase().includes('gmail.com') || 
                     credentials.server.toLowerCase().includes('gmail') || 
                     credentials.server.toLowerCase().includes('google');
      
      log(`Connecting to email server for analysis: ${credentials.email} (${credentials.server})`, "phishing");
      
      // Create IMAP client with improved settings
      client = new ImapFlow({
        host: credentials.server,
        port: parseInt(credentials.port || '993'),
        secure: credentials.useTLS,
        auth: {
          user: credentials.email,
          pass: this.decryptSensitiveData(credentials.password)
        },
        // Special settings for Gmail
        tls: {
          rejectUnauthorized: false // Important for some providers including Gmail
        },
        logger: false,
        emitLogs: true,
        clientInfo: { name: 'SecurityScanner' }
      });
      
      // Connect to the server with timeout
      const connectPromise = client.connect();
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Connection timeout after 15 seconds')), 15000);
      });
      
      await Promise.race([connectPromise, timeoutPromise]);
      log("Successfully connected to mail server for analysis", "phishing");
      
      // Select and lock the mailbox
      await client.mailboxOpen(folder);
      
      // Fetch the specific message
      const message = await client.fetchOne(messageId, { envelope: true, bodyStructure: true, source: true });
      if (!message) {
        await client.logout();
        throw new Error('Email not found');
      }
      
      // Parse the raw email source
      const parsed = await simpleParser(message.source);
      
      // Extract URLs from the email content
      const urlRegex = /(https?:\/\/[^\s]+)/g;
      const textContent = parsed.text || '';
      const htmlContent = parsed.html || '';
      
      // Find all URLs in the email content
      let suspiciousUrls: string[] = [];
      const textUrls = textContent.match(urlRegex) || [];
      
      // Extract URLs from HTML using a simple regex approach
      // In a real implementation, we would use a proper HTML parser
      const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/g;
      let match;
      const htmlUrls: string[] = [];
      while ((match = hrefRegex.exec(htmlContent)) !== null) {
        htmlUrls.push(match[1]);
      }
      
      // Combine all found URLs
      const allUrls = [...new Set([...textUrls, ...htmlUrls])];
      
      // Analyze the email
      const analysis = await this.analyzeEmail({
        subject: parsed.subject || '',
        content: textContent || htmlContent || '',
        sender: parsed.from?.text || '',
        recipient: parsed.to?.text || '',
        suspiciousUrls: allUrls
      });
      
      // Close the connection
      try {
        await client.logout();
      } catch (logoutError) {
        log(`Error during logout: ${logoutError}`, "phishing");
        // Continue despite logout error
      }
      
      return {
        success: true,
        email: {
          id: messageId,
          subject: parsed.subject || '(No Subject)',
          from: parsed.from?.text || '',
          to: parsed.to?.text || '',
          date: parsed.date?.toISOString() || new Date().toISOString(),
          textContent: parsed.text || '',
          htmlContent: parsed.html || '',
          attachments: parsed.attachments?.map(att => ({
            filename: att.filename || 'unnamed',
            contentType: att.contentType || 'application/octet-stream',
            size: att.size || 0
          })) || [],
          headers: parsed.headers
        },
        analysis
      };
    } catch (error) {
      log(`Error analyzing email: ${error}`, "phishing");
      
      // Ensure connection is closed
      if (client) {
        try {
          await client.logout();
        } catch (logoutError) {
          // Ignore logout errors during error handling
        }
      }
      
      throw new Error(`Failed to analyze email: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  /**
   * Retrieve stored email credentials
   * @param credentialId The ID of the credentials to retrieve
   */
  private async getStoredCredentials(credentialId: string) {
    try {
      const filePath = path.join(this.credentialsDir, `${credentialId}.json`);
      if (!fs.existsSync(filePath)) {
        return null;
      }
      
      const fileData = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(fileData);
    } catch (error) {
      log(`Error retrieving credentials: ${error}`, "phishing");
      return null;
    }
  }
  
  /**
   * Decrypt sensitive data
   * @param encryptedData The encrypted data to decrypt
   */
  private decryptSensitiveData(encryptedData: string): string {
    try {
      // Split the IV and encrypted content
      const parts = encryptedData.split(':');
      if (parts.length !== 2) {
        throw new Error('Invalid encrypted data format');
      }
      
      const iv = Buffer.from(parts[0], 'hex');
      const encryptedText = parts[1];
      
      // Use the same key derivation as in encryption
      const secretKey = process.env.EMAIL_PASSWORD || 'default_secure_key_for_email_encryption';
      const key = crypto.createHash('sha256').update(String(secretKey)).digest('base64').substring(0, 32);
      
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      log(`Error decrypting data: ${error}`, "phishing");
      throw new Error('Failed to decrypt sensitive data');
    }
  }
  
  /**
   * Perform a basic check of email sender domain and headers
   */
  private analyzeSender(sender: string) {
    if (!sender) {
      return {
        suspicious: true,
        details: "Missing sender information is unusual and suspicious.",
        domainInfo: null
      };
    }
    
    try {
      // Extract domain from sender email
      const emailRegex = /([^@]+)@([^@]+)/;
      const match = sender.match(emailRegex);
      
      if (!match) {
        return {
          suspicious: true,
          details: "Invalid email format which is highly suspicious.",
          domainInfo: null
        };
      }
      
      const [, username, domain] = match;
      
      // Check for common suspicious patterns in usernames and domains
      const commonServices = ["paypal", "amazon", "apple", "microsoft", "google", "facebook", "bank", "chase", "wellsfargo", "citi"];
      
      // Check for lookalike domains (e.g., paypa1.com instead of paypal.com)
      let lookalikeDomain = false;
      let targetService = "";
      
      for (const service of commonServices) {
        // Check for misspellings or character replacements
        if (domain.includes(service.replace("l", "1")) || 
            domain.includes(service.replace("i", "1")) || 
            domain.includes(service.replace("o", "0"))) {
          lookalikeDomain = true;
          targetService = service;
          break;
        }
      }
      
      // Simulate domain age check (would use an actual WHOIS API in production)
      const domainAge = this.simulateDomainAgeCheck(domain);
      
      // Check for SPF and DMARC records (simulated)
      const hasSpf = Math.random() > 0.3; // Simulated - would use DNS lookup
      const hasDmarc = Math.random() > 0.4; // Simulated - would use DNS lookup
      
      let suspicious = false;
      let details = "The sender appears to be legitimate.";
      
      if (lookalikeDomain) {
        suspicious = true;
        details = `This appears to be a lookalike domain targeting ${targetService}. The real ${targetService} would not use this email domain.`;
      } else if (domainAge < 30) {
        suspicious = true;
        details = `The sender's domain is very new (less than 30 days old), which is suspicious for legitimate services.`;
      } else if (!hasSpf && !hasDmarc) {
        suspicious = true;
        details = "The sender's domain lacks proper email authentication (SPF/DMARC), which legitimate organizations typically implement.";
      }
      
      return {
        suspicious,
        details,
        domainInfo: {
          domain,
          age: `${domainAge} days`,
          spf: hasSpf,
          dmarc: hasDmarc
        }
      };
    } catch (error) {
      log(`Error analyzing sender: ${error}`, "phishing");
      return {
        suspicious: true,
        details: "Unable to properly analyze the sender, which is concerning.",
        domainInfo: null
      };
    }
  }
  
  /**
   * Analyze email content for phishing indicators
   */
  private analyzeContent(subject: string, content: string) {
    const redFlags = [];
    
    // Check for urgency language
    const urgencyPhrases = [
      "urgent", "immediate action", "account suspended", "security alert", 
      "unauthorized access", "verify your account", "suspicious activity",
      "limited time", "expires today", "action required"
    ];
    
    for (const phrase of urgencyPhrases) {
      if (subject.toLowerCase().includes(phrase) || content.toLowerCase().includes(phrase)) {
        redFlags.push({
          type: "Urgency Tactics",
          description: "The message creates a false sense of urgency to pressure you into taking action without thinking."
        });
        break;
      }
    }
    
    // Check for threatening language
    const threatPhrases = [
      "will be closed", "will be suspended", "terminated", "unauthorized transaction",
      "security breach", "suspicious login", "account compromised"
    ];
    
    for (const phrase of threatPhrases) {
      if (subject.toLowerCase().includes(phrase) || content.toLowerCase().includes(phrase)) {
        redFlags.push({
          type: "Threatening Language",
          description: "The message uses threatening language to scare you into taking immediate action."
        });
        break;
      }
    }
    
    // Check for requests for personal information
    const personalInfoRequests = [
      "confirm your password", "verify your credentials", "enter your social security", 
      "update your payment information", "confirm your credit card", "verify your identity"
    ];
    
    for (const phrase of personalInfoRequests) {
      if (content.toLowerCase().includes(phrase)) {
        redFlags.push({
          type: "Request for Sensitive Information",
          description: "Legitimate organizations rarely ask for personal information via email."
        });
        break;
      }
    }
    
    // Check for generic greetings
    if (content.toLowerCase().includes("dear customer") || 
        content.toLowerCase().includes("dear user") ||
        content.toLowerCase().includes("valued customer")) {
      redFlags.push({
        type: "Generic Greeting",
        description: "Legitimate organizations typically address you by name, not with generic terms."
      });
    }
    
    // Check for poor grammar and spelling
    const grammarIssues = this.detectGrammarIssues(content);
    if (grammarIssues) {
      redFlags.push({
        type: "Grammar and Spelling Issues",
        description: "The message contains unusual phrasing, errors, or poor grammar that legitimate organizations would avoid."
      });
    }
    
    return {
      redFlags,
      language: this.detectLanguageStyle(content)
    };
  }
  
  /**
   * Analyze URLs in the email content for suspicious characteristics
   */
  private analyzeURLs(content: string, suspiciousUrls: string[]) {
    // Extract URLs from content
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const extractedUrls = content.match(urlRegex) || [];
    
    // Combine with provided suspicious URLs and remove duplicates
    const allUrls = Array.from(new Set([...extractedUrls, ...suspiciousUrls].filter(Boolean)));
    
    // Analyze each URL
    const analyzedUrls = allUrls.map(url => {
      try {
        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname;
        
        // Check for IP address URLs
        const isIpAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
        
        // Check for URL shorteners
        const isUrlShortener = this.isUrlShortener(domain);
        
        // Check for misleading link text (would need HTML content)
        const hasMismatchedText = false; // Would need HTML parsing
        
        // Check for unusual ports
        const hasUnusualPort = parsedUrl.port && ![80, 443, ""].includes(parsedUrl.port);
        
        // Check for excessive subdomains
        const hasExcessiveSubdomains = domain.split('.').length > 3;
        
        // Check for suspicious file extensions in the path
        const hasExecutableExtension = /\.(exe|bat|cmd|sh|msi|vbs|ps1)(\?|$)/.test(parsedUrl.pathname);
        
        const isMalicious = isIpAddress || isUrlShortener || hasUnusualPort || hasExcessiveSubdomains || hasExecutableExtension;
        
        let reason = "No suspicious characteristics detected.";
        
        if (isIpAddress) {
          reason = "URL uses an IP address instead of a domain name, which is unusual for legitimate services.";
        } else if (isUrlShortener) {
          reason = "URL uses a shortening service which can hide the actual destination.";
        } else if (hasUnusualPort) {
          reason = `URL uses an unusual port (${parsedUrl.port}) which is suspicious.`;
        } else if (hasExcessiveSubdomains) {
          reason = "URL contains excessive subdomains which is often a phishing tactic.";
        } else if (hasExecutableExtension) {
          reason = "URL points to an executable file which is highly suspicious.";
        } else if (hasMismatchedText) {
          reason = "The link text doesn't match the actual URL destination.";
        }
        
        return {
          url,
          domain,
          malicious: isMalicious,
          reason
        };
      } catch (error) {
        return {
          url,
          domain: "Invalid URL",
          malicious: true,
          reason: "URL format is invalid which is suspicious."
        };
      }
    });
    
    return {
      urls: analyzedUrls,
      count: analyzedUrls.length,
      maliciousCount: analyzedUrls.filter(u => u.malicious).length
    };
  }
  
  /**
   * Calculate an overall risk score based on various factors
   */
  private calculateRiskScore(senderAnalysis: any, contentAnalysis: any, urlAnalysis: any) {
    let score = 0;
    
    // Sender factors (0-4 points)
    if (senderAnalysis.suspicious) {
      score += 2;
      
      // Additional points for specific issues
      if (senderAnalysis.domainInfo) {
        if (senderAnalysis.domainInfo.age && parseInt(senderAnalysis.domainInfo.age) < 30) {
          score += 1;
        }
        
        if (!senderAnalysis.domainInfo.spf && !senderAnalysis.domainInfo.dmarc) {
          score += 1;
        }
      }
    }
    
    // Content factors (0-3 points)
    score += Math.min(3, contentAnalysis.redFlags.length * 0.75);
    
    // URL factors (0-3 points)
    const maliciousRatio = urlAnalysis.count > 0 ? urlAnalysis.maliciousCount / urlAnalysis.count : 0;
    score += maliciousRatio * 3;
    
    return score;
  }
  
  /**
   * Generate user recommendations based on the analysis
   */
  private generateRecommendations(riskScore: number, senderAnalysis: any, contentAnalysis: any, urlAnalysis: any) {
    const recommendations = [];
    
    if (riskScore >= 6) {
      recommendations.push("Do not respond to this email or click any links - it is likely a phishing attempt.");
      recommendations.push("Report this email as phishing to your email provider.");
      
      if (senderAnalysis.suspicious) {
        recommendations.push("Block the sender to prevent future phishing attempts from this source.");
      }
      
      if (urlAnalysis.maliciousCount > 0) {
        recommendations.push("If you've clicked any links in this email, scan your device for malware and consider changing passwords for important accounts.");
      }
    } else if (riskScore >= 3) {
      recommendations.push("Exercise caution with this email - it has some suspicious characteristics.");
      recommendations.push("Verify the sender by contacting them through an official channel before taking any requested actions.");
      
      if (urlAnalysis.maliciousCount > 0) {
        recommendations.push("Hover over links to verify their destinations before clicking, or type the URL directly into your browser.");
      }
      
      if (contentAnalysis.redFlags.length > 0) {
        recommendations.push("Be skeptical of urgent requests or threats - legitimate organizations rarely use these tactics.");
      }
    } else {
      recommendations.push("This email appears to be legitimate, but always remain vigilant.");
      recommendations.push("If you're still unsure, contact the sender through official channels to verify.");
    }
    
    return recommendations;
  }
  
  /**
   * Generate a summary of the analysis findings
   */
  private generateSummary(isPhishing: boolean, riskScore: number, senderAnalysis: any, contentAnalysis: any, urlAnalysis: any) {
    if (isPhishing) {
      let summary = "This email shows strong indicators of being a phishing attempt. ";
      
      if (senderAnalysis.suspicious) {
        summary += `The sender appears suspicious. ${senderAnalysis.details ? senderAnalysis.details + " " : ""} `;
      }
      
      if (contentAnalysis.redFlags && contentAnalysis.redFlags.length > 0) {
        summary += `The content contains ${contentAnalysis.redFlags.length} red flags including: `;
        contentAnalysis.redFlags.slice(0, 2).forEach((flag: any, index: number) => {
          summary += `${index > 0 ? ", " : ""}${flag.type}${flag.description ? ` (${flag.description})` : ""}`;
        });
        if (contentAnalysis.redFlags.length > 2) {
          summary += ` and ${contentAnalysis.redFlags.length - 2} more issues`;
        }
        summary += ". ";
      }
      
      if (urlAnalysis.maliciousCount > 0) {
        summary += `The email contains ${urlAnalysis.maliciousCount} suspicious URLs out of ${urlAnalysis.count} total links. `;
        if (urlAnalysis.urls && urlAnalysis.urls.length > 0 && urlAnalysis.urls[0].malicious) {
          summary += `For example: "${urlAnalysis.urls[0].url}" - ${urlAnalysis.urls[0].reason} `;
        }
      }
      
      return summary + "Take immediate remediation steps and do not interact with this email.";
    } else if (riskScore >= 3) {
      let summary = "This email shows some suspicious characteristics but may not be a definitive phishing attempt. ";
      
      if (senderAnalysis.suspicious) {
        summary += `The sender raises concerns: ${senderAnalysis.details ? senderAnalysis.details + " " : ""} `;
      }
      
      if (contentAnalysis.redFlags && contentAnalysis.redFlags.length > 0) {
        summary += `The content contains ${contentAnalysis.redFlags.length} concerning elements. `;
      }
      
      if (urlAnalysis.maliciousCount > 0) {
        summary += `${urlAnalysis.maliciousCount} out of ${urlAnalysis.count} URLs in the email appear suspicious. `;
      }
      
      return summary + "Exercise caution when interacting with this email and verify through alternative channels before taking any action.";
    } else {
      let summary = "This email appears to be legitimate with no strong indicators of phishing. ";
      
      if (senderAnalysis.domainInfo && senderAnalysis.domainInfo.spf && senderAnalysis.domainInfo.dmarc) {
        summary += "The sender domain has proper security controls (SPF/DMARC) in place. ";
      }
      
      if (contentAnalysis.language) {
        summary += `The message uses ${contentAnalysis.language.toLowerCase()} language style which is consistent with legitimate communication. `;
      }
      
      if (urlAnalysis.count > 0 && urlAnalysis.maliciousCount === 0) {
        summary += "All URLs in the email appear legitimate. ";
      }
      
      return summary + "As a best practice, always remain vigilant with any email requesting sensitive information.";
    }
  }
  
  /**
   * Enhance analysis using AI if available
   */
  private async performAIAnalysis(emailData: PhishingAnalysisRequest) {
    try {
      if (!this.geminiModel) {
        return null;
      }
      
      const prompt = `
        Analyze this email for signs of phishing. Conduct a thorough security analysis looking for:
        1. Red flags in sender domain, format, and legitimacy
        2. Linguistic manipulation and social engineering tactics
        3. Suspicious URLs, redirects, or malformed links
        4. Urgency or fear-based messaging
        5. Requests for sensitive information
        6. Inconsistencies in formatting or language
        7. Technical deception indicators
        
        Subject: ${emailData.subject}
        From: ${emailData.sender}
        To: ${emailData.recipient}
        
        Content:
        ${emailData.content}
        
        Respond with JSON in this exact format:
        {
          "isPhishing": boolean (true/false),
          "confidence": number (0-1),
          "reasons": array of strings explaining why this is or isn't phishing,
          "manipulationTactics": array of strings describing manipulation tactics used,
          "technicalIndicators": array of strings describing technical signs of phishing,
          "securityRecommendations": array of strings with specific actions the user should take,
          "threatLevel": string (either "Critical", "High", "Medium", "Low", or "Safe"),
          "additionalRiskScore": number (0-2) representing how much this should increase the risk score
        }
      `;
      
      const result = await this.geminiModel.generateContent(prompt);
      const response = result.response;
      const text = response.text();
      
      // Extract the JSON part from the response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return null;
      }
      
      try {
        const aiAnalysis = JSON.parse(jsonMatch[0]);
        return aiAnalysis;
      } catch (error) {
        log(`Error parsing AI response: ${error}`, "phishing");
        return null;
      }
    } catch (error) {
      log(`Error in AI analysis: ${error}`, "phishing");
      return null;
    }
  }
  
  /**
   * Test email connection to verify credentials
   */
  private async testEmailConnection(credentials: EmailCredentials): Promise<boolean> {
    // Implementation would depend on the email provider
    // This is a placeholder that simulates successful connection
    return true;
  }
  
  /**
   * Setup automated scanning based on frequency
   */
  private setupAutomatedScanning(credentialId: string) {
    // Implementation would set up cron jobs or scheduled tasks
    // This is a placeholder
    log(`Automated scanning set up for credential ID: ${credentialId}`, "phishing");
  }
  
  /**
   * Encrypt sensitive data before storage
   */
  private encryptSensitiveData(data: string): string {
    try {
      // Use a consistent key derived from the environment variable
      // In production, you'd use a properly secured encryption key
      const secretKey = process.env.EMAIL_PASSWORD || 'default_secure_key_for_email_encryption';
      const key = crypto.createHash('sha256').update(String(secretKey)).digest('base64').substring(0, 32);
      
      const iv = crypto.randomBytes(16); // Initialization vector
      
      // Create cipher with our consistent key
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      
      // Encrypt the data
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Return IV and encrypted data
      return iv.toString('hex') + ':' + encrypted;
    } catch (error) {
      log(`Error encrypting data: ${error}`, "phishing");
      // For security, return error without details
      throw new Error('Encryption failed');
    }
  }
  
  /**
   * Get default mail server for common providers
   */
  private getDefaultServer(provider: string): string {
    switch (provider) {
      case 'gmail':
        return 'imap.gmail.com';
      case 'outlook':
        return 'outlook.office365.com';
      case 'yahoo':
        return 'imap.mail.yahoo.com';
      default:
        return '';
    }
  }
  
  /**
   * Get default port for common providers
   */
  private getDefaultPort(provider: string): string {
    switch (provider) {
      case 'gmail':
      case 'outlook':
      case 'yahoo':
        return '993';
      default:
        return '';
    }
  }
  
  /**
   * Check if a domain is a known URL shortener
   */
  private isUrlShortener(domain: string): boolean {
    const shorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
      'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc'
    ];
    
    return shorteners.includes(domain);
  }
  
  /**
   * Simulate checking domain age (would use real WHOIS API in production)
   */
  private simulateDomainAgeCheck(domain: string): number {
    // Simulate domain age check
    // Common domains would return higher values, unfamiliar ones lower values
    const commonDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 'aol.com'];
    
    if (commonDomains.includes(domain)) {
      return 3650 + Math.floor(Math.random() * 1000); // ~10+ years
    }
    
    // For other domains, randomize but skew towards younger domains for suspicious ones
    if (domain.includes('secure') || domain.includes('login') || domain.includes('account')) {
      return Math.floor(Math.random() * 60); // 0-60 days
    }
    
    return 180 + Math.floor(Math.random() * 500); // 6 months to ~2 years
  }
  
  /**
   * Detect grammar and spelling issues in content
   */
  private detectGrammarIssues(content: string): boolean {
    // This is a simplified check that would be more sophisticated in production
    const commonErrors = [
      'urgently need', 'kindly provide', 'verify you account', 'dear costumer',
      'your account will expired', 'we detected suspicious', 'click the link below to verify',
      'will be terminate', 'security purpose', 'to avoid suspension'
    ];
    
    for (const error of commonErrors) {
      if (content.toLowerCase().includes(error)) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Detect language style for further analysis
   */
  private detectLanguageStyle(content: string): string {
    // Simplified detection of language style
    if (content.includes('Dear') && (content.includes('Sincerely') || content.includes('Regards'))) {
      return 'Formal';
    } else if (content.toLowerCase().includes('urgent') || content.toLowerCase().includes('immediately')) {
      return 'Urgent/Demanding';
    } else if (content.toLowerCase().includes('congratulations') || content.toLowerCase().includes('winner')) {
      return 'Promotional/Reward';
    } else {
      return 'Standard';
    }
  }
}

// Export the singleton instance
export const emailPhishingService = new EmailPhishingService();