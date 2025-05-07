import { GoogleGenerativeAI } from "@google/generative-ai";
import { type Vulnerability, type Scan, RiskLevel } from "@shared/schema";

// Interface for AI-enhanced analysis report
export interface AIEnhancedReport {
  summary: string;
  technicalDetails: string;
  recommendations: string[];
  businessImpact: string;
  references: string[];
}

/**
 * AI-powered vulnerability analyzer
 * Uses Google's Gemini API to provide deeper insights into detected vulnerabilities
 */
export class AIVulnerabilityAnalyzer {
  private genAI: GoogleGenerativeAI;
  private geminiModel: any;
  private apiKey: string;
  
  constructor() {
    // Initialize the Gemini API with the provided key
    this.apiKey = process.env.GEMINI_API_KEY || "AIzaSyA_lui4mrxScOdVQHgl96edRAUyro5pU3w";
    
    if (!this.apiKey) {
      console.warn("GEMINI_API_KEY not set. AI-enhanced reporting will be disabled.");
    }
    
    this.genAI = new GoogleGenerativeAI(this.apiKey);
    this.geminiModel = this.genAI.getGenerativeModel({ model: "gemini-pro" });
  }
  
  /**
   * Generate an enhanced analysis of a vulnerability
   */
  async analyzeVulnerability(vulnerability: Vulnerability): Promise<AIEnhancedReport | null> {
    if (!this.apiKey) {
      return null;
    }
    
    try {
      // Create a prompt for vulnerability analysis
      const prompt = `
You are a cybersecurity expert specialized in vulnerability analysis. 
Analyze the following vulnerability information in detail:

Vulnerability: ${vulnerability.name}
Description: ${vulnerability.description}
Severity: ${vulnerability.severity}
Location: ${vulnerability.location || "Unknown"}

Provide a comprehensive analysis with the following sections:

1. Summary (Brief overview)
2. Technical Details (Detailed technical explanation)
3. Recommendations (List of specific mitigation steps)
4. Business Impact (How this could affect a business)
5. References (Technical documentation or CVE references)

Use markdown formatting for your response, with clear section headers.
`;
      
      // Get response from Gemini API
      const result = await this.geminiModel.generateContent(prompt);
      const response = await result.response;
      const text = response.text();
      
      // Parse the AI response into structured format
      return this.parseAIResponse(text);
    } catch (error) {
      console.error("AI analysis failed:", error);
      return null;
    }
  }
  
  /**
   * Generate a comprehensive scan report with AI insights
   */
  async generateScanReport(scan: Scan, vulnerabilities: Vulnerability[]): Promise<string | null> {
    if (!this.apiKey) {
      return null;
    }
    
    try {
      // Calculate vulnerability statistics
      const highRisk = vulnerabilities.filter(v => v.severity === RiskLevel.HIGH).length;
      const mediumRisk = vulnerabilities.filter(v => v.severity === RiskLevel.MEDIUM).length;
      const lowRisk = vulnerabilities.filter(v => v.severity === RiskLevel.LOW).length;
      const infoRisk = vulnerabilities.filter(v => v.severity === RiskLevel.INFO).length;
      
      // Create a summary of vulnerabilities
      const vulnSummary = vulnerabilities.map(v => 
        `- ${v.name} (${v.severity}): ${v.description.substring(0, 100)}...`
      ).join('\n');
      
      // Create prompt for scan analysis
      const prompt = `
You are a cybersecurity expert tasked with creating a comprehensive security assessment report.
Analyze the following scan results for ${scan.url}:

Scan Statistics:
- High Risk Vulnerabilities: ${highRisk}
- Medium Risk Vulnerabilities: ${mediumRisk}
- Low Risk Vulnerabilities: ${lowRisk}
- Informational: ${infoRisk}

Vulnerability Summary:
${vulnSummary}

Create a detailed security assessment report with the following sections:
1. Executive Summary
2. Risk Assessment
3. Detailed Findings
4. Recommendations and Remediation Steps
5. Follow-up Actions

Use markdown formatting for your response, with clear section headers.
`;
      
      // Get response from Gemini API
      const result = await this.geminiModel.generateContent(prompt);
      const response = await result.response;
      const text = response.text();
      
      return text;
    } catch (error) {
      console.error("AI scan report generation failed:", error);
      return null;
    }
  }
  
  /**
   * Parse the AI response into structured format
   */
  private parseAIResponse(response: string): AIEnhancedReport {
    // Default structure
    const result: AIEnhancedReport = {
      summary: "",
      technicalDetails: "",
      recommendations: [],
      businessImpact: "",
      references: []
    };
    
    try {
      // Extract summary section
      const summaryMatch = response.match(/(?:^|\n)#+\s*(?:1\.\s*)?Summary\s*(?:\n|$)([\s\S]*?)(?=\n#+\s*(?:2\.\s*)?Technical|$)/i);
      if (summaryMatch && summaryMatch[1]) {
        result.summary = summaryMatch[1].trim();
      }
      
      // Extract technical details
      const technicalMatch = response.match(/(?:^|\n)#+\s*(?:2\.\s*)?Technical Details\s*(?:\n|$)([\s\S]*?)(?=\n#+\s*(?:3\.\s*)?Recommendations|$)/i);
      if (technicalMatch && technicalMatch[1]) {
        result.technicalDetails = technicalMatch[1].trim();
      }
      
      // Extract recommendations
      const recommendationsMatch = response.match(/(?:^|\n)#+\s*(?:3\.\s*)?Recommendations\s*(?:\n|$)([\s\S]*?)(?=\n#+\s*(?:4\.\s*)?Business Impact|$)/i);
      if (recommendationsMatch && recommendationsMatch[1]) {
        result.recommendations = recommendationsMatch[1]
          .split(/\n[*-]\s+|\n\d+\.\s+/)
          .map(r => r.trim())
          .filter(r => r.length > 0);
      }
      
      // Extract business impact
      const impactMatch = response.match(/(?:^|\n)#+\s*(?:4\.\s*)?Business Impact\s*(?:\n|$)([\s\S]*?)(?=\n#+\s*(?:5\.\s*)?References|$)/i);
      if (impactMatch && impactMatch[1]) {
        result.businessImpact = impactMatch[1].trim();
      }
      
      // Extract references
      const referencesMatch = response.match(/(?:^|\n)#+\s*(?:5\.\s*)?References\s*(?:\n|$)([\s\S]*?)(?=$)/i);
      if (referencesMatch && referencesMatch[1]) {
        result.references = referencesMatch[1]
          .split(/\n[*-]\s+|\n\d+\.\s+/)
          .map(r => r.trim())
          .filter(r => r.length > 0);
      }
    } catch (error) {
      console.error("Failed to parse AI response:", error);
    }
    
    return result;
  }
}

// Create and export an instance of the analyzer
export const aiAnalyzer = new AIVulnerabilityAnalyzer();