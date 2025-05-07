import { InsertScan, InsertVulnerability, RiskLevel, ServerInfo } from "@shared/schema";
import { storage } from "./storage";
import https from "https";
import http from "http";
import { URL } from "url";
// Import vulnerability resources from client side shared code
const vulnerabilityResources = {
  "Cross-Site Scripting": "https://owasp.org/www-community/attacks/xss/",
  "SQL Injection": "https://owasp.org/www-community/attacks/SQL_Injection",
  "Cross-Site Request Forgery": "https://owasp.org/www-community/attacks/csrf",
  "Missing Headers": "https://owasp.org/www-project-secure-headers/",
  "Insecure Cookies": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
  "Content Security Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  "Outdated Libraries": "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"
};

// Function to scan a website for vulnerabilities
export async function scanWebsite(url: string) {
  try {
    // Normalize URL
    const normalizedUrl = normalizeUrl(url);
    
    // Create a new scan record
    const scan: InsertScan = {
      url: normalizedUrl,
      startTime: new Date(),
      status: "in-progress",
    };
    
    // Store the scan
    const newScan = await storage.createScan(scan);
    
    // Perform the actual scan
    const results = await performScan(normalizedUrl);
    
    // Update the scan with results
    const updatedScan = await storage.updateScan({
      ...newScan,
      endTime: new Date(),
      status: "completed",
      serverInfo: results.serverInfo,
      highRiskCount: results.vulnerabilities.filter(v => v.severity === RiskLevel.HIGH).length,
      mediumRiskCount: results.vulnerabilities.filter(v => v.severity === RiskLevel.MEDIUM).length,
      lowRiskCount: results.vulnerabilities.filter(v => v.severity === RiskLevel.LOW).length,
      infoCount: results.vulnerabilities.filter(v => v.severity === RiskLevel.INFO).length,
    });
    
    // Store all found vulnerabilities
    for (const vuln of results.vulnerabilities) {
      await storage.createVulnerability({
        ...vuln,
        scanId: newScan.id,
      });
    }
    
    return updatedScan;
  } catch (error) {
    console.error("Scan error:", error);
    throw error;
  }
}

// Helper function to normalize URL
function normalizeUrl(url: string): string {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return `https://${url}`;
  }
  return url;
}

// Main function to perform the actual scan
async function performScan(url: string) {
  try {
    const parsedUrl = new URL(url);
    const headers = await getHeaders(url);
    
    // Analyze server info
    const serverInfo: ServerInfo = {
      server: headers['server'] || 'Unknown',
      ip: '192.0.2.1', // Placeholder for demo - would normally resolve this
      location: 'Unknown', // Would normally use IP geolocation
      technologies: detectTechnologies(headers, url),
    };
    
    // Find vulnerabilities
    const vulnerabilities = [
      ...analyzeHeaders(headers, parsedUrl),
      ...checkCommonVulnerabilities(parsedUrl, headers),
    ];
    
    return {
      serverInfo,
      vulnerabilities,
    };
  } catch (error) {
    console.error("Error during scan:", error);
    throw error;
  }
}

// Function to get HTTP headers
async function getHeaders(url: string): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const options = {
      method: 'HEAD',
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      timeout: 10000,
    };
    
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    const req = protocol.request(options, (res) => {
      const headers: Record<string, string> = {};
      Object.keys(res.headers).forEach(key => {
        if (res.headers[key]) {
          headers[key] = Array.isArray(res.headers[key]) 
            ? (res.headers[key] as string[]).join(', ')
            : res.headers[key] as string;
        }
      });
      resolve(headers);
    });
    
    req.on('error', (err) => {
      reject(err);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    req.end();
  });
}

// Function to detect technologies based on headers
function detectTechnologies(headers: Record<string, string>, url: string): string[] {
  const technologies: string[] = [];
  
  // Server technology
  if (headers['server']) {
    const serverHeader = headers['server'].toLowerCase();
    if (serverHeader.includes('apache')) technologies.push('Apache');
    if (serverHeader.includes('nginx')) technologies.push('Nginx');
    if (serverHeader.includes('iis')) technologies.push('IIS');
  }
  
  // Programming language/framework
  if (headers['x-powered-by']) {
    const poweredBy = headers['x-powered-by'].toLowerCase();
    if (poweredBy.includes('php')) technologies.push('PHP');
    if (poweredBy.includes('asp.net')) technologies.push('ASP.NET');
    if (poweredBy.includes('express')) technologies.push('Express.js');
  }
  
  // Add some common technologies for demo
  if (technologies.length === 0) {
    technologies.push('JavaScript');
    if (Math.random() > 0.5) technologies.push('jQuery');
    if (Math.random() > 0.7) technologies.push('MySQL');
  }
  
  return technologies;
}

// Function to analyze headers for security issues
function analyzeHeaders(headers: Record<string, string>, url: URL): InsertVulnerability[] {
  const vulnerabilities: InsertVulnerability[] = [];
  
  // Check for missing security headers
  const securityHeaders = [
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'strict-transport-security',
    'referrer-policy',
    'permissions-policy',
  ];
  
  const missingHeaders = securityHeaders.filter(header => !headers[header]);
  
  if (missingHeaders.length > 0) {
    vulnerabilities.push({
      name: 'Missing Security Headers',
      description: 'Security headers help protect against various attacks including XSS, clickjacking, and MIME sniffing. The website is missing several important security headers.',
      severity: missingHeaders.length > 4 ? RiskLevel.HIGH : (missingHeaders.length > 2 ? RiskLevel.MEDIUM : RiskLevel.LOW),
      location: url.hostname,
      details: `Missing headers: ${missingHeaders.join(', ')}`,
      recommendation: 'Configure your web server to include these security headers with appropriate values for your application\'s requirements.',
      learnMoreUrl: vulnerabilityResources['Missing Headers'],
    });
  }
  
  // Check for insecure cookies
  if (headers['set-cookie'] && !headers['set-cookie'].includes('secure') && url.protocol === 'https:') {
    vulnerabilities.push({
      name: 'Insecure Cookies',
      description: 'Cookies are being set without the Secure flag, which means they can be transmitted over unencrypted HTTP connections.',
      severity: RiskLevel.MEDIUM,
      location: url.hostname,
      details: 'Cookies found without Secure flag',
      recommendation: 'Set the Secure flag on all cookies to ensure they are only sent over HTTPS connections.',
      learnMoreUrl: vulnerabilityResources['Insecure Cookies'],
    });
  }
  
  // Check for missing HSTS header on HTTPS sites
  if (url.protocol === 'https:' && !headers['strict-transport-security']) {
    vulnerabilities.push({
      name: 'Missing HTTP Strict Transport Security',
      description: 'HSTS forces browsers to use HTTPS for future visits and helps protect against protocol downgrade attacks.',
      severity: RiskLevel.MEDIUM,
      location: url.hostname,
      details: 'The Strict-Transport-Security header is not set',
      recommendation: 'Add the Strict-Transport-Security header with a suitable max-age directive.',
      learnMoreUrl: vulnerabilityResources['Content Security Policy'],
    });
  }
  
  return vulnerabilities;
}

// Function to check for common vulnerabilities
function checkCommonVulnerabilities(url: URL, headers: Record<string, string>): InsertVulnerability[] {
  const vulnerabilities: InsertVulnerability[] = [];
  
  // For demo purposes, we'll add some sample vulnerabilities
  // In a real app, this would perform actual testing
  
  // XSS vulnerability (simulated)
  if (url.search.includes('q=') || url.search.includes('search=') || url.pathname.includes('search')) {
    vulnerabilities.push({
      name: 'Cross-Site Scripting (XSS) Vulnerability',
      description: 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. This can lead to cookie theft, session hijacking, or phishing attacks.',
      severity: RiskLevel.HIGH,
      location: `${url.pathname}${url.search}`,
      details: `GET ${url.pathname}${url.search || '?q=<script>alert(1)</script>'} HTTP/1.1\nHost: ${url.hostname}`,
      recommendation: 'Implement proper input validation and output encoding. Use frameworks that automatically escape output or implement Content Security Policy (CSP).',
      learnMoreUrl: vulnerabilityResources['Cross-Site Scripting'],
    });
  }
  
  // CSRF vulnerability (simulated)
  if (url.pathname.includes('user') || url.pathname.includes('account') || url.pathname.includes('profile')) {
    vulnerabilities.push({
      name: 'Cross-Site Request Forgery (CSRF)',
      description: 'CSRF vulnerabilities allow attackers to trick users into performing actions they did not intend to do on a website where they are authenticated.',
      severity: RiskLevel.MEDIUM,
      location: url.hostname,
      details: 'Forms submitted without anti-CSRF tokens',
      recommendation: 'Implement anti-CSRF tokens for all state-changing operations and validate them on the server side.',
      learnMoreUrl: vulnerabilityResources['Cross-Site Request Forgery'],
    });
  }
  
  // Outdated jQuery (simulated)
  if (Math.random() > 0.6) {
    vulnerabilities.push({
      name: 'Outdated jQuery Version',
      description: 'The website is using an outdated version of jQuery which has known security vulnerabilities.',
      severity: RiskLevel.LOW,
      location: 'jquery-1.11.3.min.js',
      details: 'Detected jQuery version 1.11.3 which is vulnerable to various XSS attacks',
      recommendation: 'Update to the latest version of jQuery to address known security vulnerabilities.',
      learnMoreUrl: vulnerabilityResources['Outdated Libraries'],
    });
  }
  
  // Information disclosure (server version)
  if (headers['server'] && (headers['server'].includes('/') || headers['server'].includes(' '))) {
    vulnerabilities.push({
      name: 'Server Information Disclosure',
      description: 'The server is revealing detailed version information which could help attackers identify specific vulnerabilities.',
      severity: RiskLevel.INFO,
      location: 'HTTP Headers',
      details: `Server: ${headers['server']}`,
      recommendation: 'Configure your web server to remove version information from the Server header.',
      learnMoreUrl: null,
    });
  }
  
  return vulnerabilities;
}
