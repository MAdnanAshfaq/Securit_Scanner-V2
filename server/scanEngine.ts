import { InsertScan, InsertVulnerability, RiskLevel, ServerInfo } from "@shared/schema";
import { storage } from "./storage";
import https from "https";
import http from "http";
import { URL } from "url";
import { performAttack } from "./attackEngine";

// Function to scan a website for vulnerabilities
export async function scanWebsite(url: string) {
  if (!url) {
    throw new Error("URL is required");
  }

  try {
    const validUrl = new URL(url);
    if (!validUrl.protocol.startsWith('http')) {
      throw new Error("URL must use HTTP or HTTPS protocol");
    }

    const normalizedUrl = normalizeUrl(url);
    console.log("Starting scan for URL:", normalizedUrl);
    
    // Create scan record
    const scan: InsertScan = {
      url: normalizedUrl,
      status: "in-progress",
      startTime: new Date(),
    };
    
    const newScan = await storage.createScan(scan);
    
    // Perform actual security tests
    const results = await performSecurityTests(normalizedUrl);
    
    // Update scan with results
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
    
    // Store vulnerabilities
    for (const vuln of results.vulnerabilities) {
      await storage.createVulnerability({
        ...vuln,
        scanId: newScan.id,
        severity: vuln.severity.toString()
      });
    }
    
    return updatedScan;
  } catch (error) {
    console.error("Scan error:", error);
    // Create failed scan record
    const failedScan: InsertScan = {
      url: url,
      startTime: new Date(),
      endTime: new Date(),
      status: "failed",
      serverInfo: { server: "Unknown", ip: "Unknown", location: "Unknown", technologies: [] },
      highRiskCount: 0,
      mediumRiskCount: 0,
      lowRiskCount: 0,
      infoCount: 0
    };
    
    await storage.createScan(failedScan);
    throw new Error(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function performSecurityTests(url: string) {
  const parsedUrl = new URL(url);
  const headers = await getHeaders(url);
  const serverInfo = await getServerInfo(url, headers);
  const vulnerabilities: InsertVulnerability[] = [];

  // Create a scan record first to get the scanId
  const scan = await storage.createScan({
    url,
    status: 'in-progress',
    startTime: new Date()
  });

  // Real SQL Injection Testing
  const sqlResults = await performAttack("sql-injection", url, "GET", "search", "' OR '1'='1");
  if (sqlResults.success && sqlResults.details?.potentiallyVulnerable) {
    vulnerabilities.push({
      name: "SQL Injection Vulnerability",
      scanId: scan.id,
      description: sqlResults.results,
      severity: RiskLevel.HIGH.toString(),
      location: url,
      details: JSON.stringify(sqlResults.details),
      recommendation: "Implement prepared statements and input validation",
      learnMoreUrl: "https://owasp.org/www-community/attacks/SQL_Injection"
    });
  }

  // Real XSS Testing
  const xssResults = await performAttack("xss", url, "GET", "q", "<script>alert(1)</script>");
  if (xssResults.success && xssResults.details?.isReflected) {
    vulnerabilities.push({
      name: "Cross-Site Scripting (XSS)",
      scanId: scan.id,
      description: xssResults.results,
      severity: RiskLevel.HIGH.toString(),
      location: url,
      details: JSON.stringify(xssResults.details),
      recommendation: "Implement proper output encoding",
      learnMoreUrl: "https://owasp.org/www-community/attacks/xss/"
    });
  }

  // SSRF Testing
  const ssrfResults = await performAttack("ssrf", url, "GET", "url", "http://169.254.169.254/");
  if (ssrfResults.success && ssrfResults.details?.potentiallyVulnerable) {
    vulnerabilities.push({
      name: "Server-Side Request Forgery",
      scanId: scan.id,
      description: ssrfResults.results,
      severity: RiskLevel.HIGH.toString(),
      location: url,
      details: JSON.stringify(ssrfResults.details),
      recommendation: "Validate and sanitize URL inputs",
      learnMoreUrl: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
    });
  }

  // Security Headers Analysis
  const headerVulnerabilities = await analyzeSecurityHeaders(headers, parsedUrl);
  vulnerabilities.push(...headerVulnerabilities.map(v => ({
    ...v,
    scanId: scan.id,
    severity: v.severity.toString()
  })));

  // SSL/TLS Analysis
  const sslVulnerabilities = await analyzeSSLConfiguration(parsedUrl);
  vulnerabilities.push(...sslVulnerabilities.map(v => ({
    ...v,
    scanId: scan.id,
    severity: v.severity.toString()
  })));

  return {
    serverInfo,
    vulnerabilities
  };
}

async function getServerInfo(url: string, headers: Record<string, string>): Promise<ServerInfo> {
  const parsedUrl = new URL(url);
  const technologies = await detectTechnologies(url, headers);
  const ipAddress = await resolveIP(parsedUrl.hostname);
  
  return {
    server: headers['server'] || 'Unknown',
    ip: ipAddress,
    location: await getIPLocation(ipAddress),
    technologies
  };
}

async function resolveIP(hostname: string): Promise<string> {
  try {
    const { resolve4 } = await import('dns/promises');
    const addresses = await resolve4(hostname);
    return addresses[0];
  } catch (error) {
    return 'Unknown';
  }
}

async function getIPLocation(ip: string): Promise<string> {
  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();
    return `${data.city}, ${data.country_name}`;
  } catch (error) {
    return 'Unknown';
  }
}

async function detectTechnologies(url: string, headers: Record<string, string>): Promise<string[]> {
  const technologies: string[] = [];
  
  // Server Detection
  if (headers['server']) {
    technologies.push(headers['server']);
  }
  
  // Framework Detection
  if (headers['x-powered-by']) {
    technologies.push(headers['x-powered-by']);
  }
  
  // Try to detect CMS and other technologies
  try {
    const response = await fetch(url);
    const html = await response.text();
    
    // WordPress Detection
    if (html.includes('wp-content') || html.includes('wp-includes')) {
      technologies.push('WordPress');
    }
    
    // React Detection
    if (html.includes('react') || html.includes('reactjs')) {
      technologies.push('React');
    }
    
    // Other framework detection logic...
  } catch (error) {
    console.error('Error detecting technologies:', error);
  }
  
  return technologies;
}

async function analyzeSecurityHeaders(headers: Record<string, string>, url: URL): Promise<InsertVulnerability[]> {
  const vulnerabilities: InsertVulnerability[] = [];
  
  // Check for missing security headers
  const requiredHeaders = {
    'strict-transport-security': {
      name: 'Missing HSTS Header',
      severity: RiskLevel.HIGH,
      recommendation: 'Add Strict-Transport-Security header'
    },
    'content-security-policy': {
      name: 'Missing CSP Header',
      severity: RiskLevel.HIGH,
      recommendation: 'Implement Content Security Policy'
    },
    'x-frame-options': {
      name: 'Missing X-Frame-Options Header',
      severity: RiskLevel.MEDIUM,
      recommendation: 'Add X-Frame-Options header'
    }
    // Add more security header checks
  };

  for (const [header, config] of Object.entries(requiredHeaders)) {
    if (!headers[header]) {
      vulnerabilities.push({
        name: config.name,
        scanId: 0, // This will be updated when the vulnerability is added to the scan
        description: `The ${header} security header is missing`,
        severity: config.severity.toString(),
        location: url.toString(),
        details: `Current headers: ${JSON.stringify(headers)}`,
        recommendation: config.recommendation,
        learnMoreUrl: `https://owasp.org/www-project-secure-headers/#${header}`
      });
    }
  }

  return vulnerabilities;
}

async function analyzeSSLConfiguration(url: URL): Promise<InsertVulnerability[]> {
  if (url.protocol !== 'https:') {
    return [{
      name: 'Insecure Protocol',
      scanId: 0, // This will be updated when the vulnerability is added to the scan
      description: 'The site is not using HTTPS',
      severity: RiskLevel.HIGH.toString(),
      location: url.toString(),
      details: 'Site is using unencrypted HTTP',
      recommendation: 'Enable HTTPS with a valid SSL certificate',
      learnMoreUrl: 'https://owasp.org/www-project-transport-layer-protection-cheat-sheet/'
    }];
  }

  // Implement SSL/TLS version and cipher suite checks
  return [];
}

function normalizeUrl(url: string): string {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return `https://${url}`;
  }
  return url;
}

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
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    req.end();
  });
}

async function checkXSSVulnerabilities(url: string, scanId: number) {
  // ... existing code ...
  await storage.insertVulnerability({
    name: 'XSS Vulnerability',
    scanId,
    description: 'Cross-Site Scripting vulnerability detected',
    severity: RiskLevel.HIGH,
    location: url,
    details: 'The application is vulnerable to XSS attacks',
    recommendation: 'Implement proper input validation and output encoding',
    learnMoreUrl: 'https://owasp.org/www-community/attacks/xss/'
  });
  // ... existing code ...
}

async function checkSQLInjectionVulnerabilities(url: string, scanId: number) {
  // ... existing code ...
  await storage.insertVulnerability({
    name: 'SQL Injection Vulnerability',
    scanId,
    description: 'SQL Injection vulnerability detected',
    severity: RiskLevel.HIGH,
    location: url,
    details: 'The application is vulnerable to SQL injection attacks',
    recommendation: 'Use parameterized queries and input validation',
    learnMoreUrl: 'https://owasp.org/www-community/attacks/SQL_Injection'
  });
  // ... existing code ...
}

async function checkCSRFVulnerabilities(url: string, scanId: number) {
  // ... existing code ...
  await storage.insertVulnerability({
    name: 'CSRF Vulnerability',
    scanId,
    description: 'Cross-Site Request Forgery vulnerability detected',
    severity: RiskLevel.MEDIUM,
    location: url,
    details: 'The application is vulnerable to CSRF attacks',
    recommendation: 'Implement CSRF tokens and SameSite cookies',
    learnMoreUrl: 'https://owasp.org/www-community/attacks/csrf'
  });
  // ... existing code ...
}

async function checkFileUploadVulnerabilities(url: string, scanId: number) {
  // ... existing code ...
  await storage.insertVulnerability({
    name: 'Unsafe File Upload',
    scanId,
    description: 'Unsafe file upload vulnerability detected',
    severity: RiskLevel.HIGH,
    location: url,
    details: 'The application allows unsafe file uploads',
    recommendation: 'Implement strict file type validation and scanning',
    learnMoreUrl: 'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'
  });
  // ... existing code ...
}

async function checkDirectoryTraversalVulnerabilities(url: string, scanId: number) {
  // ... existing code ...
  await storage.insertVulnerability({
    name: 'Directory Traversal',
    scanId,
    description: 'Directory traversal vulnerability detected',
    severity: RiskLevel.HIGH,
    location: url,
    details: 'The application is vulnerable to directory traversal attacks',
    recommendation: 'Implement proper path validation and sanitization',
    learnMoreUrl: 'https://owasp.org/www-community/attacks/Path_Traversal'
  });
  // ... existing code ...
}
