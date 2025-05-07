import { RiskLevel } from "@shared/schema";

// Helper functions for scanning features

/**
 * Formats a URL for display (removes protocol)
 */
export function formatUrl(url: string): string {
  return url.replace(/^https?:\/\//, "");
}

/**
 * Generates scan result statistics
 */
export function getScanStats(vulnerabilities: any[]) {
  return {
    highRisk: vulnerabilities.filter(v => v.severity === RiskLevel.HIGH).length,
    mediumRisk: vulnerabilities.filter(v => v.severity === RiskLevel.MEDIUM).length,
    lowRisk: vulnerabilities.filter(v => v.severity === RiskLevel.LOW).length,
    info: vulnerabilities.filter(v => v.severity === RiskLevel.INFO).length,
    total: vulnerabilities.length
  };
}

/**
 * Map of vulnerability types to educational resources
 */
export const vulnerabilityResources = {
  "Cross-Site Scripting": "https://owasp.org/www-community/attacks/xss/",
  "SQL Injection": "https://owasp.org/www-community/attacks/SQL_Injection",
  "Cross-Site Request Forgery": "https://owasp.org/www-community/attacks/csrf",
  "Missing Headers": "https://owasp.org/www-project-secure-headers/",
  "Insecure Cookies": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
  "Content Security Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  "Outdated Libraries": "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"
};

/**
 * Maps a severity level to a risk label
 */
export function getRiskLabel(severity: RiskLevel): string {
  switch (severity) {
    case RiskLevel.HIGH:
      return "High Risk";
    case RiskLevel.MEDIUM:
      return "Medium Risk";
    case RiskLevel.LOW:
      return "Low Risk";
    case RiskLevel.INFO:
      return "Informational";
    default:
      return "Unknown";
  }
}

/**
 * Validates if a URL is in the correct format
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}
