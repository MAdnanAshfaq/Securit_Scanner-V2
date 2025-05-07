import PDFDocument from 'pdfkit';
import { ChartJSNodeCanvas } from 'chartjs-node-canvas';
import { type Vulnerability, type Scan, RiskLevel } from "@shared/schema";
import { aiAnalyzer } from "./aiAnalysis";
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { storage } from './storage';

// Get current directory equivalent to __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration for chart generation
const chartJSNodeCanvas = new ChartJSNodeCanvas({
  width: 600,
  height: 400,
  backgroundColour: '#ffffff',
  plugins: {
    modern: ['chartjs-plugin-datalabels']
  }
});

/**
 * Generate PDF report for a security scan
 */
export async function generatePDFReport(scanId: number): Promise<string> {
  try {
    // Get scan data
    const scan = await storage.getScanById(scanId);
    if (!scan) {
      throw new Error(`Scan with ID ${scanId} not found`);
    }
    
    // Get vulnerabilities
    const vulnerabilities = await storage.getVulnerabilitiesByScanId(scanId);
    
    // Get AI-enhanced analysis for each vulnerability
    const vulnerabilityAnalyses = await Promise.all(
      vulnerabilities.map(async (vuln) => {
        return {
          vulnerability: vuln,
          analysis: await aiAnalyzer.analyzeVulnerability(vuln)
        };
      })
    );
    
    // Generate overall scan report
    const scanReport = await aiAnalyzer.generateScanReport(scan, vulnerabilities);
    
    // Create a new PDF document
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    
    // Set up the report directory
    const reportsDir = path.join(__dirname, '..', 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }
    
    // Create file path for the report
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filePath = path.join(reportsDir, `security-report-${scan.id}-${timestamp}.pdf`);
    
    // Pipe the PDF to a file
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);
    
    // Add report header
    addReportHeader(doc, scan);
    
    // Add executive summary
    if (scanReport) {
      addExecutiveSummary(doc, scanReport);
    }
    
    // Add vulnerability statistics chart
    await addVulnerabilityStatistics(doc, vulnerabilities);
    
    // Add detailed findings for each vulnerability
    for (const { vulnerability, analysis } of vulnerabilityAnalyses) {
      await addVulnerabilityDetails(doc, vulnerability, analysis);
    }
    
    // Add report footer
    addReportFooter(doc);
    
    // Finalize the PDF
    doc.end();
    
    // Return the path to the generated PDF
    return new Promise((resolve, reject) => {
      stream.on('finish', () => {
        resolve(filePath);
      });
      
      stream.on('error', (err) => {
        reject(err);
      });
    });
  } catch (error) {
    console.error('PDF report generation failed:', error);
    throw error;
  }
}

/**
 * Add report header to the PDF
 */
function addReportHeader(doc: PDFKit.PDFDocument, scan: Scan) {
  // Add logo or title
  doc.font('Helvetica-Bold')
     .fontSize(24)
     .fillColor('#2563eb')
     .text('Security Vulnerability Report', { align: 'center' });
  
  doc.moveDown();
  
  // Add scan information
  doc.font('Helvetica')
     .fontSize(12)
     .fillColor('#000000')
     .text(`Target: ${scan.url}`, { align: 'center' });
  
  doc.moveDown(0.5);
  
  const scanDate = new Date(scan.startTime || Date.now()).toLocaleString();
  doc.text(`Scan Date: ${scanDate}`, { align: 'center' });
  
  // Add horizontal line
  doc.moveDown();
  doc.moveTo(50, doc.y)
     .lineTo(doc.page.width - 50, doc.y)
     .stroke('#9ca3af');
  
  doc.moveDown();
}

/**
 * Add executive summary from AI report
 */
function addExecutiveSummary(doc: PDFKit.PDFDocument, reportText: string) {
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .fillColor('#2563eb')
     .text('Executive Summary', { underline: true });
  
  doc.moveDown(0.5);
  
  doc.font('Helvetica')
     .fontSize(12)
     .fillColor('#000000')
     .text(reportText.substring(0, 1000) + '...', {
       align: 'left',
       columns: 1,
       width: doc.page.width - 100,
       height: 300
     });
  
  doc.moveDown();
}

/**
 * Add vulnerability statistics chart
 */
async function addVulnerabilityStatistics(doc: PDFKit.PDFDocument, vulnerabilities: Vulnerability[]) {
  doc.addPage();
  
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .fillColor('#2563eb')
     .text('Vulnerability Statistics', { underline: true });
  
  doc.moveDown(0.5);
  
  // Count vulnerabilities by severity
  const highCount = vulnerabilities.filter(v => v.severity === RiskLevel.HIGH).length;
  const mediumCount = vulnerabilities.filter(v => v.severity === RiskLevel.MEDIUM).length;
  const lowCount = vulnerabilities.filter(v => v.severity === RiskLevel.LOW).length;
  const infoCount = vulnerabilities.filter(v => v.severity === RiskLevel.INFO).length;
  
  // Generate severity distribution chart
  const severityChartConfig = {
    type: 'pie' as const,
    data: {
      labels: ['High', 'Medium', 'Low', 'Informational'],
      datasets: [{
        data: [highCount, mediumCount, lowCount, infoCount],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
        borderWidth: 1
      }]
    },
    options: {
      plugins: {
        legend: {
          position: 'right' as const,
          labels: {
            boxWidth: 15
          }
        },
        title: {
          display: true,
          text: 'Vulnerability Severity Distribution',
          font: {
            size: 16
          }
        },
        datalabels: {
          formatter: (value: number, ctx: any) => {
            if (value === 0) return '';
            return value;
          },
          color: '#ffffff',
          font: {
            weight: 'bold' as const
          }
        }
      }
    }
  };
  
  // Generate chart image
  const severityChartImage = await chartJSNodeCanvas.renderToBuffer(severityChartConfig);
  
  // Add chart to PDF
  doc.image(severityChartImage, {
    fit: [500, 300],
    align: 'center',
    valign: 'center'
  });
  
  doc.moveDown(2);
  
  // Add summary table
  doc.font('Helvetica-Bold')
     .fontSize(14)
     .text('Summary of Findings');
  
  doc.moveDown(0.5);
  
  const tableTop = doc.y;
  const tableLeft = 100;
  const colWidth = 150;
  const rowHeight = 30;
  
  // Draw table header
  doc.font('Helvetica-Bold')
     .fontSize(12)
     .fillColor('#ffffff')
     .rect(tableLeft, tableTop, colWidth, rowHeight)
     .fill('#2563eb')
     .fillColor('#ffffff')
     .text('Severity', tableLeft + 10, tableTop + 10)
     .rect(tableLeft + colWidth, tableTop, colWidth, rowHeight)
     .fill('#2563eb')
     .text('Count', tableLeft + colWidth + 10, tableTop + 10);
  
  // Draw table rows
  let currentY = tableTop + rowHeight;
  
  // High
  doc.fillColor('#000000')
     .rect(tableLeft, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text('High', tableLeft + 10, currentY + 10)
     .rect(tableLeft + colWidth, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text(highCount.toString(), tableLeft + colWidth + 10, currentY + 10);
  
  currentY += rowHeight;
  
  // Medium
  doc.rect(tableLeft, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text('Medium', tableLeft + 10, currentY + 10)
     .rect(tableLeft + colWidth, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text(mediumCount.toString(), tableLeft + colWidth + 10, currentY + 10);
  
  currentY += rowHeight;
  
  // Low
  doc.rect(tableLeft, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text('Low', tableLeft + 10, currentY + 10)
     .rect(tableLeft + colWidth, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text(lowCount.toString(), tableLeft + colWidth + 10, currentY + 10);
  
  currentY += rowHeight;
  
  // Info
  doc.rect(tableLeft, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text('Informational', tableLeft + 10, currentY + 10)
     .rect(tableLeft + colWidth, currentY, colWidth, rowHeight)
     .stroke('#d1d5db')
     .text(infoCount.toString(), tableLeft + colWidth + 10, currentY + 10);
}

/**
 * Add detailed vulnerability information to PDF
 */
async function addVulnerabilityDetails(
  doc: PDFKit.PDFDocument, 
  vulnerability: Vulnerability, 
  analysis: any
) {
  // Add a new page for each vulnerability
  doc.addPage();
  
  // Vulnerability title with severity indicator
  const severityColors: Record<string, string> = {
    [RiskLevel.HIGH]: '#ef4444',
    [RiskLevel.MEDIUM]: '#f97316',
    [RiskLevel.LOW]: '#eab308',
    [RiskLevel.INFO]: '#3b82f6'
  };
  
  doc.font('Helvetica-Bold')
     .fontSize(18)
     .fillColor(severityColors[vulnerability.severity] || '#000000')
     .text(`${vulnerability.name} (${vulnerability.severity.toUpperCase()})`, { underline: true });
  
  doc.moveDown(0.5);
  
  // Vulnerability description
  doc.font('Helvetica')
     .fontSize(12)
     .fillColor('#000000')
     .text('Description:', { continued: true, underline: true })
     .text(` ${vulnerability.description}`);
  
  doc.moveDown();
  
  // Location
  if (vulnerability.location) {
    doc.font('Helvetica-Bold')
       .text('Location:', { continued: true, underline: true })
       .font('Helvetica')
       .text(` ${vulnerability.location}`);
    
    doc.moveDown();
  }
  
  // Add AI enhanced analysis if available
  if (analysis) {
    // Summary
    doc.font('Helvetica-Bold')
       .fontSize(14)
       .fillColor('#2563eb')
       .text('Analysis Summary');
    
    doc.moveDown(0.5);
    
    doc.font('Helvetica')
       .fontSize(12)
       .fillColor('#000000')
       .text(analysis.summary || 'No summary available.');
    
    doc.moveDown();
    
    // Technical details
    doc.font('Helvetica-Bold')
       .fontSize(14)
       .fillColor('#2563eb')
       .text('Technical Details');
    
    doc.moveDown(0.5);
    
    doc.font('Helvetica')
       .fontSize(12)
       .fillColor('#000000')
       .text(analysis.technicalDetails || 'No technical details available.');
    
    doc.moveDown();
    
    // Recommendations
    doc.font('Helvetica-Bold')
       .fontSize(14)
       .fillColor('#2563eb')
       .text('Recommendations');
    
    doc.moveDown(0.5);
    
    doc.font('Helvetica')
       .fontSize(12)
       .fillColor('#000000');
    
    if (analysis.recommendations && analysis.recommendations.length > 0) {
      analysis.recommendations.forEach((rec: string, index: number) => {
        doc.text(`${index + 1}. ${rec}`);
        doc.moveDown(0.5);
      });
    } else {
      doc.text('No recommendations available.');
    }
    
    doc.moveDown();
    
    // Business impact
    doc.font('Helvetica-Bold')
       .fontSize(14)
       .fillColor('#2563eb')
       .text('Business Impact');
    
    doc.moveDown(0.5);
    
    doc.font('Helvetica')
       .fontSize(12)
       .fillColor('#000000')
       .text(analysis.businessImpact || 'No business impact assessment available.');
    
    doc.moveDown();
    
    // References
    doc.font('Helvetica-Bold')
       .fontSize(14)
       .fillColor('#2563eb')
       .text('References');
    
    doc.moveDown(0.5);
    
    doc.font('Helvetica')
       .fontSize(12)
       .fillColor('#000000');
    
    if (analysis.references && analysis.references.length > 0) {
      analysis.references.forEach((ref: string, index: number) => {
        doc.text(`${index + 1}. ${ref}`);
        doc.moveDown(0.5);
      });
    } else {
      doc.text('No references available.');
    }
  } else {
    doc.font('Helvetica')
       .fontSize(12)
       .fillColor('#000000')
       .text('Enhanced analysis not available for this vulnerability.');
  }
}

/**
 * Add footer to the report
 */
function addReportFooter(doc: PDFKit.PDFDocument) {
  // Add a new page for the footer if needed
  if (doc.y > doc.page.height - 150) {
    doc.addPage();
  }
  
  doc.moveDown(4);
  
  // Add disclaimer
  doc.font('Helvetica-Bold')
     .fontSize(14)
     .fillColor('#ef4444')
     .text('Disclaimer', { underline: true });
  
  doc.moveDown(0.5);
  
  doc.font('Helvetica')
     .fontSize(10)
     .fillColor('#000000')
     .text(
       'This report is provided for informational purposes only. The findings in this report are based on automated ' +
       'scans and may include false positives or miss certain vulnerabilities. It is recommended to verify all findings ' +
       'manually before taking action. The creators of this report are not responsible for any damages that may arise ' +
       'from the use of this information. Always follow ethical hacking practices and obtain proper authorization before ' +
       'testing any systems.'
     );
  
  doc.moveDown(2);
  
  // Add report generation timestamp
  const timestamp = new Date().toLocaleString();
  doc.font('Helvetica')
     .fontSize(10)
     .fillColor('#6b7280')
     .text(`Report generated on ${timestamp}`, { align: 'center' });
  
  // Finalize the document first
  doc.flushPages();
  
  // Get total number of pages
  const range = doc.bufferedPageRange();
  const pageCount = range.count;

  // Add page numbers
  for (let i = 0; i < pageCount; i++) {
    try {
      doc.switchToPage(i);
      
      // Add page number at the bottom with safe margins
      doc.font('Helvetica')
         .fontSize(10)
         .fillColor('#6b7280')
         .text(
           `Page ${i + 1} of ${pageCount}`,
           50,
           doc.page.height - 70,
           { align: 'center', width: doc.page.width - 100 }
         );
    } catch (err) {
      console.warn(`Could not add page number to page ${i + 1}`, err);
      continue;
    }
  }
}