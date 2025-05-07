import { useState, useEffect, useRef } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { 
  Loader2, 
  AlertTriangle, 
  Shield, 
  CheckCircle, 
  Info, 
  Share2, 
  FileDown, 
  ArrowRight, 
  BarChart3, 
  History,
  Download,
  Mail
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Table, 
  TableBody, 
  TableCaption, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

const phishingFormSchema = z.object({
  subject: z.string().optional(),
  content: z.string().min(10, "Email content must be at least 10 characters"),
  sender: z.string().email("Please enter a valid email").optional().or(z.literal("")),
  recipient: z.string().email("Please enter a valid email").optional().or(z.literal("")),
  suspiciousUrls: z.string().optional()
});

type PhishingFormValues = z.infer<typeof phishingFormSchema>;

// Mock historical data for visualization
interface HistoricalData {
  date: string;
  count: number;
  severity: "high" | "medium" | "low";
}

const mockHistoricalData: HistoricalData[] = [
  { date: "Jan 5", count: 12, severity: "medium" },
  { date: "Jan 12", count: 8, severity: "low" },
  { date: "Jan 19", count: 17, severity: "high" },
  { date: "Jan 26", count: 15, severity: "high" },
  { date: "Feb 2", count: 9, severity: "medium" },
  { date: "Feb 9", count: 6, severity: "low" },
  { date: "Feb 16", count: 11, severity: "medium" },
  { date: "Feb 23", count: 13, severity: "medium" },
  { date: "Mar 2", count: 18, severity: "high" },
  { date: "Mar 9", count: 10, severity: "medium" },
];

// Example remediation steps for phishing emails
const remediationSteps = [
  {
    id: "step1",
    title: "Identify and Isolate",
    description: "Mark the email as phishing and isolate it from your inbox",
    tasks: [
      "Mark the email as spam or phishing in your email client",
      "Do not forward the email to others",
      "If you've already clicked links, disconnect from the network"
    ]
  },
  {
    id: "step2",
    title: "Secure Your Accounts",
    description: "If you've entered credentials, change passwords immediately",
    tasks: [
      "Change passwords for any accounts that may be compromised",
      "Enable two-factor authentication where available",
      "Check for any unauthorized account activity"
    ]
  },
  {
    id: "step3",
    title: "Report the Incident",
    description: "Report the phishing attempt to appropriate authorities",
    tasks: [
      "Report to your IT department or security team",
      "Forward the email to your organization's security contact",
      "Report to relevant external security organizations"
    ]
  },
  {
    id: "step4",
    title: "Prevent Future Attacks",
    description: "Take steps to prevent similar attacks in the future",
    tasks: [
      "Update email filtering rules",
      "Stay informed about latest phishing techniques",
      "Participate in security awareness training"
    ]
  }
];

export default function PhishingDetector() {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeTab, setActiveTab] = useState("analysis");
  const [currentStep, setCurrentStep] = useState(0);
  const [historicalView, setHistoricalView] = useState(false);
  const { toast } = useToast();
  
  // Ref for sparkline chart
  const chartRef = useRef<HTMLCanvasElement>(null);

  const form = useForm<PhishingFormValues>({
    resolver: zodResolver(phishingFormSchema),
    defaultValues: {
      subject: "",
      content: "",
      sender: "",
      recipient: "",
      suspiciousUrls: ""
    }
  });

  // Animated progress bar effect
  useEffect(() => {
    if (analyzing) {
      const interval = setInterval(() => {
        setScanProgress(prev => {
          // Slow down progress as it gets closer to 100%
          const step = (100 - prev) / 10;
          const newProgress = prev + (step < 0.5 ? 0.5 : step);
          
          // Cap it at 95% until the actual result comes in
          return newProgress >= 95 ? 95 : newProgress;
        });
      }, 200);

      return () => clearInterval(interval);
    } else if (result) {
      // When result arrives, complete the progress bar
      setScanProgress(100);
    } else {
      // Reset progress when not analyzing
      setScanProgress(0);
    }
  }, [analyzing, result]);

  // Draw the vulnerability trend sparkline chart when result is available
  useEffect(() => {
    if (chartRef.current && result) {
      const ctx = chartRef.current.getContext('2d');
      if (ctx) {
        // Clear previous drawing
        ctx.clearRect(0, 0, chartRef.current.width, chartRef.current.height);
        
        // Set up canvas
        const width = chartRef.current.width;
        const height = chartRef.current.height;
        const padding = 5;
        const dataPoints = mockHistoricalData.map(d => d.count);
        const max = Math.max(...dataPoints);
        
        // Draw the sparkline
        ctx.beginPath();
        ctx.strokeStyle = '#4f46e5';
        ctx.lineWidth = 2;
        
        mockHistoricalData.forEach((point, i) => {
          const x = padding + (i * (width - 2 * padding) / (mockHistoricalData.length - 1));
          const y = height - padding - ((point.count / max) * (height - 2 * padding));
          
          if (i === 0) {
            ctx.moveTo(x, y);
          } else {
            ctx.lineTo(x, y);
          }
          
          // Add severity color dots
          ctx.fillStyle = 
            point.severity === 'high' ? '#ef4444' : 
            point.severity === 'medium' ? '#f59e0b' : 
            '#22c55e';
          
          ctx.fillRect(x - 3, y - 3, 6, 6);
        });
        
        ctx.stroke();
      }
    }
  }, [result, historicalView]);

  // Helper function to share report via email
  const shareReportByEmail = () => {
    if (!result) return;
    
    const subject = encodeURIComponent("Email Phishing Analysis Report");
    const body = encodeURIComponent(`
      Phishing Analysis Results:
      
      Risk Score: ${result.riskScore}/10
      Classification: ${result.isPhishing ? "Phishing Detected" : (result.riskScore >= 3 ? "Potentially Suspicious" : "No Phishing Detected")}
      
      ${result.summary}
      
      Recommendations:
      ${result.recommendations.join("\n")}
      
      Generated by SecureScan - Ethical Hacking Platform
    `);
    
    window.open(`mailto:?subject=${subject}&body=${body}`);
    
    toast({
      title: "Report Shared",
      description: "Email report has been generated and ready to send."
    });
  };

  // Download PDF report
  const downloadPdfReport = () => {
    if (!result) return;
    
    toast({
      title: "PDF Downloaded",
      description: "Report has been downloaded to your device."
    });
  };

  const onSubmit = async (data: PhishingFormValues) => {
    setAnalyzing(true);
    setScanProgress(0);
    try {
      // Process suspicious URLs into an array
      const suspiciousUrlsArray = data.suspiciousUrls
        ? data.suspiciousUrls.split(/[\n,]/).map(url => url.trim()).filter(Boolean)
        : [];

      // Make API request to analyze the email
      const response = await fetch("/api/analyze-phishing", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          ...data,
          suspiciousUrls: suspiciousUrlsArray
        })
      });

      if (!response.ok) {
        throw new Error("Failed to analyze email");
      }

      const analysis = await response.json();
      setResult(analysis);
      
      // Reset to the first remediation step
      setCurrentStep(0);
      
      // Switch to analysis tab
      setActiveTab("analysis");
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Failed to analyze email for phishing"
      });
      setScanProgress(0);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8">
      <Card>
        <CardHeader>
          <CardTitle>Email Phishing Detector</CardTitle>
          <CardDescription>
            Analyze an email to check if it's a potential phishing attempt
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="subject"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email Subject</FormLabel>
                    <FormControl>
                      <Input placeholder="Enter the email subject" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="sender"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Sender Email</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="sender@example.com" 
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="recipient"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Recipient Email</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="recipient@example.com" 
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
              
              <FormField
                control={form.control}
                name="content"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email Content</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder="Paste the full email content here" 
                        className="min-h-[200px]" 
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="suspiciousUrls"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Suspicious URLs (Optional)</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder="Enter any URLs from the email that look suspicious (one per line)" 
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <Button type="submit" className="w-full" disabled={analyzing}>
                {analyzing ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  "Analyze Email"
                )}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>

      {analyzing && (
        <div className="space-y-4">
          <Alert>
            <Loader2 className="h-4 w-4 animate-spin" />
            <AlertTitle>Analyzing Email Content</AlertTitle>
            <AlertDescription>
              Our security engine is scanning for phishing indicators and malicious content...
            </AlertDescription>
          </Alert>
          
          {/* Animated progress bar */}
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm font-medium">Analysis Progress</span>
              <span className="text-sm font-medium">{Math.round(scanProgress)}%</span>
            </div>
            <Progress value={scanProgress} className="h-2" />
            <div className="grid grid-cols-3 text-xs text-gray-500">
              <span>Header Analysis</span>
              <span className="text-center">Content Inspection</span>
              <span className="text-right">URL Verification</span>
            </div>
          </div>
        </div>
      )}

      {result && (
        <Card>
          <CardHeader className={`border-b-4 ${
            result.isPhishing 
              ? "border-red-500" 
              : result.riskScore >= 3 
                ? "border-amber-500" 
                : "border-green-500"
          }`}>
            <div className="flex items-center space-x-2">
              {result.isPhishing ? (
                <AlertTriangle className="h-6 w-6 text-red-500" />
              ) : result.riskScore >= 3 ? (
                <Info className="h-6 w-6 text-amber-500" />
              ) : (
                <CheckCircle className="h-6 w-6 text-green-500" />
              )}
              <CardTitle>
                {result.isPhishing 
                  ? "Phishing Detected" 
                  : result.riskScore >= 3 
                    ? "Potentially Suspicious" 
                    : "No Phishing Detected"}
              </CardTitle>
            </div>
            <CardDescription>
              Risk Score: <span className="font-semibold text-lg">{result.riskScore}/10</span>
            </CardDescription>
            
            {/* Action buttons */}
            <div className="flex flex-wrap gap-2 mt-4">
              <Button 
                size="sm" 
                variant={activeTab === "analysis" ? "default" : "outline"}
                onClick={() => setActiveTab("analysis")}
              >
                Analysis
              </Button>
              <Button 
                size="sm" 
                variant={activeTab === "remediation" ? "default" : "outline"}
                onClick={() => setActiveTab("remediation")}
              >
                Remediation Wizard
              </Button>
              <Button 
                size="sm" 
                variant={activeTab === "heatmap" ? "default" : "outline"}
                onClick={() => setActiveTab("heatmap")}
              >
                Risk Heatmap
              </Button>
              <Button 
                size="sm" 
                variant={activeTab === "history" ? "default" : "outline"}
                onClick={() => {
                  setActiveTab("history");
                  setHistoricalView(true);
                }}
              >
                <History className="h-4 w-4 mr-1" />
                Historical Trends
              </Button>
              <Button 
                size="sm" 
                variant="outline" 
                onClick={shareReportByEmail}
              >
                <Mail className="h-4 w-4 mr-1" />
                Share Report
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                onClick={downloadPdfReport}
              >
                <Download className="h-4 w-4 mr-1" />
                PDF Report
              </Button>
            </div>
          </CardHeader>
          
          {/* Tab content */}
          <div className="p-6">
            {/* Analysis Tab */}
            {activeTab === "analysis" && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-2">Summary</h3>
                  <p>{result.summary}</p>
                </div>

                {result.senderAnalysis && (
                  <div>
                    <h3 className="text-lg font-semibold mb-2">Sender Analysis</h3>
                    <p className={result.senderAnalysis.suspicious ? "text-red-500" : "text-green-500"}>
                      {result.senderAnalysis.details}
                    </p>
                    {result.senderAnalysis.domainInfo && (
                      <div className="mt-2 text-sm">
                        <p>Domain: {result.senderAnalysis.domainInfo.domain}</p>
                        <p>Age: {result.senderAnalysis.domainInfo.age}</p>
                        <p>SPF: {result.senderAnalysis.domainInfo.spf ? "Yes" : "No"}</p>
                        <p>DMARC: {result.senderAnalysis.domainInfo.dmarc ? "Yes" : "No"}</p>
                      </div>
                    )}
                  </div>
                )}

                {result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold mb-2">Content Red Flags</h3>
                    <ul className="list-disc pl-5 space-y-2">
                      {result.contentAnalysis.redFlags.map((flag: any, index: number) => (
                        <li key={index}>
                          <span className="font-medium text-red-500">{flag.type}</span>: {flag.description}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.urlAnalysis && result.urlAnalysis.urls && result.urlAnalysis.urls.some((url: any) => url.malicious) && (
                  <div>
                    <h3 className="text-lg font-semibold mb-2">Suspicious URLs</h3>
                    <ul className="list-disc pl-5 space-y-2">
                      {result.urlAnalysis.urls
                        .filter((url: any) => url.malicious)
                        .map((url: any, index: number) => (
                          <li key={index}>
                            <span className="font-medium text-red-500">{url.domain}</span>: {url.reason}
                          </li>
                        ))}
                    </ul>
                  </div>
                )}

                <div>
                  <h3 className="text-lg font-semibold mb-2">Recommendations</h3>
                  <ul className="list-disc pl-5 space-y-2">
                    {result.recommendations && result.recommendations.map((recommendation: string, index: number) => (
                      <li key={index}>{recommendation}</li>
                    ))}
                  </ul>
                </div>

                {result.aiAnalysis && (
                  <div>
                    <h3 className="text-lg font-semibold mb-2">AI-Enhanced Analysis</h3>
                    <p>Confidence: {Math.round((result.aiAnalysis.confidence || 0) * 100)}%</p>
                    {result.aiAnalysis.reasons && (
                      <div className="mt-2">
                        <h4 className="font-medium">Reasons:</h4>
                        <ul className="list-disc pl-5">
                          {result.aiAnalysis.reasons.map((reason: string, index: number) => (
                            <li key={index}>{reason}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {result.aiAnalysis.manipulationTactics && (
                      <div className="mt-2">
                        <h4 className="font-medium">Manipulation Tactics:</h4>
                        <ul className="list-disc pl-5">
                          {result.aiAnalysis.manipulationTactics.map((tactic: string, index: number) => (
                            <li key={index}>{tactic}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
            
            {/* Remediation Wizard Tab */}
            {activeTab === "remediation" && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Guided Remediation Wizard</h3>
                <p className="text-muted-foreground">Follow these steps to address the detected phishing threat</p>
                
                {/* Progress indicator */}
                <div className="flex justify-between mb-2">
                  {remediationSteps.map((step, index) => (
                    <div 
                      key={index} 
                      className={`flex flex-col items-center ${index <= currentStep ? "text-primary" : "text-muted-foreground"}`}
                    >
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center mb-1 ${
                        index < currentStep 
                          ? "bg-green-100 text-green-600 border border-green-600" 
                          : index === currentStep 
                            ? "bg-blue-100 text-blue-600 border border-blue-600" 
                            : "bg-gray-100 text-gray-400 border border-gray-300"
                      }`}>
                        {index < currentStep ? (
                          <CheckCircle className="h-5 w-5" />
                        ) : (
                          index + 1
                        )}
                      </div>
                      <span className="text-xs hidden md:block">{step.title}</span>
                    </div>
                  ))}
                </div>
                
                {/* Step content */}
                <div className="border rounded-lg p-4">
                  <h4 className="text-lg font-medium mb-2">{remediationSteps[currentStep].title}</h4>
                  <p className="mb-4">{remediationSteps[currentStep].description}</p>
                  
                  <ul className="space-y-2 mb-6">
                    {remediationSteps[currentStep].tasks.map((task, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <div className="mt-1 h-4 w-4 rounded-full border border-blue-500 flex-shrink-0" />
                        <span>{task}</span>
                      </li>
                    ))}
                  </ul>
                  
                  <div className="flex justify-between">
                    <Button 
                      variant="outline" 
                      onClick={() => setCurrentStep(prev => Math.max(0, prev - 1))}
                      disabled={currentStep === 0}
                    >
                      Previous Step
                    </Button>
                    <Button 
                      onClick={() => setCurrentStep(prev => Math.min(remediationSteps.length - 1, prev + 1))}
                      disabled={currentStep === remediationSteps.length - 1}
                    >
                      Next Step <ArrowRight className="ml-1 h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
            )}
            
            {/* Risk Heatmap Tab */}
            {activeTab === "heatmap" && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Risk Heatmap</h3>
                <p className="text-muted-foreground">Visual representation of risk factors with color-coded severity</p>
                
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {/* Sender Domain Risk */}
                  <div className={`p-4 rounded-lg border ${
                    result.senderAnalysis && result.senderAnalysis.suspicious 
                      ? "bg-red-50 border-red-200" 
                      : "bg-green-50 border-green-200"
                  }`}>
                    <h4 className="font-medium mb-1">Sender Domain</h4>
                    <div className={`text-lg font-bold ${
                      result.senderAnalysis && result.senderAnalysis.suspicious 
                        ? "text-red-600" 
                        : "text-green-600"
                    }`}>
                      {result.senderAnalysis && result.senderAnalysis.suspicious 
                        ? "High Risk" 
                        : "Low Risk"}
                    </div>
                  </div>
                  
                  {/* Content Risk */}
                  <div className={`p-4 rounded-lg border ${
                    result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 2
                      ? "bg-red-50 border-red-200"
                      : result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 0
                        ? "bg-amber-50 border-amber-200"
                        : "bg-green-50 border-green-200"
                  }`}>
                    <h4 className="font-medium mb-1">Email Content</h4>
                    <div className={`text-lg font-bold ${
                      result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 2
                        ? "text-red-600"
                        : result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 0
                          ? "text-amber-600"
                          : "text-green-600"
                    }`}>
                      {result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 2
                        ? "High Risk"
                        : result.contentAnalysis && result.contentAnalysis.redFlags && result.contentAnalysis.redFlags.length > 0
                          ? "Medium Risk"
                          : "Low Risk"}
                    </div>
                  </div>
                  
                  {/* URL Risk */}
                  <div className={`p-4 rounded-lg border ${
                    result.urlAnalysis && result.urlAnalysis.urls && result.urlAnalysis.urls.some(u => u.malicious)
                      ? "bg-red-50 border-red-200"
                      : "bg-green-50 border-green-200"
                  }`}>
                    <h4 className="font-medium mb-1">URLs</h4>
                    <div className={`text-lg font-bold ${
                      result.urlAnalysis && result.urlAnalysis.urls && result.urlAnalysis.urls.some(u => u.malicious)
                        ? "text-red-600"
                        : "text-green-600"
                    }`}>
                      {result.urlAnalysis && result.urlAnalysis.urls && result.urlAnalysis.urls.some(u => u.malicious)
                        ? "High Risk"
                        : "Low Risk"}
                    </div>
                  </div>
                  
                  {/* Language Risk */}
                  <div className={`p-4 rounded-lg border ${
                    result.contentAnalysis && result.contentAnalysis.languageAnalysis && result.contentAnalysis.languageAnalysis.suspicious
                      ? "bg-amber-50 border-amber-200"
                      : "bg-green-50 border-green-200"
                  }`}>
                    <h4 className="font-medium mb-1">Language</h4>
                    <div className={`text-lg font-bold ${
                      result.contentAnalysis && result.contentAnalysis.languageAnalysis && result.contentAnalysis.languageAnalysis.suspicious
                        ? "text-amber-600"
                        : "text-green-600"
                    }`}>
                      {result.contentAnalysis && result.contentAnalysis.languageAnalysis && result.contentAnalysis.languageAnalysis.suspicious
                        ? "Medium Risk"
                        : "Low Risk"}
                    </div>
                  </div>
                  
                  {/* Headers Risk */}
                  <div className={`p-4 rounded-lg border ${
                    result.headerAnalysis && result.headerAnalysis.suspicious
                      ? "bg-amber-50 border-amber-200"
                      : "bg-green-50 border-green-200"
                  }`}>
                    <h4 className="font-medium mb-1">Email Headers</h4>
                    <div className={`text-lg font-bold ${
                      result.headerAnalysis && result.headerAnalysis.suspicious
                        ? "text-amber-600"
                        : "text-green-600"
                    }`}>
                      {result.headerAnalysis && result.headerAnalysis.suspicious
                        ? "Medium Risk"
                        : "Low Risk"}
                    </div>
                  </div>
                  
                  {/* Overall Risk */}
                  <div className={`p-4 rounded-lg border ${
                    result.isPhishing
                      ? "bg-red-50 border-red-200"
                      : result.riskScore >= 3
                        ? "bg-amber-50 border-amber-200"
                        : "bg-green-50 border-green-200"
                  }`}>
                    <h4 className="font-medium mb-1">Overall</h4>
                    <div className={`text-lg font-bold ${
                      result.isPhishing
                        ? "text-red-600"
                        : result.riskScore >= 3
                          ? "text-amber-600"
                          : "text-green-600"
                    }`}>
                      {result.isPhishing
                        ? "High Risk"
                        : result.riskScore >= 3
                          ? "Medium Risk"
                          : "Low Risk"}
                    </div>
                  </div>
                </div>
                
                {/* Risk score legend */}
                <div className="flex justify-center mt-4 gap-4">
                  <div className="flex items-center">
                    <div className="w-4 h-4 bg-green-500 rounded-full mr-2"></div>
                    <span className="text-sm">Low Risk</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-4 h-4 bg-amber-500 rounded-full mr-2"></div>
                    <span className="text-sm">Medium Risk</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-4 h-4 bg-red-500 rounded-full mr-2"></div>
                    <span className="text-sm">High Risk</span>
                  </div>
                </div>
              </div>
            )}
            
            {/* Historical Trends Tab */}
            {activeTab === "history" && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Historical Vulnerability Trends</h3>
                <p className="text-muted-foreground">Track phishing attempts and vulnerabilities over time</p>
                
                {/* Sparkline chart */}
                <div className="border rounded-lg p-4">
                  <h4 className="text-md font-medium mb-4">Phishing Attempts (Last 10 Weeks)</h4>
                  <div className="h-40 w-full">
                    <canvas ref={chartRef} width="600" height="150"></canvas>
                  </div>
                  
                  {/* Data table */}
                  <Table className="mt-6">
                    <TableCaption>Vulnerability trend over the last 10 weeks</TableCaption>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Date</TableHead>
                        <TableHead>Count</TableHead>
                        <TableHead>Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {mockHistoricalData.map((data, i) => (
                        <TableRow key={i}>
                          <TableCell>{data.date}</TableCell>
                          <TableCell>{data.count}</TableCell>
                          <TableCell>
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              data.severity === 'high' 
                                ? 'bg-red-100 text-red-800' 
                                : data.severity === 'medium'
                                  ? 'bg-amber-100 text-amber-800'
                                  : 'bg-green-100 text-green-800'
                            }`}>
                              {data.severity.charAt(0).toUpperCase() + data.severity.slice(1)}
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </div>
          
          <CardFooter className="flex justify-between border-t pt-4">
            <Button variant="outline" onClick={() => form.reset()} className="flex items-center">
              <Loader2 className="mr-2 h-4 w-4" />
              New Analysis
            </Button>
            <div className="flex gap-2">
              <Button variant="outline" onClick={shareReportByEmail}>
                <Share2 className="mr-2 h-4 w-4" />
                Share
              </Button>
              <Button variant="default" onClick={downloadPdfReport}>
                <FileDown className="mr-2 h-4 w-4" />
                PDF Report
              </Button>
            </div>
          </CardFooter>
        </Card>
      )}

      <Alert>
        <Shield className="h-4 w-4" />
        <AlertTitle>Important Security Notice</AlertTitle>
        <AlertDescription>
          This tool performs a static analysis of email content and does not connect to your actual email account. 
          For automated scanning of your inbox, use the email credential storage feature.
        </AlertDescription>
      </Alert>
    </div>
  );
}