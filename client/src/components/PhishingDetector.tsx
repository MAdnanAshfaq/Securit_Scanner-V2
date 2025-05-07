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
          <CardTitle>Email Content Analysis</CardTitle>
          <CardDescription>
            Paste the content of a suspicious email to analyze it for phishing indicators
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
          
          <CardContent className="p-6">
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

                {result.urlAnalysis && result.urlAnalysis.suspiciousUrls && result.urlAnalysis.suspiciousUrls.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold mb-2">Suspicious URLs</h3>
                    <ul className="list-disc pl-5 space-y-2">
                      {result.urlAnalysis.suspiciousUrls.map((url: any, index: number) => (
                        <li key={index}>
                          <span className="font-medium text-red-500">{url.url}</span>: {url.reason}
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
                    <p className="mb-2">Confidence: {Math.round((result.aiAnalysis.confidence || 0) * 100)}%</p>
                    <p>{result.aiAnalysis.summary}</p>
                  </div>
                )}
              </div>
            )}
            
            {/* Remediation Wizard Tab */}
            {activeTab === "remediation" && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold">Remediation Wizard</h3>
                  <div className="flex items-center text-sm text-muted-foreground">
                    Step {currentStep + 1} of {remediationSteps.length}
                  </div>
                </div>
                
                <div className="border rounded-lg p-6 bg-card space-y-4">
                  <div className="space-y-2">
                    <h4 className="text-xl font-semibold">{remediationSteps[currentStep].title}</h4>
                    <p className="text-muted-foreground">{remediationSteps[currentStep].description}</p>
                  </div>
                  
                  <div className="pt-4">
                    <h5 className="text-sm font-medium mb-3">Task Checklist:</h5>
                    <ul className="space-y-3">
                      {remediationSteps[currentStep].tasks.map((task, index) => (
                        <li key={index} className="flex items-start gap-2">
                          <div className="w-5 h-5 rounded-full border-2 border-primary flex-shrink-0 flex items-center justify-center mt-0.5">
                            <CheckCircle className="h-3 w-3 text-primary" />
                          </div>
                          <span>{task}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
                
                <div className="flex justify-between mt-6">
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
                    Next Step <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
            
            {/* Risk Heatmap Tab */}
            {activeTab === "heatmap" && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-4">Email Risk Heatmap</h3>
                  <p className="text-muted-foreground mb-6">
                    This heatmap illustrates the risk level of different elements in the analyzed email.
                  </p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="border-l-4 border-l-amber-500">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">Sender Address</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex justify-between items-center">
                          <span className="font-mono text-sm">{result?.sender || "unknown@example.com"}</span>
                          <Badge variant={result?.senderAnalysis?.suspicious ? "destructive" : "outline"}>
                            {result?.senderAnalysis?.suspicious ? "Suspicious" : "Legitimate"}
                          </Badge>
                        </div>
                      </CardContent>
                    </Card>
                    
                    <Card className={`border-l-4 ${result?.contentAnalysis?.redFlags?.length > 0 ? "border-l-red-500" : "border-l-green-500"}`}>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">Email Content</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex justify-between items-center">
                          <span>Contains red flags</span>
                          <Badge variant={result?.contentAnalysis?.redFlags?.length > 0 ? "destructive" : "outline"}>
                            {result?.contentAnalysis?.redFlags?.length || 0} detected
                          </Badge>
                        </div>
                      </CardContent>
                    </Card>
                    
                    <Card className={`border-l-4 ${result?.urlAnalysis?.suspiciousUrls?.length > 0 ? "border-l-red-500" : "border-l-green-500"}`}>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">URLs & Links</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex justify-between items-center">
                          <span>Suspicious URLs</span>
                          <Badge variant={result?.urlAnalysis?.suspiciousUrls?.length > 0 ? "destructive" : "outline"}>
                            {result?.urlAnalysis?.suspiciousUrls?.length || 0} detected
                          </Badge>
                        </div>
                      </CardContent>
                    </Card>
                    
                    <Card className="border-l-4 border-l-blue-500">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">Overall Score</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex justify-between items-center">
                          <span>Risk Rating</span>
                          <Badge className="text-white" style={{
                            backgroundColor: 
                              result?.riskScore > 7 ? '#ef4444' : 
                              result?.riskScore > 3 ? '#f59e0b' : 
                              '#22c55e'
                          }}>
                            {result?.riskScore}/10
                          </Badge>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </div>
            )}
            
            {/* Historical Trends Tab */}
            {activeTab === "history" && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-2">Historical Phishing Trends</h3>
                  <p className="text-muted-foreground mb-6">
                    Visualization of phishing trends detected by our system over time
                  </p>
                  
                  <div className="mb-6">
                    <canvas 
                      ref={chartRef} 
                      width="600" 
                      height="150" 
                      className="w-full h-auto"
                    />
                    <div className="flex justify-center mt-2 space-x-6">
                      <div className="flex items-center">
                        <span className="w-3 h-3 block bg-red-500 rounded-full mr-2"></span>
                        <span className="text-xs">High Risk</span>
                      </div>
                      <div className="flex items-center">
                        <span className="w-3 h-3 block bg-amber-500 rounded-full mr-2"></span>
                        <span className="text-xs">Medium Risk</span>
                      </div>
                      <div className="flex items-center">
                        <span className="w-3 h-3 block bg-green-500 rounded-full mr-2"></span>
                        <span className="text-xs">Low Risk</span>
                      </div>
                    </div>
                  </div>
                  
                  <Table>
                    <TableCaption>
                      Recent phishing detection history across all users
                    </TableCaption>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Date</TableHead>
                        <TableHead>Detected Emails</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead className="text-right">Trend</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {mockHistoricalData.map((data, i) => (
                        <TableRow key={i}>
                          <TableCell>{data.date}</TableCell>
                          <TableCell>{data.count}</TableCell>
                          <TableCell>
                            <Badge variant={
                              data.severity === "high" ? "destructive" : 
                              data.severity === "medium" ? "default" : 
                              "outline"
                            }>
                              {data.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            {i > 0 ? (
                              data.count > mockHistoricalData[i-1].count ? (
                                <span className="text-red-500">+{data.count - mockHistoricalData[i-1].count}</span>
                              ) : data.count < mockHistoricalData[i-1].count ? (
                                <span className="text-green-500">-{mockHistoricalData[i-1].count - data.count}</span>
                              ) : (
                                <span className="text-gray-500">-</span>
                              )
                            ) : (
                              <span className="text-gray-500">-</span>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}