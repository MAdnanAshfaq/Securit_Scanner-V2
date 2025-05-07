import { useState } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, AlertTriangle, Shield, CheckCircle, Info } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const phishingFormSchema = z.object({
  subject: z.string().optional(),
  content: z.string().min(10, "Email content must be at least 10 characters"),
  sender: z.string().email("Please enter a valid email").optional().or(z.literal("")),
  recipient: z.string().email("Please enter a valid email").optional().or(z.literal("")),
  suspiciousUrls: z.string().optional()
});

type PhishingFormValues = z.infer<typeof phishingFormSchema>;

export default function PhishingDetector() {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<any>(null);
  const { toast } = useToast();

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

  const onSubmit = async (data: PhishingFormValues) => {
    setAnalyzing(true);
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
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Failed to analyze email for phishing"
      });
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

      {result && (
        <Card className={`border-4 ${
          result.isPhishing 
            ? "border-red-500" 
            : result.riskScore >= 3 
              ? "border-amber-500" 
              : "border-green-500"
        }`}>
          <CardHeader>
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
              Risk Score: <span className="font-semibold">{result.riskScore}/10</span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
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

            {result.contentAnalysis && result.contentAnalysis.redFlags.length > 0 && (
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

            {result.urlAnalysis && result.urlAnalysis.urls.some((url: any) => url.malicious) && (
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
                {result.recommendations.map((recommendation: string, index: number) => (
                  <li key={index}>{recommendation}</li>
                ))}
              </ul>
            </div>

            {result.aiAnalysis && (
              <div>
                <h3 className="text-lg font-semibold mb-2">AI-Enhanced Analysis</h3>
                <p>Confidence: {Math.round(result.aiAnalysis.confidence * 100)}%</p>
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
          </CardContent>
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