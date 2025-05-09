import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Inbox, AlertTriangle, Mail, Calendar, Paperclip, RefreshCw, Shield, Eye } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ScrollArea } from '@/components/ui/scroll-area';
import { formatDistanceToNow } from 'date-fns';
import { useToast } from '@/hooks/use-toast';

interface Email {
  id: number;
  subject: string;
  from: string;
  to: string;
  date: string;
  textContent: string;
  htmlContent: string;
  attachments: Array<{
    filename: string;
    contentType: string;
    size: number;
  }>;
  flags?: string[];
}

interface EmailAnalysis {
  isPhishing: boolean;
  riskScore: number;
  summary: string;
  senderAnalysis: {
    suspicious: boolean;
    details: string;
    domainInfo: any;
  };
  contentAnalysis: {
    redFlags: Array<{
      type: string;
      description: string;
    }>;
    language: string;
  };
  urlAnalysis: {
    suspiciousUrls: Array<{
      url: string;
      reason: string;
    }>;
    secureUrls: number;
    insecureUrls: number;
  };
  recommendations: string[];
  aiAnalysis?: any;
}

interface EmailViewerProps {
  credentialId: string;
}

export default function EmailViewer({ credentialId }: EmailViewerProps) {
  const [emails, setEmails] = useState<Email[]>([]);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [emailAnalysis, setEmailAnalysis] = useState<EmailAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState({
    fetchingEmails: false,
    analyzingEmail: false
  });
  const [currentFolder, setCurrentFolder] = useState('INBOX');
  const { toast } = useToast();

  // Fetch emails when the component loads or folder changes
  useEffect(() => {
    fetchEmails();
  }, [credentialId, currentFolder]);

  const fetchEmails = async () => {
    if (!credentialId) return;

    setIsLoading(prev => ({ ...prev, fetchingEmails: true }));
    try {
      const response = await fetch(`/api/emails/${credentialId}?folder=${currentFolder}`);

      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Unknown error occurred');
      }

      setEmails(data.emails || []);

      toast({
        title: "Emails Retrieved",
        description: `Found ${data.emails.length} emails in ${currentFolder}`,
      });
    } catch (error) {
      console.error('Error fetching emails:', error);
      toast({
        title: "Error Retrieving Emails",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
    } finally {
      setIsLoading(prev => ({ ...prev, fetchingEmails: false }));
    }
  };

  const analyzeEmail = async (emailId: number, folder: string) => {
    if (!credentialId) {
      toast({
        title: "Error",
        description: "No email account connected. Please connect your email account first.",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(prev => ({ ...prev, analyzingEmail: true }));
    try {
      const response = await fetch(`/api/analyze-email/${credentialId}/${emailId}?folder=${folder}`);
      const contentType = response.headers.get("content-type");

      if (!response.ok) {
        const errorData = contentType?.includes("application/json") ? await response.json() : { message: "Failed to analyze email" };

        if (response.status === 404) {
          toast({
            title: "Analysis Failed",
            description: "Email not found. Please try selecting the email again.",
            variant: "destructive"
          });
          setIsLoading(prev => ({ ...prev, analyzingEmail: false }));
          return;
        }
        if (response.status === 500) {
          toast({
            title: "Analysis Failed",
            description: errorData.message || "Unable to analyze this email. Please try selecting the email again.",
            variant: "destructive"
          });
          setIsLoading(prev => ({ ...prev, analyzingEmail: false }));
          return;
        }
        if (response.status === 401) {
          toast({
            title: "Session Expired",
            description: "Your email session has expired. Please reconnect your account.",
            variant: "destructive"
          });
          localStorage.removeItem('emailCredentialId');
          localStorage.removeItem('connectedEmail');
          window.location.reload();
          return;
        }
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || data.message || 'Unknown error occurred');
      }

      if (!data.email || !data.analysis) {
        throw new Error('Invalid response format from server');
      }

      setSelectedEmail(data.email);
      setEmailAnalysis(data.analysis);

      toast({
        title: "Email Analysis Complete",
        description: data.analysis.isPhishing 
          ? "⚠️ This email appears to be a phishing attempt!" 
          : "✓ This email appears to be legitimate.",
        variant: data.analysis.isPhishing ? "destructive" : "default"
      });
    } catch (error) {
      console.error('Error analyzing email:', error);
      toast({
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
    } finally {
      setIsLoading(prev => ({ ...prev, analyzingEmail: false }));
    }
  };

  const analyzeAllEmails = async () => {
    if (!credentialId) {
      toast({
        title: "Error",
        description: "No email account connected. Please connect your email account first.",
        variant: "destructive"
      });
      return;
    }

    if (!emails || emails.length === 0) {
      toast({
        title: "Info",
        description: "No emails to analyze.",
        variant: "info"
      });
      return;
    }

    setIsLoading(prev => ({ ...prev, analyzingEmail: true }));
    try {
      // Iterate over each email and analyze it
      for (const email of emails) {
        try {
          // Await the analysis of each email to ensure they are processed sequentially
          await analyzeEmail(email.id, currentFolder);
        } catch (analysisError) {
          console.error(`Error analyzing email ${email.id}:`, analysisError);
          toast({
            title: "Analysis Failed",
            description: `Failed to analyze email ${email.subject}. See console for details.`,
            variant: "destructive"
          });
          // Continue to the next email even if one fails
        }
      }

      toast({
        title: "Batch Analysis Complete",
        description: "All emails have been analyzed.",
        variant: "success"
      });

    } finally {
      setIsLoading(prev => ({ ...prev, analyzingEmail: false }));
    }
  };

  const renderEmailContent = () => {
    if (!selectedEmail) return null;

    return (
      <div className="space-y-4">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-xl font-semibold">{selectedEmail.subject}</h2>
            <div className="text-sm text-gray-600 mt-1">
              <div><span className="font-semibold">From:</span> {selectedEmail.from}</div>
              <div><span className="font-semibold">To:</span> {selectedEmail.to}</div>
              <div><span className="font-semibold">Date:</span> {new Date(selectedEmail.date).toLocaleString()}</div>
            </div>
          </div>

          <div className="flex gap-2">
            <Button 
              variant="outline" 
              size="sm" 
              onClick={() => analyzeEmail(selectedEmail.id, currentFolder)}
              disabled={isLoading.analyzingEmail}
            >
              {isLoading.analyzingEmail ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 mr-2" />
                  Analyze Email
                </>
              )}
            </Button>
            <Button
              variant="default"
              size="sm"
              onClick={() => analyzeAllEmails()}
              disabled={isLoading.analyzingEmail || emails.length === 0}
            >
              <Shield className="h-4 w-4 mr-2" />
              Analyze All Emails
            </Button>
          </div>
        </div>

        <Separator />

        <Tabs defaultValue="formatted">
          <TabsList>
            <TabsTrigger value="formatted">Formatted View</TabsTrigger>
            <TabsTrigger value="text">Text View</TabsTrigger>
            <TabsTrigger value="html">HTML View</TabsTrigger>
          </TabsList>

          <TabsContent value="formatted" className="pt-4">
            {selectedEmail.htmlContent ? (
              <div 
                className="email-content-frame p-4 border rounded-md bg-white"
                style={{ maxHeight: '400px', overflow: 'auto' }}
                dangerouslySetInnerHTML={{ __html: selectedEmail.htmlContent }}
              />
            ) : (
              <div className="whitespace-pre-wrap p-4 border rounded-md bg-white">
                {selectedEmail.textContent}
              </div>
            )}
          </TabsContent>

          <TabsContent value="text" className="pt-4">
            <div 
              className="font-mono text-sm whitespace-pre-wrap p-4 border rounded-md bg-gray-50"
              style={{ maxHeight: '400px', overflow: 'auto' }}
            >
              {selectedEmail.textContent || 'No text content available'}
            </div>
          </TabsContent>

          <TabsContent value="html" className="pt-4">
            <div 
              className="font-mono text-sm whitespace-pre-wrap p-4 border rounded-md bg-gray-50"
              style={{ maxHeight: '400px', overflow: 'auto' }}
            >
              {selectedEmail.htmlContent || 'No HTML content available'}
            </div>
          </TabsContent>
        </Tabs>

        {selectedEmail.attachments.length > 0 && (
          <>
            <Separator />
            <div>
              <h3 className="text-sm font-semibold mb-2">Attachments ({selectedEmail.attachments.length}):</h3>
              <div className="flex flex-wrap gap-2">
                {selectedEmail.attachments.map((att, index) => (
                  <Badge key={index} variant="outline" className="flex items-center gap-1">
                    <Paperclip className="h-3 w-3" />
                    {att.filename} ({Math.round(att.size / 1024)}KB)
                  </Badge>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    );
  };

  const renderAnalysis = () => {
    if (!emailAnalysis) return null;

    const riskColor = emailAnalysis.riskScore >= 7 
      ? 'bg-red-100 border-red-400 text-red-800' 
      : emailAnalysis.riskScore >= 4 
        ? 'bg-yellow-100 border-yellow-400 text-yellow-800' 
        : 'bg-green-100 border-green-400 text-green-800';

    return (
      <div className="space-y-4 mt-6">
        <h3 className="text-lg font-semibold">Phishing Analysis Results</h3>

        <Alert className={riskColor}>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>
            {emailAnalysis.isPhishing 
              ? 'Phishing Warning: This is likely a phishing attempt!' 
              : 'Low Risk: This email appears to be legitimate.'}
          </AlertTitle>
          <AlertDescription>
            Risk Score: {emailAnalysis.riskScore}/10
          </AlertDescription>
        </Alert>

        <div className="bg-gray-50 p-4 rounded-md border">
          <h4 className="font-semibold mb-2">Summary</h4>
          <p className="text-sm text-gray-700">{emailAnalysis.summary}</p>
        </div>

        <Tabs defaultValue="redflags">
          <TabsList className="grid grid-cols-3">
            <TabsTrigger value="redflags">Red Flags</TabsTrigger>
            <TabsTrigger value="sender">Sender Analysis</TabsTrigger>
            <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
          </TabsList>

          <TabsContent value="redflags" className="pt-4">
            {emailAnalysis.contentAnalysis.redFlags.length > 0 ? (
              <div className="space-y-2">
                {emailAnalysis.contentAnalysis.redFlags.map((flag, index) => (
                  <div key={index} className="bg-red-50 p-3 rounded-md border border-red-200">
                    <div className="font-semibold text-red-800">{flag.type}</div>
                    <div className="text-sm text-red-700">{flag.description}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="bg-green-50 p-3 rounded-md border border-green-200">
                <div className="text-sm text-green-700">No suspicious content patterns were detected.</div>
              </div>
            )}

            {emailAnalysis.urlAnalysis.suspiciousUrls.length > 0 && (
              <div className="mt-4">
                <h4 className="font-semibold mb-2">Suspicious URLs:</h4>
                <div className="space-y-2">
                  {emailAnalysis.urlAnalysis.suspiciousUrls.map((url, index) => (
                    <div key={index} className="bg-yellow-50 p-2 rounded-md border border-yellow-200">
                      <div className="font-mono text-sm truncate">{url.url}</div>
                      <div className="text-xs text-yellow-700">{url.reason}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </TabsContent>

          <TabsContent value="sender" className="pt-4">
            <div className={emailAnalysis.senderAnalysis.suspicious ? 'bg-red-50 p-3 rounded-md border border-red-200' : 'bg-green-50 p-3 rounded-md border border-green-200'}>
              <div className="font-semibold">{emailAnalysis.senderAnalysis.suspicious ? 'Suspicious Sender' : 'Legitimate Sender'}</div>
              <div className="text-sm mt-1">{emailAnalysis.senderAnalysis.details}</div>

              {emailAnalysis.senderAnalysis.domainInfo && (
                <div className="mt-3 bg-white p-2 rounded-md">
                  <div className="text-xs font-semibold">Domain Information:</div>
                  <div className="text-xs">Domain: {emailAnalysis.senderAnalysis.domainInfo.domain}</div>
                  {emailAnalysis.senderAnalysis.domainInfo.age && (
                    <div className="text-xs">Age: {emailAnalysis.senderAnalysis.domainInfo.age}</div>
                  )}
                  {emailAnalysis.senderAnalysis.domainInfo.spf !== undefined && (
                    <div className="text-xs">SPF: {emailAnalysis.senderAnalysis.domainInfo.spf ? 'Yes' : 'No'}</div>
                  )}
                  {emailAnalysis.senderAnalysis.domainInfo.dmarc !== undefined && (
                    <div className="text-xs">DMARC: {emailAnalysis.senderAnalysis.domainInfo.dmarc ? 'Yes' : 'No'}</div>
                  )}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="recommendations" className="pt-4">
            <div className="space-y-2">
              {emailAnalysis.recommendations.map((rec, index) => (
                <div key={index} className="p-2 rounded-md border bg-blue-50">
                  <div className="text-sm">{rec}</div>
                </div>
              ))}
            </div>
          </TabsContent>
        </Tabs>

        {emailAnalysis.aiAnalysis && (
          <div className="mt-4 p-4 rounded-md border bg-purple-50">
            <h4 className="font-semibold mb-2">AI Enhanced Analysis</h4>
            <div className="text-sm">{emailAnalysis.aiAnalysis.summary}</div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {/* Email list sidebar */}
      <Card className="md:col-span-1">
        <CardHeader className="pb-3">
          <CardTitle className="flex justify-between items-center">
            <div className="flex items-center">
              <Inbox className="h-5 w-5 mr-2" />
              Email Inbox
            </div>
            <Button variant="ghost" size="sm" onClick={fetchEmails} disabled={isLoading.fetchingEmails}>
              {isLoading.fetchingEmails ? <RefreshCw className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {emails.length === 0 ? (
            <div className="text-center py-8 text-gray-400">
              {isLoading.fetchingEmails ? 'Loading emails...' : 'No emails found'}
            </div>
          ) : (
            <ScrollArea className="h-[500px]">
              <div className="space-y-1">
                {emails.map((email) => (
                  <div 
                    key={email.id}
                    className={`p-2 rounded-md cursor-pointer transition-colors ${
                      selectedEmail?.id === email.id
                        ? 'bg-blue-100 border-blue-300'
                        : 'hover:bg-gray-100 border-transparent'
                    } border`}
                    onClick={() => setSelectedEmail(email)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="font-semibold truncate" style={{ maxWidth: '180px' }}>
                        {email.subject || '(No Subject)'}
                      </div>
                      <div className="text-xs text-gray-500">
                        {formatDistanceToNow(new Date(email.date), { addSuffix: true })}
                      </div>
                    </div>
                    <div className="text-sm text-gray-600 truncate" style={{ maxWidth: '220px' }}>
                      {email.from}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      {/* Email content and analysis */}
      <Card className="md:col-span-2">
        <CardContent className="pt-6">
          {selectedEmail ? (
            <div>
              {renderEmailContent()}
              {renderAnalysis()}
            </div>
          ) : (
            <div className="text-center py-20 text-gray-400">
              <Mail className="h-12 w-12 mx-auto mb-4 opacity-20" />
              <p>Select an email to view its contents</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}