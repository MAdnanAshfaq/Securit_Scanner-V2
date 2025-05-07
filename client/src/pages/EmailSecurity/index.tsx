import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Mail, CheckCircle, InboxIcon } from "lucide-react";
import EmailCredentialsForm from "../../components/EmailCredentialsForm";
import EmailViewer from "../../components/EmailViewer";
import PhishingDetector from "../../components/PhishingDetector";

export default function EmailSecurityPage() {
  const [activeTab, setActiveTab] = useState("manual");
  const [credentialId, setCredentialId] = useState<string | null>(null);
  const { toast } = useToast();

  return (
    <div className="container py-10 space-y-8">
      <div className="flex flex-col">
        <h1 className="text-3xl font-bold">Email Security Center</h1>
        <p className="text-muted-foreground">
          Protect yourself from phishing attacks by analyzing suspicious emails
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Email Phishing Detector</CardTitle>
          <CardDescription>
            Analyze emails to check if they're potential phishing attempts
          </CardDescription>
        </CardHeader>
        
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid grid-cols-3">
              <TabsTrigger value="manual">Manual Analysis</TabsTrigger>
              <TabsTrigger value="gmail" disabled={!credentialId}>
                Gmail Integration {credentialId ? <CheckCircle className="ml-1 h-3 w-3" /> : null}
              </TabsTrigger>
              <TabsTrigger value="connect">Connect Email</TabsTrigger>
            </TabsList>
            
            <TabsContent value="manual" className="space-y-4">
              <PhishingDetector />
            </TabsContent>
            
            <TabsContent value="connect" className="space-y-4">
              <div className="text-center mb-4">
                <Mail className="h-12 w-12 mx-auto mb-2 text-primary" />
                <h3 className="text-xl font-bold">Connect your Gmail account</h3>
                <p className="text-muted-foreground">
                  Securely connect your Gmail account to analyze your emails for phishing attempts
                </p>
              </div>
              
              <EmailCredentialsForm onCredentialsSaved={(id) => {
                setCredentialId(id);
                toast({
                  title: "Gmail Connected",
                  description: "Your Gmail account has been connected successfully",
                });
                setActiveTab("gmail");
              }} />
            </TabsContent>
            
            <TabsContent value="gmail" className="space-y-4">
              {credentialId ? (
                <EmailViewer credentialId={credentialId} />
              ) : (
                <div className="text-center py-10">
                  <InboxIcon className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <h3 className="text-lg font-medium mb-2">No Email Account Connected</h3>
                  <p className="text-muted-foreground mb-4">
                    Connect your Gmail account to view and analyze your emails
                  </p>
                  <Button onClick={() => setActiveTab("connect")}>
                    Connect Gmail Account
                  </Button>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
      
      <div className="bg-slate-50 p-6 rounded-lg border">
        <h2 className="text-xl font-semibold mb-4">Email Security Best Practices</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-2">
            <h3 className="font-medium">Identifying Phishing Attempts</h3>
            <ul className="list-disc pl-5 space-y-1 text-sm">
              <li>Check sender email addresses carefully</li>
              <li>Be wary of urgent or threatening language</li>
              <li>Hover over links before clicking them</li>
              <li>Watch for spelling and grammar errors</li>
              <li>Be suspicious of unexpected attachments</li>
            </ul>
          </div>
          <div className="space-y-2">
            <h3 className="font-medium">If You Suspect Phishing</h3>
            <ul className="list-disc pl-5 space-y-1 text-sm">
              <li>Don't click links or download attachments</li>
              <li>Don't reply to the email</li>
              <li>Report the email to your IT department</li>
              <li>Change any potentially compromised passwords</li>
              <li>Monitor your accounts for suspicious activity</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}