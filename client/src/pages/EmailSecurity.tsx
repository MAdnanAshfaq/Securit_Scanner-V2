import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Mail, CheckCircle, InboxIcon } from "lucide-react";
import PhishingDetector from "@/components/PhishingDetector";
import EmailCredentialsForm from "@/components/EmailCredentialsForm";
import EmailViewer from "@/components/EmailViewer";

export default function EmailSecurity() {
  const [activeTab, setActiveTab] = useState("analyze");
  const [credentialId, setCredentialId] = useState<string | null>(null);
  const { toast } = useToast();

  return (
    <div className="container py-8 space-y-8">
      <div className="text-center space-y-2 max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold tracking-tight">Email Security Center</h1>
        <p className="text-lg text-muted-foreground">
          Advanced tools to detect and protect against email-based phishing attacks
        </p>
      </div>

      <Tabs 
        defaultValue="analyze" 
        value={activeTab}
        onValueChange={setActiveTab}
        className="w-full max-w-5xl mx-auto"
      >
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="analyze">Analyze Email Content</TabsTrigger>
          <TabsTrigger value="connect">Connect Email Account</TabsTrigger>
          <TabsTrigger value="gmail" disabled={!credentialId}>
            Gmail Inbox {credentialId ? <CheckCircle className="ml-1 h-3 w-3" /> : null}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="analyze" className="mt-6">
          <PhishingDetector />
        </TabsContent>
        <TabsContent value="connect" className="mt-6">
          <div className="text-center mb-4">
            <Mail className="h-12 w-12 mx-auto mb-2 text-primary/60" />
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
        <TabsContent value="gmail" className="mt-6">
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

      <div className="max-w-3xl mx-auto mt-12 space-y-4 text-center">
        <h2 className="text-2xl font-bold">How It Works</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-left mt-6">
          <div className="bg-card rounded-lg p-6 shadow-sm border">
            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4">
              <span className="text-xl font-bold text-primary">1</span>
            </div>
            <h3 className="text-lg font-semibold mb-2">Static Analysis</h3>
            <p className="text-muted-foreground">
              Paste email content and get an instant analysis of potential phishing indicators
              like spoofed domains, suspicious URLs, and social engineering tactics.
            </p>
          </div>
          
          <div className="bg-card rounded-lg p-6 shadow-sm border">
            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4">
              <span className="text-xl font-bold text-primary">2</span>
            </div>
            <h3 className="text-lg font-semibold mb-2">AI-Enhanced Detection</h3>
            <p className="text-muted-foreground">
              Our system uses advanced AI to identify sophisticated phishing attempts
              that traditional scanners might miss, providing detailed insights.
            </p>
          </div>
          
          <div className="bg-card rounded-lg p-6 shadow-sm border">
            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4">
              <span className="text-xl font-bold text-primary">3</span>
            </div>
            <h3 className="text-lg font-semibold mb-2">Automated Protection</h3>
            <p className="text-muted-foreground">
              Connect your email account for continuous monitoring and get alerts when
              suspicious emails are detected, before you even open them.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}