import { useState } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Loader2, Lock, Mail, Shield, AlertTriangle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";

const emailCredentialsSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  password: z.string().min(1, "Password is required"),
  provider: z.string().min(1, "Provider is required"),
  server: z.string().optional(),
  port: z.string().optional(),
  useTLS: z.boolean().default(true),
  autoScan: z.boolean().default(false),
  scanFrequency: z.string().default("daily")
});

type EmailCredentialsValues = z.infer<typeof emailCredentialsSchema>;

interface EmailCredentialsFormProps {
  onCredentialsSaved?: (credentialId: string) => void;
}

export default function EmailCredentialsForm({ onCredentialsSaved }: EmailCredentialsFormProps) {
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);
  const { toast } = useToast();

  const form = useForm<EmailCredentialsValues>({
    resolver: zodResolver(emailCredentialsSchema),
    defaultValues: {
      email: "",
      password: "",
      provider: "",
      server: "",
      port: "",
      useTLS: true,
      autoScan: false,
      scanFrequency: "daily"
    }
  });

  const providerSelected = form.watch("provider");
  const autoScanEnabled = form.watch("autoScan");

  const onSubmit = async (data: EmailCredentialsValues) => {
    setSubmitting(true);
    try {
      const response = await fetch("/api/email-credentials", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        throw new Error("Failed to store email credentials");
      }

      const result = await response.json();
      setSuccess(true);
      toast({
        title: "Success",
        description: "Email credentials stored securely for scanning",
      });
      
      // Call the callback if provided
      if (onCredentialsSaved && result.credentialId) {
        onCredentialsSaved(result.credentialId);
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Failed to Store Credentials",
        description: error instanceof Error ? error.message : "An unknown error occurred"
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="w-full max-w-xl mx-auto space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Connect Email Account</CardTitle>
          <CardDescription>
            Securely store your email credentials to enable automated phishing detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          {success ? (
            <div className="text-center py-4 space-y-4">
              <Shield className="w-12 h-12 text-green-500 mx-auto" />
              <h3 className="text-xl font-bold">Email Account Connected</h3>
              <p>
                Your email credentials have been securely stored. The system will now scan your inbox for 
                phishing attempts based on your settings.
              </p>
              <Button
                onClick={() => {
                  setSuccess(false);
                  form.reset();
                }}
                className="mt-4"
              >
                Connect Another Account
              </Button>
            </div>
          ) : (
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <FormField
                  control={form.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Email Address</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                          <Input className="pl-10" placeholder="you@example.com" {...field} />
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                          <Input className="pl-10" type="password" placeholder="••••••••" {...field} />
                        </div>
                      </FormControl>
                      <FormDescription>
                        Your password is encrypted and never stored in plaintext
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="provider"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Email Provider</FormLabel>
                      <Select 
                        onValueChange={field.onChange} 
                        defaultValue={field.value}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select email provider" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="gmail">Gmail</SelectItem>
                          <SelectItem value="outlook">Outlook / Office 365</SelectItem>
                          <SelectItem value="yahoo">Yahoo Mail</SelectItem>
                          <SelectItem value="other">Other Provider</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                {providerSelected === "other" && (
                  <div className="grid grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="server"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>IMAP Server</FormLabel>
                          <FormControl>
                            <Input placeholder="imap.example.com" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    
                    <FormField
                      control={form.control}
                      name="port"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Port</FormLabel>
                          <FormControl>
                            <Input placeholder="993" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                )}
                
                <FormField
                  control={form.control}
                  name="useTLS"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                      <div className="space-y-0.5">
                        <FormLabel className="text-base">Use TLS Encryption</FormLabel>
                        <FormDescription>
                          Securely connect to your email server with TLS
                        </FormDescription>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="autoScan"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                      <div className="space-y-0.5">
                        <FormLabel className="text-base">Enable Automated Scanning</FormLabel>
                        <FormDescription>
                          Automatically scan your inbox for phishing emails
                        </FormDescription>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />
                
                {autoScanEnabled && (
                  <FormField
                    control={form.control}
                    name="scanFrequency"
                    render={({ field }) => (
                      <FormItem className="space-y-3">
                        <FormLabel>Scan Frequency</FormLabel>
                        <FormControl>
                          <RadioGroup
                            onValueChange={field.onChange}
                            defaultValue={field.value}
                            className="flex flex-col space-y-1"
                          >
                            <div className="flex items-center space-x-2">
                              <RadioGroupItem value="hourly" id="hourly" />
                              <Label htmlFor="hourly">Hourly</Label>
                            </div>
                            <div className="flex items-center space-x-2">
                              <RadioGroupItem value="daily" id="daily" />
                              <Label htmlFor="daily">Daily</Label>
                            </div>
                            <div className="flex items-center space-x-2">
                              <RadioGroupItem value="weekly" id="weekly" />
                              <Label htmlFor="weekly">Weekly</Label>
                            </div>
                          </RadioGroup>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                )}
                
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Security Notice</AlertTitle>
                  <AlertDescription>
                    Your credentials are stored securely and only used for phishing detection.
                    For Gmail accounts, you may need to create an app password if you have 2FA enabled.
                  </AlertDescription>
                </Alert>
                
                <Button type="submit" className="w-full" disabled={submitting}>
                  {submitting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Connecting...
                    </>
                  ) : (
                    "Connect Email Account"
                  )}
                </Button>
              </form>
            </Form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}