import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { FileText, Mail, Download, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";

// Form validation schema
const emailFormSchema = z.object({
  email: z.string().email({
    message: "Please enter a valid email address.",
  }),
});

type EmailFormValues = z.infer<typeof emailFormSchema>;

interface ReportGeneratorProps {
  scanUrl: string;
}

export default function ReportGenerator({ scanUrl }: ReportGeneratorProps) {
  const { toast } = useToast();
  const [isGenerating, setIsGenerating] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [isEmailDialogOpen, setIsEmailDialogOpen] = useState(false);

  // Initialize form
  const form = useForm<EmailFormValues>({
    resolver: zodResolver(emailFormSchema),
    defaultValues: {
      email: "",
    },
    mode: "onBlur",
  });

  const generateReport = async () => {
    try {
      setIsGenerating(true);
      
      const response = await apiRequest("GET", "/api/generate-report");
      const data = await response.json();
      
      if (data.success) {
        setReportUrl(data.reportUrl);
        toast({
          title: "Report Generated",
          description: "Your security report has been successfully generated.",
        });
      } else {
        throw new Error(data.message || "Failed to generate report");
      }
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to generate report. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const sendReportByEmail = async (data: EmailFormValues) => {
    if (!reportUrl) {
      toast({
        title: "Error",
        description: "Please generate a report first.",
        variant: "destructive",
      });
      return;
    }

    try {
      setIsSending(true);
      
      const response = await apiRequest(
        "POST",
        "/api/email-report",
        {
          email: data.email,
          reportUrl,
          scanUrl,
        }
      );
      
      const responseData = await response.json();
      
      if (responseData.success) {
        toast({
          title: "Report Sent",
          description: `The report has been emailed to ${data.email}`,
        });
        setIsEmailDialogOpen(false);
        form.reset();
      } else {
        throw new Error(responseData.message || "Failed to send report");
      }
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to send report. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
      <div className="flex flex-col space-y-4">
        <h3 className="text-xl font-semibold flex items-center">
          <FileText className="mr-2 h-5 w-5 text-blue-600" />
          AI-Enhanced Security Report
        </h3>
        
        <p className="text-gray-600 dark:text-gray-400 text-sm">
          Generate a comprehensive PDF report with detailed analysis of all vulnerabilities, 
          including AI-powered insights, severity graphs, and remediation recommendations.
        </p>
        
        <div className="flex flex-col sm:flex-row gap-3 mt-2">
          <Button
            onClick={generateReport}
            disabled={isGenerating}
            className="bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-700 hover:to-violet-700"
          >
            {isGenerating ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileText className="mr-2 h-4 w-4" />
                Generate PDF Report
              </>
            )}
          </Button>
          
          {reportUrl && (
            <>
              <Button 
                variant="outline" 
                className="border-blue-500 text-blue-600 hover:bg-blue-50 dark:border-blue-400 dark:text-blue-400 dark:hover:bg-gray-700"
                asChild
              >
                <a href={reportUrl} target="_blank" rel="noopener noreferrer">
                  <Download className="mr-2 h-4 w-4" />
                  Download PDF
                </a>
              </Button>
              
              <Dialog open={isEmailDialogOpen} onOpenChange={setIsEmailDialogOpen}>
                <DialogTrigger asChild>
                  <Button 
                    variant="outline"
                    className="border-blue-500 text-blue-600 hover:bg-blue-50 dark:border-blue-400 dark:text-blue-400 dark:hover:bg-gray-700"
                  >
                    <Mail className="mr-2 h-4 w-4" />
                    Email Report
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[425px]">
                  <DialogHeader>
                    <DialogTitle>Email Security Report</DialogTitle>
                    <DialogDescription>
                      Enter the email address where you'd like to receive the security report.
                    </DialogDescription>
                  </DialogHeader>
                  
                  <Form {...form}>
                    <form onSubmit={form.handleSubmit(sendReportByEmail)} className="space-y-4 py-4">
                      <FormField
                        control={form.control}
                        name="email"
                        render={({ field }) => (
                          <FormItem>
                            <Label htmlFor="email" className="text-right">
                              Email
                            </Label>
                            <FormControl>
                              <Input id="email" placeholder="your.email@example.com" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <DialogFooter>
                        <Button 
                          type="submit" 
                          disabled={isSending}
                          className="bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-700 hover:to-violet-700"
                        >
                          {isSending ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Sending...
                            </>
                          ) : "Send Report"}
                        </Button>
                      </DialogFooter>
                    </form>
                  </Form>
                </DialogContent>
              </Dialog>
            </>
          )}
        </div>
      </div>
    </div>
  );
}