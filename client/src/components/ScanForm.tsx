import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Shield } from "lucide-react";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { urlSchema } from "@shared/schema";
import { useScan } from "@/hooks/useScan";

interface ScanFormProps {
  onScanComplete: (url: string) => void;
}

export default function ScanForm({ onScanComplete }: ScanFormProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { startScan } = useScan();

  const form = useForm<z.infer<typeof urlSchema>>({
    resolver: zodResolver(urlSchema),
    defaultValues: {
      url: "",
    },
  });

  const handleScan = async (values: z.infer<typeof urlSchema>) => {
    setIsSubmitting(true);
    try {
      await startScan(values.url);
      onScanComplete(values.url);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleScan)} className="mb-4">
        <div className="space-y-3">
          <label htmlFor="url" className="block text-sm font-medium text-neutral-400 mb-2">
            Enter website URL to scan
          </label>
          <div className="flex flex-col sm:flex-row">
            <FormField
              control={form.control}
              name="url"
              render={({ field }) => (
                <FormItem className="flex-grow">
                  <FormControl>
                    <Input
                      {...field}
                      id="url"
                      type="url"
                      placeholder="https://example.com"
                      className="px-4 py-3 rounded-lg border border-neutral-200 focus:outline-none focus:ring-2 focus:ring-primary mb-3 sm:mb-0 sm:mr-3"
                      disabled={isSubmitting}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button
              type="submit"
              className="scan-button bg-primary hover:bg-blue-600 text-white px-8 py-3 rounded-lg font-medium shadow-md flex items-center justify-center"
              disabled={isSubmitting}
            >
              <Shield className="mr-2 h-5 w-5" />
              {isSubmitting ? "Scanning..." : "Scan Website"}
            </Button>
          </div>
        </div>
      </form>
    </Form>
  );
}
