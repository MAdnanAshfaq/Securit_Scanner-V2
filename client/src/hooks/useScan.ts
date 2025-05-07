import { useState, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Scan, Vulnerability } from "@shared/schema";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export function useScan() {
  const [progress, setProgress] = useState(0);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Start a new scan
  const scanMutation = useMutation({
    mutationFn: async (url: string) => {
      const response = await apiRequest("POST", "/api/scan", { url });
      return response.json();
    },
    onSuccess: (data) => {
      // Invalidate the scan query to refresh data
      queryClient.invalidateQueries({ queryKey: ["/api/scan"] });
      startProgressSimulation();
    },
    onError: (error) => {
      toast({
        title: "Scan failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Get latest scan results
  const scanQuery = useQuery({
    queryKey: ["/api/scan"],
    enabled: scanMutation.isSuccess || progress === 100,
  });

  // Get vulnerabilities for current scan
  const vulnerabilitiesQuery = useQuery({
    queryKey: ["/api/vulnerabilities"],
    enabled: scanMutation.isSuccess || progress === 100,
  });

  // Simulated progress for the scan
  const startProgressSimulation = () => {
    setProgress(0);
    const interval = setInterval(() => {
      setProgress((prev) => {
        const newProgress = prev + Math.random() * 5;
        if (newProgress >= 100) {
          clearInterval(interval);
          queryClient.invalidateQueries({ queryKey: ["/api/scan"] });
          queryClient.invalidateQueries({ queryKey: ["/api/vulnerabilities"] });
          return 100;
        }
        return newProgress;
      });
    }, 500);
  };

  const startScan = async (url: string) => {
    try {
      await scanMutation.mutateAsync(url);
      toast({
        title: "Scan started",
        description: `Scanning ${url}...`,
      });
    } catch (error) {
      // Error handling is in the mutation callbacks
    }
  };

  // Determine if scanning is in progress
  const isLoading = scanMutation.isPending || (progress < 100 && progress > 0);

  return {
    startScan,
    scan: scanQuery.data as Scan,
    vulnerabilities: (vulnerabilitiesQuery.data || []) as Vulnerability[],
    isLoading,
    progress,
  };
}
