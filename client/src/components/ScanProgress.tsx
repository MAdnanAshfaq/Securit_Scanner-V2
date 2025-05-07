import { Card, CardContent } from "@/components/ui/card";
import { RefreshCcwDot } from "lucide-react";

interface ScanProgressProps {
  progress: number;
  url: string;
}

export default function ScanProgress({ progress, url }: ScanProgressProps) {
  const formattedUrl = url.replace(/^https?:\/\//, "");
  const logMessages = [
    `> Initializing scan on target: ${formattedUrl}`,
    "> Checking for open ports...",
    "> Analyzing HTTP headers...",
    "> Crawling site structure...",
    "> Testing for common vulnerabilities...",
  ];

  const visibleLogs = Math.ceil((progress / 100) * logMessages.length);

  return (
    <Card className="bg-white rounded-lg shadow-md p-6 mb-8">
      <div className="flex items-center mb-4">
        <div className="w-8 h-8 mr-3 rounded-full bg-primary opacity-75 flex items-center justify-center">
          <RefreshCcwDot className="h-5 w-5 text-white animate-spin" />
        </div>
        <h3 className="font-medium text-lg">Scanning in progress...</h3>
      </div>
      <div className="mb-4">
        <div className="h-2 w-full bg-neutral-200 rounded-full overflow-hidden">
          <div 
            className="scan-progress-indicator h-full bg-gradient-to-r from-primary to-secondary"
            style={{ width: `${progress}%` }}
          ></div>
        </div>
        <div className="flex justify-between text-sm text-neutral-300 mt-1">
          <span>Starting scan</span>
          <span>{progress}%</span>
        </div>
      </div>
      <div className="bg-neutral-100 p-4 rounded-lg font-mono text-sm">
        {logMessages.slice(0, visibleLogs).map((message, index) => (
          <p key={index} className="text-neutral-300">{message}</p>
        ))}
      </div>
    </Card>
  );
}
