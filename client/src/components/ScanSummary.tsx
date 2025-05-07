import { Card, CardContent } from "@/components/ui/card";
import { BarChart4 } from "lucide-react";
import { Scan } from "@shared/schema";

interface ScanSummaryProps {
  scan: Scan;
}

export default function ScanSummary({ scan }: ScanSummaryProps) {
  // Format scan duration
  const formatDuration = () => {
    if (!scan.startTime || !scan.endTime) return "N/A";
    
    const start = new Date(scan.startTime);
    const end = new Date(scan.endTime);
    const durationMs = end.getTime() - start.getTime();
    
    const hours = Math.floor(durationMs / (1000 * 60 * 60));
    const minutes = Math.floor((durationMs % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((durationMs % (1000 * 60)) / 1000);
    
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  };

  return (
    <Card className="bg-white rounded-lg shadow-md p-6 mb-8">
      <div className="flex items-center mb-4">
        <BarChart4 className="text-primary h-6 w-6 mr-2" />
        <h3 className="font-medium text-xl">Scan Summary</h3>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-neutral-100 p-4 rounded-lg text-center">
          <div className="text-risk-high text-2xl font-bold">{scan.highRiskCount}</div>
          <div className="text-sm font-medium">High Risk Issues</div>
        </div>
        <div className="bg-neutral-100 p-4 rounded-lg text-center">
          <div className="text-risk-medium text-2xl font-bold">{scan.mediumRiskCount}</div>
          <div className="text-sm font-medium">Medium Risk Issues</div>
        </div>
        <div className="bg-neutral-100 p-4 rounded-lg text-center">
          <div className="text-risk-low text-2xl font-bold">{scan.lowRiskCount}</div>
          <div className="text-sm font-medium">Low Risk Issues</div>
        </div>
        <div className="bg-neutral-100 p-4 rounded-lg text-center">
          <div className="text-risk-info text-2xl font-bold">{scan.infoCount}</div>
          <div className="text-sm font-medium">Informational</div>
        </div>
      </div>
      
      {/* URL info card */}
      <div className="bg-neutral-100 p-4 rounded-lg mb-4">
        <div className="flex flex-wrap">
          <div className="w-full md:w-1/2 mb-2 md:mb-0">
            <span className="font-medium">Target URL:</span>
            <span className="ml-2 font-mono text-sm">{scan.url}</span>
          </div>
          <div className="w-full md:w-1/2">
            <span className="font-medium">Scan Duration:</span>
            <span className="ml-2 font-mono text-sm">{formatDuration()}</span>
          </div>
        </div>
      </div>
      
      {/* Server info */}
      <div className="bg-neutral-100 p-4 rounded-lg">
        <h4 className="font-medium mb-2">Server Information</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm font-mono">
          <div>
            <span className="text-neutral-300">Server:</span>{" "}
            <span>{scan.serverInfo?.server || "Unknown"}</span>
          </div>
          <div>
            <span className="text-neutral-300">IP:</span>{" "}
            <span>{scan.serverInfo?.ip || "Unknown"}</span>
          </div>
          <div>
            <span className="text-neutral-300">Location:</span>{" "}
            <span>{scan.serverInfo?.location || "Unknown"}</span>
          </div>
          <div>
            <span className="text-neutral-300">Technologies:</span>{" "}
            <span>
              {scan.serverInfo?.technologies
                ? scan.serverInfo.technologies.join(", ")
                : "Unknown"}
            </span>
          </div>
        </div>
      </div>
    </Card>
  );
}
