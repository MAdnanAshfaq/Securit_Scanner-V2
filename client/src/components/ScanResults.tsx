import { useState, useEffect } from "react";
import { useScan } from "@/hooks/useScan";
import ScanProgress from "@/components/ScanProgress";
import ScanSummary from "@/components/ScanSummary";
import VulnerabilityItem from "@/components/VulnerabilityItem";
import AttackSimulator from "@/components/AttackSimulator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { FileDown, Activity, Zap } from "lucide-react";
import { RiskLevel } from "@shared/schema";

interface ScanResultsProps {
  url: string;
}

export default function ScanResults({ url }: ScanResultsProps) {
  const { scan, vulnerabilities, isLoading, progress } = useScan();
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [sortOrder, setSortOrder] = useState<string>("high-to-low");
  
  // Filter the vulnerabilities based on selected severity
  const filteredVulnerabilities = vulnerabilities.filter((vuln) => {
    if (filterSeverity === "all") return true;
    return vuln.severity === filterSeverity;
  });

  // Sort the vulnerabilities based on selected order
  const sortedVulnerabilities = [...filteredVulnerabilities].sort((a, b) => {
    const severityOrder = { 
      [RiskLevel.HIGH]: 3, 
      [RiskLevel.MEDIUM]: 2, 
      [RiskLevel.LOW]: 1, 
      [RiskLevel.INFO]: 0 
    };
    
    if (sortOrder === "high-to-low") {
      return severityOrder[b.severity as RiskLevel] - severityOrder[a.severity as RiskLevel];
    } else if (sortOrder === "low-to-high") {
      return severityOrder[a.severity as RiskLevel] - severityOrder[b.severity as RiskLevel];
    } else if (sortOrder === "category") {
      return a.name.localeCompare(b.name);
    }
    return 0;
  });

  const handleExportReport = () => {
    // In a real implementation, this would generate and download a report
    const reportData = {
      url,
      scan,
      vulnerabilities,
      timestamp: new Date().toISOString(),
    };
    
    const reportBlob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: "application/json",
    });
    
    const url = URL.createObjectURL(reportBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `securescope-report-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <section className="bg-neutral-100 py-12" id="scan-results">
      <div className="container mx-auto px-4">
        <h2 className="text-2xl font-bold font-sans text-neutral-400 mb-6">Scan Results</h2>
        
        {/* Show progress during scanning */}
        {isLoading && <ScanProgress progress={progress} url={url} />}
        
        {/* Show results after scan completes */}
        {!isLoading && scan && (
          <>
            <ScanSummary scan={scan} />
            
            {/* Results Tabs */}
            <Card className="bg-white rounded-lg shadow-md overflow-hidden">
              <Tabs defaultValue="vulnerabilities">
                <div className="border-b">
                  <TabsList className="w-full justify-start h-auto bg-transparent">
                    <TabsTrigger 
                      value="vulnerabilities"
                      className="px-6 py-4 font-medium data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none"
                    >
                      Vulnerabilities
                    </TabsTrigger>
                    <TabsTrigger 
                      value="headers"
                      className="px-6 py-4 font-medium data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none"
                    >
                      Headers
                    </TabsTrigger>
                    <TabsTrigger 
                      value="certificate"
                      className="px-6 py-4 font-medium data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none"
                    >
                      Certificate
                    </TabsTrigger>
                    <TabsTrigger 
                      value="technologies"
                      className="px-6 py-4 font-medium data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none"
                    >
                      Technologies
                    </TabsTrigger>
                    <TabsTrigger 
                      value="attack-simulator"
                      className="px-6 py-4 font-medium data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none flex items-center"
                    >
                      <Zap className="h-4 w-4 mr-1" />
                      Attack Simulator
                    </TabsTrigger>
                  </TabsList>
                </div>
                
                {/* Filter controls */}
                <div className="p-4 border-b bg-neutral-100">
                  <div className="flex flex-wrap items-center">
                    <div className="mr-4 mb-2 sm:mb-0">
                      <label className="text-sm font-medium text-neutral-400 mr-2">Filter:</label>
                      <Select 
                        value={filterSeverity} 
                        onValueChange={setFilterSeverity}
                      >
                        <SelectTrigger className="w-[180px] bg-white border border-neutral-200 h-8 text-sm">
                          <SelectValue placeholder="All Issues" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Issues</SelectItem>
                          <SelectItem value={RiskLevel.HIGH}>High Risk</SelectItem>
                          <SelectItem value={RiskLevel.MEDIUM}>Medium Risk</SelectItem>
                          <SelectItem value={RiskLevel.LOW}>Low Risk</SelectItem>
                          <SelectItem value={RiskLevel.INFO}>Informational</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="mr-4 mb-2 sm:mb-0">
                      <label className="text-sm font-medium text-neutral-400 mr-2">Sort by:</label>
                      <Select 
                        value={sortOrder} 
                        onValueChange={setSortOrder}
                      >
                        <SelectTrigger className="w-[220px] bg-white border border-neutral-200 h-8 text-sm">
                          <SelectValue placeholder="Severity (High to Low)" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="high-to-low">Severity (High to Low)</SelectItem>
                          <SelectItem value="low-to-high">Severity (Low to High)</SelectItem>
                          <SelectItem value="category">Category</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex-grow"></div>
                    <Button
                      variant="default"
                      className="bg-primary text-white px-4 py-1 h-8 text-sm flex items-center"
                      onClick={handleExportReport}
                    >
                      <FileDown className="h-4 w-4 mr-1" />
                      Export Report
                    </Button>
                  </div>
                </div>
                
                <TabsContent value="vulnerabilities" className="p-4">
                  {sortedVulnerabilities.length > 0 ? (
                    sortedVulnerabilities.map((vuln) => (
                      <VulnerabilityItem key={vuln.id} vulnerability={vuln} />
                    ))
                  ) : (
                    <div className="text-center py-8">
                      <Activity className="h-12 w-12 mx-auto text-neutral-300 mb-2" />
                      <p className="text-neutral-300">No vulnerabilities detected with the current filter.</p>
                    </div>
                  )}
                </TabsContent>
                
                <TabsContent value="headers" className="p-4">
                  <CardContent>
                    <h3 className="font-medium mb-4">HTTP Headers</h3>
                    <div className="bg-neutral-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                      {scan.serverInfo ? (
                        Object.entries(scan.serverInfo).map(([key, value]) => (
                          <div key={key} className="mb-1">
                            <span className="text-neutral-300">{key}: </span>
                            <span>{typeof value === 'object' ? JSON.stringify(value) : value}</span>
                          </div>
                        ))
                      ) : (
                        <p className="text-neutral-300">No header information available</p>
                      )}
                    </div>
                  </CardContent>
                </TabsContent>
                
                <TabsContent value="certificate" className="p-4">
                  <CardContent>
                    <div className="text-center py-8">
                      <p className="text-neutral-300">Certificate information not available in this version.</p>
                    </div>
                  </CardContent>
                </TabsContent>
                
                <TabsContent value="technologies" className="p-4">
                  <CardContent>
                    <h3 className="font-medium mb-4">Detected Technologies</h3>
                    {scan.serverInfo && scan.serverInfo.technologies ? (
                      <div className="flex flex-wrap gap-2">
                        {scan.serverInfo.technologies.map((tech, index) => (
                          <div key={index} className="bg-neutral-100 px-3 py-1 rounded-full text-sm">
                            {tech}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-neutral-300">No technologies detected</p>
                    )}
                  </CardContent>
                </TabsContent>
                
                <TabsContent value="attack-simulator" className="p-4">
                  <AttackSimulator url={url} scan={scan} />
                </TabsContent>
              </Tabs>
            </Card>
          </>
        )}
      </div>
    </section>
  );
}
