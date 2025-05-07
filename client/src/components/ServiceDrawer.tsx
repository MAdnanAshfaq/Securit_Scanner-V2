
import { useState } from "react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Link } from "wouter";
import { 
  Menu, 
  Search, 
  Shield, 
  Code, 
  Lock, 
  Database, 
  ExternalLink, 
  FileText, 
  AlertCircle, 
  Mail,
  PenTool,
  Activity,
  Bug,
  Key
} from "lucide-react";

export interface Service {
  name: string;
  description: string;
  icon: React.ReactNode;
  href: string;
  isNew?: boolean;
}

const services: Service[] = [
  {
    name: "Website Scanner",
    description: "Comprehensive website security analysis",
    icon: <Search className="h-5 w-5" />,
    href: "/features"
  },
  {
    name: "Vulnerability Testing",
    description: "Advanced penetration testing suite",
    icon: <Shield className="h-5 w-5" />,
    href: "/vulnerability-test"
  },
  {
    name: "Real-time Monitoring",
    description: "Monitor security events in real-time",
    icon: <Activity className="h-5 w-5" />,
    href: "/monitoring",
    isNew: true
  },
  {
    name: "Email Security",
    description: "Advanced email threat detection",
    icon: <Mail className="h-5 w-5" />,
    href: "/email-security"
  },
  {
    name: "Decoder Tool",
    description: "Decode and analyze security data",
    icon: <Code className="h-5 w-5" />,
    href: "/decoder"
  },
  {
    name: "Database Security",
    description: "Comprehensive database protection",
    icon: <Database className="h-5 w-5" />,
    href: "/database-security"
  },
  {
    name: "SSL Certificate Checker",
    description: "Verify SSL/TLS configuration",
    icon: <Lock className="h-5 w-5" />,
    href: "/ssl-checker"
  },
  {
    name: "Security Reports",
    description: "AI-powered security analysis reports",
    icon: <FileText className="h-5 w-5" />,
    href: "/reports"
  },
  {
    name: "Bug Bounty Platform",
    description: "Manage and track security findings",
    icon: <Bug className="h-5 w-5" />,
    href: "/bug-bounty",
    isNew: true
  },
  {
    name: "API Security",
    description: "Test and secure API endpoints",
    icon: <Key className="h-5 w-5" />,
    href: "/api-security",
    isNew: true
  },
  {
    name: "Security Education",
    description: "Interactive security learning platform",
    icon: <PenTool className="h-5 w-5" />,
    href: "/education"
  }
];

export default function ServiceDrawer() {
  const [open, setOpen] = useState(false);

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="icon" className="fixed bottom-4 right-4 z-50 rounded-full shadow-lg h-14 w-14 bg-primary">
          <Menu className="h-6 w-6 text-primary-foreground" />
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-full sm:max-w-md overflow-y-auto">
        <SheetHeader className="pb-4">
          <SheetTitle>Security Services</SheetTitle>
          <SheetDescription>
            Access our comprehensive security testing toolkit
          </SheetDescription>
        </SheetHeader>
        <Separator className="my-4" />
        <div className="grid gap-4">
          {services.map((service, i) => (
            <Link
              key={i}
              href={service.href}
              onClick={() => setOpen(false)}
            >
              <div className="flex items-start gap-4 p-3 rounded-lg hover:bg-accent transition-colors cursor-pointer relative">
                <div className="p-2 rounded-md bg-primary/10 text-primary">
                  {service.icon}
                </div>
                <div className="flex-grow">
                  <div className="font-medium flex items-center gap-2">
                    {service.name}
                    {service.isNew && (
                      <span className="px-2 py-0.5 text-xs bg-primary/20 text-primary rounded-full">New</span>
                    )}
                  </div>
                  <div className="text-sm text-muted-foreground">{service.description}</div>
                </div>
                <ExternalLink className="h-4 w-4 ml-auto text-muted-foreground" />
              </div>
            </Link>
          ))}
        </div>
      </SheetContent>
    </Sheet>
  );
}
