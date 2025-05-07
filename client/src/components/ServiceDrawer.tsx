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
  PenTool 
} from "lucide-react";

export interface Service {
  name: string;
  description: string;
  icon: React.ReactNode;
  href: string;
}

const services: Service[] = [
  {
    name: "Website Scanner",
    description: "Scan any website for security vulnerabilities",
    icon: <Search className="h-5 w-5" />,
    href: "/features"
  },
  {
    name: "Vulnerability Testing",
    description: "Perform penetration testing to find security issues",
    icon: <Shield className="h-5 w-5" />,
    href: "/features"
  },
  {
    name: "Email Security",
    description: "Analyze emails for phishing and security threats",
    icon: <Mail className="h-5 w-5" />,
    href: "/email-security"
  },
  {
    name: "Decoder Tool",
    description: "Analyze and decode hashes, tokens, and encoded data",
    icon: <Code className="h-5 w-5" />,
    href: "/decoder"
  },
  {
    name: "Database Security",
    description: "Test databases for injection vulnerabilities",
    icon: <Database className="h-5 w-5" />,
    href: "/features"
  },
  {
    name: "SSL Certificate Checker",
    description: "Verify SSL certificate validity and configuration",
    icon: <Lock className="h-5 w-5" />,
    href: "/features"
  },
  {
    name: "Security Reports",
    description: "Generate comprehensive security reports",
    icon: <FileText className="h-5 w-5" />,
    href: "/features"
  },
  {
    name: "Security Education",
    description: "Learn about security best practices",
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
          <SheetTitle>Our Services</SheetTitle>
          <SheetDescription>
            Discover our comprehensive suite of security testing tools
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
              <div className="flex items-start gap-4 p-3 rounded-lg hover:bg-accent transition-colors cursor-pointer">
                <div className="p-2 rounded-md bg-primary/10 text-primary">
                  {service.icon}
                </div>
                <div className="flex-grow">
                  <div className="font-medium">{service.name}</div>
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