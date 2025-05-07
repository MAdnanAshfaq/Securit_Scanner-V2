import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { ChevronRight, BookOpen, Shield, AlertCircle, Lock } from "lucide-react";

const securityResources = [
  {
    id: 1,
    title: "OWASP Top Ten",
    description: "The Open Web Application Security Project's list of the 10 most critical web application security risks.",
    link: "https://owasp.org/www-project-top-ten/",
    icon: <AlertCircle className="h-8 w-8 text-red-500" />,
    category: "Vulnerabilities",
  },
  {
    id: 2,
    title: "Web Application Security Testing Guide",
    description: "Comprehensive guide on how to test for web application security vulnerabilities.",
    link: "https://owasp.org/www-project-web-security-testing-guide/",
    icon: <BookOpen className="h-8 w-8 text-blue-500" />,
    category: "Testing",
  },
  {
    id: 3,
    title: "Common Vulnerability Scoring System",
    description: "Framework for communicating the characteristics and severity of software vulnerabilities.",
    link: "https://www.first.org/cvss/",
    icon: <Shield className="h-8 w-8 text-green-500" />,
    category: "Standards",
  },
  {
    id: 4,
    title: "Security Headers",
    description: "A guide to HTTP security headers and how to implement them to secure your website.",
    link: "https://securityheaders.com/",
    icon: <Lock className="h-8 w-8 text-purple-500" />,
    category: "Hardening",
  },
];

export default function Resources() {
  return (
    <section className="w-full py-12 bg-gray-50 dark:bg-gray-900">
      <div className="container px-4 md:px-6">
        <div className="flex flex-col items-center justify-center space-y-4 text-center">
          <div className="space-y-2">
            <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">
              Security Resources
            </h2>
            <p className="max-w-[700px] text-gray-500 md:text-xl/relaxed lg:text-base/relaxed xl:text-xl/relaxed dark:text-gray-400">
              Explore our comprehensive collection of cybersecurity resources to help you understand and mitigate security vulnerabilities.
            </p>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-8">
          {securityResources.map((resource) => (
            <Card key={resource.id} className="transition-all duration-200 hover:shadow-lg">
              <CardHeader>
                <div className="flex items-center gap-2 mb-2">
                  {resource.icon}
                  <span className="text-sm font-medium px-2.5 py-0.5 rounded bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                    {resource.category}
                  </span>
                </div>
                <CardTitle className="text-xl">{resource.title}</CardTitle>
                <CardDescription>{resource.description}</CardDescription>
              </CardHeader>
              <CardFooter>
                <a 
                  href={resource.link} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                  Read more
                  <ChevronRight className="ml-1 h-4 w-4" />
                </a>
              </CardFooter>
            </Card>
          ))}
        </div>
        
        <div className="flex justify-center mt-8">
          <Button asChild className="bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-700 hover:to-violet-700">
            <Link href="/education">
              View all security resources
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
}