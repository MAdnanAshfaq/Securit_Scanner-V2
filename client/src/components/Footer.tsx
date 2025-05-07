import { Link } from "wouter";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { 
  Github, 
  Twitter, 
  Linkedin, 
  Mail,
  Shield,
  AlertTriangle,
  FileText,
  Users,
  Book,
  Heart,
  Hash,
  Search,
  MailQuestion
} from "lucide-react";

export default function Footer() {
  return (
    <footer className="w-full py-12 bg-gray-900 text-gray-200">
      <div className="container px-4 md:px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Company Info */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Company</h3>
            <div className="flex items-start">
              <Shield className="h-5 w-5 mr-2 text-blue-400" />
              <span className="text-xl font-bold bg-gradient-to-r from-blue-400 to-violet-400 text-transparent bg-clip-text">
                SecureScan
              </span>
            </div>
            <p className="text-sm text-gray-400">
              Providing cutting-edge security assessment tools for ethical hackers and security professionals since 2023.
            </p>
            <div className="flex space-x-4">
              <a 
                href="https://twitter.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-blue-400 transition-colors"
              >
                <Twitter className="h-5 w-5" />
                <span className="sr-only">Twitter</span>
              </a>
              <a 
                href="https://github.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-gray-200 transition-colors"
              >
                <Github className="h-5 w-5" />
                <span className="sr-only">GitHub</span>
              </a>
              <a 
                href="https://linkedin.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-blue-500 transition-colors"
              >
                <Linkedin className="h-5 w-5" />
                <span className="sr-only">LinkedIn</span>
              </a>
              <a 
                href="mailto:contact@securescan.com" 
                className="text-gray-400 hover:text-red-400 transition-colors"
              >
                <Mail className="h-5 w-5" />
                <span className="sr-only">Email</span>
              </a>
            </div>
          </div>
          
          {/* Quick Links */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Quick Links</h3>
            <ul className="space-y-2">
              <li>
                <Link href="/" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Shield className="h-4 w-4 mr-2" />
                  Home
                </Link>
              </li>
              <li>
                <Link href="/about" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Users className="h-4 w-4 mr-2" />
                  About Us
                </Link>
              </li>
              <li>
                <Link href="/features" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <AlertTriangle className="h-4 w-4 mr-2" />
                  Features
                </Link>
              </li>
              <li>
                <Link href="/education" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Book className="h-4 w-4 mr-2" />
                  Security Resources
                </Link>
              </li>
              <li>
                <Link href="/decoder" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Hash className="h-4 w-4 mr-2" />
                  Decoder Tool
                </Link>
              </li>
              <li>
                <Link href="/email-security" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <MailQuestion className="h-4 w-4 mr-2" />
                  Email Security
                </Link>
              </li>
              <li>
                <Link href="/contact" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Mail className="h-4 w-4 mr-2" />
                  Contact
                </Link>
              </li>
            </ul>
          </div>
          
          {/* Tools */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Security Tools</h3>
            <ul className="space-y-2">
              <li>
                <Link href="/#scanner" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Search className="h-4 w-4 mr-2" />
                  Website Scanner
                </Link>
              </li>
              <li>
                <Link href="/decoder" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Hash className="h-4 w-4 mr-2" />
                  Hash Decoder
                </Link>
              </li>
              <li>
                <Link href="/decoder?tab=universal" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Hash className="h-4 w-4 mr-2" />
                  Universal Decoder
                </Link>
              </li>
              <li>
                <Link href="/decoder?tab=qr" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <Hash className="h-4 w-4 mr-2" />
                  QR Code Decoder
                </Link>
              </li>
              <li>
                <Link href="/email-security" className="text-gray-400 hover:text-white transition-colors flex items-center">
                  <MailQuestion className="h-4 w-4 mr-2" />
                  Email Phishing Detector
                </Link>
              </li>
            </ul>
          </div>
          
          {/* Resources */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Resources</h3>
            <ul className="space-y-2">
              <li>
                <a 
                  href="https://owasp.org/www-project-top-ten/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors flex items-center"
                >
                  <AlertTriangle className="h-4 w-4 mr-2" />
                  OWASP Top 10
                </a>
              </li>
              <li>
                <a 
                  href="https://www.sans.org/security-resources/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors flex items-center"
                >
                  <FileText className="h-4 w-4 mr-2" />
                  SANS Resources
                </a>
              </li>
              <li>
                <a 
                  href="https://nvd.nist.gov/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors flex items-center"
                >
                  <Shield className="h-4 w-4 mr-2" />
                  NVD Database
                </a>
              </li>
            </ul>
          </div>
          
          {/* Newsletter Signup */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Stay Updated</h3>
            <p className="text-sm text-gray-400">
              Subscribe to our newsletter for the latest security news and updates.
            </p>
            <form className="space-y-2">
              <div className="flex gap-2">
                <Input 
                  type="email" 
                  placeholder="Your email" 
                  className="bg-gray-800 border-gray-700 focus:border-blue-500 text-white" 
                />
                <Button 
                  type="submit" 
                  className="bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-700 hover:to-violet-700"
                >
                  Subscribe
                </Button>
              </div>
              <p className="text-xs text-gray-500">
                We respect your privacy. Unsubscribe at any time.
              </p>
            </form>
          </div>
        </div>
        
        <Separator className="my-8 bg-gray-700" />
        
        <div className="flex flex-col md:flex-row items-center justify-between">
          <p className="text-sm text-gray-400">
            © 2023 SecureScan. All rights reserved.
          </p>
          <div className="flex gap-4 mt-4 md:mt-0">
            <Link href="/privacy" className="text-xs text-gray-400 hover:text-white transition-colors">
              Privacy Policy
            </Link>
            <Link href="/terms" className="text-xs text-gray-400 hover:text-white transition-colors">
              Terms of Service
            </Link>
            <Link href="/disclaimer" className="text-xs text-gray-400 hover:text-white transition-colors">
              Legal Disclaimer
            </Link>
          </div>
          <p className="text-xs text-gray-500 mt-4 md:mt-0 flex items-center">
            Made with <Heart className="h-3 w-3 mx-1 text-red-500" /> for security professionals
          </p>
        </div>
      </div>
    </footer>
  );
}