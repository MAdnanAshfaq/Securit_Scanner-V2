import { Shield, Send } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

export default function Footer() {
  const [email, setEmail] = useState("");
  const { toast } = useToast();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email) {
      // In a real implementation, this would send the email to a subscription service
      toast({
        title: "Thanks for subscribing!",
        description: "You'll receive our security newsletter soon.",
      });
      setEmail("");
    }
  };

  return (
    <footer className="bg-neutral-400 text-white py-8 border-t border-gray-700">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <div className="flex items-center mb-4">
              <Shield className="h-5 w-5 mr-2" />
              <h2 className="text-xl font-bold font-sans">SecureScope</h2>
            </div>
            <p className="text-neutral-200 text-sm">
              Empowering ethical hackers and security professionals with powerful scanning tools.
            </p>
          </div>
          
          <div>
            <h3 className="font-medium mb-4">Resources</h3>
            <ul className="space-y-2 text-neutral-200">
              <li><a href="#" className="hover:text-white transition-colors">Documentation</a></li>
              <li><a href="#" className="hover:text-white transition-colors">API Reference</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Blog</a></li>
            </ul>
          </div>
          
          <div>
            <h3 className="font-medium mb-4">Company</h3>
            <ul className="space-y-2 text-neutral-200">
              <li><a href="/about" className="hover:text-white transition-colors">About Us</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Privacy Policy</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Terms of Service</a></li>
            </ul>
          </div>
          
          <div>
            <h3 className="font-medium mb-4">Stay Updated</h3>
            <p className="text-neutral-200 text-sm mb-3">
              Subscribe to our newsletter for the latest security updates.
            </p>
            <form onSubmit={handleSubmit}>
              <div className="flex">
                <Input 
                  type="email" 
                  placeholder="Enter your email" 
                  className="bg-neutral-300 text-black rounded-l-lg focus:outline-none flex-grow" 
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
                <Button 
                  type="submit" 
                  className="bg-primary hover:bg-blue-600 px-4 py-2 rounded-r-lg transition-colors"
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </form>
          </div>
        </div>
        
        <div className="border-t border-gray-700 mt-8 pt-8 text-center text-neutral-200 text-sm">
          <p>&copy; {new Date().getFullYear()} SecureScope. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}
