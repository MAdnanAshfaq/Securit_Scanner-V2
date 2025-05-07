import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Menu } from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { LogOut } from "lucide-react";

const navLinks = [
  { label: "Home", href: "/" },
  { label: "Features", href: "/#features" },
  { label: "Education", href: "/#education" },
  { label: "Decoder", href: "/decoder", protected: true },
  { label: "Email Security", href: "/email-security", protected: true },
  { label: "About", href: "/about" },
];

export default function Header() {
  const [, setLocation] = useLocation();
  const [isOpen, setIsOpen] = useState(false);

  const handleNavigation = (href: string) => {
    setIsOpen(false);
    if (href.startsWith("/#")) {
      // Handle smooth scrolling for same-page anchors
      const elementId = href.substring(2);
      const element = document.getElementById(elementId);
      if (element) {
        element.scrollIntoView({ behavior: "smooth" });
      } else {
        // If element not found on current page, navigate to homepage first
        setLocation("/");
        setTimeout(() => {
          document.getElementById(elementId)?.scrollIntoView({ behavior: "smooth" });
        }, 100);
      }
    } else {
      setLocation(href);
    }
  };

  return (
    <header className="header-gradient text-white shadow-md">
      <div className="container mx-auto px-4 py-3">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center mb-4 md:mb-0">
            <Shield className="h-6 w-6 mr-2" />
            <h1 className="text-2xl font-bold font-sans">SecureScope</h1>
          </div>
          
          {/* Desktop Navigation */}
          <nav className="hidden md:block">
            <ul className="flex space-x-6">
              {navLinks.map((link, index) => (
                <li key={index}>
                  <button 
                    onClick={() => handleNavigation(link.href)}
                    className="hover:text-neutral-200 transition-colors font-medium"
                  >
                    {link.label}
                  </button>
                </li>
              ))}
            </ul>
            <div className="flex items-center ml-6">
              {isAuthenticated ? (
                <Button variant="ghost" onClick={logout} size="sm">
                  <LogOut className="h-4 w-4 mr-2" />
                  Logout
                </Button>
              ) : (
                <Button variant="default" onClick={() => handleNavigation('/login')} size="sm">
                  Login
                </Button>
              )}
            </div>
          </nav>
          
          {/* Mobile Navigation */}
          <Sheet open={isOpen} onOpenChange={setIsOpen}>
            <SheetTrigger asChild className="md:hidden">
              <Button variant="ghost" size="icon" className="text-white">
                <Menu className="h-6 w-6" />
              </Button>
            </SheetTrigger>
            <SheetContent>
              <div className="flex flex-col space-y-4 mt-8">
                {navLinks.map((link, index) => (
                  <button
                    key={index}
                    onClick={() => handleNavigation(link.href)}
                    className="text-foreground hover:text-primary transition-colors py-2 text-left font-medium"
                  >
                    {link.label}
                  </button>
                ))}
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  );
}
