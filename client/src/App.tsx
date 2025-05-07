import { Switch, Route, Link } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import Home from "@/pages/Home";
import Features from "@/pages/Features";
import Education from "@/pages/Education";
import About from "@/pages/About";
import Contact from "@/pages/Contact";
import Decoder from "@/pages/Decoder";
import EmailSecurity from "@/pages/EmailSecurity";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import ServiceDrawer from "@/components/ServiceDrawer";
import Router from "@/Router";
import { AuthProvider } from "@/contexts/AuthContext";

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider>
          <Toaster />
          <Router />
          <ServiceDrawer />
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;