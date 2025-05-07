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

function Router() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header />
      <main className="flex-grow">
        <Switch>
          <Route path="/" component={Home} />
          <Route path="/features" component={Features} />
          <Route path="/education" component={Education} />
          <Route path="/about" component={About} />
          <Route path="/contact" component={Contact} />
          <Route path="/decoder" component={Decoder} />
          <Route path="/email-security" component={EmailSecurity} />
          <Route component={NotFound} />
        </Switch>
      </main>
      <Footer />
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
        <ServiceDrawer />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
