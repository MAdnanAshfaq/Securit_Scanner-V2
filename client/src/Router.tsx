
import { Switch, Route } from "wouter";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import ServiceDrawer from "@/components/ServiceDrawer";
import NotFound from "@/pages/not-found";
import Home from "@/pages/Home";
import Features from "@/pages/Features";
import Education from "@/pages/Education";
import About from "@/pages/About";
import Contact from "@/pages/Contact";
import Decoder from "@/pages/Decoder";
import EmailSecurity from "@/pages/EmailSecurity";
import Login from "@/pages/Login";
import { useAuth } from "@/contexts/AuthContext";
import { useEffect } from "react";
import { useLocation } from "wouter";
import ProtectedRoute from "@/components/ProtectedRoute";

export default function Router() {
  const { isAuthenticated } = useAuth();
  const [location, setLocation] = useLocation();

  useEffect(() => {
    if (!isAuthenticated && location !== '/login') {
      setLocation('/login');
    }
  }, [isAuthenticated, location, setLocation]);

  return (
    <div className="flex flex-col min-h-screen">
      <Header />
      <main className="flex-grow">
        <Switch>
          <Route path="/login" component={Login} />
          <Route path="/">
            <ProtectedRoute>
              <Home />
            </ProtectedRoute>
          </Route>
          <Route path="/features">
            <ProtectedRoute>
              <Features />
            </ProtectedRoute>
          </Route>
          <Route path="/education">
            <ProtectedRoute>
              <Education />
            </ProtectedRoute>
          </Route>
          <Route path="/about">
            <ProtectedRoute>
              <About />
            </ProtectedRoute>
          </Route>
          <Route path="/contact">
            <ProtectedRoute>
              <Contact />
            </ProtectedRoute>
          </Route>
          <Route path="/decoder">
            <ProtectedRoute>
              <Decoder />
            </ProtectedRoute>
          </Route>
          <Route path="/email-security">
            <ProtectedRoute>
              <EmailSecurity />
            </ProtectedRoute>
          </Route>
          <Route component={NotFound} />
        </Switch>
      </main>
      <Footer />
    </div>
  );
}
