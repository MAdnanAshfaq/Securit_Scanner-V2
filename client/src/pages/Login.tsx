
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/contexts/AuthContext";
import { Shield } from "lucide-react";
import { useLocation } from "wouter";

export default function LoginPage() {
  const { login } = useAuth();
  const [, setLocation] = useLocation();

  const handleLogin = () => {
    login();
    setLocation('/');
  };

  return (
    <div className="container flex items-center justify-center min-h-[80vh]">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-bold">Welcome to SecureScope</CardTitle>
          <CardDescription>Please login to access security services</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex justify-center">
            <Shield className="w-16 h-16 text-primary" />
          </div>
          <Button 
            className="w-full" 
            size="lg"
            onClick={handleLogin}
          >
            Login to Continue
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
