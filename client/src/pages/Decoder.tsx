import { useLocation } from "wouter";
import DecodingTool from "@/components/DecodingTool";

export default function Decoder() {
  const [location] = useLocation();
  
  // Extract tab parameter from URL if present
  const tabParam = new URLSearchParams(location.split('?')[1]).get('tab');
  const initialTab = tabParam === 'universal' ? 'universal' : 
                    tabParam === 'qr' ? 'qr' : 'hash';
  
  return (
    <div className="container mx-auto py-12">
      <DecodingTool initialTab={initialTab} />
    </div>
  );
}