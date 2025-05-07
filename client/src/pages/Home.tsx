import { useState, useRef } from "react";
import ScanForm from "@/components/ScanForm";
import ScanResults from "@/components/ScanResults";
import Disclaimer from "@/components/Disclaimer";
import Features from "@/pages/Features";
import Education from "@/pages/Education";

export default function Home() {
  const [scanUrl, setScanUrl] = useState<string>("");
  const scanResultsRef = useRef<HTMLDivElement>(null);

  const handleScanComplete = (url: string) => {
    setScanUrl(url);
    // Scroll to scan results
    if (scanResultsRef.current) {
      scanResultsRef.current.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <section className="bg-white py-12 md:py-20 border-b">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center">
            <div className="md:w-1/2 mb-8 md:mb-0 pr-0 md:pr-8">
              <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold font-sans text-neutral-400 mb-4">
                Scan. Detect. Secure.
              </h1>
              <p className="text-lg text-neutral-300 mb-6">
                Discover vulnerabilities in any website with our advanced security scanner. 
                Identify weaknesses before malicious hackers do.
              </p>
              <div className="bg-neutral-100 p-6 rounded-lg shadow-sm">
                <ScanForm onScanComplete={handleScanComplete} />
                <p className="text-sm text-neutral-300 italic mt-3">
                  Safe, ethical scanning with no verification required. For educational purposes only.
                </p>
              </div>
            </div>
            <div className="md:w-1/2">
              <img
                src="https://images.unsplash.com/photo-1563986768609-322da13575f3?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&h=980"
                alt="Cybersecurity protection concept"
                className="rounded-lg shadow-lg w-full"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Scan Results Section */}
      <div ref={scanResultsRef}>
        {scanUrl && <ScanResults url={scanUrl} />}
      </div>

      {/* Features Section */}
      <Features />

      {/* Education Section */}
      <Education />

      {/* Disclaimer Section */}
      <Disclaimer />
    </div>
  );
}
