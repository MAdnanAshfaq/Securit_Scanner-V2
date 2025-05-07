import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

export default function Education() {
  const educationItems = [
    {
      title: "Understanding Cross-Site Scripting (XSS)",
      description: "XSS attacks occur when malicious scripts are injected into trusted websites. Learn how these attacks work and how to prevent them.",
      url: "#xss"
    },
    {
      title: "SQL Injection Prevention Guide",
      description: "SQL injection remains one of the most dangerous vulnerabilities. Discover best practices for protecting your databases.",
      url: "#sql-injection"
    }
  ];

  return (
    <section id="education" className="py-12 bg-neutral-100">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold font-sans text-neutral-400 mb-3">
            Security Knowledge Base
          </h2>
          <p className="text-neutral-300 max-w-3xl mx-auto">
            Learn about common web vulnerabilities and how to protect against them.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {educationItems.map((item, index) => (
            <div key={index} className="bg-white rounded-lg overflow-hidden shadow-sm">
              <div className="p-6">
                <h3 className="font-sans font-semibold text-xl mb-2">{item.title}</h3>
                <p className="text-neutral-300 mb-4">{item.description}</p>
                <a href={item.url} className="text-primary hover:underline flex items-center text-sm font-medium">
                  Read more
                  <ArrowRight className="w-4 h-4 ml-1" />
                </a>
              </div>
            </div>
          ))}
        </div>

        <div className="text-center mt-8">
          <Button 
            variant="default" 
            className="bg-primary hover:bg-blue-600 text-white px-6 py-3 rounded-lg font-medium transition-colors"
          >
            View All Security Resources
          </Button>
        </div>
      </div>
    </section>
  );
}
