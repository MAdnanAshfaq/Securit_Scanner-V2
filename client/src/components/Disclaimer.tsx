import { AlertTriangle } from "lucide-react";

export default function Disclaimer() {
  return (
    <section className="py-8 bg-neutral-400 text-white">
      <div className="container mx-auto px-4">
        <div className="bg-opacity-20 bg-black p-6 rounded-lg">
          <div className="flex items-start">
            <AlertTriangle className="h-8 w-8 text-red-500 mr-3 mt-1" />
            <div>
              <h3 className="font-sans font-semibold text-xl mb-2">Legal Disclaimer</h3>
              <p className="mb-2">SecureScope is designed for educational purposes and ethical security testing only. You must:</p>
              <ul className="list-disc pl-5 mb-3 space-y-1">
                <li>Only scan websites you own or have explicit permission to test</li>
                <li>Follow responsible disclosure practices when reporting vulnerabilities</li>
                <li>Understand that unauthorized scanning may violate computer fraud and abuse laws</li>
                <li>Use this tool at your own risk and responsibility</li>
              </ul>
              <p className="text-sm">By using SecureScope, you agree to adhere to ethical hacking principles and applicable laws.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
