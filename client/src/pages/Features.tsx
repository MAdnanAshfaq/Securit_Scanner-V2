import { Shield, FileSearch, FileText } from "lucide-react";

export default function Features() {
  const features = [
    {
      icon: <FileSearch className="w-8 h-8 text-primary" />,
      title: "Comprehensive Scans",
      description: "Test for the OWASP Top 10 vulnerabilities and many more security issues with our advanced scanning engine."
    },
    {
      icon: <FileText className="w-8 h-8 text-primary" />,
      title: "Detailed Reports",
      description: "Receive comprehensive reports with vulnerability explanations, risk levels, and remediation recommendations."
    },
    {
      icon: <Shield className="w-8 h-8 text-primary" />,
      title: "Responsible Disclosure",
      description: "Learn how to properly disclose vulnerabilities to website owners with our ethical hacking guidelines."
    }
  ];

  return (
    <section id="features" className="py-12 bg-white">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold font-sans text-neutral-400 mb-3">
            Advanced Security Features
          </h2>
          <p className="text-neutral-300 max-w-3xl mx-auto">
            Our scanning engine uses professional-grade techniques to identify vulnerabilities 
            that could compromise your website security.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <div key={index} className="bg-neutral-100 rounded-lg p-6 shadow-sm">
              <div className="text-primary mb-4">
                {feature.icon}
              </div>
              <h3 className="font-sans font-semibold text-xl mb-2">{feature.title}</h3>
              <p className="text-neutral-300">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
