import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

export default function About() {
  return (
    <div className="container mx-auto px-4 py-16">
      <h1 className="text-4xl font-bold mb-8 text-center">About SecureScope</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
        <Card className="shadow-md">
          <CardHeader>
            <CardTitle>Our Mission</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-neutral-300">
              SecureScope was founded with a mission to make the web safer for everyone. We believe that by providing 
              powerful security scanning tools to developers and security professionals, we can help improve the overall 
              security posture of websites across the internet.
            </p>
          </CardContent>
        </Card>
        <Card className="shadow-md">
          <CardHeader>
            <CardTitle>Ethical Approach</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-neutral-300">
              We are committed to ethical security testing practices. Our platform is designed to help 
              identify vulnerabilities without causing harm to the target websites. We encourage responsible
              disclosure of any security issues discovered.
            </p>
          </CardContent>
        </Card>
      </div>

      <Separator className="my-12" />

      <div className="mb-12">
        <h2 className="text-3xl font-bold mb-6 text-center">How We Help</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="shadow-sm">
            <CardHeader>
              <CardTitle className="text-xl">For Developers</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-neutral-300">
                Security testing built into your development workflow to catch vulnerabilities before they reach production.
              </p>
            </CardContent>
          </Card>
          <Card className="shadow-sm">
            <CardHeader>
              <CardTitle className="text-xl">For Security Professionals</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-neutral-300">
                Advanced scanning capabilities to supplement your manual testing and help you cover more ground.
              </p>
            </CardContent>
          </Card>
          <Card className="shadow-sm">
            <CardHeader>
              <CardTitle className="text-xl">For Website Owners</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-neutral-300">
                Understand your website's security posture and get actionable recommendations for improvement.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      <Separator className="my-12" />

      <div className="text-center mb-12">
        <h2 className="text-3xl font-bold mb-6">Contact Us</h2>
        <p className="text-lg text-neutral-300 mb-4">
          Have questions about our platform or need assistance? Reach out to our team.
        </p>
        <p className="text-primary font-medium">support@securescope.com</p>
      </div>
    </div>
  );
}
