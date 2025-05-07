import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { Separator } from '@/components/ui/separator';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { apiRequest } from '@/lib/queryClient';
import { Clipboard, Check, AlertCircle, Upload, Search, Hash, Copy, Key, QrCode, FileCode, RefreshCw } from 'lucide-react';

interface DecodingToolProps {
  initialTab?: 'hash' | 'universal' | 'qr';
}

export default function DecodingTool({ initialTab = 'hash' }: DecodingToolProps) {
  const { toast } = useToast();
  const [hashInput, setHashInput] = useState('');
  const [hashResult, setHashResult] = useState<any>(null);
  const [universalInput, setUniversalInput] = useState('');
  const [universalResult, setUniversalResult] = useState<any>(null);
  const [qrResult, setQrResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState({
    hash: false,
    universal: false,
    qr: false
  });
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Function to handle hash decoding
  const decodeHash = async () => {
    if (!hashInput.trim()) {
      toast({
        title: "Error",
        description: "Please enter a hash to decode",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(prev => ({ ...prev, hash: true }));
    try {
      // Use fetch directly for better error handling instead of apiRequest
      const response = await fetch('/api/decode-hash', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ hash: hashInput.trim() })
      });
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.message || 'Unknown error occurred');
      }
      
      setHashResult(result.result);
      toast({
        title: "Hash Analysis Complete",
        description: "We've analyzed your hash and found potential matches.",
      });
    } catch (error) {
      console.error('Hash decoding error:', error);
      toast({
        title: "Decoding Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
    } finally {
      setIsLoading(prev => ({ ...prev, hash: false }));
    }
  };

  // Function to handle universal decoding
  const decodeUniversal = async () => {
    if (!universalInput.trim()) {
      toast({
        title: "Error",
        description: "Please enter data to decode",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(prev => ({ ...prev, universal: true }));
    try {
      // Use fetch directly for better error handling instead of apiRequest
      const response = await fetch('/api/universal-decode', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: universalInput.trim() })
      });
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.message || 'Unknown error occurred');
      }
      
      setUniversalResult(result.result);
      toast({
        title: "Decoding Complete",
        description: "We've analyzed your data and found potential interpretations.",
      });
    } catch (error) {
      console.error('Universal decoding error:', error);
      toast({
        title: "Decoding Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
    } finally {
      setIsLoading(prev => ({ ...prev, universal: false }));
    }
  };

  // Function to handle QR code image upload and decoding
  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Check if the file is an image
    if (!file.type.includes('image')) {
      toast({
        title: "Invalid File",
        description: "Please upload an image file (JPEG, PNG, etc.)",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(prev => ({ ...prev, qr: true }));
    try {
      // Create a FormData instance
      const formData = new FormData();
      formData.append('image', file);

      // Send the file to the server
      const response = await fetch('/api/decode-qr', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      setQrResult(result.result);
      
      toast({
        title: "QR Code Decoded",
        description: result.result.decoded 
          ? "Successfully decoded QR code content"
          : "Could not decode QR code content",
        variant: result.result.decoded ? "default" : "destructive"
      });
    } catch (error) {
      console.error('QR decoding error:', error);
      toast({
        title: "QR Decoding Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
    } finally {
      setIsLoading(prev => ({ ...prev, qr: false }));
      // Reset the file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // Function to copy text to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      toast({
        title: "Copied to clipboard",
        description: "Text has been copied to your clipboard",
      });
    }).catch((err) => {
      console.error('Failed to copy:', err);
      toast({
        title: "Copy Failed",
        description: "Could not copy to clipboard",
        variant: "destructive"
      });
    });
  };

  return (
    <div className="w-full max-w-6xl mx-auto p-4">
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-500 to-violet-600 bg-clip-text text-transparent">
          Advanced Decoding Tools
        </h1>
        <p className="text-gray-600 mt-2">
          Decode hashes, encrypted data, session keys, and QR codes with 100% accuracy
        </p>
      </div>

      <Tabs defaultValue={initialTab}>
        <TabsList className="grid w-full grid-cols-3 mb-8">
          <TabsTrigger value="hash" className="flex items-center gap-2">
            <Hash className="h-4 w-4" />
            Hash Decoder
          </TabsTrigger>
          <TabsTrigger value="universal" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            Universal Decoder
          </TabsTrigger>
          <TabsTrigger value="qr" className="flex items-center gap-2">
            <QrCode className="h-4 w-4" />
            QR Code Decoder
          </TabsTrigger>
        </TabsList>

        {/* Hash Decoder Tab */}
        <TabsContent value="hash">
          <Card>
            <CardHeader>
              <CardTitle>Hash Decoder</CardTitle>
              <CardDescription>
                Decode MD5, SHA1, SHA256, SHA512 hashes and more with our advanced hash analysis tool.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex flex-col md:flex-row gap-4">
                  <div className="flex-1">
                    <Input
                      placeholder="Enter your hash (e.g., 5f4dcc3b5aa765d61d8327deb882cf99)"
                      value={hashInput}
                      onChange={(e) => setHashInput(e.target.value)}
                      className="w-full"
                    />
                  </div>
                  <Button 
                    onClick={decodeHash} 
                    disabled={isLoading.hash}
                    className="bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-700 hover:to-violet-700"
                  >
                    {isLoading.hash ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Decoding...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        Decode Hash
                      </>
                    )}
                  </Button>
                </div>

                {hashResult && (
                  <div className="mt-6 border rounded-lg p-4">
                    <div className="mb-4 flex items-center justify-between">
                      <div>
                        <span className="text-sm font-semibold">Hash Type:</span>
                        <Badge variant="outline" className="ml-2 text-blue-600 bg-blue-50">
                          {hashResult.identifiedType}
                        </Badge>
                      </div>
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => copyToClipboard(hashResult.originalHash)}
                        className="flex items-center gap-1"
                      >
                        <Copy className="h-3 w-3" />
                        Copy Hash
                      </Button>
                    </div>

                    {hashResult.decoded ? (
                      <Alert className="bg-green-50 border-green-200">
                        <Check className="h-4 w-4 text-green-600" />
                        <AlertTitle className="text-green-700">Hash Decoded Successfully</AlertTitle>
                        <AlertDescription className="text-green-700">
                          We've found potential plaintext values for this hash.
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <Alert className="bg-yellow-50 border-yellow-200">
                        <AlertCircle className="h-4 w-4 text-yellow-600" />
                        <AlertTitle className="text-yellow-700">Hash Analysis Complete</AlertTitle>
                        <AlertDescription className="text-yellow-700">
                          We couldn't directly decode this hash, but we've provided an analysis below.
                        </AlertDescription>
                      </Alert>
                    )}

                    <Accordion type="single" collapsible className="mt-4">
                      {hashResult.decoded && hashResult.possiblePlainText.length > 0 && (
                        <AccordionItem value="plaintext">
                          <AccordionTrigger className="text-blue-600 font-medium">
                            Possible Plaintext Values
                          </AccordionTrigger>
                          <AccordionContent>
                            <div className="space-y-2">
                              {hashResult.possiblePlainText.map((text: string, index: number) => (
                                <div key={index} className="flex items-center justify-between py-2 px-3 rounded-md bg-gray-50">
                                  <span className="font-mono">{text}</span>
                                  <Button 
                                    variant="ghost" 
                                    size="sm"
                                    onClick={() => copyToClipboard(text)}
                                  >
                                    <Copy className="h-3 w-3" />
                                  </Button>
                                </div>
                              ))}
                            </div>
                          </AccordionContent>
                        </AccordionItem>
                      )}

                      {hashResult.securityAnalysis && (
                        <AccordionItem value="security">
                          <AccordionTrigger className="text-blue-600 font-medium">
                            Security Analysis
                          </AccordionTrigger>
                          <AccordionContent>
                            <div className="space-y-3">
                              <div>
                                <span className="font-semibold">What type of hash is this?</span> <br/>
                                <span className="text-sm text-gray-700">
                                  {hashResult.securityAnalysis.algorithm === 'MD5' && 'This is an MD5 hash, which is an older algorithm commonly used for file verification but not secure for passwords.'}
                                  {hashResult.securityAnalysis.algorithm === 'SHA1' && 'This is a SHA1 hash, which was once widely used but is now considered outdated for security-critical applications.'}
                                  {hashResult.securityAnalysis.algorithm === 'SHA256' && 'This is a SHA256 hash, which is a modern, secure hashing algorithm widely used today.'}
                                  {hashResult.securityAnalysis.algorithm === 'SHA512' && 'This is a SHA512 hash, which is a very secure algorithm used for sensitive data and high-security applications.'}
                                  {hashResult.securityAnalysis.algorithm === 'SHA3' && 'This is a SHA3 hash, which is the newest and most secure SHA algorithm.'}
                                  {hashResult.securityAnalysis.algorithm === 'BCRYPT' && 'This is a bcrypt hash, specifically designed for securely storing passwords.'}
                                  {!['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3', 'BCRYPT'].includes(hashResult.securityAnalysis.algorithm) && `This is a ${hashResult.securityAnalysis.algorithm} format.`}
                                </span>
                              </div>
                              <div>
                                <span className="font-semibold">How secure is this hash?</span><br/>
                                <div className="flex items-center mt-1">
                                  <Badge variant={
                                    hashResult.securityAnalysis.strength.includes('weak') 
                                      ? 'destructive' 
                                      : hashResult.securityAnalysis.strength.includes('strong')
                                        ? 'default'
                                        : 'secondary'
                                  }>
                                    {hashResult.securityAnalysis.strength}
                                  </Badge>
                                  <span className="ml-2 text-sm text-gray-700">
                                    {hashResult.securityAnalysis.strength.includes('weak') && 
                                      'This type of hash is considered insecure and should not be used for passwords or sensitive data.'}
                                    {hashResult.securityAnalysis.strength.includes('strong') && 
                                      'This hash type is secure and appropriate for most security applications.'}
                                    {hashResult.securityAnalysis.strength.includes('very strong') && 
                                      'This hash type provides excellent security and is appropriate for even the most sensitive applications.'}
                                    {!hashResult.securityAnalysis.strength.includes('weak') && 
                                      !hashResult.securityAnalysis.strength.includes('strong') && 
                                      'The security of this hash type is uncertain or depends on how it is being used.'}
                                  </span>
                                </div>
                              </div>
                              {hashResult.securityAnalysis.entropy !== undefined && (
                                <div>
                                  <span className="font-semibold">Entropy:</span> {hashResult.securityAnalysis.entropy.toFixed(2)}
                                </div>
                              )}
                              {hashResult.securityAnalysis.vulnerabilities?.length > 0 && (
                                <div>
                                  <span className="font-semibold">Vulnerabilities:</span>
                                  <ul className="list-disc pl-5 mt-1 text-sm">
                                    {hashResult.securityAnalysis.vulnerabilities.map((vuln: string, index: number) => (
                                      <li key={index}>{vuln}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {hashResult.securityAnalysis.recommendations?.length > 0 && (
                                <div>
                                  <span className="font-semibold">Recommendations:</span>
                                  <ul className="list-disc pl-5 mt-1 text-sm">
                                    {hashResult.securityAnalysis.recommendations.map((rec: string, index: number) => (
                                      <li key={index}>{rec}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          </AccordionContent>
                        </AccordionItem>
                      )}

                      {hashResult.tokenAnalysis && (
                        <AccordionItem value="token">
                          <AccordionTrigger className="text-blue-600 font-medium">
                            Token Analysis
                          </AccordionTrigger>
                          <AccordionContent>
                            <div className="space-y-3">
                              <div>
                                <span className="font-semibold">Structure:</span> {hashResult.tokenAnalysis.structure}
                              </div>
                              {hashResult.tokenAnalysis.timestamp && (
                                <div>
                                  <span className="font-semibold">Embedded Timestamp:</span> {hashResult.tokenAnalysis.timestamp}
                                </div>
                              )}
                              {hashResult.tokenAnalysis.likelyUsage?.length > 0 && (
                                <div>
                                  <span className="font-semibold">Likely Usage:</span>
                                  <ul className="list-disc pl-5 mt-1 text-sm">
                                    {hashResult.tokenAnalysis.likelyUsage.map((usage: string, index: number) => (
                                      <li key={index}>{usage}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          </AccordionContent>
                        </AccordionItem>
                      )}

                      {hashResult.decodingMethod && (
                        <AccordionItem value="method">
                          <AccordionTrigger className="text-blue-600 font-medium">
                            Decoding Method
                          </AccordionTrigger>
                          <AccordionContent>
                            <p className="text-sm">
                              This hash was {hashResult.decoded ? 'decoded' : 'analyzed'} using: <span className="font-semibold">{hashResult.decodingMethod}</span>
                            </p>
                            {hashResult.salt && (
                              <p className="text-sm mt-2">
                                Salt used: <span className="font-mono">{hashResult.salt}</span>
                              </p>
                            )}
                          </AccordionContent>
                        </AccordionItem>
                      )}
                    </Accordion>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Universal Decoder Tab */}
        <TabsContent value="universal">
          <Card>
            <CardHeader>
              <CardTitle>Universal Decoder</CardTitle>
              <CardDescription>
                Decode any type of encoded or encrypted data including base64, JWT tokens, URL encoding, and more.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex flex-col space-y-4">
                  <textarea
                    className="w-full min-h-[120px] p-3 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter encoded data, JWT token, URL encoded string, or any other encoded text..."
                    value={universalInput}
                    onChange={(e) => setUniversalInput(e.target.value)}
                  />
                  <Button 
                    onClick={decodeUniversal} 
                    disabled={isLoading.universal}
                    className="bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-700 hover:to-violet-700"
                  >
                    {isLoading.universal ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Decoding...
                      </>
                    ) : (
                      <>
                        <FileCode className="h-4 w-4 mr-2" />
                        Decode Data
                      </>
                    )}
                  </Button>
                </div>

                {universalResult && (
                  <div className="mt-6 border rounded-lg p-4">
                    <div className="mb-4">
                      <span className="text-sm font-semibold">Original Input:</span>
                      <div className="mt-1 p-2 bg-gray-50 rounded font-mono text-xs overflow-x-auto max-h-24 overflow-y-auto">
                        {universalResult.original}
                      </div>
                    </div>

                    {universalResult.decoded ? (
                      <Alert className="bg-green-50 border-green-200">
                        <Check className="h-4 w-4 text-green-600" />
                        <AlertTitle className="text-green-700">Data Decoded Successfully</AlertTitle>
                        <AlertDescription className="text-green-700">
                          We've found {universalResult.possibleDecodings.length} potential interpretation(s) for this data.
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <Alert className="bg-yellow-50 border-yellow-200">
                        <AlertCircle className="h-4 w-4 text-yellow-600" />
                        <AlertTitle className="text-yellow-700">Decoding Analysis Complete</AlertTitle>
                        <AlertDescription className="text-yellow-700">
                          We couldn't find a way to decode this data with our current methods.
                        </AlertDescription>
                      </Alert>
                    )}

                    {universalResult.analysis?.length > 0 && (
                      <div className="mt-4">
                        <h3 className="font-semibold text-blue-600 mb-2">Analysis</h3>
                        <ul className="list-disc pl-5 space-y-1">
                          {universalResult.analysis.map((item: string, index: number) => (
                            <li key={index} className="text-sm">{item}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {universalResult.possibleDecodings?.length > 0 && (
                      <div className="mt-4">
                        <h3 className="font-semibold text-blue-600 mb-2">Possible Interpretations</h3>
                        <div className="space-y-3">
                          {universalResult.possibleDecodings.map((decoding: any, index: number) => (
                            <div key={index} className="border rounded p-3 bg-gray-50">
                              <div className="flex items-center justify-between mb-2">
                                <Badge variant="outline" className="text-blue-600 bg-blue-50">
                                  {decoding.type}
                                </Badge>
                                {typeof decoding.result === 'string' && (
                                  <Button 
                                    variant="ghost" 
                                    size="sm"
                                    onClick={() => copyToClipboard(decoding.result)}
                                  >
                                    <Copy className="h-3 w-3 mr-1" />
                                    Copy
                                  </Button>
                                )}
                              </div>
                              <Separator className="my-2" />
                              <div className="font-mono text-xs break-all">
                                {typeof decoding.result === 'string' ? (
                                  decoding.result
                                ) : (
                                  <pre>{JSON.stringify(decoding.result, null, 2)}</pre>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* QR Code Decoder Tab */}
        <TabsContent value="qr">
          <Card>
            <CardHeader>
              <CardTitle>QR Code Decoder</CardTitle>
              <CardDescription>
                Upload QR code images to extract and decode the embedded information.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="flex items-center justify-center w-full">
                  <label 
                    htmlFor="qrImage" 
                    className="flex flex-col items-center justify-center w-full h-64 border-2 border-dashed rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100"
                  >
                    <div className="flex flex-col items-center justify-center pt-5 pb-6">
                      <Upload className="w-10 h-10 mb-3 text-gray-400" />
                      <p className="mb-2 text-sm text-gray-500">
                        <span className="font-semibold">Click to upload</span> or drag and drop
                      </p>
                      <p className="text-xs text-gray-500">
                        SVG, PNG, JPG or GIF
                      </p>
                      {isLoading.qr && (
                        <div className="mt-4 flex items-center justify-center">
                          <RefreshCw className="animate-spin h-5 w-5 mr-2 text-blue-500" />
                          <p className="text-sm text-blue-500">Decoding QR code...</p>
                        </div>
                      )}
                    </div>
                    <input 
                      id="qrImage" 
                      type="file" 
                      className="hidden"
                      accept="image/*"
                      onChange={handleFileChange}
                      ref={fileInputRef}
                      disabled={isLoading.qr}
                    />
                  </label>
                </div>

                {qrResult && (
                  <div className="mt-6 border rounded-lg p-4">
                    {qrResult.decoded ? (
                      <>
                        <Alert className="bg-green-50 border-green-200">
                          <Check className="h-4 w-4 text-green-600" />
                          <AlertTitle className="text-green-700">QR Code Decoded Successfully</AlertTitle>
                          <AlertDescription className="text-green-700">
                            Method: {qrResult.decodingMethod}
                          </AlertDescription>
                        </Alert>

                        <div className="mt-4">
                          <h3 className="font-semibold text-blue-600 mb-2">Decoded Content</h3>
                          <div className="flex items-center justify-between">
                            <div className="font-mono text-sm border p-3 bg-gray-50 rounded-md w-full break-all">
                              {qrResult.text}
                            </div>
                            <Button 
                              variant="outline" 
                              className="ml-2 flex-shrink-0"
                              onClick={() => copyToClipboard(qrResult.text)}
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>

                        {/* Try to auto-detect if it's a URL */}
                        {qrResult.text.match(/^https?:\/\//i) && (
                          <div className="mt-4">
                            <Button 
                              variant="outline" 
                              className="text-blue-600"
                              onClick={() => window.open(qrResult.text, '_blank')}
                            >
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                              </svg>
                              Open URL
                            </Button>
                          </div>
                        )}

                        {/* Universal decode the content */}
                        <div className="mt-4">
                          <Button 
                            variant="outline" 
                            className="text-violet-600"
                            onClick={() => {
                              setUniversalInput(qrResult.text);
                              document.querySelector('[data-state="inactive"][value="universal"]')?.dispatchEvent(
                                new MouseEvent('click', { bubbles: true })
                              );
                            }}
                          >
                            <FileCode className="h-4 w-4 mr-2" />
                            Further Analyze with Universal Decoder
                          </Button>
                        </div>
                      </>
                    ) : (
                      <Alert variant="destructive">
                        <AlertCircle className="h-4 w-4" />
                        <AlertTitle>Failed to Decode QR Code</AlertTitle>
                        <AlertDescription>
                          {qrResult.error || "We couldn't decode this QR code. Please try a clearer image."}
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}