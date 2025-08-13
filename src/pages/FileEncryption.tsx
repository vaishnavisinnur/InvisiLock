import { useState, useRef } from "react";
import { Shield, ArrowLeft, Upload, Download, Eye, EyeOff, FileText } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";

const FileEncryption = () => {
  const [activeTab, setActiveTab] = useState("encryption");
  const [showPassword, setShowPassword] = useState(false);
  const [showPublicKey, setShowPublicKey] = useState(false);
  const [password, setPassword] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [usePassword, setUsePassword] = useState(true);
  const [processedFileName, setProcessedFileName] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleDragOver = (event: React.DragEvent) => {
    event.preventDefault();
  };

  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault();
    const file = event.dataTransfer.files[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleProcess = () => {
    if (!selectedFile || (!password && usePassword) || (!publicKey && !usePassword)) return;
    
    const fileName = selectedFile.name;
    const processedName = activeTab === 'encryption' 
      ? `${fileName}.encrypted` 
      : fileName.replace('.encrypted', '');
    
    setProcessedFileName(processedName);
    console.log(`${activeTab === 'encryption' ? 'Encrypting' : 'Decrypting'} file:`, fileName);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b border-crypto-border">
        <Link to="/" className="flex items-center gap-2 text-primary hover:text-primary/80 transition-colors">
          <ArrowLeft className="w-5 h-5" />
          <span>Back to Home</span>
        </Link>
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-primary" />
          <span className="text-2xl font-bold text-foreground">InvisiLock</span>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-col items-center justify-center px-6 py-12">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold text-primary mb-4">InvisiLock</h1>
          <p className="text-crypto-text-muted max-w-lg">
            Secure your files with password-based encryption. Upload a file, set a 
            password, and encrypt or decrypt with ease.
          </p>
          <div className="flex items-center justify-center gap-2 text-sm text-crypto-text-muted mt-4">
            <Shield className="w-4 h-4" />
            <span>All processing happens in your browser - your files never leave your device</span>
          </div>
        </div>

        <Card className="w-full max-w-4xl shadow-elegant">
          <CardHeader>
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid w-full grid-cols-2 bg-crypto-surface">
                <TabsTrigger value="encryption" className="data-[state=active]:bg-card">
                  Encryption
                </TabsTrigger>
                <TabsTrigger value="decryption" className="data-[state=active]:bg-card">
                  Decryption
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </CardHeader>

          <CardContent className="space-y-6">
            {/* File Selection */}
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="choose-file" 
                  checked 
                  className="data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                />
                <Label htmlFor="choose-file" className="text-sm font-medium">
                  Choose files to {activeTab === 'encryption' ? 'encrypt' : 'decrypt'}
                </Label>
              </div>
              
              <div
                className="border-2 border-dashed border-crypto-border rounded-lg p-8 text-center bg-crypto-surface hover:bg-crypto-surface-hover transition-colors cursor-pointer"
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileSelect}
                  className="hidden"
                />
                
                {selectedFile ? (
                  <div className="space-y-2">
                    <FileText className="w-8 h-8 mx-auto text-primary" />
                    <p className="font-semibold text-foreground">{selectedFile.name}</p>
                    <p className="text-sm text-crypto-text-muted">
                      {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <Upload className="w-8 h-8 mx-auto text-crypto-text-muted" />
                    <div>
                      <p className="font-semibold text-foreground">Drag & Drop or Browse files</p>
                      <p className="text-sm text-crypto-text-muted">
                        Files are not uploaded to a server, everything is done offline in your browser.
                      </p>
                    </div>
                    <Button variant="secondary" size="sm">
                      Browse Files
                    </Button>
                  </div>
                )}
              </div>
            </div>

            {/* Authentication Method */}
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="enter-password" 
                  checked={usePassword} 
                  onCheckedChange={(checked) => setUsePassword(checked as boolean)}
                  className="data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                />
                <Label htmlFor="enter-password" className="text-sm font-medium">
                  Enter a password
                </Label>
              </div>

              {usePassword && (
                <div className="max-w-md">
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Password"
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              )}

              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="use-public-key" 
                  checked={!usePassword} 
                  onCheckedChange={(checked) => setUsePassword(!(checked as boolean))}
                  className="data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                />
                <Label htmlFor="use-public-key" className="text-sm font-medium">
                  Use public key
                </Label>
              </div>

              {!usePassword && (
                <div className="max-w-md">
                  <div className="relative">
                    <Input
                      type={showPublicKey ? "text" : "password"}
                      value={publicKey}
                      onChange={(e) => setPublicKey(e.target.value)}
                      placeholder="Public Key"
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setShowPublicKey(!showPublicKey)}
                    >
                      {showPublicKey ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex gap-4 justify-center pt-4">
              <Button 
                onClick={handleProcess}
                disabled={!selectedFile || (!password && usePassword) || (!publicKey && !usePassword)}
                className="min-w-32"
              >
                {activeTab === "encryption" ? "ENCRYPT" : "DECRYPT"}
              </Button>
              
              {processedFileName && (
                <Button variant="secondary">
                  <Download className="w-4 h-4 mr-2" />
                  Download {processedFileName}
                </Button>
              )}
            </div>

            {/* Download Section */}
            {processedFileName && (
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="download-files" 
                    checked 
                    className="data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                  />
                  <Label htmlFor="download-files" className="text-sm font-medium">
                    Download {activeTab === 'encryption' ? 'encrypted' : 'decrypted'} files
                  </Label>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default FileEncryption;