import { useState, useRef } from "react";
import { Shield, ArrowLeft, Upload, Download, Eye, EyeOff } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThemeToggle } from "@/components/theme-toggle";

const ImageEncryption = () => {
  const [activeTab, setActiveTab] = useState("encryption");
  const [showPassword, setShowPassword] = useState(false);
  const [password, setPassword] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
    }
  };

  const handleDragOver = (event: React.DragEvent) => {
    event.preventDefault();
  };

  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault();
    const file = event.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) {
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
    }
  };

  const handleProcess = () => {
    if (!selectedFile || !password) return;
    // Demo implementation - in real app, use proper image encryption
    console.log(`${activeTab === 'encryption' ? 'Encrypting' : 'Decrypting'} image:`, selectedFile.name);
  };

  return (
    <div className="min-h-screen bg-background transition-colors duration-300">
      {/* Theme Toggle */}
      <div className="absolute top-6 right-6 z-10">
        <ThemeToggle />
      </div>

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
            Secure your images with password-based encryption. Upload an image, set a 
            password, and encrypt or decrypt with ease.
          </p>
          <div className="flex items-center justify-center gap-2 text-sm text-crypto-text-muted mt-4">
            <Shield className="w-4 h-4" />
            <span>All processing happens in your browser - your images never leave your device</span>
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
            {/* Password Input */}
            <div className="max-w-md mx-auto">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
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

            {/* File Upload Area */}
            <div
              className="border-2 border-dashed border-crypto-border rounded-lg p-12 text-center bg-crypto-surface hover:bg-crypto-surface-hover transition-colors cursor-pointer"
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileSelect}
                className="hidden"
              />
              
              {selectedFile ? (
                <div className="space-y-4">
                  {previewUrl && (
                    <img
                      src={previewUrl}
                      alt="Preview"
                      className="max-w-xs max-h-48 mx-auto rounded-lg shadow-card"
                    />
                  )}
                  <div>
                    <p className="font-semibold text-foreground">{selectedFile.name}</p>
                    <p className="text-sm text-crypto-text-muted">
                      {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <Upload className="w-12 h-12 mx-auto text-crypto-text-muted" />
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">Drag & Drop or Browse files</h3>
                    <p className="text-crypto-text-muted">
                      Files are not uploaded to a server, everything is done offline in your browser.
                    </p>
                  </div>
                  <Button variant="secondary">
                    Browse Files
                  </Button>
                </div>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex gap-4 justify-center">
              <Button 
                onClick={handleProcess}
                disabled={!selectedFile || !password}
                className="min-w-32"
              >
                {activeTab === "encryption" ? "Encrypt" : "Decrypt"}
              </Button>
              
              {selectedFile && (
                <Button variant="secondary">
                  <Download className="w-4 h-4 mr-2" />
                  Download Result
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ImageEncryption;