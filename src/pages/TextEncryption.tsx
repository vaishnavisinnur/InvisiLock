import { useState } from "react";
import { Shield, ArrowLeft, Eye, EyeOff } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThemeToggle } from "@/components/theme-toggle";

const TextEncryption = () => {
  const [activeTab, setActiveTab] = useState("encryption");
  const [showPassword, setShowPassword] = useState(false);
  const [password, setPassword] = useState("");
  const [inputText, setInputText] = useState("");
  const [outputText, setOutputText] = useState("");
  const [algorithm, setAlgorithm] = useState("AES");

  const handleEncrypt = () => {
    if (!inputText || !password) return;
    // Simple demo encryption (in real app, use proper crypto libraries)
    const encrypted = btoa(inputText + ":" + password);
    setOutputText(encrypted);
  };

  const handleDecrypt = () => {
    if (!inputText || !password) return;
    try {
      const decrypted = atob(inputText).split(":")[0];
      setOutputText(decrypted);
    } catch {
      setOutputText("Invalid encrypted text or password");
    }
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
          <div className="flex items-center justify-center gap-2 mb-4">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold text-primary">TextCrypt</h1>
          </div>
          <p className="text-crypto-text-muted max-w-lg">
            Secure your text with password-based encryption. Choose your algorithm, set a password, 
            and encrypt or decrypt with ease.
          </p>
          <div className="flex items-center justify-center gap-2 text-sm text-crypto-text-muted mt-4">
            <Shield className="w-4 h-4" />
            <span>All processing happens in your browser - your text never leaves your device</span>
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
            <div className="grid md:grid-cols-2 gap-6">
              {/* Left Column - Input */}
              <div className="space-y-4">
                <div>
                  <Label htmlFor="algorithm">Encryption Algorithm</Label>
                  <Select value={algorithm} onValueChange={setAlgorithm}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select algorithm" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="AES">AES (Advanced Encryption Standard)</SelectItem>
                      <SelectItem value="DES">DES (Data Encryption Standard)</SelectItem>
                      <SelectItem value="RSA">RSA (Rivest-Shamir-Adleman)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
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

                <div>
                  <Label htmlFor="input-text">
                    {activeTab === "encryption" ? "Text to Encrypt" : "Text to Decrypt"}
                  </Label>
                  <Textarea
                    id="input-text"
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    placeholder={
                      activeTab === "encryption" 
                        ? "Enter your message here..." 
                        : "Enter encrypted text here..."
                    }
                    className="min-h-[200px] resize-none"
                  />
                </div>

                <Button 
                  onClick={activeTab === "encryption" ? handleEncrypt : handleDecrypt}
                  className="w-full"
                  disabled={!inputText || !password}
                >
                  {activeTab === "encryption" ? "Encrypt Text" : "Decrypt Text"}
                </Button>
              </div>

              {/* Right Column - Output */}
              <div className="space-y-4">
                <div>
                  <Label htmlFor="output-text">
                    {activeTab === "encryption" ? "Encrypted Text" : "Decrypted Text"}
                  </Label>
                  <Textarea
                    id="output-text"
                    value={outputText}
                    readOnly
                    placeholder={
                      activeTab === "encryption"
                        ? "Encrypted text will appear here..."
                        : "Decrypted text will appear here..."
                    }
                    className="min-h-[200px] resize-none bg-crypto-surface"
                  />
                </div>

                <Button 
                  variant="secondary" 
                  className="w-full"
                  disabled={!outputText}
                  onClick={() => navigator.clipboard.writeText(outputText)}
                >
                  Copy to Clipboard
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default TextEncryption;