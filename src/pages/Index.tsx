import { Shield, FileText, Image, File } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ThemeToggle } from "@/components/theme-toggle";

const Index = () => {
  return (
    <div className="min-h-screen bg-background transition-colors duration-300">
      {/* Theme Toggle */}
      <div className="absolute top-6 right-6 z-10">
        <ThemeToggle />
      </div>

      {/* Hero Section */}
      <div className="flex flex-col items-center justify-center px-6 py-20">
        {/* Logo */}
        <div className="mb-8">
          <div className="w-16 h-16 bg-card rounded-full flex items-center justify-center shadow-card mb-6">
            <div className="w-6 h-6 bg-primary rotate-45 rounded-sm"></div>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-5xl font-bold text-foreground mb-6">InvisiLock</h1>
        
        {/* Subtitle */}
        <div className="bg-card px-8 py-4 rounded-full shadow-card mb-8">
          <p className="text-lg text-foreground">Your Gateway to Secure Encryption Solutions</p>
        </div>

        {/* Description */}
        <p className="text-crypto-text-muted text-center mb-12 max-w-lg">
          Choose your encryption method below to begin
        </p>

        {/* Encryption Options */}
        <div className="bg-crypto-surface p-8 rounded-3xl shadow-elegant">
          <div className="grid md:grid-cols-3 gap-6 max-w-4xl">
            {/* File Encryption */}
            <Link to="/file">
              <Card className="group cursor-pointer hover:shadow-card transition-all duration-200 hover:scale-105 bg-card border-crypto-border">
                <CardContent className="p-8 text-center">
                  <File className="w-12 h-12 mx-auto mb-4 text-primary" />
                  <h3 className="text-lg font-semibold text-foreground">File Encryption</h3>
                </CardContent>
              </Card>
            </Link>

            {/* Image Encryption */}
            <Link to="/image">
              <Card className="group cursor-pointer hover:shadow-card transition-all duration-200 hover:scale-105 bg-card border-crypto-border">
                <CardContent className="p-8 text-center">
                  <Image className="w-12 h-12 mx-auto mb-4 text-primary" />
                  <h3 className="text-lg font-semibold text-foreground">Image Encryption</h3>
                </CardContent>
              </Card>
            </Link>

            {/* Text Encryption */}
            <Link to="/text">
              <Card className="group cursor-pointer hover:shadow-card transition-all duration-200 hover:scale-105 bg-card border-crypto-border">
                <CardContent className="p-8 text-center">
                  <FileText className="w-12 h-12 mx-auto mb-4 text-primary" />
                  <h3 className="text-lg font-semibold text-foreground">Text Encryption</h3>
                </CardContent>
              </Card>
            </Link>
          </div>
        </div>
      </div>

      {/* About Section */}
      <div className="px-6 pb-20">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-foreground mb-8">About This Project</h2>
          <div className="w-16 h-0.5 bg-primary mx-auto mb-8"></div>
          
          <div className="prose prose-lg mx-auto text-crypto-text-muted leading-relaxed">
            <p className="mb-6">
              This tool empowers users to securely encrypt and decrypt text files and image files, offering a 
              critical layer of protection for sensitive data in an era of escalating digital threats. By leveraging 
              industry-standard cryptographic protocols, it ensures that personal documents, confidential 
              information, and private communications remain secure from unauthorized access.
            </p>
            
            <p className="mb-6">
              Built with privacy-first principles, all encryption and decryption processes happen entirely 
              within your browser - your data never leaves your device. This local processing approach 
              guarantees that your sensitive information remains completely under your control.
            </p>
            
            <div className="flex items-center justify-center gap-2 text-sm text-crypto-text-muted mt-8">
              <Shield className="w-4 h-4" />
              <span>All processing happens in your browser - your data never leaves your device</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;