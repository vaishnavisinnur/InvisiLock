import React, { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { toast } from "sonner";
import {
  Upload,
  Lock,
  Unlock,
  Download,
  X,
  Eye,
  EyeOff,
  RotateCcw,
  FileKey2,
} from "lucide-react";

// ---------- Types ----------
interface EncryptedPackage {
  salt: string; // base64
  iv: string; // base64
  data: string; // base64 ciphertext
  originalType: string; // e.g., image/png
  filename: string; // original filename
}

// ---------- Helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

const bufToBase64 = (buf: ArrayBuffer) => {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
};

const base64ToBuf = (b64: string) => {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};

const getPasswordStrength = (pwd: string) => {
  if (pwd.length === 0) return { strength: "", color: "" };
  if (pwd.length < 6) return { strength: "weak", color: "text-red-500" };
  if (pwd.length < 10) return { strength: "medium", color: "text-yellow-500" };
  return { strength: "strong", color: "text-green-500" };
};

// AES-GCM with PBKDF2 (secure + reliable)
async function deriveKey(password: string, salt: Uint8Array) {
  const enc = new TextEncoder();
const normalizedSalt = new Uint8Array(salt.byteLength);
  normalizedSalt.set(salt);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: normalizedSalt, // now guaranteed safe
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function generateEncryptedPreview(cipherB64: string): string {
  // purely visual; DOES NOT contain real data (we save real data to .invlk file)
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  canvas.width = 480;
  canvas.height = 320;
  if (!ctx) return "";
  const img = ctx.createImageData(canvas.width, canvas.height);
  const bytes = atob(cipherB64);
  const L = bytes.length;
  for (let i = 0, p = 0; i < img.data.length; i += 4, p++) {
    const v = bytes.charCodeAt(p % L);
    img.data[i] = (v * 29 + p) % 256; // R
    img.data[i + 1] = (v * 73 + p * 3) % 256; // G
    img.data[i + 2] = (v * 131 + p * 7) % 256; // B
    img.data[i + 3] = 255; // A
  }
  ctx.putImageData(img, 0, 0);
  return canvas.toDataURL("image/png");
}

export const ImageEncryption: React.FC = () => {
  // Files/state
  const [selectedFile, setSelectedFile] = useState<File | null>(null); // raw image for encryption
  const [previewUrl, setPreviewUrl] = useState<string>("");

  const [encryptedPkg, setEncryptedPkg] = useState<EncryptedPackage | null>(
    null
  );
  const [encryptedPreviewUrl, setEncryptedPreviewUrl] = useState<string>("");

  const [decryptedUrl, setDecryptedUrl] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [showPassword, setShowPassword] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const passwordStrength = useMemo(
    () => getPasswordStrength(password),
    [password]
  );

  // Revoke object URLs to avoid leaking + duplicate-looking images
  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
      if (encryptedPreviewUrl) URL.revokeObjectURL(encryptedPreviewUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const clearAll = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
    if (encryptedPreviewUrl) URL.revokeObjectURL(encryptedPreviewUrl);

    setSelectedFile(null);
    setPreviewUrl("");
    setEncryptedPkg(null);
    setEncryptedPreviewUrl("");
    setDecryptedUrl("");
    setPassword("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // -------- File selection / drop --------
  const tryLoadEncryptedPackage = async (file: File) => {
    try {
      const txt = await file.text();
      const obj = JSON.parse(txt) as Partial<EncryptedPackage>;
      if (
        obj &&
        typeof obj.salt === "string" &&
        typeof obj.iv === "string" &&
        typeof obj.data === "string" &&
        typeof obj.originalType === "string" &&
        typeof obj.filename === "string"
      ) {
        setSelectedFile(null);
        setPreviewUrl("");
        setEncryptedPkg(obj as EncryptedPackage);
        // make a visual preview for the encrypted payload
        const preview = generateEncryptedPreview(obj.data);
        setEncryptedPreviewUrl(preview);
        toast.success("Encrypted package loaded. Enter password to decrypt.");
        return true;
      }
    } catch (_) {
      // not a JSON package; ignore
    }
    return false;
  };

  const handleFileSelect = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // If it's our encrypted package (.invlk or .json with expected fields), load it
    const isPkg =
      file.name.endsWith(".invlk") ||
      file.type === "application/json" ||
      file.type === "text/plain";
    if (isPkg && (await tryLoadEncryptedPackage(file))) return;

    // otherwise expect an image to encrypt
    if (file && file.type.startsWith("image/")) {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
      setEncryptedPkg(null);
      setEncryptedPreviewUrl("");
      setDecryptedUrl("");
      setPassword("");
    } else {
      toast.error("Please select an image or a valid .invlk encrypted file");
    }
  };

  const handleDrop = async (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const file = event.dataTransfer.files?.[0];
    if (!file) return;

    const isPkg =
      file.name.endsWith(".invlk") ||
      file.type === "application/json" ||
      file.type === "text/plain";
    if (isPkg && (await tryLoadEncryptedPackage(file))) return;

    if (file && file.type.startsWith("image/")) {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
      setEncryptedPkg(null);
      setEncryptedPreviewUrl("");
      setDecryptedUrl("");
      setPassword("");
    } else {
      toast.error("Please drop an image or a valid .invlk encrypted file");
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
  };

  // -------- Encrypt --------
  const handleEncrypt = async () => {
    if (!selectedFile || !password) {
      toast.error("Please select an image and enter a password");
      return;
    }

    setIsEncrypting(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(password, salt);

      const fileBuf = await selectedFile.arrayBuffer();
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        fileBuf
      );

      const pkg: EncryptedPackage = {
        salt: bufToBase64(salt.buffer),
        iv: bufToBase64(iv.buffer),
        data: bufToBase64(cipher),
        originalType: selectedFile.type,
        filename: selectedFile.name,
      };

      setEncryptedPkg(pkg);
      // purely visual encrypted preview
      const preview = generateEncryptedPreview(pkg.data);
      setEncryptedPreviewUrl(preview);

      toast.success("Image encrypted successfully!");
    } catch (err) {
      console.error(err);
      toast.error("Error encrypting image");
    } finally {
      setIsEncrypting(false);
    }
  };

  // -------- Decrypt --------
  const handleDecrypt = async () => {
    if (!encryptedPkg || !password) {
      toast.error("Please load an encrypted file and enter the password");
      return;
    }

    setIsDecrypting(true);
    try {
      const salt = new Uint8Array(base64ToBuf(encryptedPkg.salt));
      const iv = new Uint8Array(base64ToBuf(encryptedPkg.iv));
      const key = await deriveKey(password, salt);

      const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        base64ToBuf(encryptedPkg.data)
      );

      const blob = new Blob([plainBuf], { type: encryptedPkg.originalType });
      if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
      setDecryptedUrl(URL.createObjectURL(blob));
      toast.success("Image decrypted successfully!");
    } catch (err) {
      console.error(err);
      toast.error("Failed to decrypt. Check your password or file.");
    } finally {
      setIsDecrypting(false);
    }
  };

  // -------- Downloads --------
  const handleDownloadEncrypted = () => {
    if (!encryptedPkg) {
      toast.error("No encrypted file to download");
      return;
    }
    const blob = new Blob([JSON.stringify(encryptedPkg)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${encryptedPkg.filename.replace(/\.[^.]+$/, "")}.invlk`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast.success("Encrypted file downloaded (.invlk)");
  };

  const handleDownloadDecrypted = () => {
    if (!decryptedUrl) {
      toast.error("No decrypted image to download");
      return;
    }
    const a = document.createElement("a");
    a.href = decryptedUrl;
    a.download = `decrypted_${
      encryptedPkg?.filename || selectedFile?.name || "image"
    }`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast.success("Decrypted image downloaded");
  };

  const handleReset = () => clearAll();
  const handleRemoveFile = () => clearAll();

  const hasAnything = !!(
    previewUrl || encryptedPkg || encryptedPreviewUrl || decryptedUrl
  );

  const canEncrypt = !!selectedFile && !!password && !isEncrypting;
  const canDecrypt = !!encryptedPkg && !!password && !isDecrypting;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">InvisiLock</h1>
          <p className="text-slate-600">
            Secure your images with password-based encryption. Upload an image to
            encrypt, or upload a .invlk file to decrypt.
          </p>
          <div className="flex items-center justify-center gap-1 text-sm text-slate-500 mt-2">
            <Lock className="h-4 w-4" />
            <span>
              All processing happens in your browser - your files never leave
              your device
            </span>
          </div>
        </div>

        {/* Main Card */}
        <Card className="bg-white shadow-xl border-0">
          <CardContent className="p-8">
            {!hasAnything ? (
              // Upload area
              <div
                className="border-2 border-dashed border-slate-300 rounded-lg p-12 text-center hover:border-blue-400 transition-colors cursor-pointer"
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-slate-700 mb-2">
                  Drag & Drop or Browse files
                </h3>
                <p className="text-sm text-slate-500 mb-4">
                  Images to encrypt (PNG/JPG/etc) or encrypted packages
                  (.invlk). Everything is done offline.
                </p>
                <Button variant="outline">Browse Files</Button>
                <Input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*,.invlk,application/json,text/plain"
                  onChange={handleFileSelect}
                  className="hidden"
                />
              </div>
            ) : (
              // Processing area
              <div className="space-y-6">
                {/* File Info */}
                {(selectedFile || encryptedPkg) && (
                  <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-blue-100 rounded flex items-center justify-center">
                        {selectedFile ? (
                          <Upload className="h-4 w-4 text-blue-600" />
                        ) : (
                          <FileKey2 className="h-4 w-4 text-blue-600" />
                        )}
                      </div>
                      <div>
                        <p className="font-medium text-slate-700">
                          {selectedFile?.name || encryptedPkg?.filename}
                        </p>
                        <p className="text-sm text-slate-500">
                          {selectedFile
                            ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                            : ".invlk encrypted package"}
                        </p>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" onClick={handleRemoveFile}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                )}

                {/* Password */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-700">
                    Password
                  </label>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      placeholder="Enter password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowPassword((s) => !s)}
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  {password && (
                    <p className={`text-sm ${passwordStrength.color}`}>
                      Password strength: {passwordStrength.strength}
                    </p>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="flex flex-wrap gap-3">
                  <Button
                    onClick={handleEncrypt}
                    disabled={!canEncrypt}
                    className="flex items-center gap-2"
                  >
                    <Lock className="h-4 w-4" />
                    {isEncrypting ? "Encrypting..." : "Encrypt"}
                  </Button>

                  <Button
                    onClick={handleDecrypt}
                    disabled={!canDecrypt}
                    variant="outline"
                    className="flex items-center gap-2"
                  >
                    <Unlock className="h-4 w-4" />
                    {isDecrypting ? "Decrypting..." : "Decrypt"}
                  </Button>

                  {encryptedPkg && (
                    <Button
                      onClick={handleDownloadEncrypted}
                      variant="outline"
                      className="flex items-center gap-2"
                    >
                      <Download className="h-4 w-4" />
                      Download Encrypted (.invlk)
                    </Button>
                  )}

                  {decryptedUrl && (
                    <Button
                      onClick={handleDownloadDecrypted}
                      variant="outline"
                      className="flex items-center gap-2"
                    >
                      <Download className="h-4 w-4" />
                      Download Decrypted
                    </Button>
                  )}

                  <Button onClick={handleReset} variant="ghost" className="flex items-center gap-2">
                    <RotateCcw className="h-4 w-4" />
                    Reset
                  </Button>
                </div>

                {/* Previews (no duplicates) */}
                <div className="space-y-4">
                  {previewUrl && (
                    <div>
                      <h3 className="text-sm font-medium text-slate-700 mb-2">
                        Original Image
                      </h3>
                      <div className="border rounded-lg overflow-hidden">
                        <img
                          src={previewUrl}
                          alt="Original"
                          className="w-full max-h-64 object-contain bg-slate-50"
                        />
                      </div>
                    </div>
                  )}

                  {encryptedPkg && (
                    <div>
                      <h3 className="text-sm font-medium text-slate-700 mb-2">
                        Encrypted Preview (visual only)
                      </h3>
                      <div className="border rounded-lg overflow-hidden">
                        <img
                          src={encryptedPreviewUrl}
                          alt="Encrypted"
                          className="w-full max-h-64 object-contain bg-slate-50"
                        />
                      </div>
                    </div>
                  )}

                  {decryptedUrl && (
                    <div>
                      <h3 className="text-sm font-medium text-slate-700 mb-2">
                        Decrypted Image
                      </h3>
                      <div className="border rounded-lg overflow-hidden">
                        <img
                          src={decryptedUrl}
                          alt="Decrypted"
                          className="w-full max-h-64 object-contain bg-slate-50"
                        />
                      </div>
                    </div>
                  )}

                  {encryptedPkg && (
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                      <div className="flex items-start gap-2">
                        <div className="w-5 h-5 bg-yellow-100 rounded-full flex items-center justify-center mt-0.5">
                          <span className="text-yellow-600 text-xs font-bold">!</span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-yellow-800">Important:</p>
                          <p className="text-sm text-yellow-700">
                            Keep your password safe. Encrypted files are saved as
                            <code className="mx-1">.invlk</code> and can only be
                            opened with the same password.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
