import React, { useState, useRef, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { Upload, Lock, Unlock, Download, X, Eye, EyeOff, RotateCcw } from 'lucide-react';

interface EncryptedImageData {
  encryptedData: string;
  originalType: string;
  filename: string;
  encryptedImageUrl: string;
}

export default function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string>('');
  const [encryptedImage, setEncryptedImage] = useState<EncryptedImageData | null>(null);
  const [decryptedUrl, setDecryptedUrl] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [isEncryptedFileUploaded, setIsEncryptedFileUploaded] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /**
   * Converts a Base64 string to an ArrayBuffer.
   * @param base64 The Base64 string to convert.
   * @returns An ArrayBuffer.
   */
  const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };

  /**
   * Converts an ArrayBuffer to a Base64 string.
   * @param buffer The ArrayBuffer to convert.
   * @returns A Base64 string.
   */
  const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  /**
   * Derives a key from a password using PBKDF2 for strong encryption.
   * @param password The user-provided password.
   * @param salt The salt to use for key derivation.
   * @returns A Promise that resolves to the derived crypto key.
   */


 const getKey = async (password: string, salt: Uint8Array): Promise<CryptoKey> => {
  const enc = new TextEncoder();
  const passwordBuffer = enc.encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(salt), // ✅ ensures correct ArrayBuffer backing
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

  /**
   * Encrypts data using AES-GCM with a password-derived key.
   * @param data The data to encrypt (as a Base64 string).
   * @param password The password for encryption.
   * @returns A Promise resolving to an ArrayBuffer containing salt, IV, and encrypted data.
   */
  const aesEncrypt = async (data: string, password: string): Promise<ArrayBuffer> => {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await getKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const dataBytes = new Uint8Array(enc.encode(data));
    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      dataBytes.buffer,
    );

    const resultBuffer = new ArrayBuffer(salt.length + iv.length + encryptedData.byteLength);
    const resultView = new Uint8Array(resultBuffer);
    resultView.set(salt, 0);
    resultView.set(iv, salt.length);
    resultView.set(new Uint8Array(encryptedData), salt.length + iv.length);
    return resultBuffer;
  };

  /**
   * Decrypts data using AES-GCM.
   * @param encryptedBuffer An ArrayBuffer containing salt, IV, and encrypted data.
   * @param password The password for decryption.
   * @returns A Promise resolving to the decrypted data as a string.
   */
  const aesDecrypt = async (encryptedBuffer: ArrayBuffer, password: string): Promise<string> => {
    const salt = new Uint8Array(encryptedBuffer.slice(0, 16));
    const iv = new Uint8Array(encryptedBuffer.slice(16, 28));
    const encryptedData = encryptedBuffer.slice(28);

    const key = await getKey(password, salt);

    try {
      const decryptedData = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encryptedData,
      );
      const dec = new TextDecoder();
      return dec.decode(decryptedData);
    } catch (e) {
      throw new Error('Decryption failed, incorrect password or corrupted data.');
    }
  };
  
  /**
   * Embeds a string of encrypted data into the pixel data of a NEW image using LSB steganography.
   * The new canvas size is dynamically calculated to ensure the data fits.
   * @param secretData The string of encrypted data to hide. This is expected to be a Base64 string.
   * @returns A Promise that resolves to the new base64 data URL of the image with hidden data.
   */
  const embedDataInImage = (secretData: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      // Use a TextEncoder to get a Uint8Array, which is a safer way to handle binary data.
      const secretDataBytes = new TextEncoder().encode(secretData);
      
      const totalBytes = secretDataBytes.length;
      // We need 4 bytes for length prefix, then the data bytes
      const headerBytes = new Uint8Array(4);
      const dataView = new DataView(headerBytes.buffer);
      dataView.setUint32(0, totalBytes, false); // Store length in big-endian format
      
      const totalPixelsNeeded = Math.ceil((totalBytes + 4) * 8 / 3); // 8 bits per byte, 3 bits per pixel
      const canvasSize = Math.ceil(Math.sqrt(totalPixelsNeeded));
      
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = canvasSize;
      canvas.height = canvasSize;

      if (!ctx) {
        return reject(new Error('Could not get canvas context'));
      }
      
      // Fill canvas with a static-like pattern
      const imageData = ctx.createImageData(canvas.width, canvas.height);
      const data = imageData.data;
      for (let i = 0; i < data.length; i += 4) {
        const noise = Math.floor(Math.random() * 255);
        data[i] = noise;
        data[i + 1] = noise;
        data[i + 2] = noise;
        data[i + 3] = 255;
      }
      ctx.putImageData(imageData, 0, 0);
      
      const maxBytes = (data.length / 4);
      if (totalPixelsNeeded > maxBytes) {
        return reject(new Error('Data is too large to embed in this image.'));
      }
      
      // Combine header and data into a single byte stream to be hidden
      const fullDataBytes = new Uint8Array(headerBytes.length + secretDataBytes.length);
      fullDataBytes.set(headerBytes, 0);
      fullDataBytes.set(secretDataBytes, headerBytes.length);
      
      let bitIndex = 0;
      for (let byteIndex = 0; byteIndex < fullDataBytes.length; byteIndex++) {
        const byte = fullDataBytes[byteIndex];
        for (let bitPosition = 7; bitPosition >= 0; bitPosition--) {
          const bit = (byte >> bitPosition) & 1;
          const pixelIndex = Math.floor(bitIndex / 3);
          const channelIndex = (bitIndex % 3);
          const dataIndex = pixelIndex * 4 + channelIndex;
          if (dataIndex < data.length) {
            const pixelValue = data[dataIndex];
            data[dataIndex] = (pixelValue & 0xFE) | bit;
          }
          bitIndex++;
        }
      }
      
      ctx.putImageData(imageData, 0, 0);
      resolve(canvas.toDataURL('image/png'));
    });
  };

  /**
   * Extracts hidden data from an image's pixel data.
   * @param imageDataUrl The base64 data URL of the source image.
   * @returns A Promise that resolves to the extracted string data (Base64 encoded).
   */
  const extractDataFromImage = (imageDataUrl: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          return reject(new Error('Could not get canvas context'));
        }
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const data = imageData.data;
        
        // First, extract the length of the embedded data from the first 4 pixels
        const headerBytes = new Uint8Array(4);
        let bitIndex = 0;
        for (let byteIndex = 0; byteIndex < headerBytes.length; byteIndex++) {
          let byte = 0;
          for (let bitPosition = 7; bitPosition >= 0; bitPosition--) {
            const pixelIndex = Math.floor(bitIndex / 3);
            const channelIndex = (bitIndex % 3);
            const dataIndex = pixelIndex * 4 + channelIndex;
            if (dataIndex >= data.length) {
              return reject(new Error('Corrupted or no hidden data found.'));
            }
            const bit = (data[dataIndex] & 1);
            byte |= (bit << bitPosition);
            bitIndex++;
          }
          headerBytes[byteIndex] = byte;
        }

        const dataView = new DataView(headerBytes.buffer);
        const dataLength = dataView.getUint32(0, false);
        if (isNaN(dataLength) || dataLength <= 0 || dataLength > (data.length * 8 / 4)) {
            return reject(new Error('Corrupted or no hidden data found.'));
        }

        const extractedBytes = new Uint8Array(dataLength);
        const startIndex = headerBytes.length * 8;
        
        bitIndex = 0;
        for (let byteIndex = 0; byteIndex < dataLength; byteIndex++) {
          let byte = 0;
          for (let bitPosition = 7; bitPosition >= 0; bitPosition--) {
            const currentBitIndex = startIndex + bitIndex;
            const pixelIndex = Math.floor(currentBitIndex / 3);
            const channelIndex = (currentBitIndex % 3);
            const dataIndex = pixelIndex * 4 + channelIndex;
            if (dataIndex >= data.length) {
              return reject(new Error('Corrupted or incomplete hidden data.'));
            }
            const bit = (data[dataIndex] & 1);
            byte |= (bit << bitPosition);
            bitIndex++;
          }
          extractedBytes[byteIndex] = byte;
        }

        try {
          const extractedString = new TextDecoder().decode(extractedBytes);
          resolve(extractedString);
        } catch (e) {
          reject(new Error('Failed to decode hidden data.'));
        }
      };
      img.onerror = () => reject(new Error('Could not load image for steganography extraction'));
      img.src = imageDataUrl;
    });
  };
  
  const processFile = useCallback(async (file: File) => {
    if (!file || !file.type.startsWith('image/')) {
      toast.error('Please select a valid image file');
      return;
    }
    
    setSelectedFile(file);
    setDecryptedUrl('');
    setPassword('');
    setPreviewUrl('');
    setEncryptedImage(null);
    setIsEncryptedFileUploaded(false);

    const reader = new FileReader();
    reader.onload = async (e) => {
      const dataUrl = e.target?.result as string;
      try {
        const extractedDataBase64 = await extractDataFromImage(dataUrl);
        setEncryptedImage({
          encryptedData: extractedDataBase64,
          originalType: file.type,
          filename: file.name,
          encryptedImageUrl: dataUrl
        });
        setIsEncryptedFileUploaded(true);
        toast.success('Encrypted image detected! You can now decrypt it.');
      } catch (error) {
        console.log('Not an encrypted image:', error);
        setPreviewUrl(URL.createObjectURL(file));
        toast.info('This appears to be a regular image. You can encrypt it.');
      }
    };
    reader.readAsDataURL(file);
  }, []);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const file = event.dataTransfer.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
  };

  const getPasswordStrength = (pwd: string) => {
    if (pwd.length === 0) return { strength: '', color: '' };
    if (pwd.length < 6) return { strength: 'weak', color: 'text-red-500' };
    if (pwd.length < 10) return { strength: 'medium', color: 'text-yellow-500' };
    return { strength: 'strong', color: 'text-green-500' };
  };

  const handleEncrypt = async () => {
    if (!selectedFile || !password) {
      toast.error('Please select an image and enter a password');
      return;
    }

    if (isEncrypting) return;

    setIsEncrypting(true);
    setDecryptedUrl('');
    setEncryptedImage(null);
    setIsEncryptedFileUploaded(false);
    
    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const originalDataUrl = e.target?.result as string;
        
        try {
          const encryptedBuffer = await aesEncrypt(originalDataUrl, password);
          const encryptedBase64 = arrayBufferToBase64(encryptedBuffer);

          const encryptedImageUrl = await embedDataInImage(encryptedBase64);

          setEncryptedImage({
            encryptedData: encryptedBase64,
            originalType: selectedFile.type,
            filename: selectedFile.name,
            encryptedImageUrl
          });
          toast.success('Image encrypted successfully!');
          setPreviewUrl(URL.createObjectURL(selectedFile));
        } catch (stegoError) {
          console.error('Steganography or encryption error:', stegoError);
          toast.error('Failed to embed data. Image might be too large.');
        } finally {
          setIsEncrypting(false);
        }
      };
      reader.readAsDataURL(selectedFile);
    } catch (error) {
      toast.error('Error encrypting image');
      setIsEncrypting(false);
    }
  };

  const handleDecrypt = async () => {
    if (!encryptedImage || !password) {
      toast.error('Please upload an encrypted image and enter a password to decrypt');
      return;
    }

    if (isDecrypting) return;
    setIsDecrypting(true);
    setDecryptedUrl('');

    try {
      const encryptedBuffer = base64ToArrayBuffer(encryptedImage.encryptedData);
      const decryptedDataUrl = await aesDecrypt(encryptedBuffer, password);
      
      if (decryptedDataUrl.startsWith('data:image/')) {
        setDecryptedUrl(decryptedDataUrl);
        toast.success('Image decrypted successfully!');
      } else {
        throw new Error('Decrypted data is not a valid image.');
      }
    } catch (error) {
      console.error('Decryption error:', error);
      toast.error('Failed to decrypt image. Check your password.');
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleDownload = () => {
    if (!encryptedImage) {
      toast.error('No encrypted image to download');
      return;
    }

    const a = document.createElement('a');
    a.href = encryptedImage.encryptedImageUrl;
    a.download = `encrypted_${encryptedImage.filename.replace(/\.[^/.]+$/, "")}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    toast.success('Encrypted image downloaded as PNG!');
  };

  const handleDownloadDecrypted = () => {
    if (!decryptedUrl) {
      toast.error('No decrypted image to download');
      return;
    }

    const a = document.createElement('a');
    a.href = decryptedUrl;
    a.download = `decrypted_${encryptedImage?.filename || 'image.png'}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    toast.success('Decrypted image downloaded!');
  };

  const handleReset = () => {
    setSelectedFile(null);
    setPreviewUrl('');
    setEncryptedImage(null);
    setDecryptedUrl('');
    setPassword('');
    setIsEncryptedFileUploaded(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleRemoveFile = () => {
    handleReset();
  };

  const passwordStrength = getPasswordStrength(password);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 py-8 px-4 font-inter">
      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">InvisiLock</h1>
          <p className="text-slate-600">
            Secure your images with password-based encryption. Upload an image, set a password, and encrypt or decrypt with ease.
          </p>
          <div className="flex items-center justify-center gap-1 text-sm text-slate-500 mt-2">
            <Lock className="h-4 w-4" />
            <span>All processing happens in your browser - your images never leave your device</span>
          </div>
        </div>

        {/* Main Card */}
        <Card className="bg-white shadow-xl border-0 rounded-xl">
          <CardContent className="p-8">
            {!selectedFile ? (
              /* File Upload Area */
              <div
                className="border-2 border-dashed border-slate-300 rounded-lg p-12 text-center hover:border-blue-400 transition-colors cursor-pointer"
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-slate-700 mb-2">Drag & Drop or Browse files</h3>
                <p className="text-sm text-slate-500 mb-4">
                  Upload images for encryption. Downloaded encrypted images can be re-uploaded for decryption. All processing is done offline in your browser.
                </p>
                <Button variant="outline" className="rounded-lg">Browse Files</Button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  onChange={handleFileSelect}
                  className="hidden"
                />
              </div>
            ) : (
              /* File Processing Area */
              <div className="space-y-6">
                {/* File Info */}
                <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-blue-100 rounded-md flex items-center justify-center">
                      <Upload className="h-4 w-4 text-blue-600" />
                    </div>
                    <div>
                      <p className="font-medium text-slate-700">{selectedFile.name}</p>
                      <p className="text-sm text-slate-500">{(selectedFile.size / 1024).toFixed(1)} KB</p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleRemoveFile}
                    className="rounded-full"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>

                {/* Password Input */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-700">Encryption Password</label>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      placeholder="Enter password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pr-10 rounded-lg"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 rounded-r-lg"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
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
                    disabled={isEncrypting || !password || !!encryptedImage}
                    className="flex items-center gap-2 rounded-lg"
                  >
                    <Lock className="h-4 w-4" />
                    {isEncrypting ? 'Encrypting...' : 'Encrypt'}
                  </Button>
                  
                  <Button
                    onClick={handleDecrypt}
                    disabled={isDecrypting || !password || !isEncryptedFileUploaded}
                    variant="outline"
                    className="flex items-center gap-2 rounded-lg"
                  >
                    <Unlock className="h-4 w-4" />
                    {isDecrypting ? 'Decrypting...' : 'Decrypt'}
                  </Button>
                  
                  {encryptedImage && (
                    <Button
                      onClick={handleDownload}
                      variant="outline"
                      className="flex items-center gap-2 rounded-lg"
                    >
                      <Download className="h-4 w-4" />
                      Download Encrypted
                    </Button>
                  )}
                  
                  {decryptedUrl && (
                    <Button
                      onClick={handleDownloadDecrypted}
                      variant="outline"
                      className="flex items-center gap-2 rounded-lg"
                    >
                      <Download className="h-4 w-4" />
                      Download Decrypted
                    </Button>
                  )}
                  
                  <Button
                    onClick={handleReset}
                    variant="ghost"
                    className="flex items-center gap-2 rounded-lg"
                  >
                    <RotateCcw className="h-4 w-4" />
                    Reset
                  </Button>
                </div>

                {/* Images Display */}
                {/* Condition for displaying a regular, un-encrypted image that can be encrypted */}
                {(!encryptedImage && previewUrl) && (
                    <div className="space-y-4">
                        <div>
                          <h3 className="text-sm font-medium text-slate-700 mb-2">Original Image</h3>
                          <div className="border rounded-lg overflow-hidden">
                            <img
                              src={previewUrl}
                              alt="Original"
                              className="w-full max-h-64 object-contain bg-slate-50"
                            />
                          </div>
                        </div>
                    </div>
                )}
                {/* Condition for displaying images after encryption, before decryption */}
                {encryptedImage && !isEncryptedFileUploaded && (
                    <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <h3 className="text-sm font-medium text-slate-700 mb-2">Original Image</h3>
                                <div className="border rounded-lg overflow-hidden">
                                  <img
                                      src={previewUrl}
                                      alt="Original"
                                      className="w-full h-48 object-cover bg-slate-50"
                                  />
                                </div>
                            </div>
                            <div>
                                <h3 className="text-sm font-medium text-slate-700 mb-2">Encrypted Image</h3>
                                <div className="border rounded-lg overflow-hidden">
                                  <img
                                      src={encryptedImage.encryptedImageUrl}
                                      alt="Encrypted"
                                      className="w-full h-48 object-cover bg-slate-50"
                                  />
                                </div>
                            </div>
                        </div>
                    </div>
                )}
                {/* Condition for displaying images after uploading an encrypted file for decryption */}
                {isEncryptedFileUploaded && (
                  <div className="space-y-4">
                    {/* Before decryption */}
                    {!decryptedUrl && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <h3 className="text-sm font-medium text-slate-700 mb-2">Encrypted Image</h3>
                                <div className="border rounded-lg overflow-hidden">
                                  <img
                                      src={encryptedImage?.encryptedImageUrl}
                                      alt="Encrypted"
                                      className="w-full h-48 object-cover bg-slate-50"
                                  />
                                </div>
                            </div>
                            <div>
                                <h3 className="text-sm font-medium text-slate-700 mb-2">Decrypted Image</h3>
                                <div className="border rounded-lg overflow-hidden flex items-center justify-center h-48 bg-slate-50 text-slate-400">
                                  <span>Decrypt to see the image</span>
                                </div>
                            </div>
                        </div>
                    )}
                    {/* After decryption */}
                    {decryptedUrl && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h3 className="text-sm font-medium text-slate-700 mb-2">Encrypted Image</h3>
                          <div className="border rounded-lg overflow-hidden">
                            <img
                              src={encryptedImage?.encryptedImageUrl}
                              alt="Encrypted"
                              className="w-full h-48 object-cover bg-slate-50"
                            />
                          </div>
                        </div>
                        <div>
                          <h3 className="text-sm font-medium text-slate-700 mb-2">Decrypted Image</h3>
                          <div className="border rounded-lg overflow-hidden">
                            <img
                              src={decryptedUrl}
                              alt="Decrypted"
                              className="w-full h-48 object-cover bg-slate-50"
                            />
                          </div>
                        </div>
                      </div>
                    )}
                    
                    {encryptedImage && (
                      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                        <div className="flex items-start gap-2">
                          <div className="w-5 h-5 bg-yellow-100 rounded-full flex items-center justify-center mt-0.5">
                            <span className="text-yellow-600 text-xs font-bold">!</span>
                          </div>
                          <div>
                            <p className="text-sm font-medium text-yellow-800">Important:</p>
                            <p className="text-sm text-yellow-700">
                              Make sure to remember your password! There is no way to recover an encrypted image if you forget the password used for encryption.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};