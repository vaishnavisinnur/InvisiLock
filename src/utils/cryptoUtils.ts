// src/utils/cryptoUtils.ts

export async function encryptData(imageBuffer: ArrayBuffer, password: string): Promise<ArrayBuffer> {
  const imageBitmap = await createImageBitmap(new Blob([imageBuffer]));
  const canvas = document.createElement("canvas");
  canvas.width = imageBitmap.width;
  canvas.height = imageBitmap.height;
  const ctx = canvas.getContext("2d")!;
  ctx.drawImage(imageBitmap, 0, 0);

  const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const pixels = imgData.data;

  // Simple XOR encryption with password-derived key
  const key = new TextEncoder().encode(password);
  for (let i = 0; i < pixels.length; i++) {
    pixels[i] ^= key[i % key.length];
  }

  ctx.putImageData(imgData, 0, 0);

  // Export scrambled PNG as ArrayBuffer
  const blob = await new Promise<Blob>((resolve) => canvas.toBlob(b => resolve(b!), "image/png"));
  return await blob.arrayBuffer();
}

export async function decryptData(imageBuffer: ArrayBuffer, password: string): Promise<ArrayBuffer> {
  // Since XOR is symmetric, same process as encrypt
  return encryptData(imageBuffer, password);
}
