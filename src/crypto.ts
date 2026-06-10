const textEncoder = new TextEncoder();

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

export { bufToHex, hexToBuf };

export async function deriveKeys(password: string): Promise<{
  roomId: string;
  aesKey: CryptoKey;
  hmacKey: CryptoKey;
  aesBits: ArrayBuffer;
  hmacBits: ArrayBuffer;
}> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'HKDF',
    false,
    ['deriveBits', 'deriveKey']
  );

  const roomIdBuf = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new ArrayBuffer(0), info: textEncoder.encode('room-id') },
    keyMaterial,
    128
  );
  const roomId = bufToHex(roomIdBuf);

  const aesBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new ArrayBuffer(0), info: textEncoder.encode('aes-key') },
    keyMaterial,
    256
  );
  const aesKey = await crypto.subtle.importKey(
    'raw', aesBits,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const hmacBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new ArrayBuffer(0), info: textEncoder.encode('hmac-key') },
    keyMaterial,
    256
  );
  const hmacKey = await crypto.subtle.importKey(
    'raw', hmacBits,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

  return { roomId, aesKey, hmacKey, aesBits, hmacBits };
}

export async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
}

export async function exportPublicKey(key: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey('raw', key);
}

export async function importPublicKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

export async function deriveECDHShared(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
}

export async function combineKeys(
  baseAESBits: ArrayBuffer,
  baseHMACBits: ArrayBuffer,
  ecdhSecret: ArrayBuffer
): Promise<{ aesKey: CryptoKey; hmacKey: CryptoKey }> {
  const combinedAES = new Uint8Array(64);
  combinedAES.set(new Uint8Array(baseAESBits), 0);
  combinedAES.set(new Uint8Array(ecdhSecret), 32);
  const aesMaterial = await crypto.subtle.importKey('raw', combinedAES, 'HKDF', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new ArrayBuffer(0), info: textEncoder.encode('session-aes') },
    aesMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const combinedHMAC = new Uint8Array(64);
  combinedHMAC.set(new Uint8Array(baseHMACBits), 0);
  combinedHMAC.set(new Uint8Array(ecdhSecret), 32);
  const hmacMaterial = await crypto.subtle.importKey('raw', combinedHMAC, 'HKDF', false, ['deriveKey']);
  const hmacKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new ArrayBuffer(0), info: textEncoder.encode('session-hmac') },
    hmacMaterial,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

  return { aesKey, hmacKey };
}

export async function encryptChunk(
  aesKey: CryptoKey,
  hmacKey: CryptoKey,
  chunkIndex: number,
  plaintext: ArrayBuffer
): Promise<ArrayBuffer> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    plaintext
  );

  const hmacInput = new Uint8Array(4 + 12 + ciphertext.byteLength);
  const hw = new DataView(hmacInput.buffer);
  hw.setUint32(0, chunkIndex, false);
  hmacInput.set(iv, 4);
  hmacInput.set(new Uint8Array(ciphertext), 16);

  const hmac = await crypto.subtle.sign('HMAC', hmacKey, hmacInput);

  const packet = new Uint8Array(4 + 12 + ciphertext.byteLength + 32);
  const pw = new DataView(packet.buffer);
  pw.setUint32(0, chunkIndex, false);
  packet.set(iv, 4);
  packet.set(new Uint8Array(ciphertext), 16);
  packet.set(new Uint8Array(hmac), 16 + ciphertext.byteLength);

  return packet.buffer;
}

export async function decryptChunk(
  aesKey: CryptoKey,
  hmacKey: CryptoKey,
  packet: ArrayBuffer
): Promise<{ chunkIndex: number; plaintext: ArrayBuffer }> {
  const data = new Uint8Array(packet);
  const view = new DataView(packet);

  const chunkIndex = view.getUint32(0, false);
  const iv = data.slice(4, 16);
  const ciphertextLen = packet.byteLength - 4 - 12 - 32;
  const ciphertext = data.slice(16, 16 + ciphertextLen);
  const receivedHmac = data.slice(16 + ciphertextLen);

  const hmacInput = new Uint8Array(4 + 12 + ciphertext.length);
  const hw = new DataView(hmacInput.buffer);
  hw.setUint32(0, chunkIndex, false);
  hmacInput.set(iv, 4);
  hmacInput.set(ciphertext, 16);

  const valid = await crypto.subtle.verify('HMAC', hmacKey, receivedHmac, hmacInput);
  if (!valid) throw new Error('HMAC verification failed for chunk ' + chunkIndex);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    ciphertext
  );

  return { chunkIndex, plaintext };
}

export async function hashBuffer(buf: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return bufToHex(hash);
}

export function zeroBuffer(buf: ArrayBuffer): void {
  new Uint8Array(buf).fill(0);
}

export function bufToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuf(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

const CHUNK_SIZE = 65536;

export { CHUNK_SIZE };
