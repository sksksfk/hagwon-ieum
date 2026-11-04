// Browser-only ES module: no persistence, DOM, network, or password retention.
export const VAULT_FORMAT = 'hagwon-ieum-vault';
export const KDF_ITERATIONS = 310000;
const vaultMaxPlaintextBytes = 5 * 1024 * 1024;
const vaultMaxCiphertextBytes = vaultMaxPlaintextBytes + 16;
const vaultFields = ['format', 'version', 'kdf', 'iterations', 'salt', 'iv', 'ciphertext'];
// AAD is deliberately independent of object/property order and authenticates v1.
const vaultAAD = new TextEncoder().encode(VAULT_FORMAT + ':v1');
const vaultUnlockError = '비밀번호가 올바르지 않거나 암호화 파일이 손상되었습니다.';

export function assertVaultPassword(password) {
  if (typeof password !== 'string' || !password.trim()) {
    throw new Error('비밀번호는 공백이 아닌 12~256자여야 합니다.');
  }
  let vaultCount = 0;
  for (const vaultPoint of password) {
    if (++vaultCount > 256) throw new Error('비밀번호는 12~256자여야 합니다.');
  }
  if (vaultCount < 12) throw new Error('비밀번호는 12~256자여야 합니다.');
  return password;
}

function vaultEncodeBase64(bytes) {
  let vaultBinary = '';
  // Small chunks avoid argument limits on multi-megabyte browser backups.
  for (let vaultOffset = 0; vaultOffset < bytes.length; vaultOffset += 8192) {
    let vaultChunk = '';
    const vaultEnd = Math.min(bytes.length, vaultOffset + 8192);
    for (let vaultIndex = vaultOffset; vaultIndex < vaultEnd; vaultIndex++) {
      vaultChunk += String.fromCharCode(bytes[vaultIndex]);
    }
    vaultBinary += vaultChunk;
  }
  return btoa(vaultBinary);
}

function vaultDecodeBase64(value, minBytes, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 ||
      value.length > 4 * Math.ceil(maxBytes / 3) || value.length % 4 !== 0) {
    throw new Error('암호화 파일의 인코딩 또는 크기가 올바르지 않습니다.');
  }
  // Scan quartets instead of a large repeated regex (which can overflow stacks).
  const vaultPadding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const vaultSize = value.length / 4 * 3 - vaultPadding;
  if (vaultSize < minBytes || vaultSize > maxBytes) throw new Error('암호화 파일 크기가 올바르지 않습니다.');
  for (let vaultIndex = 0; vaultIndex < value.length - vaultPadding; vaultIndex++) {
    const vaultCode = value.charCodeAt(vaultIndex);
    if (!((vaultCode >= 65 && vaultCode <= 90) || (vaultCode >= 97 && vaultCode <= 122) ||
          (vaultCode >= 48 && vaultCode <= 57) || vaultCode === 43 || vaultCode === 47)) {
      throw new Error('암호화 파일의 Base64가 올바르지 않습니다.');
    }
  }
  const vaultBinary = atob(value);
  const vaultBytes = new Uint8Array(vaultBinary.length);
  for (let vaultIndex = 0; vaultIndex < vaultBinary.length; vaultIndex++) {
    vaultBytes[vaultIndex] = vaultBinary.charCodeAt(vaultIndex);
  }
  // atob accepts nonzero padding bits; canonical encoding must not.
  if (vaultEncodeBase64(vaultBytes) !== value) throw new Error('암호화 파일의 Base64가 올바르지 않습니다.');
  return vaultBytes;
}

export function validateVaultEnvelope(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input))) {
    throw new Error('지원하지 않는 암호화 파일 형식입니다.');
  }
  const vaultKeys = Reflect.ownKeys(input);
  if (vaultKeys.length !== vaultFields.length || vaultKeys.some(vaultKey => !vaultFields.includes(vaultKey))) {
    throw new Error('암호화 파일의 필드가 올바르지 않습니다.');
  }
  const vaultEnvelope = {};
  for (const vaultField of vaultFields) {
    const vaultDescriptor = Object.getOwnPropertyDescriptor(input, vaultField);
    if (!vaultDescriptor || !Object.hasOwn(vaultDescriptor, 'value') || !vaultDescriptor.enumerable) {
      throw new Error('암호화 파일의 필드가 올바르지 않습니다.');
    }
    vaultEnvelope[vaultField] = vaultDescriptor.value;
  }
  if (vaultEnvelope.format !== VAULT_FORMAT || vaultEnvelope.version !== 1 ||
      vaultEnvelope.kdf !== 'PBKDF2-SHA256' || vaultEnvelope.iterations !== KDF_ITERATIONS) {
    throw new Error('지원하지 않는 암호화 파일 형식입니다.');
  }
  vaultDecodeBase64(vaultEnvelope.salt, 16, 16);
  vaultDecodeBase64(vaultEnvelope.iv, 12, 12);
  vaultDecodeBase64(vaultEnvelope.ciphertext, 16, vaultMaxCiphertextBytes);
  return vaultEnvelope;
}

function vaultCheckJSON(value, ancestors) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'object' || ancestors.has(value)) throw new Error('지원하지 않는 JSON 값입니다.');
  const vaultArray = Array.isArray(value);
  if (!(vaultArray ? [Array.prototype, null] : [Object.prototype, null]).includes(Object.getPrototypeOf(value))) {
    throw new Error('일반 JSON 객체만 암호화할 수 있습니다.');
  }
  const vaultKeys = Reflect.ownKeys(value);
  if (vaultArray && (vaultKeys.length !== value.length + 1 || value.length > vaultMaxPlaintextBytes / 2)) {
    throw new Error('빈 배열 요소 또는 너무 큰 JSON 배열입니다.');
  }
  ancestors.add(value);
  for (const vaultKey of vaultKeys) {
    if (vaultArray && vaultKey === 'length') continue;
    const vaultDescriptor = Object.getOwnPropertyDescriptor(value, vaultKey);
    if (typeof vaultKey !== 'string' || !vaultDescriptor.enumerable || !Object.hasOwn(vaultDescriptor, 'value') ||
        (vaultArray && (!/^(0|[1-9][0-9]*)$/.test(vaultKey) || Number(vaultKey) >= value.length))) {
      throw new Error('지원하지 않는 JSON 속성입니다.');
    }
    vaultCheckJSON(vaultDescriptor.value, ancestors);
  }
  ancestors.delete(value);
}

function vaultSerialize(data) {
  vaultCheckJSON(data, new WeakSet());
  const vaultJSON = JSON.stringify(data);
  // UTF-16 length is a cheap lower bound before allocating the UTF-8 buffer.
  if (vaultJSON.length > vaultMaxPlaintextBytes) throw new Error('암호화할 데이터는 5MiB 이하여야 합니다.');
  const vaultBytes = new TextEncoder().encode(vaultJSON);
  if (vaultBytes.byteLength > vaultMaxPlaintextBytes) throw new Error('암호화할 데이터는 5MiB 이하여야 합니다.');
  return vaultBytes;
}

async function vaultDeriveKey(password, salt) {
  const vaultPasswordBytes = new TextEncoder().encode(password);
  try {
    const vaultMaterial = await globalThis.crypto.subtle.importKey('raw', vaultPasswordBytes, 'PBKDF2', false, ['deriveKey']);
    return await globalThis.crypto.subtle.deriveKey(
      {name: 'PBKDF2', hash: 'SHA-256', salt, iterations: KDF_ITERATIONS},
      vaultMaterial, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']
    );
  } finally {
    vaultPasswordBytes.fill(0);
  }
}

async function vaultEncryptBytes(bytes, key, saltBase64) {
  vaultDecodeBase64(saltBase64, 16, 16);
  if (!key || key.type !== 'secret' || key.extractable !== false ||
      key.algorithm?.name !== 'AES-GCM' || key.algorithm?.length !== 256 ||
      !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
    throw new Error('유효한 잠금 해제 키가 필요합니다.');
  }
  const vaultIV = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const vaultCiphertext = await globalThis.crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: vaultIV, additionalData: vaultAAD, tagLength: 128}, key, bytes
  );
  return {
    format: VAULT_FORMAT, version: 1, kdf: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS,
    salt: saltBase64, iv: vaultEncodeBase64(vaultIV), ciphertext: vaultEncodeBase64(new Uint8Array(vaultCiphertext))
  };
}

export async function createVault(data, password) {
  assertVaultPassword(password);
  const vaultBytes = vaultSerialize(data);
  const vaultSalt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  try {
    const vaultKey = await vaultDeriveKey(password, vaultSalt);
    const vaultEnvelope = await vaultEncryptBytes(vaultBytes, vaultKey, vaultEncodeBase64(vaultSalt));
    return {envelope: vaultEnvelope, key: vaultKey};
  } finally {
    vaultBytes.fill(0);
  }
}

export async function encryptVault(data, key, saltBase64) {
  const vaultBytes = vaultSerialize(data);
  try {
    return await vaultEncryptBytes(vaultBytes, key, saltBase64);
  } finally {
    vaultBytes.fill(0);
  }
}

export async function unlockVault(envelope, password) {
  let vaultPlaintext;
  try {
    assertVaultPassword(password);
    const vaultEnvelope = validateVaultEnvelope(envelope);
    const vaultKey = await vaultDeriveKey(password, vaultDecodeBase64(vaultEnvelope.salt, 16, 16));
    vaultPlaintext = new Uint8Array(await globalThis.crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: vaultDecodeBase64(vaultEnvelope.iv, 12, 12), additionalData: vaultAAD, tagLength: 128},
      vaultKey, vaultDecodeBase64(vaultEnvelope.ciphertext, 16, vaultMaxCiphertextBytes)
    ));
    const vaultData = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(vaultPlaintext));
    return {data: vaultData, key: vaultKey};
  } catch {
    // Do not disclose password validity, plaintext, or a crypto/parser error.
    throw new Error(vaultUnlockError);
  } finally {
    vaultPlaintext?.fill(0);
  }
}
