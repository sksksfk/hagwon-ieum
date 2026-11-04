import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {VAULT_FORMAT, KDF_ITERATIONS, validateVaultEnvelope, assertVaultPassword, createVault, encryptVault, unlockVault} from '../vault.js';

const password = '가족 잠금 암호 2026!';
const maxBytes = 5 * 1024 * 1024;
// Synthetic fixture only, never real contacts or credentials.
const family = {
  version: 1,
  children: [{id: 'child-a', name: '서윤', grade: '초등 3학년'}, {id: 'child-b', name: '도윤', grade: '초등 1학년'}],
  contacts: [{name: '돌봄 선생님', phone: '010-1234-5678'}],
  schoolPlans: [{childId: 'child-a', school: '가상 이음초등학교', care: {teacher: '김선생', room: '돌봄 2교실', phone: '02-123-4567'}, after: [{title: '과학 실험', end: '15:00'}]}],
  schedules: [{childId: 'child-b', title: '태권도', place: '가상 이음도장 서울시 예시로 123', vehicle: '2호차'}],
  fees: [{id: 'fee-a', childId: 'child-a', academy: '가상 영어학원', amount: 230000, dueDay: 15}],
  payments: [{feeId: 'fee-a', month: '2026-11', paidDate: '2026-11-03', amount: 230000}],
  prefs: {showNow: true}, note: '한글과 이모지 🌱, 따옴표 " 및 줄바꿈\n'
};
const fixture = createVault(family, password);
const flip = encoded => {
  const bytes = Buffer.from(encoded, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
};
const genericError = '비밀번호가 올바르지 않거나 암호화 파일이 손상되었습니다.';

test('exports use the fixed v1 format and PBKDF2 work factor', () => {
  assert.equal(VAULT_FORMAT, 'hagwon-ieum-vault');
  assert.equal(KDF_ITERATIONS, 310000);
});

test('Korean multi-child school, contacts, timetable and fees round-trip', async () => {
  const {envelope} = await fixture;
  const result = await unlockVault(JSON.parse(JSON.stringify(envelope)), password);
  assert.deepEqual(result.data, family);
  assert.deepEqual(Object.keys(result).sort(), ['data', 'key']);
});

test('envelope has exact metadata and no plaintext, password, location or contacts', async () => {
  const {envelope} = await fixture;
  assert.deepEqual(Object.keys(envelope), ['format', 'version', 'kdf', 'iterations', 'salt', 'iv', 'ciphertext']);
  const json = JSON.stringify(envelope);
  for (const secret of [password, '서윤', '도윤', '010-1234-5678', '02-123-4567', '가상 이음도장', '서울시 예시로 123', 'schoolPlans', 'payments']) assert.equal(json.includes(secret), false);
  assert.equal(Buffer.from(envelope.salt, 'base64').length, 16);
  assert.equal(Buffer.from(envelope.iv, 'base64').length, 12);
  assert.equal(Buffer.from(envelope.ciphertext, 'base64').length, Buffer.byteLength(JSON.stringify(family)) + 16);
});

test('created and unlocked AES-GCM256 keys are non-extractable', async () => {
  const created = await fixture;
  const unlocked = await unlockVault(created.envelope, password);
  for (const key of [created.key, unlocked.key]) {
    assert.equal(key.extractable, false);
    assert.equal(key.type, 'secret');
    assert.equal(key.algorithm.name, 'AES-GCM');
    assert.equal(key.algorithm.length, 256);
    assert.deepEqual([...key.usages].sort(), ['decrypt', 'encrypt']);
    await assert.rejects(crypto.subtle.exportKey('raw', key));
  }
});

test('every create gets a new salt and IV even for the same data/password', async () => {
  const first = await fixture;
  const second = await createVault(family, password);
  assert.notEqual(first.envelope.salt, second.envelope.salt);
  assert.notEqual(first.envelope.iv, second.envelope.iv);
  assert.notEqual(first.envelope.ciphertext, second.envelope.ciphertext);
});

test('re-encryption keeps salt/key and refreshes IV and ciphertext', async () => {
  const {envelope, key} = await fixture;
  const next = await encryptVault(family, key, envelope.salt);
  const third = await encryptVault({...family, note: '수정한 납부 메모'}, key, envelope.salt);
  assert.equal(next.salt, envelope.salt);
  assert.equal(third.salt, envelope.salt);
  assert.equal(new Set([envelope.iv, next.iv, third.iv]).size, 3);
  assert.notEqual(next.ciphertext, envelope.ciphertext);
  assert.deepEqual((await unlockVault(next, password)).data, family);
  assert.equal((await unlockVault(third, password)).data.note, '수정한 납부 메모');
});

test('wrong password returns only the generic Korean failure', async () => {
  const {envelope} = await fixture;
  await assert.rejects(unlockVault(envelope, '잘못된 다른 비밀번호 2026!'), error => {
    assert.equal(error.message, genericError);
    assert.equal('data' in error, false);
    assert.equal('cause' in error, false);
    return true;
  });
});

test('ciphertext, salt and IV tampering all fail identically', async () => {
  const {envelope} = await fixture;
  for (const field of ['ciphertext', 'salt', 'iv']) await assert.rejects(unlockVault({...envelope, [field]: flip(envelope[field])}, password), {message: genericError});
});

test('metadata tampering and short unlock password reveal no detailed failure', async () => {
  const {envelope} = await fixture;
  for (const patch of [{format: 'other'}, {version: 2}, {kdf: 'PBKDF2-SHA1'}, {iterations: 1}, {extra: 'x'}]) await assert.rejects(unlockVault({...envelope, ...patch}, password), {message: genericError});
  await assert.rejects(unlockVault(envelope, 'short'), {message: genericError});
});

test('password minimum/maximum are Unicode codepoints and nonblank', () => {
  for (const bad of [undefined, null, 123, '', 'short', 'a'.repeat(11), ' '.repeat(12), '\t\n'.repeat(10), 'a'.repeat(257), '😀'.repeat(257), '😀'.repeat(11)]) assert.throws(() => assertVaultPassword(bad));
  for (const good of ['a'.repeat(12), 'a'.repeat(256), '😀'.repeat(12), '😀'.repeat(256), ' '.repeat(11) + 'a']) assert.equal(assertVaultPassword(good), good);
});

test('create rejects short passwords', async () => {
  await assert.rejects(createVault(family, 'short'));
});

test('password whitespace is significant and never trimmed', async () => {
  const spaced = '  keep my spaces  ';
  const {envelope} = await createVault({value: '보호'}, spaced);
  assert.deepEqual((await unlockVault(envelope, spaced)).data, {value: '보호'});
  await assert.rejects(unlockVault(envelope, spaced.trim()), {message: genericError});
});

test('password Unicode normalization is not changed', async () => {
  const composed = 'é'.repeat(12);
  const {envelope} = await createVault(null, composed);
  assert.equal((await unlockVault(envelope, composed)).data, null);
  await assert.rejects(unlockVault(envelope, composed.normalize('NFD')), {message: genericError});
});

test('validated envelope is a fresh canonical object and does not mutate input', async () => {
  const {envelope} = await fixture;
  const reordered = Object.fromEntries(Object.entries(envelope).reverse());
  Object.freeze(reordered);
  const result = validateVaultEnvelope(reordered);
  assert.notEqual(result, reordered);
  assert.deepEqual(result, envelope);
  assert.deepEqual(Object.keys(result), Object.keys(envelope));
});

test('envelope rejects missing, unknown, symbol, hidden and accessor fields', async () => {
  const {envelope} = await fixture;
  const missing = {...envelope}; delete missing.iv;
  const symbolic = {...envelope, [Symbol('secret')]: true};
  const hidden = {...envelope}; Object.defineProperty(hidden, 'iv', {value: envelope.iv, enumerable: false});
  const accessor = {...envelope}; Object.defineProperty(accessor, 'salt', {get() {throw new Error('must not execute');}, enumerable: true});
  for (const bad of [null, [], '', new Date(), missing, {...envelope, data: family}, symbolic, hidden, accessor]) assert.throws(() => validateVaultEnvelope(bad));
});

test('fixed format/version/KDF/iterations reject incorrect values and types', async () => {
  const {envelope} = await fixture;
  for (const patch of [{format: 'HAGWON-IEUM-VAULT'}, {version: 0}, {version: 2}, {version: '1'}, {kdf: 'AES-GCM'}, {iterations: 309999}, {iterations: 310001}, {iterations: '310000'}]) assert.throws(() => validateVaultEnvelope({...envelope, ...patch}));
});

test('strict Base64 rejects whitespace, URL alphabet, padding and nonzero pad bits', async () => {
  const {envelope} = await fixture;
  for (const salt of ['', 123, envelope.salt + '\n', ' ' + envelope.salt, envelope.salt.replace(/=+$/, ''), '!!!!'.repeat(6), '____'.repeat(6), 'AAAA=AAA', 'AAAAAAAAAAAAAAAAAAAAAB==']) assert.throws(() => validateVaultEnvelope({...envelope, salt}));
  assert.throws(() => validateVaultEnvelope({...envelope, ciphertext: 'AAAAAAAAAAAAAAAAAAAAAB=='}));
});

test('salt/IV exact byte lengths and GCM minimum tag length are enforced', async () => {
  const {envelope} = await fixture;
  for (const [field, sizes] of [['salt', [0, 15, 17]], ['iv', [0, 11, 13]], ['ciphertext', [0, 1, 15]]]) {
    for (const size of sizes) assert.throws(() => validateVaultEnvelope({...envelope, [field]: Buffer.alloc(size).toString('base64')}));
  }
  validateVaultEnvelope({...envelope, ciphertext: Buffer.alloc(16).toString('base64')});
});

test('oversized Base64 and ciphertext cannot exceed 5MiB plus GCM tag', async () => {
  const {envelope} = await fixture;
  assert.throws(() => validateVaultEnvelope({...envelope, salt: 'A'.repeat(1000)}));
  assert.throws(() => validateVaultEnvelope({...envelope, iv: 'A'.repeat(1000)}));
  assert.throws(() => validateVaultEnvelope({...envelope, ciphertext: Buffer.alloc(maxBytes + 17).toString('base64')}));
});

test('5MiB JSON plaintext boundary round-trips without base64 argument overflow', async () => {
  const {envelope, key} = await fixture;
  const data = 'x'.repeat(maxBytes - 2);
  const large = await encryptVault(data, key, envelope.salt);
  assert.equal(Buffer.from(large.ciphertext, 'base64').length, maxBytes + 16);
  assert.deepEqual(validateVaultEnvelope(large), large);
  assert.equal((await unlockVault(large, password)).data, data);
});

test('UTF-8 byte size rather than character count limits JSON data', async () => {
  const {envelope, key} = await fixture;
  await assert.rejects(encryptVault('x'.repeat(maxBytes - 1), key, envelope.salt));
  await assert.rejects(encryptVault('가'.repeat(Math.floor(maxBytes / 3) + 1), key, envelope.salt));
  await assert.rejects(createVault('x'.repeat(maxBytes), password));
});

test('unsupported JSON values fail rather than silently dropping or changing them', async () => {
  const {envelope, key} = await fixture;
  const circular = {}; circular.self = circular;
  const accessor = {}; Object.defineProperty(accessor, 'value', {get() {throw new Error('must not execute');}, enumerable: true});
  const hidden = {}; Object.defineProperty(hidden, 'hidden', {value: 1});
  const extraArray = [1]; extraArray.extra = 2;
  const invalid = [undefined, NaN, Infinity, -Infinity, 1n, Symbol('x'), () => {}, {value: undefined}, {value: NaN}, {value: 1n}, [undefined], new Array(2), new Date(), new Map(), new Set(), new Number(1), /test/, circular, accessor, hidden, {[Symbol('x')]: 1}, {toJSON() {return {}; }}, extraArray];
  for (const data of invalid) await assert.rejects(encryptVault(data, key, envelope.salt));
});

test('JSON primitive roots, null-prototype objects and repeated noncyclic references work', async () => {
  const {envelope, key} = await fixture;
  const repeated = {name: '공유 참조'};
  for (const data of [null, false, 0, '한글', [repeated, repeated], Object.assign(Object.create(null), {a: 1})]) {
    const encrypted = await encryptVault(data, key, envelope.salt);
    const decoded = await unlockVault(encrypted, password);
    assert.deepEqual(decoded.data, JSON.parse(JSON.stringify(data)));
  }
});

test('encrypt rejects missing/extractable/wrong keys and invalid salt', async () => {
  const {envelope, key} = await fixture;
  const extractable = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt']);
  const wrongLength = await crypto.subtle.generateKey({name: 'AES-GCM', length: 128}, false, ['encrypt', 'decrypt']);
  for (const badKey of [null, {}, extractable, wrongLength]) await assert.rejects(encryptVault({}, badKey, envelope.salt));
  await assert.rejects(encryptVault({}, key, 'invalid'));
});

test('independent PBKDF2/AES-GCM verifies exact SHA256/AAD/tag settings', async () => {
  const {envelope} = await fixture;
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt: Buffer.from(envelope.salt, 'base64'), iterations: 310000}, material, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
  const settings = {name: 'AES-GCM', iv: Buffer.from(envelope.iv, 'base64'), additionalData: new TextEncoder().encode('hagwon-ieum-vault:v1'), tagLength: 128};
  const plain = await crypto.subtle.decrypt(settings, key, Buffer.from(envelope.ciphertext, 'base64'));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(plain)), family);
  await assert.rejects(crypto.subtle.decrypt({...settings, additionalData: new TextEncoder().encode('hagwon-ieum-vault:v2')}, key, Buffer.from(envelope.ciphertext, 'base64')));
});

test('authenticated invalid JSON and UTF-8 still return only generic unlock errors', async () => {
  const {envelope, key} = await fixture;
  for (const bytes of [new TextEncoder().encode('not JSON'), new Uint8Array([0xff])]) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('hagwon-ieum-vault:v1'), tagLength: 128}, key, bytes);
    const malformed = {...envelope, iv: Buffer.from(iv).toString('base64'), ciphertext: Buffer.from(cipher).toString('base64')};
    await assert.rejects(unlockVault(malformed, password), {message: genericError});
  }
});

test('stripped exports concatenate with core without global name collisions', async () => {
  const core = await readFile(new URL('../core.js', import.meta.url), 'utf8');
  const vault = await readFile(new URL('../vault.js', import.meta.url), 'utf8');
  runInNewContext(core.replaceAll('export ', '') + '\n' + vault.replaceAll('export ', '') + '\nif (VAULT_FORMAT !== "hagwon-ieum-vault") throw Error("format");', {TextEncoder, TextDecoder});
});
