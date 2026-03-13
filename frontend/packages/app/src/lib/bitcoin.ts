/**
 * Bitcoin deposit address derivation.
 *
 * Ports the Rust implementation from:
 *   - fastcrypto_tbls::threshold_schnorr::key_derivation (HKDF-SHA3-256 tweak)
 *   - hashi-types::guardian::bitcoin_utils (taproot script-path address)
 *
 * Algorithm:
 *   1. tweak = HKDF-SHA3-256(ikm = x(mpcKey) || suiAddress, salt = [], info = [], len = 64)
 *   2. scalar = tweak mod n  (secp256k1 group order)
 *   3. derivedPoint = mpcKey + scalar * G
 *   4. xOnly = x-coordinate of derivedPoint (with even Y normalization)
 *   5. address = P2TR script-path using NUMS internal key + <xOnly> OP_CHECKSIG leaf
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, concatBytes, hexToBytes, numberToBytesBE } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bech32, bech32m } from '@scure/base';

/**
 * Convert a 33-byte ark-works compressed secp256k1 point to standard bitcoin
 * compressed format (02/03 prefix + 32-byte big-endian x).
 *
 * ark-works format: 32 bytes x (little-endian) + 1 flag byte
 *
 * ark-works uses "positive/negative" Y convention:
 *   flag 0x00 = "positive" Y  (y <= (p-1)/2)
 *   flag 0x80 = "negative" Y  (y > (p-1)/2)
 *
 * Bitcoin uses even/odd Y convention:
 *   02 prefix = even Y  (y % 2 == 0)
 *   03 prefix = odd Y   (y % 2 == 1)
 *
 * These are NOT the same! We must recover the actual Y to determine even/odd.
 */
export function arkworksToCompressedHex(arkBytes: number[] | Uint8Array): string {
	if (arkBytes.length !== 33) {
		throw new Error(`Expected 33 bytes, got ${arkBytes.length}`);
	}
	const xLE = Array.from(arkBytes.slice(0, 32));
	const flag = arkBytes[32];
	const xBE = xLE.slice().reverse();
	const xHex = xBE.map((b) => b.toString(16).padStart(2, '0')).join('');

	// Recover the full point to determine actual Y parity.
	// Try with 02 prefix (even Y), check if it matches the ark-works flag.
	const x = BigInt('0x' + xHex);
	const isArkPositive = (flag & 0x80) === 0; // 0x00 = positive (y <= (p-1)/2)

	// secp256k1 field prime
	const P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
	const halfP = (P - 1n) / 2n;

	// Recover Y from x: y^2 = x^3 + 7 mod p
	const x3 = modPow(x, 3n, P);
	const y2 = (x3 + 7n) % P;
	const y = modPow(y2, (P + 1n) / 4n, P); // sqrt via p ≡ 3 mod 4

	// Pick the Y that matches the ark-works flag
	const yPositive = y <= halfP ? y : P - y; // "positive" = smaller half
	const actualY = isArkPositive ? yPositive : P - yPositive;

	// Now determine Bitcoin prefix from even/odd
	const prefix = actualY % 2n === 0n ? '02' : '03';
	return prefix + xHex;
}

/** Modular exponentiation: base^exp mod m */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
	let result = 1n;
	base = base % m;
	while (exp > 0n) {
		if (exp % 2n === 1n) result = (result * base) % m;
		exp = exp / 2n;
		base = (base * base) % m;
	}
	return result;
}

// secp256k1 group order
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

// BIP-341 NUMS (Nothing-Up-My-Sleeve) internal key — no known private key
const NUMS_X = BigInt('0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0');

const Point = schnorr.Point;

/**
 * Derive a Bitcoin taproot deposit address from the committee's MPC public key
 * and a recipient Sui address.
 *
 * @param mpcPubkeyHex - 33-byte compressed secp256k1 public key (hex, with 02/03 prefix)
 * @param suiAddress   - 32-byte Sui address (hex, with or without 0x prefix)
 * @param network      - 'mainnet' | 'testnet' (controls bech32m prefix)
 * @returns Bitcoin P2TR address string
 */
export function deriveDepositAddress(
	mpcPubkeyHex: string,
	suiAddress: string,
	network: 'mainnet' | 'testnet' | 'regtest' = 'testnet',
): string {
	// 1. Parse the MPC public key (33-byte compressed) into a curve point
	const mpcPoint = Point.fromHex(mpcPubkeyHex);

	// 2. Extract x-coordinate as 32 bytes big-endian
	const mpcAffine = mpcPoint.toAffine();
	const xBytes = numberToBytesBE(mpcAffine.x, 32);

	// 3. Parse the Sui address (remove 0x prefix if present)
	const addrHex = suiAddress.startsWith('0x') ? suiAddress.slice(2) : suiAddress;
	const addrBytes = hexToBytes(addrHex);

	// 4. Compute tweak via HKDF-SHA3-256
	//    ikm = x_bytes || sui_address (64 bytes)
	//    salt = empty, info = empty, output = 64 bytes
	const ikm = concatBytes(xBytes, addrBytes);
	const tweakBytes = hkdf(sha3_256, ikm, new Uint8Array(0), new Uint8Array(0), 64);

	// 5. Reduce 64 bytes mod group order to get scalar
	const tweakScalar = bytesToNumberBE(tweakBytes) % N;

	// 6. Derive new point: mpcKey + tweakScalar * G
	const tweakPoint = Point.BASE.multiply(tweakScalar);
	const derivedPoint = mpcPoint.add(tweakPoint);

	// 7. Get x-only representation (32 bytes)
	const derived = derivedPoint.toAffine();
	const xOnly = numberToBytesBE(derived.x, 32);

	// 8. Build P2TR address with script-path spending
	return buildTaprootScriptPathAddress(xOnly, network);
}

/**
 * Build a P2TR address using script-path spending with a single
 * <pubkey> OP_CHECKSIG leaf and a NUMS internal key.
 *
 * taproot_output_key = internal_key + t*G
 * where t = tagged_hash("TapTweak", internal_key || merkle_root)
 */
function buildTaprootScriptPathAddress(
	xOnlyPubkey: Uint8Array,
	network: 'mainnet' | 'testnet' | 'regtest',
): string {
	// Build the leaf script: <xOnlyPubkey> OP_CHECKSIG
	const leafScript = concatBytes(
		Uint8Array.of(0x20), // push 32 bytes
		xOnlyPubkey,
		Uint8Array.of(0xac), // OP_CHECKSIG
	);

	// Compute the leaf hash: tagged_hash("TapLeaf", [leafVersion, compactSize(script), script])
	const leafVersion = 0xc0; // TapScript leaf version
	const scriptLen = compactSize(leafScript.length);
	const leafData = concatBytes(Uint8Array.of(leafVersion), scriptLen, leafScript);
	const leafHash = taggedHash('TapLeaf', leafData);

	// For a single-leaf tree, the merkle root IS the leaf hash
	const merkleRoot = leafHash;

	// Internal key is NUMS point (x-only, 32 bytes)
	const internalKey = numberToBytesBE(NUMS_X, 32);

	// Compute the tweak: t = tagged_hash("TapTweak", internal_key || merkle_root)
	const tweakHash = taggedHash('TapTweak', concatBytes(internalKey, merkleRoot));
	const t = bytesToNumberBE(tweakHash) % N;

	// Compute output key: P = lift_x(internal_key) + t*G
	const internalPoint = schnorr.utils.lift_x(NUMS_X);
	const tweakPoint = Point.BASE.multiply(t);
	const outputPoint = internalPoint.add(tweakPoint);
	const outputAffine = outputPoint.toAffine();

	// The output key x-coordinate (32 bytes)
	const outputKey = numberToBytesBE(outputAffine.x, 32);

	// Encode as bech32m: witness version 1 + 32-byte output key
	const hrp = network === 'mainnet' ? 'bc' : network === 'regtest' ? 'bcrt' : 'tb';
	const words = [1, ...bech32m.toWords(outputKey)]; // witness v1
	return bech32m.encode(hrp, words);
}

// -- Helpers --

/** BIP-340/341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data) */
function taggedHash(tag: string, data: Uint8Array): Uint8Array {
	const tagBytes = new TextEncoder().encode(tag);
	const tagHash = sha256(tagBytes);
	return sha256(concatBytes(tagHash, tagHash, data));
}

/** Bitcoin compact size encoding */
function compactSize(n: number): Uint8Array {
	if (n < 0xfd) return Uint8Array.of(n);
	if (n <= 0xffff) {
		const buf = new Uint8Array(3);
		buf[0] = 0xfd;
		buf[1] = n & 0xff;
		buf[2] = (n >> 8) & 0xff;
		return buf;
	}
	throw new Error('compactSize too large');
}

/**
 * Extract the witness program bytes from a Bitcoin bech32/bech32m address.
 *
 * This matches the Rust `witness_program_from_address` function which extracts:
 *   - P2WPKH (v0): 20 bytes
 *   - P2TR (v1): 32 bytes
 */
export function bitcoinAddressToWitnessProgram(address: string): number[] {
	// Try bech32m first (taproot / v1+), then bech32 (segwit v0)
	let decoded: { prefix: string; words: number[] };
	try {
		decoded = bech32m.decode(address as `${string}1${string}`);
	} catch {
		decoded = bech32.decode(address as `${string}1${string}`);
	}

	const [witnessVersion, ...dataWords] = decoded.words;
	const program = bech32m.fromWords(dataWords);

	if (witnessVersion === 0 && program.length !== 20 && program.length !== 32) {
		throw new Error(`Invalid witness v0 program length: ${program.length}`);
	}
	if (witnessVersion === 1 && program.length !== 32) {
		throw new Error(`Invalid witness v1 program length: ${program.length}`);
	}

	return Array.from(program);
}

/**
 * Re-encode raw witness program bytes back into a Bitcoin bech32/bech32m address.
 *
 * @param program - Raw witness program bytes (20 for P2WPKH, 32 for P2TR)
 * @param network - 'mainnet' | 'testnet' | 'regtest'
 */
export function witnessProgramToAddress(
	program: number[] | Uint8Array,
	network: 'mainnet' | 'testnet' | 'regtest' = 'regtest',
): string {
	const hrp = network === 'mainnet' ? 'bc' : network === 'regtest' ? 'bcrt' : 'tb';

	// 20 bytes → P2WPKH (witness v0, bech32), 32 bytes → P2TR (witness v1, bech32m)
	if (program.length === 20) {
		const words = [0, ...bech32.toWords(Uint8Array.from(program))];
		return bech32.encode(hrp, words);
	}
	const words = [1, ...bech32m.toWords(Uint8Array.from(program))];
	return bech32m.encode(hrp, words);
}
