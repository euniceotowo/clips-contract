/**
 * backend-mint.js — Issue #270
 *
 * Example Node.js script showing how the backend prepares and submits a
 * ClipCash NFT mint transaction to the Stellar network.
 *
 * Usage:
 *   SIGNER_SECRET=<ed25519-hex>  \
 *   ADMIN_SECRET=<stellar-secret-key>  \
 *   CONTRACT_ID=<contract-address>  \
 *   NETWORK=testnet  \
 *   node backend-mint.js <clip_id> <wallet_address> <metadata_uri>
 *
 * Example:
 *   SIGNER_SECRET=abc123... ADMIN_SECRET=SABC... CONTRACT_ID=CABC... \
 *   node backend-mint.js 42 GABC... ipfs://QmXyz...
 *
 * The script:
 *   1. Builds the canonical Ed25519 signature payload
 *   2. Signs it with the backend signer key
 *   3. Assembles and submits the mint transaction
 *   4. Prints the resulting signed XDR and token ID
 */

import nacl from "tweetnacl";
import {
  Keypair,
  Networks,
  TransactionBuilder,
  BASE_FEE,
  xdr,
  hash,
  Address,
  nativeToScVal,
  scValToNative,
  SorobanRpc,
  Contract,
} from "@stellar/stellar-sdk";
import { createHash } from "crypto";

// ---------------------------------------------------------------------------
// Configuration — read from environment variables
// ---------------------------------------------------------------------------

const SIGNER_SECRET_HEX = process.env.SIGNER_SECRET; // hex-encoded 32-byte Ed25519 seed
const ADMIN_SECRET = process.env.ADMIN_SECRET; // Stellar secret key (S...)
const CONTRACT_ID = process.env.CONTRACT_ID; // Soroban contract address (C...)
const NETWORK = process.env.NETWORK ?? "testnet"; // "testnet" | "mainnet"

const RPC_URLS = {
  testnet: "https://soroban-testnet.stellar.org",
  mainnet: "https://soroban-mainnet.stellar.org",
};

const NETWORK_PASSPHRASES = {
  testnet: Networks.TESTNET,
  mainnet: Networks.PUBLIC,
};

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const [, , clipIdArg, walletAddress, metadataUri] = process.argv;

if (!clipIdArg || !walletAddress || !metadataUri) {
  console.error(
    "Usage: node backend-mint.js <clip_id> <wallet_address> <metadata_uri>"
  );
  process.exit(1);
}

const clipId = parseInt(clipIdArg, 10);
if (isNaN(clipId) || clipId < 0) {
  console.error("clip_id must be a non-negative integer");
  process.exit(1);
}

if (!SIGNER_SECRET_HEX || !ADMIN_SECRET || !CONTRACT_ID) {
  console.error(
    "Required env vars: SIGNER_SECRET (hex), ADMIN_SECRET (Stellar secret), CONTRACT_ID"
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Build the canonical mint signature payload
//
// payload = SHA-256(
//   clip_id_le_4_bytes
//   || SHA-256(XDR(owner_address))   // 32 bytes
//   || SHA-256(UTF-8(metadata_uri))  // 32 bytes
// )
// ---------------------------------------------------------------------------

/**
 * Compute the 32-byte message that the backend must sign before minting.
 *
 * @param {number} clipId - u32 clip identifier
 * @param {string} ownerAddress - Stellar G-address of the future NFT owner
 * @param {string} metadataUri - IPFS / Arweave URI
 * @returns {Buffer} 32-byte SHA-256 digest
 */
function buildMintPayload(clipId, ownerAddress, metadataUri) {
  // clip_id as 4-byte little-endian
  const clipIdBytes = Buffer.alloc(4);
  clipIdBytes.writeUInt32LE(clipId, 0);

  // SHA-256( XDR(owner_address) )
  const ownerXdr = new Address(ownerAddress).toScVal().toXDR();
  const ownerHash = createHash("sha256").update(ownerXdr).digest();

  // SHA-256( UTF-8(metadata_uri) )
  const uriHash = createHash("sha256")
    .update(Buffer.from(metadataUri, "utf8"))
    .digest();

  // SHA-256( clip_id_le4 || owner_hash || uri_hash )
  const preimage = Buffer.concat([clipIdBytes, ownerHash, uriHash]);
  return createHash("sha256").update(preimage).digest();
}

// ---------------------------------------------------------------------------
// Sign the payload with the backend Ed25519 key
// ---------------------------------------------------------------------------

/**
 * Sign a 32-byte message with the backend Ed25519 signing key.
 *
 * @param {Buffer} message - 32-byte payload
 * @param {string} signerSecretHex - hex-encoded 32-byte Ed25519 seed
 * @returns {Buffer} 64-byte Ed25519 signature
 */
function signPayload(message, signerSecretHex) {
  const seed = Buffer.from(signerSecretHex, "hex");
  if (seed.length !== 32) {
    throw new Error("SIGNER_SECRET must be a 64-character hex string (32 bytes)");
  }
  const keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
  const sig = nacl.sign.detached(new Uint8Array(message), keypair.secretKey);
  return Buffer.from(sig);
}

// ---------------------------------------------------------------------------
// Build Soroban ScVal arguments for the mint call
// ---------------------------------------------------------------------------

/**
 * Encode a Royalty struct as an ScVal map.
 *
 * @param {string} recipientAddress - Primary royalty recipient G-address
 * @param {number} basisPoints - Royalty in basis points (e.g. 500 = 5%)
 * @param {string|null} assetAddress - SEP-0041 asset contract address, or null for XLM
 * @returns {xdr.ScVal}
 */
function royaltyToScVal(recipientAddress, basisPoints, assetAddress = null) {
  const recipientScVal = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("basis_points"),
      val: nativeToScVal(basisPoints, { type: "u32" }),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("recipient"),
      val: new Address(recipientAddress).toScVal(),
    }),
  ]);

  const recipientsVec = xdr.ScVal.scvVec([recipientScVal]);

  const assetVal = assetAddress
    ? xdr.ScVal.scvVec([new Address(assetAddress).toScVal()]) // Some(address)
    : xdr.ScVal.scvVec([]); // None — represented as empty option

  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("asset_address"),
      val: assetAddress
        ? xdr.ScVal.scvVec([new Address(assetAddress).toScVal()])
        : xdr.ScVal.scvVoid(),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("recipients"),
      val: recipientsVec,
    }),
  ]);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const rpcUrl = RPC_URLS[NETWORK];
  const networkPassphrase = NETWORK_PASSPHRASES[NETWORK];

  if (!rpcUrl) {
    console.error(`Unknown NETWORK: ${NETWORK}. Use "testnet" or "mainnet".`);
    process.exit(1);
  }

  console.log(`\nClipCash Backend Mint Script`);
  console.log(`  Network:      ${NETWORK}`);
  console.log(`  Contract:     ${CONTRACT_ID}`);
  console.log(`  Clip ID:      ${clipId}`);
  console.log(`  Wallet:       ${walletAddress}`);
  console.log(`  Metadata URI: ${metadataUri}\n`);

  // 1. Build and sign the payload
  const payload = buildMintPayload(clipId, walletAddress, metadataUri);
  const signature = signPayload(payload, SIGNER_SECRET_HEX);
  console.log(`Signature (hex): ${signature.toString("hex")}`);

  // 2. Set up Stellar SDK
  const server = new SorobanRpc.Server(rpcUrl);
  const adminKeypair = Keypair.fromSecret(ADMIN_SECRET);
  const adminAccount = await server.getAccount(adminKeypair.publicKey());

  // 3. Build the mint transaction
  const contract = new Contract(CONTRACT_ID);

  // Royalty: 5% to the wallet owner, XLM (no asset address)
  const royaltyScVal = royaltyToScVal(walletAddress, 500, null);

  const mintOp = contract.call(
    "mint",
    new Address(walletAddress).toScVal(),          // to
    nativeToScVal(clipId, { type: "u32" }),         // clip_id
    nativeToScVal(metadataUri, { type: "string" }), // metadata_uri
    xdr.ScVal.scvVoid(),                            // image (None)
    xdr.ScVal.scvVoid(),                            // animation_url (None)
    royaltyScVal,                                   // royalty
    nativeToScVal(false, { type: "bool" }),         // is_soulbound
    nativeToScVal(signature, { type: "bytes" })     // signature (BytesN<64>)
  );

  const tx = new TransactionBuilder(adminAccount, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(mintOp)
    .setTimeout(30)
    .build();

  // 4. Simulate to get the footprint and resource fee
  const simResult = await server.simulateTransaction(tx);

  if (SorobanRpc.Api.isSimulationError(simResult)) {
    console.error("Simulation failed:", simResult.error);
    process.exit(1);
  }

  const preparedTx = SorobanRpc.assembleTransaction(tx, simResult).build();

  // 5. Sign and output the XDR
  preparedTx.sign(adminKeypair);
  const signedXdr = preparedTx.toEnvelope().toXDR("base64");

  console.log(`\nSigned XDR:\n${signedXdr}\n`);

  // 6. Submit the transaction
  console.log("Submitting transaction...");
  const sendResult = await server.sendTransaction(preparedTx);

  if (sendResult.status === "ERROR") {
    console.error("Submission failed:", sendResult.errorResult);
    process.exit(1);
  }

  console.log(`Transaction hash: ${sendResult.hash}`);
  console.log("Waiting for confirmation...");

  // 7. Poll for the result
  let getResult;
  do {
    await new Promise((r) => setTimeout(r, 2000));
    getResult = await server.getTransaction(sendResult.hash);
  } while (getResult.status === SorobanRpc.Api.GetTransactionStatus.NOT_FOUND);

  if (getResult.status === SorobanRpc.Api.GetTransactionStatus.FAILED) {
    console.error("Transaction failed:", getResult);
    process.exit(1);
  }

  // Extract the returned token ID from the result
  const tokenId = scValToNative(getResult.returnValue);
  console.log(`\nMint successful! Token ID: ${tokenId}`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
