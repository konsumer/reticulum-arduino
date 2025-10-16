#include "Reticulum.h"

Reticulum::Reticulum() {
  RNG.begin("Reticulum");
}

Reticulum::~Reticulum() {}

bool Reticulum::identityCreate(Identity & identity) {
  // Generate X25519 keypair for encryption using Curve25519::dh1()
  uint8_t f[32];
  Curve25519::dh1(identity.encryptPublic, f);
  memcpy(identity.encryptPrivate, f, 32);

  // Generate Ed25519 keypair for signing
  Ed25519::generatePrivateKey(identity.signPrivate);
  Ed25519::derivePublicKey(identity.signPublic, identity.signPrivate);

  return true;
}

bool Reticulum::identityFromBytes(Identity& identity, const uint8_t* privateBytes) {
  // First 32 bytes: encryption private key
  memcpy(identity.encryptPrivate, privateBytes, ENCRYPT_KEY_SIZE);
  // Next 32 bytes: signing private key
  memcpy(identity.signPrivate, privateBytes + ENCRYPT_KEY_SIZE, SIGN_KEY_SIZE);

  // Derive X25519 public key from private using eval() with base point 9
  uint8_t basepoint[32] = {9};  // Standard X25519 base point
  for (int i = 1; i < 32; i++) basepoint[i] = 0;
  
  if (!Curve25519::eval(identity.encryptPublic, identity.encryptPrivate, basepoint)) {
    return false;
  }
  
  // Derive Ed25519 public key
  Ed25519::derivePublicKey(identity.signPublic, identity.signPrivate);

  return true;
}


void Reticulum::identityToBytes(const Identity & identity, uint8_t * output) {
  memcpy(output, identity.encryptPrivate, ENCRYPT_KEY_SIZE);
  memcpy(output + ENCRYPT_KEY_SIZE, identity.signPrivate, SIGN_KEY_SIZE);
}

bool Reticulum::ratchetCreateNew(uint8_t * privateRatchet) {
  uint8_t tmpPub[32];
  Curve25519::dh1(tmpPub, privateRatchet);
  return true;
}

bool Reticulum::ratchetGetPublic(const uint8_t * privateRatchet, uint8_t * publicRatchet) {
  uint8_t tmpPriv[32];
  memcpy(tmpPriv, privateRatchet, 32);
  Curve25519::dh1(publicRatchet, tmpPriv);
  return true;
}

bool Reticulum::getDestinationHash(const Identity & identity,
  const char * appName,
    uint8_t * destHash,
    const char * aspect) {
  uint8_t identityHash[FULL_HASH_SIZE];
  uint8_t nameHash[FULL_HASH_SIZE];
  uint8_t addrHashMaterial[26];

  SHA256 sha;
  sha.reset();
  sha.update(identity.encryptPublic, ENCRYPT_KEY_SIZE);
  sha.update(identity.signPublic, SIGN_KEY_SIZE);
  sha.finalize(identityHash, FULL_HASH_SIZE);

  String fullName = String(appName);
  if (aspect != nullptr) {
    fullName += ".";
    fullName += aspect;
  }

  sha.reset();
  sha.update((uint8_t * ) fullName.c_str(), fullName.length());
  sha.finalize(nameHash, FULL_HASH_SIZE);

  memcpy(addrHashMaterial, nameHash, 10);
  memcpy(addrHashMaterial + 10, identityHash, HASH_SIZE);

  uint8_t finalHash[FULL_HASH_SIZE];
  sha.reset();
  sha.update(addrHashMaterial, 26);
  sha.finalize(finalHash, FULL_HASH_SIZE);

  memcpy(destHash, finalHash, HASH_SIZE);
  return true;
}

bool Reticulum::decodePacket(const uint8_t * packetBytes, size_t len, Packet & packet) {
  if (len < 2) return false;

  packet.raw = (uint8_t * ) malloc(len);
  if (!packet.raw) return false;
  memcpy(packet.raw, packetBytes, len);
  packet.rawLen = len;

  packet.ifacFlag = (packetBytes[0] & 0b10000000) != 0;
  packet.headerType = (packetBytes[0] & 0b01000000) != 0;
  packet.contextFlag = (packetBytes[0] & 0b00100000) != 0;
  packet.propagationType = (packetBytes[0] & 0b00010000) != 0;
  packet.destinationType = packetBytes[0] & 0b00001100;
  packet.packetType = packetBytes[0] & 0b00000011;
  packet.hops = packetBytes[1];

  size_t offset = 2;

  if (offset + HASH_SIZE > len) return false;
  memcpy(packet.destinationHash, packetBytes + offset, HASH_SIZE);
  offset += HASH_SIZE;

  if (packet.headerType) {
    if (offset + HASH_SIZE > len) return false;
    memcpy(packet.sourceHash, packetBytes + offset, HASH_SIZE);
    packet.hasSourceHash = true;
    offset += HASH_SIZE;
  } else {
    packet.hasSourceHash = false;
  }

  if (packet.contextFlag) {
    if (offset >= len) return false;
    packet.context = packetBytes[offset];
    offset += 1;
  } else {
    packet.context = CONTEXT_NONE;
  }

  size_t dataLen = len - offset;
  if (dataLen > 0) {
    packet.data = (uint8_t * ) malloc(dataLen);
    if (!packet.data) {
      free(packet.raw);
      return false;
    }
    memcpy(packet.data, packetBytes + offset, dataLen);
    packet.dataLen = dataLen;
  } else {
    packet.data = nullptr;
    packet.dataLen = 0;
  }

  return true;
}

size_t Reticulum::encodePacket(const Packet & packet, uint8_t * output, size_t maxLen) {
  uint8_t headerByte = 0;

  if (packet.ifacFlag) headerByte |= 0b10000000;
  if (packet.headerType || packet.hasSourceHash) headerByte |= 0b01000000;
  if (packet.contextFlag) headerByte |= 0b00100000;
  if (packet.propagationType) headerByte |= 0b00010000;
  headerByte |= (packet.destinationType & 0b00001100);
  headerByte |= (packet.packetType & 0b00000011);

  size_t required = 2 + HASH_SIZE;
  if (packet.headerType || packet.hasSourceHash) required += HASH_SIZE;
  if (packet.contextFlag) required += 1;
  required += packet.dataLen;

  if (required > maxLen) return 0;

  size_t offset = 0;
  output[offset++] = headerByte;
  output[offset++] = packet.hops;

  memcpy(output + offset, packet.destinationHash, HASH_SIZE);
  offset += HASH_SIZE;

  if (packet.headerType || packet.hasSourceHash) {
    memcpy(output + offset, packet.sourceHash, HASH_SIZE);
    offset += HASH_SIZE;
  }

  if (packet.contextFlag) {
    output[offset++] = packet.context;
  }

  if (packet.dataLen > 0 && packet.data) {
    memcpy(output + offset, packet.data, packet.dataLen);
    offset += packet.dataLen;
  }

  return offset;
}

void Reticulum::freePacket(Packet & packet) {
  if (packet.raw) {
    free(packet.raw);
    packet.raw = nullptr;
  }
  if (packet.data) {
    free(packet.data);
    packet.data = nullptr;
  }
}

size_t Reticulum::buildAnnounce(const Identity & identity,
  const uint8_t * destination,
    uint8_t * output, size_t maxLen,
    const char * name,
      const uint8_t * ratchetPub,
        const uint8_t * appData,
          size_t appDataLen) {
  uint8_t nameHash[FULL_HASH_SIZE];
  uint8_t randomHash[10];
  uint8_t effectiveRatchet[ENCRYPT_KEY_SIZE];
  uint8_t contextVal;

  SHA256 sha;
  sha.reset();
  sha.update((uint8_t * ) name, strlen(name));
  sha.finalize(nameHash, FULL_HASH_SIZE);

  RNG.rand(randomHash, 10);

  if (ratchetPub == nullptr || memcmp(ratchetPub, identity.encryptPublic, ENCRYPT_KEY_SIZE) == 0) {
    memcpy(effectiveRatchet, identity.encryptPublic, ENCRYPT_KEY_SIZE);
    contextVal = 0;
  } else {
    memcpy(effectiveRatchet, ratchetPub, ENCRYPT_KEY_SIZE);
    contextVal = 1;
  }

  size_t signedDataLen = HASH_SIZE + 64 + 10 + 10 + ENCRYPT_KEY_SIZE + appDataLen;
  uint8_t * signedData = (uint8_t * ) malloc(signedDataLen);
  if (!signedData) return 0;

  size_t offset = 0;
  memcpy(signedData + offset, destination, HASH_SIZE);
  offset += HASH_SIZE;
  memcpy(signedData + offset, identity.encryptPublic, ENCRYPT_KEY_SIZE);
  offset += ENCRYPT_KEY_SIZE;
  memcpy(signedData + offset, identity.signPublic, SIGN_KEY_SIZE);
  offset += SIGN_KEY_SIZE;
  memcpy(signedData + offset, nameHash, 10);
  offset += 10;
  memcpy(signedData + offset, randomHash, 10);
  offset += 10;
  memcpy(signedData + offset, effectiveRatchet, ENCRYPT_KEY_SIZE);
  offset += ENCRYPT_KEY_SIZE;
  if (appDataLen > 0 && appData) {
    memcpy(signedData + offset, appData, appDataLen);
  }

  uint8_t signature[SIGNATURE_SIZE];
  Ed25519::sign(signature, identity.signPrivate, identity.signPublic, signedData, signedDataLen);
  free(signedData);

  size_t payloadLen = 64 + 10 + 10 + SIGNATURE_SIZE + appDataLen;
  if (contextVal == 1) payloadLen += ENCRYPT_KEY_SIZE;

  uint8_t * payload = (uint8_t * ) malloc(payloadLen);
  if (!payload) return 0;

  offset = 0;
  memcpy(payload + offset, identity.encryptPublic, ENCRYPT_KEY_SIZE);
  offset += ENCRYPT_KEY_SIZE;
  memcpy(payload + offset, identity.signPublic, SIGN_KEY_SIZE);
  offset += SIGN_KEY_SIZE;
  memcpy(payload + offset, nameHash, 10);
  offset += 10;
  memcpy(payload + offset, randomHash, 10);
  offset += 10;
  if (contextVal == 1) {
    memcpy(payload + offset, effectiveRatchet, ENCRYPT_KEY_SIZE);
    offset += ENCRYPT_KEY_SIZE;
  }
  memcpy(payload + offset, signature, SIGNATURE_SIZE);
  offset += SIGNATURE_SIZE;
  if (appDataLen > 0 && appData) {
    memcpy(payload + offset, appData, appDataLen);
  }

  Packet pkt = {
    0
  };
  memcpy(pkt.destinationHash, destination, HASH_SIZE);
  pkt.packetType = PACKET_ANNOUNCE;
  pkt.destinationType = 0;
  pkt.hops = 0;
  pkt.context = contextVal;
  pkt.contextFlag = true;
  pkt.data = payload;
  pkt.dataLen = payloadLen;

  size_t result = encodePacket(pkt, output, maxLen);
  free(payload);
  return result;
}

bool Reticulum::announceParsePacket(const Packet& packet, Announce& announce) {
  const uint8_t* data = packet.data;
  size_t dataLen = packet.dataLen;

  announce.valid = false;
  announce.appData = nullptr;
  announce.appDataLen = 0;

  // Copy destination hash from packet
  memcpy(announce.destinationHash, packet.destinationHash, HASH_SIZE);

  if (dataLen < 64) return false;
  memcpy(announce.keyPubEncrypt, data, ENCRYPT_KEY_SIZE);
  memcpy(announce.keyPubSignature, data + ENCRYPT_KEY_SIZE, SIGN_KEY_SIZE);
  size_t offset = 64;

  if (dataLen < offset + 20) return false;
  memcpy(announce.nameHash, data + offset, 10); offset += 10;
  memcpy(announce.randomHash, data + offset, 10); offset += 10;

// For announces, always read ratchet from data regardless of context
if (dataLen < offset + ENCRYPT_KEY_SIZE + SIGNATURE_SIZE) return false;
memcpy(announce.ratchetPub, data + offset, ENCRYPT_KEY_SIZE); 
offset += ENCRYPT_KEY_SIZE;

  // Read signature
  if (dataLen < offset + SIGNATURE_SIZE) return false;
  memcpy(announce.signature, data + offset, SIGNATURE_SIZE); 
  offset += SIGNATURE_SIZE;

  // Everything after signature is app_data
  if (dataLen > offset) {
    announce.appDataLen = dataLen - offset;
    announce.appData = (uint8_t*)malloc(announce.appDataLen);
    if (announce.appData) {
      memcpy(announce.appData, data + offset, announce.appDataLen);
    }
  }

  // Build signed data for verification
  size_t signedDataLen = HASH_SIZE + 64 + 20 + ENCRYPT_KEY_SIZE + announce.appDataLen;
  uint8_t* signedData = (uint8_t*)malloc(signedDataLen);
  if (!signedData) return false;

  offset = 0;
  memcpy(signedData + offset, announce.destinationHash, HASH_SIZE); offset += HASH_SIZE;
  memcpy(signedData + offset, announce.keyPubEncrypt, ENCRYPT_KEY_SIZE); offset += ENCRYPT_KEY_SIZE;
  memcpy(signedData + offset, announce.keyPubSignature, SIGN_KEY_SIZE); offset += SIGN_KEY_SIZE;
  memcpy(signedData + offset, announce.nameHash, 10); offset += 10;
  memcpy(signedData + offset, announce.randomHash, 10); offset += 10;
  memcpy(signedData + offset, announce.ratchetPub, ENCRYPT_KEY_SIZE); offset += ENCRYPT_KEY_SIZE;
  if (announce.appDataLen > 0 && announce.appData) {
    memcpy(signedData + offset, announce.appData, announce.appDataLen);
  }

  // Verify signature
  announce.valid = Ed25519::verify(announce.signature, announce.keyPubSignature, 
                                   signedData, signedDataLen);
  
  free(signedData);
  return true;
}




void Reticulum::freeAnnounce(Announce & announce) {
  if (announce.appData) {
    free(announce.appData);
    announce.appData = nullptr;
  }
}

bool Reticulum::getMessageId(const Packet & packet, uint8_t * messageId) {
  if (!packet.raw || packet.rawLen < 2) return false;

  SHA256 sha;
  sha.reset();

  uint8_t modifiedHeader = packet.raw[0] & 0b00001111;
  sha.update( & modifiedHeader, 1);

  uint8_t headerType = (packet.raw[0] >> 6) & 0b11;
  if (headerType == 1) {
    if (packet.rawLen > 18) {
      sha.update(packet.raw + 18, packet.rawLen - 18);
    }
  } else {
    if (packet.rawLen > 2) {
      sha.update(packet.raw + 2, packet.rawLen - 2);
    }
  }

  sha.finalize(messageId, FULL_HASH_SIZE);
  return true;
}

size_t Reticulum::buildProof(const Identity & identity,
  const Packet & packet,
    uint8_t * output, size_t maxLen,
    const uint8_t * messageId) {
  uint8_t msgId[FULL_HASH_SIZE];

  if (messageId == nullptr) {
    if (!getMessageId(packet, msgId)) return 0;
    messageId = msgId;
  }

  uint8_t signature[SIGNATURE_SIZE];
  Ed25519::sign(signature, identity.signPrivate, identity.signPublic,
    messageId, FULL_HASH_SIZE);

  Packet proofPkt = {
    0
  };
  memcpy(proofPkt.destinationHash, messageId, HASH_SIZE);
  proofPkt.packetType = PACKET_PROOF;
  proofPkt.destinationType = 0;
  proofPkt.hops = 0;

  uint8_t proofData[1 + SIGNATURE_SIZE];
  proofData[0] = 0x00;
  memcpy(proofData + 1, signature, SIGNATURE_SIZE);

  proofPkt.data = proofData;
  proofPkt.dataLen = sizeof(proofData);

  return encodePacket(proofPkt, output, maxLen);
}

bool Reticulum::proofValidate(const Packet& packet, const Identity& identity, const uint8_t* fullPacketHash) {
  if (packet.dataLen < 1 + SIGNATURE_SIZE) {
    return false;
  }
  const uint8_t* signature = packet.data + 1;
  bool result = Ed25519::verify(signature, identity.signPublic, fullPacketHash, FULL_HASH_SIZE);
  return result;
}

size_t Reticulum::buildData(const Identity & identity,
  const Announce & recipientAnnounce,
    const uint8_t * plaintext, size_t plaintextLen,
      uint8_t * output, size_t maxLen,
      const uint8_t * ratchet) {
  uint8_t recipientIdentityHash[FULL_HASH_SIZE];
  SHA256 sha;
  sha.reset();
  sha.update(recipientAnnounce.keyPubEncrypt, ENCRYPT_KEY_SIZE);
  sha.update(recipientAnnounce.keyPubSignature, SIGN_KEY_SIZE);
  sha.finalize(recipientIdentityHash, FULL_HASH_SIZE);

  uint8_t ephemeralPriv[32];
  uint8_t ephemeralPub[32];
  Curve25519::dh1(ephemeralPub, ephemeralPriv);

  uint8_t sharedSecret[32];
  memcpy(sharedSecret, recipientAnnounce.ratchetPub, 32);
  if (!Curve25519::dh2(sharedSecret, ephemeralPriv)) return 0;

  uint8_t derivedKey[64];
  if (!hkdf(derivedKey, 64, sharedSecret, 32,
      recipientIdentityHash, HASH_SIZE, nullptr, 0)) return 0;

  uint8_t signingKey[32];
  uint8_t encryptionKey[32];
  memcpy(signingKey, derivedKey, 32);
  memcpy(encryptionKey, derivedKey + 32, 32);

  uint8_t paddedPlaintext[512];
  size_t paddedLen = pkcs7Pad(plaintext, plaintextLen, paddedPlaintext, sizeof(paddedPlaintext));
  if (paddedLen == 0) return 0;

  uint8_t iv[16];
  RNG.rand(iv, 16);

  uint8_t ciphertext[512];
  aesCbcEncrypt(encryptionKey, iv, paddedPlaintext, paddedLen, ciphertext);

  size_t signedDataLen = 16 + paddedLen;
  uint8_t * signedData = (uint8_t * ) malloc(signedDataLen);
  if (!signedData) return 0;
  memcpy(signedData, iv, 16);
  memcpy(signedData + 16, ciphertext, paddedLen);

  uint8_t hmacSig[32];
  hmacSha256(signingKey, 32, signedData, signedDataLen, hmacSig);
  free(signedData);

  size_t tokenLen = 1 + 32 + 16 + paddedLen + 32;
  uint8_t * token = (uint8_t * ) malloc(tokenLen);
  if (!token) return 0;

  size_t offset = 0;
  token[offset++] = 0x00;
  memcpy(token + offset, ephemeralPub, 32);
  offset += 32;
  memcpy(token + offset, iv, 16);
  offset += 16;
  memcpy(token + offset, ciphertext, paddedLen);
  offset += paddedLen;
  memcpy(token + offset, hmacSig, 32);

  Packet pkt = {
    0
  };
  memcpy(pkt.destinationHash, recipientAnnounce.destinationHash, HASH_SIZE);
  pkt.packetType = PACKET_DATA;
  pkt.destinationType = 0;
  pkt.hops = 0;
  pkt.data = token;
  pkt.dataLen = tokenLen;

  size_t result = encodePacket(pkt, output, maxLen);
  free(token);
  return result;
}

int Reticulum::messageDecrypt(const Packet& packet, const Identity& identity,
                              uint8_t* plaintext, size_t maxPlaintextLen,
                              const uint8_t** ratchets, size_t ratchetCount) {
  if (!packet.data || packet.dataLen <= 49) return -1;

  // Get identity hash - Python uses ONLY first 16 bytes as HKDF salt!
  uint8_t identityHashFull[FULL_HASH_SIZE];
  SHA256 sha;
  sha.reset();
  sha.update(identity.encryptPublic, ENCRYPT_KEY_SIZE);
  sha.update(identity.signPublic, SIGN_KEY_SIZE);
  sha.finalize(identityHashFull, FULL_HASH_SIZE);

  // Truncate to 16 bytes for HKDF salt
  uint8_t identityHash[HASH_SIZE];
  memcpy(identityHash, identityHashFull, HASH_SIZE);

  // Extract peer's ephemeral public key (bytes 1-32) and ciphertext (bytes 33+)
  const uint8_t* peerPubBytes = packet.data + 1;  // Skip version byte
  const uint8_t* ciphertext = packet.data + 33;
  size_t ciphertextLen = packet.dataLen - 33;

  // Try with ratchets - this is the PRIMARY method for DATA packets
  if (ratchets && ratchetCount > 0) {
    for (size_t i = 0; i < ratchetCount; i++) {
      if (!ratchets[i]) continue;

      // Make a copy of the ratchet private key (dh2 destroys it)
      uint8_t ratchetPrivCopy[32];
      memcpy(ratchetPrivCopy, ratchets[i], 32);
      
      // Perform X25519 key exchange: shared = dh2(peer_pub, ratchet_priv)
      uint8_t sharedKey[32];
      memcpy(sharedKey, peerPubBytes, 32);
      if (!Curve25519::dh2(sharedKey, ratchetPrivCopy)) continue;

      // Derive encryption and signing keys using HKDF
      uint8_t derivedKey[64];
      if (!hkdf(derivedKey, 64, sharedKey, 32, identityHash, HASH_SIZE, nullptr, 0)) continue;

      uint8_t signingKey[32];
      uint8_t encryptionKey[32];
      memcpy(signingKey, derivedKey, 32);
      memcpy(encryptionKey, derivedKey + 32, 32);

      // Verify we have enough data for HMAC
      if (ciphertextLen <= 48) continue;

      // Extract HMAC (last 32 bytes) and signed data (everything before HMAC)
      const uint8_t* receivedHmac = ciphertext + ciphertextLen - 32;
      size_t signedDataLen = ciphertextLen - 32;

      // Verify HMAC
      uint8_t expectedHmac[32];
      hmacSha256(signingKey, 32, ciphertext, signedDataLen, expectedHmac);

      if (memcmp(receivedHmac, expectedHmac, 32) != 0) continue;

      // Extract IV (first 16 bytes of ciphertext) and actual ciphertext data
      const uint8_t* iv = ciphertext;
      const uint8_t* ciphertextData = ciphertext + 16;
      size_t ciphertextDataLen = signedDataLen - 16;

      // Decrypt using AES-CBC
      uint8_t paddedPlaintext[512];
      aesCbcDecrypt(encryptionKey, iv, ciphertextData, ciphertextDataLen, paddedPlaintext);

      // Remove PKCS7 padding
      int unpaddedLen = pkcs7Unpad(paddedPlaintext, ciphertextDataLen, plaintext);
      if (unpaddedLen > 0 && (size_t)unpaddedLen <= maxPlaintextLen) {
        return unpaddedLen;
      }
    }
  }

  // If ratchet decryption failed, try with identity encryption key
  uint8_t identityPrivCopy[32];
  memcpy(identityPrivCopy, identity.encryptPrivate, 32);
  
  uint8_t sharedKey[32];
  memcpy(sharedKey, peerPubBytes, 32);
  if (Curve25519::dh2(sharedKey, identityPrivCopy)) {
    uint8_t derivedKey[64];
    if (hkdf(derivedKey, 64, sharedKey, 32, identityHash, HASH_SIZE, nullptr, 0)) {
      uint8_t signingKey[32];
      uint8_t encryptionKey[32];
      memcpy(signingKey, derivedKey, 32);
      memcpy(encryptionKey, derivedKey + 32, 32);

      if (ciphertextLen > 48) {
        const uint8_t* receivedHmac = ciphertext + ciphertextLen - 32;
        size_t signedDataLen = ciphertextLen - 32;

        uint8_t expectedHmac[32];
        hmacSha256(signingKey, 32, ciphertext, signedDataLen, expectedHmac);

        if (memcmp(receivedHmac, expectedHmac, 32) == 0) {
          const uint8_t* iv = ciphertext;
          const uint8_t* ciphertextData = ciphertext + 16;
          size_t ciphertextDataLen = signedDataLen - 16;

          uint8_t paddedPlaintext[512];
          aesCbcDecrypt(encryptionKey, iv, ciphertextData, ciphertextDataLen, paddedPlaintext);

          int unpaddedLen = pkcs7Unpad(paddedPlaintext, ciphertextDataLen, plaintext);
          if (unpaddedLen > 0 && (size_t)unpaddedLen <= maxPlaintextLen) {
            return unpaddedLen;
          }
        }
      }
    }
  }

  return -1;
}


void Reticulum::hmacSha256(const uint8_t * key, size_t keyLen,
  const uint8_t * data, size_t dataLen, uint8_t * output) {
  SHA256 sha;
  uint8_t ipad[64];
  uint8_t opad[64];

  memset(ipad, 0x36, 64);
  memset(opad, 0x5c, 64);

  for (size_t i = 0; i < keyLen && i < 64; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  sha.reset();
  sha.update(ipad, 64);
  sha.update(data, dataLen);
  uint8_t innerHash[32];
  sha.finalize(innerHash, 32);

  sha.reset();
  sha.update(opad, 64);
  sha.update(innerHash, 32);
  sha.finalize(output, 32);
}

bool Reticulum::hkdf(uint8_t * output, size_t outputLen,
  const uint8_t * deriveFrom,
    size_t deriveFromLen,
    const uint8_t * salt, size_t saltLen,
      const uint8_t * context, size_t contextLen) {
  if (outputLen == 0 || outputLen > 255 * 32) return false;

  uint8_t actualSalt[32];
  if (!salt || saltLen == 0) {
    memset(actualSalt, 0, 32);
    salt = actualSalt;
    saltLen = 32;
  }

  uint8_t prk[32];
  hmacSha256(salt, saltLen, deriveFrom, deriveFromLen, prk);

  uint8_t block[32];
  memset(block, 0, 32);
  size_t offset = 0;

  for (uint8_t i = 1; offset < outputLen; i++) {
    size_t blockInputLen = (i > 1 ? 32 : 0) + (context ? contextLen : 0) + 1;
    uint8_t * blockInput = (uint8_t * ) malloc(blockInputLen);
    if (!blockInput) return false;

    size_t pos = 0;
    if (i > 1) {
      memcpy(blockInput + pos, block, 32);
      pos += 32;
    }
    if (context && contextLen > 0) {
      memcpy(blockInput + pos, context, contextLen);
      pos += contextLen;
    }
    blockInput[pos] = i;

    hmacSha256(prk, 32, blockInput, pos + 1, block);
    free(blockInput);

    size_t toCopy = (outputLen - offset < 32) ? (outputLen - offset) : 32;
    memcpy(output + offset, block, toCopy);
    offset += toCopy;
  }

  return true;
}

void Reticulum::xorBlock(uint8_t * dest,
  const uint8_t * src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] ^= src[i];
  }
}

void Reticulum::aesCbcEncrypt(const uint8_t * key,
  const uint8_t * iv,
    const uint8_t * plaintext, size_t len, uint8_t * ciphertext) {
  AES256 aes;
  aes.setKey(key, 32);

  uint8_t block[16];
  uint8_t prevBlock[16];
  memcpy(prevBlock, iv, 16);

  for (size_t i = 0; i < len; i += 16) {
    memcpy(block, plaintext + i, 16);
    xorBlock(block, prevBlock, 16);
    aes.encryptBlock(ciphertext + i, block);
    memcpy(prevBlock, ciphertext + i, 16);
  }

  aes.clear();
}

void Reticulum::aesCbcDecrypt(const uint8_t * key,
  const uint8_t * iv,
    const uint8_t * ciphertext, size_t len, uint8_t * plaintext) {
  AES256 aes;
  aes.setKey(key, 32);

  uint8_t block[16];
  uint8_t prevBlock[16];
  memcpy(prevBlock, iv, 16);

  for (size_t i = 0; i < len; i += 16) {
    aes.decryptBlock(block, ciphertext + i);
    xorBlock(block, prevBlock, 16);
    memcpy(plaintext + i, block, 16);
    memcpy(prevBlock, ciphertext + i, 16);
  }

  aes.clear();
}

size_t Reticulum::pkcs7Pad(const uint8_t * data, size_t len, uint8_t * output, size_t maxLen) {
  uint8_t padValue = 16 - (len % 16);
  size_t paddedLen = len + padValue;

  if (paddedLen > maxLen) return 0;

  memcpy(output, data, len);
  memset(output + len, padValue, padValue);

  return paddedLen;
}

int Reticulum::pkcs7Unpad(const uint8_t * data, size_t len, uint8_t * output) {
  if (len == 0 || len % 16 != 0) return -1;

  uint8_t padValue = data[len - 1];
  if (padValue > 16 || padValue > len) return -1;

  for (size_t i = len - padValue; i < len; i++) {
    if (data[i] != padValue) return -1;
  }

  size_t unpaddedLen = len - padValue;
  memcpy(output, data, unpaddedLen);

  return unpaddedLen;
}