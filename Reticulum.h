#ifndef RETICULUM_H
#define RETICULUM_H

#include <Arduino.h>
#include <Crypto.h>
#include <SHA256.h>
#include <AES.h>
#include <Curve25519.h>
#include <Ed25519.h>
#include <RNG.h>

// Packet types
#define PACKET_DATA 0x00
#define PACKET_ANNOUNCE 0x01
#define PACKET_LINKREQUEST 0x02
#define PACKET_PROOF 0x03

// Context types
#define CONTEXT_NONE 0x00
#define CONTEXT_RESOURCE 0x01
#define CONTEXT_RESOURCE_ADV 0x02
#define CONTEXT_RESOURCE_REQ 0x03
#define CONTEXT_RESOURCE_HMU 0x04
#define CONTEXT_RESOURCE_PRF 0x05
#define CONTEXT_RESOURCE_ICL 0x06
#define CONTEXT_RESOURCE_RCL 0x07
#define CONTEXT_CACHE_REQUEST 0x08
#define CONTEXT_REQUEST 0x09
#define CONTEXT_RESPONSE 0x0A
#define CONTEXT_PATH_RESPONSE 0x0B
#define CONTEXT_COMMAND 0x0C
#define CONTEXT_COMMAND_STATUS 0x0D
#define CONTEXT_CHANNEL 0x0E
#define CONTEXT_KEEPALIVE 0xFA
#define CONTEXT_LINKIDENTIFY 0xFB
#define CONTEXT_LINKCLOSE 0xFC
#define CONTEXT_LINKPROOF 0xFD
#define CONTEXT_LRRTT 0xFE
#define CONTEXT_LRPROOF 0xFF

// Destination types
#define DEST_SINGLE 0x00
#define DEST_GROUP 0x01
#define DEST_PLAIN 0x02
#define DEST_LINK 0x03

// Key sizes
#define ENCRYPT_KEY_SIZE 32
#define SIGN_KEY_SIZE 32
#define HASH_SIZE 16
#define FULL_HASH_SIZE 32
#define SIGNATURE_SIZE 64

class Reticulum {
  public:
    // Identity structure
    struct Identity {
      uint8_t encryptPrivate[ENCRYPT_KEY_SIZE];
      uint8_t encryptPublic[ENCRYPT_KEY_SIZE];
      uint8_t signPrivate[SIGN_KEY_SIZE];
      uint8_t signPublic[SIGN_KEY_SIZE];
    };

  // Packet structure
  struct Packet {
    bool ifacFlag;
    bool headerType;
    bool contextFlag;
    bool propagationType;
    uint8_t destinationType;
    uint8_t packetType;
    uint8_t hops;
    uint8_t destinationHash[HASH_SIZE];
    uint8_t sourceHash[HASH_SIZE];
    bool hasSourceHash;
    uint8_t context;
    uint8_t * data;
    size_t dataLen;
    uint8_t * raw;
    size_t rawLen;
  };

  // Announce structure
  struct Announce {
    bool valid;
    uint8_t keyPubEncrypt[ENCRYPT_KEY_SIZE];
    uint8_t keyPubSignature[SIGN_KEY_SIZE];
    uint8_t nameHash[10];
    uint8_t randomHash[10];
    uint8_t ratchetPub[ENCRYPT_KEY_SIZE];
    uint8_t signature[SIGNATURE_SIZE];
    uint8_t * appData;
    size_t appDataLen;
    uint8_t destinationHash[HASH_SIZE];
  };

  Reticulum();
  ~Reticulum();

  // Identity operations
  bool identityCreate(Identity & identity);
  bool identityFromBytes(Identity & identity, const uint8_t * privateBytes);
  void identityToBytes(const Identity & identity, uint8_t * output);

  // Ratchet operations
  bool ratchetCreateNew(uint8_t * privateRatchet);
  bool ratchetGetPublic(const uint8_t * privateRatchet, uint8_t * publicRatchet);

  // Destination hash
  bool getDestinationHash(const Identity & identity, const char * appName, uint8_t * destHash, const char * aspect = nullptr);

  // Packet operations
  bool decodePacket(const uint8_t * packetBytes, size_t len, Packet & packet);
  size_t encodePacket(const Packet & packet, uint8_t * output, size_t maxLen);
  void freePacket(Packet & packet);

  // Announce operations
  size_t buildAnnounce(const Identity & identity, const uint8_t * destination, uint8_t * output, size_t maxLen, const char * name = "lxmf.delivery", const uint8_t * ratchetPub = nullptr, const uint8_t * appData = nullptr, size_t appDataLen = 0);
  bool announceParsePacket(const Packet & packet, Announce & announce);
  void freeAnnounce(Announce & announce);

  // Message operations
  bool getMessageId(const Packet & packet, uint8_t * messageId);
  size_t buildProof(const Identity & identity, const Packet & packet, uint8_t * output, size_t maxLen, const uint8_t * messageId = nullptr);
  bool proofValidate(const Packet & packet, const Identity & identity, const uint8_t * fullPacketHash);

  // Encryption/Decryption
  size_t buildData(const Identity & identity, const Announce & recipientAnnounce, const uint8_t * plaintext, size_t plaintextLen, uint8_t * output, size_t maxLen, const uint8_t * ratchet = nullptr);
  int messageDecrypt(const Packet & packet, const Identity & identity, uint8_t * plaintext, size_t maxPlaintextLen, const uint8_t ** ratchets = nullptr, size_t ratchetCount = 0);

  private:
    // Crypto helpers
    void sha256(const uint8_t * data, size_t len, uint8_t * hash);
    void hmacSha256(const uint8_t * key, size_t keyLen, const uint8_t * data, size_t dataLen, uint8_t * output);
    bool hkdf(uint8_t * output, size_t outputLen, const uint8_t * deriveFrom, size_t deriveFromLen, const uint8_t * salt, size_t saltLen, const uint8_t * context, size_t contextLen);

    // Manual CBC implementation
    void aesCbcEncrypt(const uint8_t * key, const uint8_t * iv, const uint8_t * plaintext, size_t len, uint8_t * ciphertext);
    void aesCbcDecrypt(const uint8_t * key, const uint8_t * iv, const uint8_t * ciphertext, size_t len, uint8_t * plaintext);

    // Padding helpers
    size_t pkcs7Pad(const uint8_t * data, size_t len, uint8_t * output, size_t maxLen);
    int pkcs7Unpad(const uint8_t * data, size_t len, uint8_t * output);

    // XOR helper
    void xorBlock(uint8_t * dest, const uint8_t * src, size_t len);
};

#endif