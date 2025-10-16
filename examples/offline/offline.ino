// Example that parses & decrypts messages from 2 real clients

#include <Reticulum.h>

Reticulum rns;

// private-keys of 2 clients

// 072ec44973a8dee8e28d230fb4af8fe4 client
const uint8_t clientABytes[64] = {32, 81, 49, 203, 150, 114, 234, 236, 138, 88, 46, 142, 1, 131, 7, 242, 66, 140, 74, 172, 94, 56, 63, 18, 233, 73, 57, 230, 114, 185, 49, 103, 119, 99, 199, 57, 141, 11, 156, 182, 239, 19, 105, 208, 35, 216, 175, 16, 184, 93, 128, 246, 87, 156, 85, 166, 245, 40, 149, 50, 101, 193, 83, 19};

// 76a93cda889a8c0a88451e02d53fd8b9 client
const uint8_t clientBBytes[64] = {232, 197, 192, 150, 22, 111, 53, 84, 134, 141, 233, 19, 59, 12, 85, 199, 171, 240, 49, 130, 48, 134, 10, 20, 46, 163, 248, 74, 10, 174, 119, 89, 20, 47, 108, 11, 132, 217, 245, 55, 206, 178, 232, 233, 103, 143, 201, 251, 119, 202, 249, 30, 33, 118, 39, 143, 180, 196, 245, 195, 235, 123, 72, 205};

// ratchet private-keys that each client used to send messages to the other
const uint8_t ratchetBytes[2][32] = {
  {32, 92, 178, 86, 196, 77, 77, 57, 57, 189, 192, 46, 42, 150, 103, 222, 66, 20, 203, 204, 101, 27, 189, 192, 163, 24, 172, 247, 236, 104, 176, 102},
  {40, 221, 77, 165, 97, 169, 188, 12, 183, 214, 68, 164, 72, 124, 1, 203, 227, 43, 1, 113, 138, 33, 241, 137, 5, 245, 97, 27, 17, 10, 92, 69}
};

// packets from real capture of conversation between the 2 clients
const uint8_t packet1Bytes[217] = {33, 0, 7, 46, 196, 73, 115, 168, 222, 232, 226, 141, 35, 15, 180, 175, 143, 228, 0, 162, 185, 176, 47, 180, 116, 159, 207, 132, 88, 118, 45, 27, 224, 174, 103, 255, 28, 170, 71, 251, 10, 82, 244, 194, 189, 109, 208, 120, 96, 167, 56, 218, 80, 168, 127, 136, 78, 110, 100, 170, 167, 11, 68, 210, 8, 104, 20, 78, 62, 38, 255, 160, 1, 198, 10, 124, 121, 125, 186, 229, 7, 142, 206, 110, 198, 11, 195, 24, 226, 192, 240, 217, 8, 115, 64, 130, 117, 83, 0, 104, 222, 16, 57, 226, 187, 33, 16, 139, 44, 188, 144, 11, 71, 98, 144, 171, 120, 103, 68, 20, 70, 219, 54, 106, 112, 251, 142, 209, 68, 140, 160, 232, 137, 189, 101, 186, 214, 216, 101, 78, 114, 102, 29, 220, 8, 155, 6, 73, 90, 185, 26, 87, 175, 197, 112, 14, 9, 95, 2, 26, 168, 206, 192, 79, 34, 186, 85, 67, 142, 252, 58, 177, 226, 169, 27, 141, 23, 189, 37, 147, 19, 241, 117, 223, 240, 64, 130, 127, 223, 17, 17, 200, 139, 239, 80, 22, 118, 56, 11, 146, 196, 14, 65, 110, 111, 110, 121, 109, 111, 117, 115, 32, 80, 101, 101, 114, 192};
const uint8_t packet2Bytes[217] = {33, 0, 118, 169, 60, 218, 136, 154, 140, 10, 136, 69, 30, 2, 213, 63, 216, 185, 0, 113, 241, 153, 240, 77, 53, 137, 202, 8, 60, 102, 255, 145, 186, 237, 98, 142, 225, 149, 23, 239, 104, 235, 32, 152, 39, 223, 58, 103, 133, 207, 91, 10, 244, 63, 176, 225, 104, 23, 99, 112, 130, 143, 205, 193, 153, 229, 174, 43, 32, 139, 87, 207, 101, 23, 159, 250, 143, 37, 115, 61, 157, 64, 188, 110, 198, 11, 195, 24, 226, 192, 240, 217, 8, 20, 154, 213, 37, 4, 0, 104, 222, 16, 59, 13, 246, 210, 32, 1, 28, 233, 218, 117, 89, 251, 214, 32, 56, 5, 1, 217, 225, 154, 252, 232, 122, 109, 12, 102, 20, 18, 243, 131, 28, 201, 21, 219, 236, 171, 232, 158, 245, 161, 26, 53, 157, 55, 87, 168, 82, 128, 195, 174, 104, 168, 182, 54, 110, 212, 17, 11, 226, 74, 64, 141, 190, 148, 107, 40, 21, 224, 232, 159, 142, 73, 132, 137, 120, 18, 43, 48, 228, 66, 175, 131, 179, 108, 239, 17, 211, 223, 105, 195, 65, 137, 21, 104, 88, 86, 2, 146, 196, 14, 65, 110, 111, 110, 121, 109, 111, 117, 115, 32, 80, 101, 101, 114, 192};
const uint8_t packet3Bytes[211] = {0, 0, 118, 169, 60, 218, 136, 154, 140, 10, 136, 69, 30, 2, 213, 63, 216, 185, 0, 245, 73, 204, 207, 141, 87, 76, 181, 32, 200, 241, 46, 166, 234, 103, 196, 244, 206, 52, 243, 1, 222, 97, 28, 217, 66, 172, 191, 182, 147, 63, 63, 122, 2, 93, 91, 109, 97, 132, 208, 77, 208, 39, 155, 128, 55, 241, 201, 193, 193, 194, 93, 239, 189, 213, 230, 42, 168, 251, 4, 80, 33, 1, 1, 74, 80, 27, 146, 53, 230, 47, 130, 59, 189, 253, 77, 133, 231, 101, 109, 118, 88, 2, 241, 21, 160, 27, 87, 184, 35, 174, 2, 204, 148, 137, 154, 227, 160, 249, 75, 247, 195, 47, 26, 115, 192, 39, 229, 201, 94, 13, 217, 76, 114, 200, 51, 234, 117, 149, 26, 245, 23, 218, 102, 94, 255, 38, 188, 164, 94, 144, 226, 234, 161, 135, 117, 230, 87, 153, 234, 11, 58, 151, 118, 69, 16, 120, 80, 219, 254, 98, 187, 31, 50, 40, 181, 10, 198, 231, 117, 0, 108, 79, 24, 214, 243, 161, 71, 66, 51, 220, 155, 19, 205, 149, 246, 166, 245, 129, 173, 11, 133, 222, 113, 150, 234, 96, 109, 57, 61, 53, 241};
const uint8_t packet4Bytes[83] = {3, 0, 40, 49, 215, 111, 26, 128, 53, 99, 133, 5, 193, 50, 254, 88, 24, 193, 0, 185, 11, 131, 160, 75, 227, 25, 70, 63, 147, 11, 18, 59, 102, 126, 170, 246, 74, 133, 232, 39, 195, 72, 49, 160, 50, 207, 114, 131, 74, 39, 37, 116, 161, 251, 7, 251, 41, 245, 189, 183, 168, 101, 112, 255, 22, 222, 127, 215, 49, 217, 133, 28, 213, 243, 50, 136, 204, 140, 221, 202, 225, 1, 7};
const uint8_t packet5Bytes[211] = {0x00, 0x00, 0x07, 0x2e, 0xc4, 0x49, 0x73, 0xa8, 0xde, 0xe8, 0xe2, 0x8d, 0x23, 0x0f, 0xb4, 0xaf, 0x8f, 0xe4, 0x00, 0xb2, 0x19, 0x1b, 0x23, 0xb7, 0x50, 0x6a, 0x33, 0x25, 0xfe, 0x28, 0x8d, 0x75, 0xa7, 0xab, 0x06, 0x70, 0x0f, 0x92, 0xc7, 0x10, 0xc1, 0x6a, 0x7f, 0x55, 0x76, 0x9a, 0xfb, 0x01, 0x4d, 0x75, 0x3b, 0x8c, 0xf3, 0x18, 0x77, 0x30, 0x11, 0x69, 0x05, 0x84, 0x3f, 0xb0, 0xde, 0x9d, 0xce, 0xc9, 0x76, 0xb1, 0x21, 0xa6, 0x42, 0x5b, 0x99, 0x5f, 0x80, 0x44, 0x28, 0x19, 0xeb, 0xe8, 0x83, 0xda, 0xb5, 0xaa, 0x72, 0xfb, 0x8a, 0x9d, 0x96, 0x84, 0x99, 0x69, 0xb0, 0x73, 0xb8, 0xe7, 0x6e, 0x44, 0x63, 0xdc, 0x8c, 0x0e, 0xce, 0xba, 0x93, 0x66, 0x65, 0xc4, 0xb6, 0x2a, 0xf1, 0xc3, 0x1d, 0xe3, 0x2b, 0xa3, 0x43, 0x3b, 0x6d, 0x5b, 0xf9, 0xce, 0xaf, 0x4e, 0x08, 0x35, 0x51, 0x26, 0xaf, 0x0e, 0xf6, 0xdd, 0x11, 0x1b, 0xde, 0xee, 0xfa, 0x49, 0x43, 0x4c, 0x69, 0xab, 0xa4, 0x21, 0x60, 0xec, 0x3e, 0x36, 0x98, 0xc2, 0xa8, 0x8d, 0x96, 0xef, 0x94, 0x0b, 0x63, 0x6d, 0xff, 0x89, 0xf2, 0xdb, 0xde, 0x33, 0x7a, 0xe0, 0xfc, 0x7c, 0xd8, 0x02, 0xde, 0x72, 0x79, 0x34, 0x58, 0xdc, 0x3a, 0x19, 0x66, 0xfb, 0x0e, 0xd2, 0x8e, 0x51, 0x3d, 0xfc, 0x77, 0x13, 0x8d, 0x53, 0xf8, 0x78, 0x75, 0xa9, 0x7a, 0x22, 0xe1, 0x1e, 0x58, 0x19, 0x1d, 0x5a, 0xe8, 0x63, 0xde, 0x24, 0xff, 0x68, 0xa3, 0xe9, 0x61};
const uint8_t packet6Bytes[83] = {3, 0, 215, 192, 232, 51, 240, 203, 222, 159, 145, 51, 205, 158, 125, 80, 139, 26, 0, 237, 47, 193, 220, 93, 161, 184, 187, 50, 167, 133, 219, 135, 57, 68, 112, 241, 89, 30, 205, 154, 156, 143, 139, 238, 2, 34, 39, 20, 159, 141, 246, 175, 157, 240, 107, 132, 182, 74, 118, 246, 145, 198, 108, 88, 210, 35, 209, 28, 229, 206, 87, 89, 111, 221, 215, 194, 187, 53, 166, 122, 206, 183, 3};

// Store message info for PROOF validation
struct MessageInfo {
  uint8_t messageId[32];
  Reticulum::Identity* recipientIdentity;  // Who will create the proof
  const char* description;
};

MessageInfo messages[2];
int messageCount = 0;

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  
  Serial.println("Offline Packet Decoder");
  Serial.println("======================\n");
  
  // Load identities
  Reticulum::Identity clientA, clientB;
  if (!rns.identityFromBytes(clientA, clientABytes)) {
    Serial.println("ERROR: Could not load client A");
    return;
  }
  if (!rns.identityFromBytes(clientB, clientBBytes)) {
    Serial.println("ERROR: Could not load client B");
    return;
  }
  
  // Get destination hashes
  uint8_t destA[16], destB[16];
  rns.getDestinationHash(clientA, "lxmf.delivery", destA);
  rns.getDestinationHash(clientB, "lxmf.delivery", destB);
  
  Serial.print("Client A: ");
  for (int i = 0; i < 16; i++) {
    if (destA[i] < 16) Serial.print("0");
    Serial.print(destA[i], HEX);
  }
  Serial.println();
  
  Serial.print("Client B: ");
  for (int i = 0; i < 16; i++) {
    if (destB[i] < 16) Serial.print("0");
    Serial.print(destB[i], HEX);
  }
  Serial.println("\n");
  
  // Packet array
  struct PacketData {
    const uint8_t* data;
    size_t length;
    const char* description;
  };
  
  PacketData packets[] = {
    {packet1Bytes, sizeof(packet1Bytes), "ANNOUNCE from A"},
    {packet2Bytes, sizeof(packet2Bytes), "ANNOUNCE from B"},
    {packet3Bytes, sizeof(packet3Bytes), "DATA A->B"},
    {packet4Bytes, sizeof(packet4Bytes), "PROOF A->B"},
    {packet5Bytes, sizeof(packet5Bytes), "DATA B->A"},
    {packet6Bytes, sizeof(packet6Bytes), "PROOF B->A"}
  };
  
  int numPackets = sizeof(packets) / sizeof(packets[0]);
  
  // Process each packet
  for (int i = 0; i < numPackets; i++) {
    Serial.print("\nPacket ");
    Serial.print(i + 1);
    Serial.print(": ");
    Serial.println(packets[i].description);
    Serial.print("  Length: ");
    Serial.print(packets[i].length);
    Serial.println(" bytes");
    
    Reticulum::Packet pkt;
    if (!rns.decodePacket(packets[i].data, packets[i].length, pkt)) {
      Serial.println("  ERROR: Failed to decode packet");
      continue;
    }
    
    Serial.print("  Type: ");
    switch(pkt.packetType) {
      case PACKET_DATA: Serial.println("DATA"); break;
      case PACKET_ANNOUNCE: Serial.println("ANNOUNCE"); break;
      case PACKET_PROOF: Serial.println("PROOF"); break;
      default: Serial.println("UNKNOWN");
    }
    
    Serial.print("  Destination: ");
    for (int j = 0; j < 16; j++) {
      if (pkt.destinationHash[j] < 16) Serial.print("0");
      Serial.print(pkt.destinationHash[j], HEX);
    }
    Serial.println();
    
    // Handle ANNOUNCE
    if (pkt.packetType == PACKET_ANNOUNCE) {
      Reticulum::Announce announce;
      if (rns.announceParsePacket(pkt, announce)) {
        Serial.print("  Signature: ");
        Serial.println(announce.valid ? "VALID ✓" : "INVALID ✗");
        
        if (announce.appDataLen > 0) {
          Serial.print("  App Data: ");
          for (size_t j = 0; j < announce.appDataLen; j++) {
            if (announce.appData[j] >= 32 && announce.appData[j] < 127) {
              Serial.write(announce.appData[j]);
            } else {
              Serial.print(".");
            }
          }
          Serial.println();
        }
        rns.freeAnnounce(announce);
      }
    }
    
    // Handle DATA
    if (pkt.packetType == PACKET_DATA) {
      Serial.print("  Data payload: ");
      Serial.print(pkt.dataLen);
      Serial.println(" bytes");
      
      uint8_t plaintext[512];
      int plaintextLen = -1;
      Reticulum::Identity* recipientIdentity = nullptr;
      
      bool isForA = memcmp(pkt.destinationHash, destA, 16) == 0;
      bool isForB = memcmp(pkt.destinationHash, destB, 16) == 0;
      
      if (isForB) {
        Serial.println("  Message from A to B");
        const uint8_t* ratchetsB[] = {ratchetBytes[1]};
        plaintextLen = rns.messageDecrypt(pkt, clientB, plaintext, sizeof(plaintext), ratchetsB, 1);
        recipientIdentity = &clientB;  // B is recipient, will send proof
      } else if (isForA) {
        Serial.println("  Message from B to A");
        const uint8_t* ratchetsA[] = {ratchetBytes[0]};
        plaintextLen = rns.messageDecrypt(pkt, clientA, plaintext, sizeof(plaintext), ratchetsA, 1);
        recipientIdentity = &clientA;  // A is recipient, will send proof
      }
      
      if (plaintextLen > 0) {
        Serial.print("  ✓ Decrypted (");
        Serial.print(plaintextLen);
        Serial.print(" bytes): ");
        for (int j = 0; j < plaintextLen; j++) {
          if (plaintext[j] >= 32 && plaintext[j] < 127) {
            Serial.write(plaintext[j]);
          } else {
            Serial.print(".");
          }
        }
        Serial.println();
        
        // Store message ID for PROOF validation
        if (messageCount < 2 && recipientIdentity) {
          rns.getMessageId(pkt, messages[messageCount].messageId);
          messages[messageCount].recipientIdentity = recipientIdentity;
          messages[messageCount].description = isForB ? "A->B" : "B->A";
          
          Serial.print("  Message ID: ");
          for (int j = 0; j < 16; j++) {
            if (messages[messageCount].messageId[j] < 16) Serial.print("0");
            Serial.print(messages[messageCount].messageId[j], HEX);
          }
          Serial.println();
          
          messageCount++;
        }
      } else {
        Serial.println("  ✗ Could not decrypt");
      }
    }
    
    // Handle PROOF
    if (pkt.packetType == PACKET_PROOF) {
      Serial.println("  PROOF packet");
      
      bool proofValid = false;
      const char* matchedMsg = nullptr;
      
      // Find matching message by comparing PROOF destination with message IDs
      for (int m = 0; m < messageCount; m++) {
        if (memcmp(pkt.destinationHash, messages[m].messageId, 16) == 0) {
          matchedMsg = messages[m].description;
          
          Serial.print("  Validating proof for message ");
          Serial.println(matchedMsg);
          
          // Validate using recipient's identity (who created the proof)
          proofValid = rns.proofValidate(pkt, *messages[m].recipientIdentity, 
                                         messages[m].messageId);
          
          Serial.print("  Proof signature: ");
          Serial.println(proofValid ? "VALID ✓" : "INVALID ✗");
          break;
        }
      }
      
      if (!matchedMsg) {
        Serial.println("  No matching message found");
      }
    }
    
    rns.freePacket(pkt);
  }
  
  Serial.println("\n======================");
  Serial.println("All packets processed!");
}

void loop() {
  delay(1000);
}
