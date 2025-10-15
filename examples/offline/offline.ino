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
// is there a better way to do an array of arrays?
const uint8_t packet1Bytes[217] = {33, 0, 7, 46, 196, 73, 115, 168, 222, 232, 226, 141, 35, 15, 180, 175, 143, 228, 0, 162, 185, 176, 47, 180, 116, 159, 207, 132, 88, 118, 45, 27, 224, 174, 103, 255, 28, 170, 71, 251, 10, 82, 244, 194, 189, 109, 208, 120, 96, 167, 56, 218, 80, 168, 127, 136, 78, 110, 100, 170, 167, 11, 68, 210, 8, 104, 20, 78, 62, 38, 255, 160, 1, 198, 10, 124, 121, 125, 186, 229, 7, 142, 206, 110, 198, 11, 195, 24, 226, 192, 240, 217, 8, 115, 64, 130, 117, 83, 0, 104, 222, 16, 57, 226, 187, 33, 16, 139, 44, 188, 144, 11, 71, 98, 144, 171, 120, 103, 68, 20, 70, 219, 54, 106, 112, 251, 142, 209, 68, 140, 160, 232, 137, 189, 101, 186, 214, 216, 101, 78, 114, 102, 29, 220, 8, 155, 6, 73, 90, 185, 26, 87, 175, 197, 112, 14, 9, 95, 2, 26, 168, 206, 192, 79, 34, 186, 85, 67, 142, 252, 58, 177, 226, 169, 27, 141, 23, 189, 37, 147, 19, 241, 117, 223, 240, 64, 130, 127, 223, 17, 17, 200, 139, 239, 80, 22, 118, 56, 11, 146, 196, 14, 65, 110, 111, 110, 121, 109, 111, 117, 115, 32, 80, 101, 101, 114, 192};
const uint8_t packet2Bytes[217] = {33, 0, 118, 169, 60, 218, 136, 154, 140, 10, 136, 69, 30, 2, 213, 63, 216, 185, 0, 113, 241, 153, 240, 77, 53, 137, 202, 8, 60, 102, 255, 145, 186, 237, 98, 142, 225, 149, 23, 239, 104, 235, 32, 152, 39, 223, 58, 103, 133, 207, 91, 10, 244, 63, 176, 225, 104, 23, 99, 112, 130, 143, 205, 193, 153, 229, 174, 43, 32, 139, 87, 207, 101, 23, 159, 250, 143, 37, 115, 61, 157, 64, 188, 110, 198, 11, 195, 24, 226, 192, 240, 217, 8, 20, 154, 213, 37, 4, 0, 104, 222, 16, 59, 13, 246, 210, 32, 1, 28, 233, 218, 117, 89, 251, 214, 32, 56, 5, 1, 217, 225, 154, 252, 232, 122, 109, 12, 102, 20, 18, 243, 131, 28, 201, 21, 219, 236, 171, 232, 158, 245, 161, 26, 53, 157, 55, 87, 168, 82, 128, 195, 174, 104, 168, 182, 54, 110, 212, 17, 11, 226, 74, 64, 141, 190, 148, 107, 40, 21, 224, 232, 159, 142, 73, 132, 137, 120, 18, 43, 48, 228, 66, 175, 131, 179, 108, 239, 17, 211, 223, 105, 195, 65, 137, 21, 104, 88, 86, 2, 146, 196, 14, 65, 110, 111, 110, 121, 109, 111, 117, 115, 32, 80, 101, 101, 114, 192};
const uint8_t packet3Bytes[211] = {0, 0, 118, 169, 60, 218, 136, 154, 140, 10, 136, 69, 30, 2, 213, 63, 216, 185, 0, 245, 73, 204, 207, 141, 87, 76, 181, 32, 200, 241, 46, 166, 234, 103, 196, 244, 206, 52, 243, 1, 222, 97, 28, 217, 66, 172, 191, 182, 147, 63, 63, 122, 2, 93, 91, 109, 97, 132, 208, 77, 208, 39, 155, 128, 55, 241, 201, 193, 193, 194, 93, 239, 189, 213, 230, 42, 168, 251, 4, 80, 33, 1, 1, 74, 80, 27, 146, 53, 230, 47, 130, 59, 189, 253, 77, 133, 231, 101, 109, 118, 88, 2, 241, 21, 160, 27, 87, 184, 35, 174, 2, 204, 148, 137, 154, 227, 160, 249, 75, 247, 195, 47, 26, 115, 192, 39, 229, 201, 94, 13, 217, 76, 114, 200, 51, 234, 117, 149, 26, 245, 23, 218, 102, 94, 255, 38, 188, 164, 94, 144, 226, 234, 161, 135, 117, 230, 87, 153, 234, 11, 58, 151, 118, 69, 16, 120, 80, 219, 254, 98, 187, 31, 50, 40, 181, 10, 198, 231, 117, 0, 108, 79, 24, 214, 243, 161, 71, 66, 51, 220, 155, 19, 205, 149, 246, 166, 245, 129, 173, 11, 133, 222, 113, 150, 234, 96, 109, 57, 61, 53, 241};
const uint8_t packet4Bytes[83] = {3, 0, 40, 49, 215, 111, 26, 128, 53, 99, 133, 5, 193, 50, 254, 88, 24, 193, 0, 185, 11, 131, 160, 75, 227, 25, 70, 63, 147, 11, 18, 59, 102, 126, 170, 246, 74, 133, 232, 39, 195, 72, 49, 160, 50, 207, 114, 131, 74, 29, 197, 136, 54, 225, 254, 76, 73, 227, 13, 236, 171, 82, 116, 125, 162, 129, 29, 184, 58, 75, 11, 132, 100, 170, 49, 224, 47, 46, 235, 191, 29, 174, 3};
const uint8_t packet5Bytes[211] = {0, 0, 7, 46, 196, 73, 115, 168, 222, 232, 226, 141, 35, 15, 180, 175, 143, 228, 0, 178, 25, 27, 35, 183, 80, 106, 51, 37, 254, 40, 141, 117, 167, 171, 6, 112, 15, 146, 199, 16, 193, 106, 127, 85, 118, 154, 251, 1, 77, 117, 59, 140, 243, 24, 119, 48, 17, 105, 5, 132, 63, 176, 222, 157, 206, 201, 118, 177, 33, 166, 66, 91, 153, 95, 128, 68, 40, 25, 235, 232, 131, 218, 181, 170, 114, 251, 138, 157, 150, 132, 153, 105, 176, 115, 184, 231, 110, 68, 99, 220, 140, 14, 206, 186, 147, 102, 101, 196, 182, 42, 241, 195, 29, 227, 43, 163, 67, 59, 109, 91, 249, 206, 175, 78, 8, 53, 81, 38, 175, 14, 246, 221, 17, 27, 222, 238, 250, 73, 67, 76, 105, 171, 164, 33, 96, 236, 62, 54, 152, 194, 168, 141, 150, 239, 148, 11, 99, 109, 255, 137, 242, 219, 222, 51, 122, 224, 252, 124, 216, 2, 222, 114, 121, 52, 88, 220, 58, 25, 102, 251, 14, 210, 142, 81, 61, 252, 119, 19, 141, 83, 248, 120, 117, 169, 122, 34, 225, 30, 88, 25, 29, 90, 232, 99, 222, 36, 255, 104, 163, 233, 97};
const uint8_t packet6Bytes[83] = {3, 0, 215, 192, 232, 51, 240, 203, 222, 159, 145, 51, 205, 158, 125, 80, 139, 26, 0, 205, 0, 206, 35, 116, 113, 96, 157, 110, 246, 78, 66, 113, 81, 254, 212, 109, 158, 183, 31, 230, 51, 127, 111, 197, 48, 169, 243, 165, 92, 115, 15, 31, 208, 159, 130, 247, 209, 45, 28, 170, 219, 193, 133, 183, 112, 63, 13, 159, 93, 182, 199, 146, 194, 223, 205, 241, 238, 211, 17, 16, 136, 134, 12};

// Array of packet pointers and lengths for easy iteration
struct PacketData {
  const uint8_t* data;
  size_t length;
  const char* description;
};

PacketData packets[] = {
  {packet1Bytes, sizeof(packet1Bytes), "Announce from Client A"},
  {packet2Bytes, sizeof(packet2Bytes), "Announce from Client B"},
  {packet3Bytes, sizeof(packet3Bytes), "Message from A to B"},
  {packet4Bytes, sizeof(packet4Bytes), "Proof of message from A to B"},
  {packet5Bytes, sizeof(packet3Bytes), "Message from B to A"},
  {packet6Bytes, sizeof(packet4Bytes), "Proof of message from B to A"}
};

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  
  Serial.println("Offline Packet Decoder");
  Serial.println("======================\n");
  
  // Load identities
  Reticulum::Identity clientA, clientB;
  rns.identityFromBytes(clientA, clientABytes);
  rns.identityFromBytes(clientB, clientBBytes);
  
  // Get destination hashes
  uint8_t destA[16], destB[16];
  rns.getDestinationHash(clientA, "lxmf.delivery", destA);
  rns.getDestinationHash(clientB, "lxmf.delivery", destB);
  
  Serial.print("Client A destination: ");
  for (int i = 0; i < 16; i++) {
    if (destA[i] < 16) Serial.print("0");
    Serial.print(destA[i], HEX);
  }
  Serial.println();
  
  Serial.print("Client B destination: ");
  for (int i = 0; i < 16; i++) {
    if (destB[i] < 16) Serial.print("0");
    Serial.print(destB[i], HEX);
  }
  Serial.println("\n");
  
  int numPackets = sizeof(packets) / sizeof(packets[0]);
  
  // Process each packet
  for (int i = 0; i < numPackets; i++) {
    Serial.print("Packet ");
    Serial.print(i + 1);
    Serial.print(": ");
    Serial.println(packets[i].description);
    Serial.print("  Length: ");
    Serial.print(packets[i].length);
    Serial.println(" bytes");
    
    Reticulum::Packet pkt;
    if (!rns.decodePacket(packets[i].data, packets[i].length, pkt)) {
      Serial.println("  ERROR: Failed to decode packet\n");
      continue;
    }
    
    // Print packet type
    Serial.print("  Type: ");
    switch(pkt.packetType) {
      case PACKET_DATA: Serial.println("DATA"); break;
      case PACKET_ANNOUNCE: Serial.println("ANNOUNCE"); break;
      case PACKET_LINKREQUEST: Serial.println("LINKREQUEST"); break;
      case PACKET_PROOF: Serial.println("PROOF"); break;
      default: Serial.println("UNKNOWN");
    }
    
    Serial.print("  Destination: ");
    for (int j = 0; j < 16; j++) {
      if (pkt.destinationHash[j] < 16) Serial.print("0");
      Serial.print(pkt.destinationHash[j], HEX);
    }
    Serial.println();
    
    // Handle ANNOUNCE packets
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
      } else {
        Serial.println("  ERROR: Failed to parse announce");
      }
    }
    
    // Handle DATA packets - try to decrypt
    if (pkt.packetType == PACKET_DATA) {
      uint8_t plaintext[256];
      int plaintextLen = -1;
      
      // Try decrypting as Client A
      const uint8_t* ratchetsA[] = {ratchetBytes[0]};
      plaintextLen = rns.messageDecrypt(pkt, clientA, plaintext, sizeof(plaintext), ratchetsA, 1);
      
      if (plaintextLen < 0) {
        // Try decrypting as Client B
        const uint8_t* ratchetsB[] = {ratchetBytes[1]};
        plaintextLen = rns.messageDecrypt(pkt, clientB, plaintext, sizeof(plaintext), ratchetsB, 1);
      }
      
      if (plaintextLen > 0) {
        Serial.print("  Decrypted (");
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
      } else {
        Serial.println("  Could not decrypt with available keys");
      }
    }
    
    // Handle PROOF packets
    if (pkt.packetType == PACKET_PROOF) {
      Serial.println("  Proof packet detected");
      // You would verify this against the original message's hash
    }
    
    Serial.println();
    rns.freePacket(pkt);
  }
  
  Serial.println("======================");
  Serial.println("All packets processed!");
}


void loop() {
}