// Basic example

#include <Reticulum.h>

Reticulum rns;

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  
  Serial.println("Reticulum Arduino Library Example");
  Serial.println("==================================");
  
  // Create identity
  Reticulum::Identity myIdentity;
  Serial.println("\nCreating identity...");
  if (rns.identityCreate(myIdentity)) {
    Serial.println("Identity created successfully!");
    
    // Print public keys
    Serial.print("Encryption Public Key: ");
    for (int i = 0; i < 32; i++) {
      if (myIdentity.encryptPublic[i] < 16) Serial.print("0");
      Serial.print(myIdentity.encryptPublic[i], HEX);
    }
    Serial.println();
    
    Serial.print("Signing Public Key: ");
    for (int i = 0; i < 32; i++) {
      if (myIdentity.signPublic[i] < 16) Serial.print("0");
      Serial.print(myIdentity.signPublic[i], HEX);
    }
    Serial.println();
    
    // Get destination hash
    uint8_t destHash[16];
    rns.getDestinationHash(myIdentity, "lxmf.delivery", destHash);
    
    Serial.print("\nDestination Hash: ");
    for (int i = 0; i < 16; i++) {
      if (destHash[i] < 16) Serial.print("0");
      Serial.print(destHash[i], HEX);
    }
    Serial.println();
    
    // Create ratchet
    Serial.println("\nCreating ratchet...");
    uint8_t ratchetPriv[32];
    uint8_t ratchetPub[32];
    rns.ratchetCreateNew(ratchetPriv);
    rns.ratchetGetPublic(ratchetPriv, ratchetPub);
    
    Serial.print("Ratchet Public Key: ");
    for (int i = 0; i < 32; i++) {
      if (ratchetPub[i] < 16) Serial.print("0");
      Serial.print(ratchetPub[i], HEX);
    }
    Serial.println();
    
    // Build announce packet
    Serial.println("\nBuilding announce packet...");
    uint8_t announcePacket[512];
    size_t announceLen = rns.buildAnnounce(myIdentity, destHash, announcePacket, sizeof(announcePacket), "lxmf.delivery");
    
    if (announceLen > 0) {
      Serial.print("Announce packet built: ");
      Serial.print(announceLen);
      Serial.println(" bytes");
      
      // Parse the announce back
      Serial.println("\nParsing announce packet...");
      Reticulum::Packet pkt;
      if (rns.decodePacket(announcePacket, announceLen, pkt)) {
        Serial.println("Packet decoded successfully");
        
        Reticulum::Announce announce;
        if (rns.announceParsePacket(pkt, announce)) {
          Serial.print("Announce parsed and signature ");
          Serial.println(announce.valid ? "VALID" : "INVALID");
          
          rns.freeAnnounce(announce);
        }
        
        rns.freePacket(pkt);
      }
    }
    
    Serial.println("\n==================================");
    Serial.println("Ready for Reticulum communication!");
  } else {
    Serial.println("Failed to create identity!");
  }
}

void loop() {
}
