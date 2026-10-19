#include <SPI.h>
#include <LoRa.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Keypad.h>

#include "src/mlkem_native.h"

#include <esp_system.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"

// ============================================================
// CHANGE ONLY THIS LINE ON EACH BOARD  (unique, 1..MAX_NODES)
// ============================================================
#define NODE_ID    3

#define MAX_NODES  10

#include "packet.h"
#include "routing.h"

// ============================================================
// LoRa
// ============================================================

#define SCK       12
#define MISO      13
#define MOSI      11
#define CS        10
#define RST       9
#define DIO0      14

#define LORA_FREQ 868E6
#define LORA_SYNC 0xA5
#define LORA_SF   7
#define LORA_BW   125E3
#define LORA_CR   5

// ============================================================
// OLED 128x32
// ============================================================

#define SCREEN_WIDTH  128
#define SCREEN_HEIGHT 32
#define OLED_SDA      7
#define OLED_SCL      8
#define OLED_ADDRESS  0x3C

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// ============================================================
// 4x3 KEYPAD
// ============================================================

const byte ROWS = 4;
const byte COLS = 3;

char keys[ROWS][COLS] =
{
  {'1', '2', '3'},
  {'4', '5', '6'},
  {'7', '8', '9'},
  {'*', '0', '#'}
};

byte rowPins[ROWS] = {1, 2, 3, 4};
byte colPins[COLS] = {5, 6, 15};

Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

// ============================================================
// ML-KEM-768
// ============================================================

#define PK_SIZE       1184
#define SK_SIZE       2400
#define CT_SIZE       1088
#define SS_SIZE       32
#define KEYGEN_COINS  64
#define ENC_COINS     32

uint8_t publicKey[PK_SIZE];
uint8_t secretKey[SK_SIZE];
uint8_t ciphertext[CT_SIZE];
uint8_t sharedSecret[SS_SIZE];
uint8_t sessionKey[32];
uint8_t keygenCoins[KEYGEN_COINS];
uint8_t encCoins[ENC_COINS];

volatile bool keypairReady = false;
volatile bool keygenStarted = false;
volatile bool keygenFailed = false;

volatile bool encapStarted = false;
volatile bool encapDone = false;
volatile bool encapFailed = false;

volatile bool decapStarted = false;
volatile bool decapDone = false;
volatile bool decapFailed = false;

volatile bool sessionKeyReady = false;

// ============================================================
// PROTOCOL TUNING
// ============================================================

#define CHUNK_SIZE            180
#define MAX_CHUNKS            16
#define MAX_RETRIES           6
#define CHUNK_ACK_TIMEOUT_MS  3500UL    // multi-hop round trip + retries
#define MSG_ACK_TIMEOUT_MS    4000UL
#define MSG_MAX_TRIES         4

#define HELLO_INTERVAL        2500UL
#define HELLO_MAX_ATTEMPTS    10

#define HANDSHAKE_STATE_TIMEOUT 30000UL

#define GCM_NONCE_SIZE   12
#define GCM_TAG_SIZE     16
#define MAX_MESSAGE_SIZE 100

// ============================================================
// HANDSHAKE STATE
// ============================================================

typedef enum HandshakeState
{
  HS_IDLE,
  HS_HELLO_WAIT,       // initiator: waiting for HELLO_ACK
  HS_INIT_SEND_PK,     // initiator: sending public key
  HS_INIT_WAIT_CT,     // initiator: waiting for ciphertext
  HS_INIT_DECAP,       // initiator: decapsulating
  HS_RESP_WAIT_PK,     // responder: waiting for public key
  HS_RESP_PROCESS_CT,  // responder: encapsulating + sending ciphertext
  HS_SECURE
} HandshakeState;

volatile HandshakeState hs = HS_IDLE;
unsigned long hsStateEnteredAt = 0;

void setState(HandshakeState newState);
void setState(HandshakeState newState)
{
  hs = newState;
  hsStateEnteredAt = millis();
}

uint8_t  peerID = 0;          // ultimate logical peer of the current session
uint32_t localNonce = 0;      // initiator's nonce (also echoed in HELLO_ACK)
uint32_t peerNonce = 0;       // responder: nonce received in HELLO
uint32_t sessionNonce = 0;    // = initiator's nonce on both sides (KDF input)

unsigned long helloLastSent = 0;
uint8_t helloAttempts = 0;
uint8_t helloHop = INVALID_NODE;

// chunk reassembly
uint8_t chunkSeen[MAX_CHUNKS];
uint8_t expectedChunks = 0;
uint8_t receivedChunks = 0;
bool pkComplete = false;
bool ctComplete = false;

// chunk ACK wait
volatile bool awaitingChunkAck = false;
volatile bool chunkAckReceived = false;
uint8_t ackWaitType = 0, ackWaitChunk = 0, ackWaitTotal = 0;

// secure messaging
uint32_t outgoingMessageID = 1;
uint32_t lastReceivedMessageID = 0;

String pendingMessage = "";
bool hasPendingMessage = false;

bool msgOutstanding = false;
uint8_t msgTries = 0;
uint8_t msgHop = INVALID_NODE;
uint32_t msgLastTx = 0;
uint32_t outstandingMsgID = 0;
uint8_t secPayload[6 + GCM_NONCE_SIZE + MAX_MESSAGE_SIZE + GCM_TAG_SIZE];
uint16_t secPayloadLen = 0;

// UI
String inputMessage = "";
uint8_t targetNodeID = 0;
bool selectingTarget = false;
bool keygenMsgShown = false;

static uint8_t rxBuf[MAX_PACKET_SIZE];

// ============================================================
// FORWARD DECLARATIONS
// ============================================================

void serviceBackground();
void resetToIdle(const char *reason);
void oledResume();

// ============================================================
// RANDOM
// ============================================================

void getRandomBytes(uint8_t *buffer, size_t length)
{
  for (size_t i = 0; i < length; i += 4)
  {
    uint32_t r = esp_random();
    size_t remaining = length - i;
    size_t copySize = (remaining >= 4) ? 4 : remaining;
    memcpy(buffer + i, &r, copySize);
  }
}

// ============================================================
// OLED  (only the main loop task ever touches the display)
// ============================================================

enum OLEDStatus
{
  OLED_NORMAL,    // neighbour bars (animated)
  OLED_SELECT,    // choosing target
  OLED_INPUT,     // typing a message
  OLED_MESSAGE,   // timed message, then back to normal/input
  OLED_BUSY       // persistent status until replaced
};

OLEDStatus oledStatus = OLED_NORMAL;
uint32_t oledStatusUntil = 0;
uint32_t oledLastNormalFrame = 0;
uint8_t oledAnimFrame = 0;
bool oledInitialized = false;

void oledDraw2(const String &line1, const String &line2)
{
  if (!oledInitialized) return;

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println(line1.substring(0, 21));
  display.setCursor(0, 16);
  display.println(line2.substring(0, 21));
  display.display();
}

// holdMs == 0 -> stays until something else is drawn
void oledShowMessage(const String &line1, const String &line2, uint32_t holdMs)
{
  oledDraw2(line1, line2);

  if (holdMs > 0)
  {
    oledStatus = OLED_MESSAGE;
    oledStatusUntil = millis() + holdMs;
  }
  else
  {
    oledStatus = OLED_BUSY;
    oledStatusUntil = 0;
  }
}

void oledShowSelect()
{
  oledStatus = OLED_SELECT;
  oledStatusUntil = 0;
  oledDraw2("SELECT TARGET", "1-9, 0 = NODE 10");
}

void oledShowInput()
{
  if (!oledInitialized) return;

  oledStatus = OLED_INPUT;
  oledStatusUntil = 0;

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.print("TO ");
  display.print(targetNodeID);
  display.print(" MSG>");

  display.setCursor(0, 16);
  String visible = inputMessage;
  if (visible.length() > 20) visible = visible.substring(visible.length() - 20);
  display.print(visible);
  display.display();
}

void oledDrawNode(int x, uint8_t node, uint8_t cost, bool selected, uint8_t pulse)
{
  const int width = 23;
  const int barX = x + 3;
  const int barW = width - 6;
  const int barBottom = 22;
  const int barMaxHeight = 10;

  int barHeight = (cost <= 1) ? 10 : (cost == 2) ? 7 : (cost == 3) ? 5 : 3;
  int barY = barBottom - barHeight + 1;

  if (selected) display.drawRect(x, 8, width, 24, SSD1306_WHITE);

  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(x + (width - 6) / 2, 9);
  display.print(node);

  display.drawRect(barX, 13, barW, barMaxHeight, SSD1306_WHITE);
  display.fillRect(barX + 1, barY, barW - 2, barHeight, SSD1306_WHITE);

  if (pulse)
  {
    int pulseX = barX + 2 + ((pulse - 1) % max(1, barW - 4));
    display.drawFastVLine(pulseX, 14, barMaxHeight - 2, SSD1306_BLACK);
  }

  display.setTextColor(SSD1306_WHITE);
  display.setCursor(x + 5, 24);
  display.print("C");
  display.print(cost);
}

void oledShowNeighbors()
{
  if (!oledInitialized) return;

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);

  display.setCursor(0, 0);
  display.print("NODE ");
  display.print(NODE_ID);

  int activeCount = 0;
  for (int i = 0; i < MAX_NEIGHBORS; i++)
    if (neighbor_table[i].active) activeCount++;

  display.setCursor(70, 0);
  display.print("N:");
  display.print(activeCount);
  display.drawFastHLine(0, 7, 128, SSD1306_WHITE);

  if (activeCount == 0)
  {
    display.setCursor(35, 13);
    display.print("NO LINKS");
    display.setCursor(37, 23);
    display.print("SEARCHING");
    for (uint8_t i = 0; i < oledAnimFrame; i++) display.print(".");
    display.display();
    return;
  }

  int slot = 0;
  for (int i = 0; i < MAX_NEIGHBORS && slot < 5; i++)
  {
    if (!neighbor_table[i].active) continue;

    uint8_t node = neighbor_table[i].neighbor_id;
    uint8_t cost = getNeighborCost(neighbor_table[i]);
    if (cost >= ROUTE_INF) continue;   // jammed neighbors are hidden

    oledDrawNode(slot * 25, node, cost, node == targetNodeID,
                 (uint8_t)((oledAnimFrame + slot) % 8));
    slot++;
  }

  display.display();
}

void oledResume()
{
  oledStatusUntil = 0;

  if (selectingTarget)       oledShowSelect();
  else if (targetNodeID != 0) oledShowInput();
  else
  {
    oledStatus = OLED_NORMAL;
    oledShowNeighbors();
  }
}

void oledTask()
{
  if (!oledInitialized) return;

  uint32_t now = millis();

  if (oledStatus == OLED_MESSAGE && (int32_t)(now - oledStatusUntil) >= 0)
    oledResume();

  if (oledStatus == OLED_NORMAL && now - oledLastNormalFrame >= 350UL)
  {
    oledLastNormalFrame = now;
    oledAnimFrame = (oledAnimFrame + 1) % 8;
    oledShowNeighbors();
  }
}

void oledBegin()
{
  Wire.begin(OLED_SDA, OLED_SCL);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS))
  {
    Serial.println("[OLED] FAILED");
    oledInitialized = false;
    return;
  }

  oledInitialized = true;
  oledDraw2(String("NODE ") + NODE_ID + "  PQC MESH", "STARTING...");
  delay(500);
}

void pqcStage(const String &line1, const String &line2)
{
  Serial.println();
  Serial.println("================================");
  Serial.println("              PQC");
  Serial.println("================================");
  Serial.println(line1);
  if (line2.length() > 0) Serial.println(line2);
  Serial.println("================================");

  oledShowMessage(line1, line2, 0);
}

// ============================================================
// ML-KEM KEYGEN TASK (core 0)
// ============================================================

void mlkemKeygenTask(void *parameter)
{
  Serial.println("[PQC] KEYGEN START");

  getRandomBytes(keygenCoins, KEYGEN_COINS);
  int result = PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(publicKey, secretKey, keygenCoins);
  memset(keygenCoins, 0, KEYGEN_COINS);

  if (result == 0)
  {
    keypairReady = true;
    keygenFailed = false;
    Serial.println("[PQC] KEYPAIR READY");
  }
  else
  {
    keygenFailed = true;
    Serial.print("[PQC] KEYGEN FAILED rc=");
    Serial.println(result);
  }

  keygenStarted = false;
  vTaskDelete(NULL);
}

void ensureKeygen()
{
  if (keypairReady || keygenStarted) return;

  keygenStarted = true;
  keygenFailed = false;

  BaseType_t result = xTaskCreatePinnedToCore(
      mlkemKeygenTask, "MLKEM_KEYGEN", 32768, NULL, 1, NULL, 0);

  if (result != pdPASS)
  {
    keygenStarted = false;
    keygenFailed = true;
    Serial.println("[PQC] KEYGEN TASK CREATE FAILED");
  }
}

// ============================================================
// SESSION KEY = SHA256(context || initiatorNonce || sharedSecret)
// ============================================================

bool deriveSessionKey()
{
  const char context[] = "PQC-LORA-SESSION-V2";
  uint8_t input[(sizeof(context) - 1) + 4 + SS_SIZE];
  size_t p = 0;

  memcpy(input + p, context, sizeof(context) - 1);
  p += sizeof(context) - 1;
  putBe32(input + p, sessionNonce);
  p += 4;
  memcpy(input + p, sharedSecret, SS_SIZE);

  int result = mbedtls_sha256(input, sizeof(input), sessionKey, 0);
  memset(input, 0, sizeof(input));

  if (result != 0)
  {
    sessionKeyReady = false;
    Serial.print("[CRYPTO] SHA256 FAILED rc=");
    Serial.println(result);
    return false;
  }

  sessionKeyReady = true;
  Serial.println("[CRYPTO] SESSION KEY READY");
  return true;
}

// ============================================================
// RESPONDER ENCAP TASK / INITIATOR DECAP TASK (core 0)
// These only compute. All radio + display work stays in loop().
// ============================================================

void responderCryptoTask(void *parameter)
{
  getRandomBytes(encCoins, ENC_COINS);

  int result = PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(ciphertext, sharedSecret, publicKey, encCoins);
  memset(encCoins, 0, ENC_COINS);

  if (result == 0 && deriveSessionKey())
    encapDone = true;
  else
    encapFailed = true;

  memset(sharedSecret, 0, SS_SIZE);
  encapStarted = false;
  vTaskDelete(NULL);
}

void startResponderCrypto()
{
  if (encapStarted) return;
  encapStarted = true;
  encapDone = false;
  encapFailed = false;
  xTaskCreatePinnedToCore(responderCryptoTask, "KEM_ENCAP", 32768, NULL, 1, NULL, 0);
}

void initiatorDecapTask(void *parameter)
{
  int result = PQCP_MLKEM_NATIVE_MLKEM768_dec(sharedSecret, ciphertext, secretKey);

  if (result == 0 && deriveSessionKey())
    decapDone = true;
  else
    decapFailed = true;

  // Ephemeral keypair: use once, then wipe so the next session gets a fresh one.
  memset(sharedSecret, 0, SS_SIZE);
  memset(secretKey, 0, SK_SIZE);
  keypairReady = false;

  decapStarted = false;
  vTaskDelete(NULL);
}

void startInitiatorDecap()
{
  if (decapStarted) return;
  decapStarted = true;
  decapDone = false;
  decapFailed = false;
  xTaskCreatePinnedToCore(initiatorDecapTask, "KEM_DECAP", 32768, NULL, 1, NULL, 0);
}

// ============================================================
// SESSION RESET HELPERS
// ============================================================

void clearChunks()
{
  memset(chunkSeen, 0, sizeof(chunkSeen));
  expectedChunks = 0;
  receivedChunks = 0;
}

void clearSession()
{
  sessionKeyReady = false;
  encapDone = encapFailed = false;
  decapDone = decapFailed = false;
  pkComplete = ctComplete = false;
  awaitingChunkAck = false;
  chunkAckReceived = false;
  msgOutstanding = false;
  helloAttempts = 0;
  helloLastSent = 0;
  keygenMsgShown = false;

  memset(sharedSecret, 0, SS_SIZE);
  memset(sessionKey, 0, sizeof(sessionKey));
  clearChunks();
}

void resetToIdle(const char *reason)
{
  Serial.print("[LINK] RESET: ");
  Serial.println(reason);

  clearSession();
  setState(HS_IDLE);
  peerID = 0;
  peerNonce = 0;
  sessionNonce = 0;

  // Give the user their message back so they can just press # again.
  if (hasPendingMessage && pendingMessage.length() > 0) inputMessage = pendingMessage;
  hasPendingMessage = false;
  pendingMessage = "";

  selectingTarget = false;

  oledShowMessage("LINK RESET", reason, 1500);
}

void enterSecure()
{
  outgoingMessageID = 1;
  lastReceivedMessageID = 0;
  msgOutstanding = false;
  setState(HS_SECURE);

  Serial.print("[PQC] SECURE SESSION with Node ");
  Serial.println(peerID);

  oledShowMessage("SECURE", String("WITH NODE ") + peerID, 1500);
}

// ============================================================
// RELIABLE CHUNK TRANSFER (end-to-end ACK, route re-resolved
// on every attempt so a jammed hop is bypassed mid-transfer)
// ============================================================

bool waitForChunkAck(uint8_t type, uint8_t chunk, uint8_t total, uint8_t hop)
{
  ackWaitType = type;
  ackWaitChunk = chunk;
  ackWaitTotal = total;
  chunkAckReceived = false;
  awaitingChunkAck = true;

  unsigned long start = millis();

  while (millis() - start < CHUNK_ACK_TIMEOUT_MS)
  {
    serviceBackground();

    if (chunkAckReceived)
    {
      awaitingChunkAck = false;
      Serial.print("[ACK] FINAL: ");
      Serial.print(chunk + 1);
      Serial.print("/");
      Serial.println(total);
      updatePDR(hop, true);
      return true;
    }

    delay(2);
  }

  awaitingChunkAck = false;
  updatePDR(hop, false);
  return false;
}

bool sendChunk(uint8_t type, uint8_t chunk, uint8_t total, const uint8_t *data, uint16_t length)
{
  static uint8_t payload[2 + CHUNK_SIZE];

  payload[0] = chunk;
  payload[1] = total;
  memcpy(payload + 2, data, length);

  for (uint8_t attempt = 1; attempt <= MAX_RETRIES; attempt++)
  {
    bool ok = sendUnicast(type, peerID, payload, 2 + length);
    uint8_t hop = lastTxHop;

    Serial.print("[TX] type=");
    Serial.print(type);
    Serial.print(" dest=");
    Serial.print(peerID);
    Serial.print(" via=");
    Serial.print(hop);
    Serial.print(" chunk ");
    Serial.print(chunk + 1);
    Serial.print("/");
    Serial.print(total);
    Serial.print(" attempt ");
    Serial.print(attempt);
    Serial.print("/");
    Serial.println(MAX_RETRIES);

    if (ok)
    {
      if (waitForChunkAck(type, chunk, total, hop)) return true;
      Serial.println("[ACK] TIMEOUT - RETRY (route re-evaluated)");
    }
    else
    {
      // No route (or TX error): penalise the hop if we had one, then
      // keep the radio/routing alive for a moment and try again.
      if (hop != INVALID_NODE) updatePDR(hop, false);
      Serial.println("[TX] NO ROUTE / TX FAIL - waiting");

      unsigned long t = millis();
      while (millis() - t < 1000UL)
      {
        serviceBackground();
        delay(2);
      }
    }
  }

  Serial.println("[TX] CHUNK FAILED");
  return false;
}

bool sendFragmented(uint8_t type, const uint8_t *data, uint16_t length)
{
  uint8_t total = (length + CHUNK_SIZE - 1) / CHUNK_SIZE;

  for (uint8_t chunk = 0; chunk < total; chunk++)
  {
    uint16_t offset = chunk * CHUNK_SIZE;
    uint16_t remaining = length - offset;
    uint16_t payloadLength = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;

    if (!sendChunk(type, chunk, total, data + offset, payloadLength)) return false;
  }

  return true;
}

void sendChunkAck(uint8_t dst, uint8_t streamType, uint8_t chunk, uint8_t total)
{
  uint8_t pl[3] = { streamType, chunk, total };
  sendUnicast(PACKET_CHUNK_ACK, dst, pl, 3);
}

// ============================================================
// HELLO / HELLO-ACK
// ============================================================

void sendHello()
{
  if (peerID == 0) return;

  uint8_t pl[4];
  putBe32(pl, localNonce);

  bool ok = sendUnicast(PACKET_HELLO, peerID, pl, 4);

  helloHop = lastTxHop;
  helloLastSent = millis();
  helloAttempts++;

  Serial.print("[HELLO] TX: Node ");
  Serial.print(NODE_ID);
  Serial.print(" -> Node ");
  Serial.print(peerID);
  Serial.print(" via ");
  Serial.print(helloHop);
  Serial.print(" attempt ");
  Serial.print(helloAttempts);
  Serial.print("/");
  Serial.print(HELLO_MAX_ATTEMPTS);
  Serial.println(ok ? "" : "  (no route / tx fail)");
}

void sendHelloAck(uint8_t dst, uint32_t nonce)
{
  uint8_t pl[4];
  putBe32(pl, nonce);
  sendUnicast(PACKET_HELLO_ACK, dst, pl, 4);

  Serial.print("[HELLO-ACK] TX -> Node ");
  Serial.println(dst);
}

// ============================================================
// PACKET HANDLERS (packets whose FINAL destination is this node)
// ============================================================

void handleHello(uint8_t src, uint32_t nonce)
{
  Serial.print("[HELLO] RX from Node ");
  Serial.println(src);

  // Retransmitted HELLO for a session we already accepted: just re-ACK.
  bool sameSession = (src == peerID && nonce == peerNonce && peerNonce != 0);
  if (sameSession &&
      (hs == HS_RESP_WAIT_PK || hs == HS_RESP_PROCESS_CT || hs == HS_SECURE))
  {
    sendHelloAck(src, nonce);
    return;
  }

  if (hs == HS_IDLE || hs == HS_SECURE)
  {
    clearSession();

    peerID = src;
    peerNonce = nonce;
    sessionNonce = nonce;

    setState(HS_RESP_WAIT_PK);

    Serial.println("[LINK] ROLE: RESPONDER");
    oledShowMessage("RESPONDER", String("PEER: ") + peerID, 0);

    sendHelloAck(src, nonce);
  }
}

void handleHelloAck(uint8_t src, uint32_t nonce)
{
  if (hs == HS_HELLO_WAIT && src == peerID && nonce == localNonce)
  {
    Serial.print("[HELLO-ACK] RX from Node ");
    Serial.println(src);

    updatePDR(helloHop, true);
    setState(HS_INIT_SEND_PK);
    oledShowMessage("INITIATOR", String("PEER: ") + peerID, 0);
  }
}

void handleChunk(uint8_t type, uint8_t src, const uint8_t *p, int plen)
{
  uint8_t chunk = p[0];
  uint8_t total = p[1];
  uint16_t dataLen = plen - 2;

  if (total == 0 || total > MAX_CHUNKS || chunk >= total) return;
  if (src != peerID) return;

  uint8_t *dest;
  uint16_t maxLen;
  bool store = false;
  bool reack = false;

  if (type == PACKET_PK_CHUNK)
  {
    dest = publicKey;
    maxLen = PK_SIZE;
    if (hs == HS_RESP_WAIT_PK) store = true;
    else if (hs == HS_RESP_PROCESS_CT || hs == HS_SECURE) reack = true;
  }
  else
  {
    dest = ciphertext;
    maxLen = CT_SIZE;
    if (hs == HS_INIT_WAIT_CT) store = true;
    else if (hs == HS_INIT_DECAP || hs == HS_SECURE) reack = true;
  }

  // Late duplicate of a finished transfer (our ACK was lost): re-ACK only.
  if (reack)
  {
    sendChunkAck(src, type, chunk, total);
    return;
  }

  if (!store) return;

  uint16_t offset = chunk * CHUNK_SIZE;
  if (offset + dataLen > maxLen) return;

  if (expectedChunks == 0)
  {
    expectedChunks = total;
    receivedChunks = 0;
    memset(chunkSeen, 0, sizeof(chunkSeen));
  }

  if (total != expectedChunks) return;

  memcpy(dest + offset, p + 2, dataLen);
  sendChunkAck(src, type, chunk, total);

  if (!chunkSeen[chunk])
  {
    chunkSeen[chunk] = 1;
    receivedChunks++;
  }

  if (receivedChunks == expectedChunks)
  {
    if (type == PACKET_PK_CHUNK) pkComplete = true;
    else ctComplete = true;
  }
}

void handleChunkAck(uint8_t src, const uint8_t *p)
{
  if (!awaitingChunkAck || src != peerID) return;

  if (p[0] == ackWaitType && p[1] == ackWaitChunk && p[2] == ackWaitTotal)
    chunkAckReceived = true;
}

void handleSecureMessage(uint8_t src, const uint8_t *p, int plen)
{
  if (hs != HS_SECURE || !sessionKeyReady || src != peerID) return;
  if (plen < 6 + GCM_NONCE_SIZE + GCM_TAG_SIZE) return;

  uint32_t id = be32(p);
  uint16_t mlen = ((uint16_t)p[4] << 8) | p[5];

  if (mlen == 0 || mlen > MAX_MESSAGE_SIZE) return;
  if (plen < 6 + GCM_NONCE_SIZE + (int)mlen + GCM_TAG_SIZE) return;

  const uint8_t *nonce = p + 6;
  const uint8_t *enc = p + 6 + GCM_NONCE_SIZE;
  const uint8_t *tag = enc + mlen;

  uint8_t aad[6] = { src, (uint8_t)NODE_ID, 0, 0, 0, 0 };
  putBe32(aad + 2, id);

  uint8_t plaintext[MAX_MESSAGE_SIZE + 1];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int result = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, sessionKey, 256);
  if (result == 0)
  {
    result = mbedtls_gcm_auth_decrypt(
        &gcm, mlen, nonce, GCM_NONCE_SIZE, aad, sizeof(aad),
        tag, GCM_TAG_SIZE, enc, plaintext);
  }
  mbedtls_gcm_free(&gcm);

  if (result != 0)
  {
    Serial.println("[CRYPTO] AES-GCM AUTH FAILED");
    return;
  }

  plaintext[mlen] = '\0';

  // ACK every authentic copy (the sender may have lost our previous ACK).
  uint8_t ackPl[4];
  putBe32(ackPl, id);
  sendUnicast(PACKET_SECURE_ACK, src, ackPl, 4);

  if (id <= lastReceivedMessageID) return;   // duplicate / replay: no re-display
  lastReceivedMessageID = id;

  Serial.print("[RX] MESSAGE FROM Node ");
  Serial.print(src);
  Serial.print(" RSSI=");
  Serial.print(LoRa.packetRssi());
  Serial.print(" : ");
  Serial.println((char *)plaintext);

  oledShowMessage(String("RX FROM ") + src, String((char *)plaintext), 8000);
}

void handleSecureAck(uint8_t src, uint32_t id)
{
  if (!msgOutstanding || src != peerID || id != outstandingMsgID) return;

  updatePDR(msgHop, true);

  msgOutstanding = false;
  hasPendingMessage = false;
  pendingMessage = "";

  Serial.println("[MSG] DELIVERED (end-to-end ACK)");
  oledShowMessage("DELIVERED", String("TO NODE ") + src, 1500);
}

void handlePacketForMe(uint8_t *pkt, int len)
{
  uint8_t type = pkt[0];
  uint8_t src = pkt[2];
  const uint8_t *p = pkt + HDR_SIZE;
  int plen = len - HDR_SIZE;

  switch (type)
  {
    case PACKET_HELLO:       if (plen >= 4) handleHello(src, be32(p)); break;
    case PACKET_HELLO_ACK:   if (plen >= 4) handleHelloAck(src, be32(p)); break;
    case PACKET_PK_CHUNK:
    case PACKET_CT_CHUNK:    if (plen >= 2) handleChunk(type, src, p, plen); break;
    case PACKET_CHUNK_ACK:   if (plen >= 3) handleChunkAck(src, p); break;
    case PACKET_SECURE_MSG:  handleSecureMessage(src, p, plen); break;
    case PACKET_SECURE_ACK:  if (plen >= 4) handleSecureAck(src, be32(p)); break;
    default: break;
  }
}

// ============================================================
// SINGLE RADIO READER
// Every packet is read here, whatever the node is doing:
//   beacon            -> routing tables
//   not for us        -> relay (works during handshake / secure session)
//   for us            -> protocol handlers
// ============================================================

void pollRadio()
{
  int packetSize = LoRa.parsePacket();
  if (packetSize <= 0) return;

  int len = 0;
  while (LoRa.available() && len < (int)sizeof(rxBuf))
    rxBuf[len++] = (uint8_t)LoRa.read();

  if (len < 2) return;
  if (rxBuf[1] != PROTOCOL_VERSION) return;

  if (rxBuf[0] == PACKET_BEACON)
  {
    processBeacon(rxBuf, len);
    return;
  }

  if (len < HDR_SIZE) return;

  uint8_t src = rxBuf[2];
  uint8_t dst = rxBuf[3];
  uint8_t nextHop = rxBuf[5];

  if (nextHop != NODE_ID) return;   // not addressed to us at this hop
  if (src == NODE_ID) return;       // our own packet echoed back

  if (dst != NODE_ID)
  {
    forwardUnicast(rxBuf, len);
    return;
  }

  handlePacketForMe(rxBuf, len);
}

void serviceBackground()
{
  pollRadio();
  routingBeaconTask();
  routingCheckTimeouts();
  oledTask();
}

// ============================================================
// AES-256-GCM: ENCRYPT INTO secPayload (resent unchanged on retry)
// ============================================================

bool prepareSecureMessage(const String &message)
{
  size_t mlen = message.length();
  if (!sessionKeyReady || mlen == 0 || mlen > MAX_MESSAGE_SIZE) return false;

  uint8_t nonce[GCM_NONCE_SIZE];
  uint8_t enc[MAX_MESSAGE_SIZE];
  uint8_t tag[GCM_TAG_SIZE];

  getRandomBytes(nonce, GCM_NONCE_SIZE);

  uint32_t id = outgoingMessageID++;

  uint8_t aad[6] = { (uint8_t)NODE_ID, peerID, 0, 0, 0, 0 };
  putBe32(aad + 2, id);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int result = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, sessionKey, 256);
  if (result == 0)
  {
    result = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT, mlen,
        nonce, GCM_NONCE_SIZE, aad, sizeof(aad),
        (const unsigned char *)message.c_str(),
        enc, GCM_TAG_SIZE, tag);
  }
  mbedtls_gcm_free(&gcm);

  if (result != 0) return false;

  uint16_t i = 0;
  putBe32(secPayload + i, id);                  i += 4;
  secPayload[i++] = (mlen >> 8) & 0xFF;
  secPayload[i++] = mlen & 0xFF;
  memcpy(secPayload + i, nonce, GCM_NONCE_SIZE); i += GCM_NONCE_SIZE;
  memcpy(secPayload + i, enc, mlen);             i += mlen;
  memcpy(secPayload + i, tag, GCM_TAG_SIZE);     i += GCM_TAG_SIZE;

  secPayloadLen = i;
  outstandingMsgID = id;
  return true;
}

// Sends the pending message, retries with fresh routing until the
// end-to-end SECURE_ACK arrives. Failures feed PDR -> reroute.
void serviceSecureSession()
{
  if (!hasPendingMessage) return;

  if (!msgOutstanding)
  {
    if (!prepareSecureMessage(pendingMessage))
    {
      hasPendingMessage = false;
      pendingMessage = "";
      oledShowMessage("ENCRYPT FAILED", "", 1500);
      return;
    }

    msgOutstanding = true;
    msgTries = 0;
    msgLastTx = 0;
  }

  if (msgLastTx != 0 && millis() - msgLastTx < MSG_ACK_TIMEOUT_MS) return;

  if (msgTries > 0) updatePDR(msgHop, false);   // previous attempt unanswered

  if (msgTries >= MSG_MAX_TRIES)
  {
    Serial.println("[MSG] FAILED - no end-to-end ACK");

    inputMessage = pendingMessage;
    hasPendingMessage = false;
    pendingMessage = "";
    msgOutstanding = false;

    oledShowMessage("SEND FAILED", "NO ACK", 2000);
    return;
  }

  bool ok = sendUnicast(PACKET_SECURE_MSG, peerID, secPayload, secPayloadLen);
  msgHop = lastTxHop;
  msgTries++;
  msgLastTx = millis();

  Serial.print("[MSG] TX attempt ");
  Serial.print(msgTries);
  Serial.print("/");
  Serial.print(MSG_MAX_TRIES);
  Serial.print(" via ");
  Serial.print(msgHop);
  Serial.println(ok ? "" : "  (no route / tx fail)");

  oledShowMessage("SENDING...", String("TO ") + peerID + " TRY " + msgTries, 0);
}

// ============================================================
// START CONNECTION / SEND
// ============================================================

void startConnection(const String &message, uint8_t target)
{
  if (message.length() == 0 || message.length() > MAX_MESSAGE_SIZE) return;

  if (target == 0 || target == NODE_ID || target > MAX_NODES)
  {
    oledShowMessage("INVALID TARGET", "PRESS * TO PICK", 1500);
    return;
  }

  if (hs != HS_IDLE && hs != HS_SECURE)
  {
    oledShowMessage("BUSY", "HANDSHAKE ACTIVE", 1200);
    return;
  }

  if (hasPendingMessage)
  {
    oledShowMessage("BUSY", "SENDING...", 1200);
    return;
  }

  phase4RecalculateRoutes();

  if (phase4GetNextHop(target) == INVALID_NODE)
  {
    Serial.print("[LINK] NO ROUTE to Node ");
    Serial.println(target);
    oledShowMessage("NO ROUTE", "NODE UNREACHABLE", 1500);
    return;
  }

  pendingMessage = message;
  hasPendingMessage = true;
  inputMessage = "";

  // Already secure with this peer: no new handshake, just send.
  if (hs == HS_SECURE && sessionKeyReady && target == peerID)
  {
    Serial.println("[LINK] Reusing secure session");
    return;
  }

  clearSession();

  peerID = target;
  localNonce = esp_random();
  if (localNonce == 0) localNonce = 1;
  sessionNonce = localNonce;
  peerNonce = 0;

  ensureKeygen();

  Serial.println();
  Serial.println("[PQC] ========================================");
  Serial.println("[PQC] PQC HANDSHAKE PREPARING");
  Serial.println("[PQC] ML-KEM-768 KEY SHARING WILL START");
  Serial.println("[PQC] ========================================");

  setState(HS_HELLO_WAIT);
  oledShowMessage("CALLING", String("DEST ") + target + " VIA " + phase4GetNextHop(target), 0);
  sendHello();
}

// ============================================================
// HANDSHAKE / SESSION STATE MACHINE (runs in loop())
// ============================================================

bool stateTimedOut()
{
  return millis() - hsStateEnteredAt > HANDSHAKE_STATE_TIMEOUT;
}

void serviceProtocol()
{
  switch (hs)
  {
    case HS_IDLE:
      break;

    case HS_HELLO_WAIT:
      if (helloAttempts == 0)
      {
        sendHello();
      }
      else if (millis() - helloLastSent >= HELLO_INTERVAL)
      {
        updatePDR(helloHop, false);   // unanswered HELLO counts against the hop

        if (helloAttempts >= HELLO_MAX_ATTEMPTS) resetToIdle("NO ANSWER");
        else sendHello();
      }
      break;

    case HS_INIT_SEND_PK:
      if (keygenFailed)
      {
        resetToIdle("KEYGEN FAILED");
        break;
      }

      if (!keypairReady)
      {
        if (!keygenMsgShown)
        {
          oledShowMessage("PQC KEYGEN", "WAIT...", 0);
          keygenMsgShown = true;
        }
        break;
      }

      keygenMsgShown = false;
      clearChunks();

      pqcStage("KEY SHARING", "ML-KEM PUBLIC KEY");
      Serial.println("[PQC] KEY SHARING: sending ML-KEM public key...");

      if (sendFragmented(PACKET_PK_CHUNK, publicKey, PK_SIZE))
      {
        clearChunks();
        ctComplete = false;
        setState(HS_INIT_WAIT_CT);
        oledShowMessage("WAIT CIPHERTEXT", String("PEER: ") + peerID, 0);
      }
      else
      {
        resetToIdle("PK TRANSFER FAILED");
      }
      break;

    case HS_INIT_WAIT_CT:
      if (stateTimedOut())
      {
        resetToIdle("PEER TIMEOUT");
        break;
      }

      if (ctComplete)
      {
        ctComplete = false;
        clearChunks();
        setState(HS_INIT_DECAP);
        startInitiatorDecap();
      }
      break;

    case HS_INIT_DECAP:
      if (decapFailed)
      {
        resetToIdle("DECAP FAILED");
      }
      else if (decapDone)
      {
        decapDone = false;
        pqcStage("KEY ESTABLISHED", "SESSION KEY READY");
        Serial.println("[PQC] shared session key established.");
        enterSecure();
      }
      else if (stateTimedOut())
      {
        resetToIdle("DECAP TIMEOUT");
      }
      break;

    case HS_RESP_WAIT_PK:
      if (stateTimedOut())
      {
        resetToIdle("PEER TIMEOUT");
        break;
      }

      if (pkComplete)
      {
        pkComplete = false;
        clearChunks();

        pqcStage("KEY SHARING", "PUBLIC KEY RECEIVED");
        Serial.println("[PQC] KEY SHARING: public key received successfully.");

        setState(HS_RESP_PROCESS_CT);
        startResponderCrypto();
      }
      break;

    case HS_RESP_PROCESS_CT:
      if (encapFailed)
      {
        resetToIdle("ENCAP FAILED");
      }
      else if (encapDone)
      {
        encapDone = false;
        pqcStage("KEY ESTABLISHED", "SESSION KEY READY");
        Serial.println("[PQC] shared session key established. Sending ciphertext...");

        if (sendFragmented(PACKET_CT_CHUNK, ciphertext, CT_SIZE)) enterSecure();
        else resetToIdle("CT TRANSFER FAILED");
      }
      else if (stateTimedOut())
      {
        resetToIdle("PEER TIMEOUT");
      }
      break;

    case HS_SECURE:
      serviceSecureSession();
      break;
  }
}

// ============================================================
// KEYPAD
//   *            pick target (then 1-9, or 0 for node 10)
//   digits       type message (numeric keypad)
//   #            send
//   * again      restart target selection
// ============================================================

void checkKeypad()
{
  char key = keypad.getKey();
  if (!key) return;

  if (hs != HS_IDLE && hs != HS_SECURE) return;   // ignore keys mid-handshake

  if (key == '*')
  {
    inputMessage = "";
    targetNodeID = 0;
    selectingTarget = true;
    oledShowSelect();
    return;
  }

  if (selectingTarget)
  {
    uint8_t chosen = 0;

    if (key >= '1' && key <= '9') chosen = key - '0';
    else if (key == '0') chosen = 10;

    if (chosen == 0 || chosen > MAX_NODES)
    {
      oledShowMessage("INVALID", "PRESS 1-9 OR 0", 1000);
      return;
    }

    if (chosen == NODE_ID)
    {
      oledShowMessage("CANT PICK SELF", "PICK ANOTHER", 1000);
      return;
    }

    targetNodeID = chosen;
    selectingTarget = false;
    oledShowInput();
    return;
  }

  if (key == '#')
  {
    if (targetNodeID == 0)
    {
      oledShowMessage("NO TARGET", "PRESS * FIRST", 1000);
      return;
    }

    if (inputMessage.length() > 0) startConnection(inputMessage, targetNodeID);
    return;
  }

  if (targetNodeID == 0)
  {
    oledShowMessage("PRESS * FIRST", "TO PICK TARGET", 1000);
    return;
  }

  if (inputMessage.length() < MAX_MESSAGE_SIZE) inputMessage += key;
  oledShowInput();
}

// ============================================================
// SERIAL
//   "<dest> <message>"   e.g.  3 hello node three
//   n t m r h            diagnostics
// ============================================================

void printHelp()
{
  Serial.println();
  Serial.println("========== COMMANDS ==========");
  Serial.println("<dest> <message>  send secure message (e.g. 3 hello)");
  Serial.println("n = neighbor table");
  Serial.println("t = topology table");
  Serial.println("m = adjacency matrix");
  Serial.println("r = route table");
  Serial.println("h = help");
  Serial.println("==============================");
}

void handleSerialLine(String line)
{
  line.trim();
  if (line.length() == 0) return;

  if (line.length() == 1 && !isDigit(line[0]))
  {
    switch (tolower(line[0]))
    {
      case 'n': print_neighbor_table(); break;
      case 't': printTopologyTable();   break;
      case 'm': phase4PrintAdjacency(); break;
      case 'r': phase4PrintRoutes();    break;
      default:  printHelp();            break;
    }
    return;
  }

  int spaceIdx = line.indexOf(' ');
  if (spaceIdx > 0)
  {
    uint8_t target = line.substring(0, spaceIdx).toInt();
    String msg = line.substring(spaceIdx + 1);
    msg.trim();
    startConnection(msg, target);
  }
  else
  {
    printHelp();
  }
}

String serialLine = "";

void checkSerial()
{
  while (Serial.available())
  {
    char c = Serial.read();

    if (c == '\n' || c == '\r')
    {
      if (serialLine.length() > 0)
      {
        handleSerialLine(serialLine);
        serialLine = "";
      }
    }
    else if (c >= 32 && c <= 126)
    {
      if (serialLine.length() < MAX_MESSAGE_SIZE + 4) serialLine += c;
    }
  }
}

// ============================================================
// SETUP & LOOP
// ============================================================

void setup()
{
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("   PQC SECURE LoRa + DYNAMIC MULTI-HOP");
  Serial.println("==========================================");
  Serial.print("NODE_ID = ");
  Serial.println(NODE_ID);

  oledBegin();
  init_routing_tables();

  SPI.begin(SCK, MISO, MOSI, CS);
  LoRa.setPins(CS, RST, DIO0);

  if (!LoRa.begin(LORA_FREQ))
  {
    Serial.println("[LORA] FAILED");
    oledShowMessage("LORA FAILED", "CHECK CONNECTION", 0);
    while (true) delay(1000);
  }

  LoRa.setSyncWord(LORA_SYNC);
  LoRa.setSpreadingFactor(LORA_SF);
  LoRa.setSignalBandwidth(LORA_BW);
  LoRa.setCodingRate4(LORA_CR);
  LoRa.enableCrc();
  LoRa.setTxPower(17, PA_OUTPUT_PA_BOOST_PIN);

  randomSeed((uint32_t)micros() ^ ((uint32_t)NODE_ID << 16) ^ esp_random());

  routingStartBeaconTimer();
  LoRa.receive();

  Serial.println("[LORA] READY");
  printHelp();

  setState(HS_IDLE);
  oledStatus = OLED_NORMAL;
  oledShowNeighbors();
}

void loop()
{
  serviceBackground();   // radio RX/relay, beacons, timeouts, OLED
  checkKeypad();
  checkSerial();
  serviceProtocol();     // handshake + secure messaging state machine

  delay(2);
}
