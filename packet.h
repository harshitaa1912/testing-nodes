#ifndef PACKET_H
#define PACKET_H

#include <Arduino.h>

// ============================================================
// PACKET TYPES
// ============================================================
// BEACON is a broadcast routing packet with its own layout.
// Everything else is a UNICAST packet with the common 9-byte
// header below, followed by a type-specific payload. Because the
// header is common, ANY node can relay ANY unicast packet
// (handshake, key chunks, encrypted messages, ACKs) without
// understanding the payload.

#define PACKET_BEACON       3

#define PACKET_HELLO        10   // payload: NONCE(4)
#define PACKET_HELLO_ACK    11   // payload: NONCE(4)
#define PACKET_PK_CHUNK     12   // payload: CHUNK(1) TOTAL(1) DATA
#define PACKET_CT_CHUNK     13   // payload: CHUNK(1) TOTAL(1) DATA
#define PACKET_CHUNK_ACK    14   // payload: STREAM_TYPE(1) CHUNK(1) TOTAL(1)
#define PACKET_SECURE_MSG   15   // payload: MSG_ID(4) LEN(2) GCM_NONCE(12) CIPHERTEXT TAG(16)
#define PACKET_SECURE_ACK   16   // payload: MSG_ID(4)

// ============================================================
// PROTOCOL
// ============================================================

#define PROTOCOL_VERSION 2      // bumped: not compatible with old DATA/ACK firmware

// ============================================================
// UNICAST HEADER (9 bytes)
//
// [0] TYPE
// [1] VERSION
// [2] SOURCE        original sender (never changed by relays)
// [3] DESTINATION   final destination (never changed by relays)
// [4] PREVIOUS_HOP  rewritten at every hop
// [5] NEXT_HOP      rewritten at every hop
// [6] TTL           decremented at every hop
// [7] SEQ_H
// [8] SEQ_L         per-source sequence number (relay duplicate filter)
// ============================================================

#define HDR_SIZE         9
#define MAX_PACKET_SIZE  255
#define MAX_PAYLOAD      (MAX_PACKET_SIZE - HDR_SIZE)

// ============================================================
// BEACON
//
// [0] TYPE
// [1] VERSION
// [2] SENDER
// [3] SEQ_H
// [4] SEQ_L
// [5] NEIGHBOR_COUNT
// Repeated: [NEIGHBOR_ID] [COST]
// ============================================================

#define BEACON_HEADER_SIZE 6
#define BEACON_MAX_SIZE    64

// ============================================================
// HELPERS
// ============================================================

static inline uint8_t buildHeader(
    uint8_t *b,
    uint8_t type,
    uint8_t source,
    uint8_t destination,
    uint8_t previousHop,
    uint8_t nextHop,
    uint8_t ttl,
    uint16_t sequence)
{
    b[0] = type;
    b[1] = PROTOCOL_VERSION;
    b[2] = source;
    b[3] = destination;
    b[4] = previousHop;
    b[5] = nextHop;
    b[6] = ttl;
    b[7] = (sequence >> 8) & 0xFF;
    b[8] = sequence & 0xFF;
    return HDR_SIZE;
}

static inline uint16_t parseSequence(const uint8_t *b)
{
    return ((uint16_t)b[7] << 8) | (uint16_t)b[8];
}

static inline uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static inline void putBe32(uint8_t *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

#endif
