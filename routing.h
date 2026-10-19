#ifndef ROUTING_H
#define ROUTING_H

#include <Arduino.h>
#include <LoRa.h>
#include "packet.h"

// ============================================================
// CONFIGURATION
// ============================================================

#ifndef MAX_NEIGHBORS
#define MAX_NEIGHBORS 6
#endif
#ifndef MAX_NODES
#define MAX_NODES 10
#endif
#ifndef INVALID_NODE
#define INVALID_NODE 255
#endif
#ifndef ROUTE_INF
#define ROUTE_INF 255
#endif
#ifndef DEFAULT_TTL
#define DEFAULT_TTL 8
#endif

#ifndef BEACON_INTERVAL_MS
#define BEACON_INTERVAL_MS 5000UL
#endif
#ifndef BEACON_GUARD_MS
#define BEACON_GUARD_MS 700UL
#endif
#ifndef BEACON_JITTER_MS
#define BEACON_JITTER_MS 1000UL
#endif
#ifndef BEACON_INITIAL_OFFSET_MS
#define BEACON_INITIAL_OFFSET_MS 1200UL
#endif

// Neighbor / advertised link considered gone after ~3 missed beacons.
#define BEACON_TIMEOUT_MS \
    ((BEACON_INTERVAL_MS * 3UL) + BEACON_JITTER_MS + 1000UL)
#define TOPOLOGY_TIMEOUT_MS \
    ((BEACON_INTERVAL_MS * 3UL) + BEACON_JITTER_MS + 1000UL)

// A neighbor marked jammed stays excluded at least this long, even
// if its beacons are still heard (a jammer may let small beacons through).
#define JAM_HOLDDOWN_MS 20000UL

#define EWMA_ALPHA      0.30f
#define MISS_THRESHOLD  3

#define SEEN_PACKET_CACHE_SIZE 32
#define SEEN_PACKET_TIMEOUT_MS 30000UL

// ============================================================
// DATA STRUCTURES
// ============================================================

struct Neighbor
{
    uint8_t  neighbor_id;
    float    pdr;
    int8_t   rssi;
    uint8_t  consecutive_misses;
    bool     is_jammed;
    uint32_t jam_time;
    uint32_t last_beacon_time;
    bool     active;
};

struct RouteEntry
{
    uint8_t  destination;
    uint8_t  primary_next_hop;
    uint8_t  backup_next_hop;
    uint8_t  primary_cost;
    uint8_t  backup_cost;
    uint16_t seq_number;
    bool     primary_active;
    bool     valid;
};

struct TopologyLink
{
    uint8_t  node_a;
    uint8_t  node_b;
    uint8_t  cost;
    uint16_t seq_number;
    uint32_t last_update_time;
    bool     valid;
};

struct SeenPacket
{
    uint8_t  source;
    uint16_t sequence;
    uint32_t time;
    bool     valid;
};

// ============================================================
// GLOBAL STATE
// ============================================================

static Neighbor     neighbor_table[MAX_NEIGHBORS];
static RouteEntry   route_table[MAX_NODES + 1];
static TopologyLink topology[MAX_NODES * MAX_NEIGHBORS];
static uint16_t     last_seq_from[MAX_NODES + 1];

static uint8_t phase4Adjacency[MAX_NODES + 1][MAX_NODES + 1];
static uint8_t phase4Distance[MAX_NODES + 1];
static uint8_t phase4NextHop[MAX_NODES + 1];
static bool    phase4Visited[MAX_NODES + 1];

static SeenPacket seenPackets[SEEN_PACKET_CACHE_SIZE];

static uint16_t myBeaconSequence = 0;
static uint16_t nextSequenceValue = 1;
static uint32_t nextBeaconDue = 0;
static uint32_t lastRadioTx = 0;

// First hop used by the most recent sendUnicast() call. The caller
// uses it to credit/penalise the right neighbor when the end-to-end
// ACK arrives (or doesn't).
static uint8_t lastTxHop = INVALID_NODE;

// ============================================================
// FORWARD DECLARATIONS
// ============================================================

static void    phase4RecalculateRoutes();
static uint8_t phase4GetNextHop(uint8_t destination);

// ============================================================
// INITIALIZE
// ============================================================

static void phase4ClearAdjacency()
{
    for (int i = 0; i <= MAX_NODES; i++)
    {
        for (int j = 0; j <= MAX_NODES; j++)
            phase4Adjacency[i][j] = ROUTE_INF;
        phase4Adjacency[i][i] = 0;
    }
}

static void init_routing_tables()
{
    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        neighbor_table[i].neighbor_id = INVALID_NODE;
        neighbor_table[i].pdr = 1.0f;
        neighbor_table[i].rssi = 0;
        neighbor_table[i].consecutive_misses = 0;
        neighbor_table[i].is_jammed = false;
        neighbor_table[i].jam_time = 0;
        neighbor_table[i].last_beacon_time = 0;
        neighbor_table[i].active = false;
    }

    for (int i = 0; i <= MAX_NODES; i++)
    {
        route_table[i].destination = i;
        route_table[i].primary_next_hop = INVALID_NODE;
        route_table[i].backup_next_hop = INVALID_NODE;
        route_table[i].primary_cost = ROUTE_INF;
        route_table[i].backup_cost = ROUTE_INF;
        route_table[i].seq_number = 0;
        route_table[i].primary_active = false;
        route_table[i].valid = false;

        last_seq_from[i] = 0;
        phase4Distance[i] = ROUTE_INF;
        phase4NextHop[i] = INVALID_NODE;
        phase4Visited[i] = false;
    }

    for (int i = 0; i < MAX_NODES * MAX_NEIGHBORS; i++)
    {
        topology[i].node_a = INVALID_NODE;
        topology[i].node_b = INVALID_NODE;
        topology[i].cost = ROUTE_INF;
        topology[i].seq_number = 0;
        topology[i].last_update_time = 0;
        topology[i].valid = false;
    }

    for (int i = 0; i < SEEN_PACKET_CACHE_SIZE; i++)
    {
        seenPackets[i].source = 0;
        seenPackets[i].sequence = 0;
        seenPackets[i].time = 0;
        seenPackets[i].valid = false;
    }

    phase4ClearAdjacency();
}

// ============================================================
// NEIGHBORS
// ============================================================

static int findNeighbor(uint8_t nodeID)
{
    for (int i = 0; i < MAX_NEIGHBORS; i++)
        if (neighbor_table[i].active && neighbor_table[i].neighbor_id == nodeID)
            return i;
    return -1;
}

static int addNeighbor(uint8_t nodeID)
{
    if (nodeID == NODE_ID) return -1;

    int existing = findNeighbor(nodeID);
    if (existing >= 0)
    {
        neighbor_table[existing].last_beacon_time = millis();
        neighbor_table[existing].active = true;
        return existing;
    }

    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (!neighbor_table[i].active)
        {
            neighbor_table[i].neighbor_id = nodeID;
            neighbor_table[i].pdr = 1.0f;
            neighbor_table[i].rssi = 0;
            neighbor_table[i].consecutive_misses = 0;
            neighbor_table[i].is_jammed = false;
            neighbor_table[i].jam_time = 0;
            neighbor_table[i].last_beacon_time = millis();
            neighbor_table[i].active = true;

            Serial.print("[ROUTING] NEW NEIGHBOR: Node ");
            Serial.println(nodeID);
            return i;
        }
    }

    Serial.println("[ROUTING] Neighbor table FULL");
    return -1;
}

static uint8_t getNeighborCost(const Neighbor &n)
{
    if (!n.active || n.is_jammed) return ROUTE_INF;

    float pdr = n.pdr;
    if (pdr < 0.20f) pdr = 0.20f;

    float cost = 1.0f / pdr;
    if (cost > 254.0f) cost = 254.0f;
    if (cost < 1.0f) cost = 1.0f;

    return (uint8_t)(cost + 0.5f);
}

// ============================================================
// PDR UPDATE (end-to-end ACK result credited to the first hop)
// ============================================================

static void updatePDR(uint8_t nodeID, bool success)
{
    int index = findNeighbor(nodeID);
    if (index < 0) return;

    Neighbor &n = neighbor_table[index];

    float sample = success ? 1.0f : 0.0f;
    n.pdr = (EWMA_ALPHA * sample) + ((1.0f - EWMA_ALPHA) * n.pdr);

    if (success)
    {
        n.consecutive_misses = 0;
    }
    else
    {
        if (n.consecutive_misses < 255) n.consecutive_misses++;

        if (n.consecutive_misses >= MISS_THRESHOLD && !n.is_jammed)
        {
            n.is_jammed = true;
            n.jam_time = millis();

            Serial.print("[PDR ALERT] Node ");
            Serial.print(nodeID);
            Serial.println(" marked JAMMED - rerouting");
        }
    }

    phase4RecalculateRoutes();
}

// ============================================================
// TOPOLOGY (links advertised by OTHER nodes)
// ============================================================

static void updateTopologyLink(uint8_t nodeA, uint8_t nodeB,
                               uint8_t cost, uint16_t sequence)
{
    if (nodeA == nodeB) return;

    int freeIndex = -1;

    for (int i = 0; i < MAX_NODES * MAX_NEIGHBORS; i++)
    {
        if (topology[i].valid &&
            topology[i].node_a == nodeA &&
            topology[i].node_b == nodeB)
        {
            // Ignore an older advertisement (but accept a rebooted sender).
            if (sequence < topology[i].seq_number &&
                (uint16_t)(topology[i].seq_number - sequence) < 1000)
                return;

            topology[i].cost = cost;
            topology[i].seq_number = sequence;
            topology[i].last_update_time = millis();
            return;
        }

        if (!topology[i].valid && freeIndex < 0) freeIndex = i;
    }

    if (freeIndex >= 0)
    {
        topology[freeIndex].node_a = nodeA;
        topology[freeIndex].node_b = nodeB;
        topology[freeIndex].cost = cost;
        topology[freeIndex].seq_number = sequence;
        topology[freeIndex].last_update_time = millis();
        topology[freeIndex].valid = true;
    }
}

static bool removeTopologyForNode(uint8_t nodeID)
{
    bool changed = false;

    for (int i = 0; i < MAX_NODES * MAX_NEIGHBORS; i++)
    {
        if (!topology[i].valid) continue;

        if (topology[i].node_a == nodeID || topology[i].node_b == nodeID)
        {
            topology[i].valid = false;
            changed = true;
        }
    }
    return changed;
}

// ============================================================
// TIMEOUTS
// ============================================================

static void routingCheckTimeouts()
{
    uint32_t now = millis();
    bool changed = false;

    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (!neighbor_table[i].active) continue;

        if (now - neighbor_table[i].last_beacon_time >= BEACON_TIMEOUT_MS)
        {
            uint8_t deadNode = neighbor_table[i].neighbor_id;

            Serial.print("[TIMEOUT] Node ");
            Serial.print(deadNode);
            Serial.println(" beacon expired");

            neighbor_table[i].active = false;
            neighbor_table[i].is_jammed = false;
            neighbor_table[i].consecutive_misses = 0;
            neighbor_table[i].neighbor_id = INVALID_NODE;

            removeTopologyForNode(deadNode);
            changed = true;
        }
    }

    for (int i = 0; i < MAX_NODES * MAX_NEIGHBORS; i++)
    {
        if (!topology[i].valid) continue;

        if (now - topology[i].last_update_time >= TOPOLOGY_TIMEOUT_MS)
        {
            topology[i].valid = false;
            changed = true;
        }
    }

    if (changed)
    {
        Serial.println("[ROUTING] Topology changed -> recalculating");
        phase4RecalculateRoutes();
    }
}

// ============================================================
// ADJACENCY / DIJKSTRA
// ============================================================

static void phase4BuildAdjacency()
{
    phase4ClearAdjacency();

    // Our own direct links come ONLY from the neighbor table, so a
    // jammed neighbor really is excluded.
    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (!neighbor_table[i].active) continue;

        uint8_t n = neighbor_table[i].neighbor_id;
        if (n == INVALID_NODE || n > MAX_NODES) continue;

        uint8_t cost = getNeighborCost(neighbor_table[i]);
        if (cost == ROUTE_INF) continue;

        phase4Adjacency[NODE_ID][n] = cost;
        phase4Adjacency[n][NODE_ID] = cost;
    }

    // Links advertised by other nodes. Anything touching this node is
    // ignored (we trust our own measurements, not other nodes' view of us).
    for (int i = 0; i < MAX_NODES * MAX_NEIGHBORS; i++)
    {
        if (!topology[i].valid) continue;

        uint8_t a = topology[i].node_a;
        uint8_t b = topology[i].node_b;
        uint8_t cost = topology[i].cost;

        if (a == INVALID_NODE || b == INVALID_NODE ||
            a == 0 || b == 0 || a > MAX_NODES || b > MAX_NODES) continue;
        if (a == NODE_ID || b == NODE_ID) continue;
        if (cost == ROUTE_INF) continue;

        if (cost < phase4Adjacency[a][b]) phase4Adjacency[a][b] = cost;
        if (cost < phase4Adjacency[b][a]) phase4Adjacency[b][a] = cost;
    }
}

static void phase4RunDijkstra()
{
    for (int i = 0; i <= MAX_NODES; i++)
    {
        phase4Distance[i] = ROUTE_INF;
        phase4NextHop[i] = INVALID_NODE;
        phase4Visited[i] = false;
    }

    phase4Distance[NODE_ID] = 0;

    for (int iteration = 0; iteration < MAX_NODES; iteration++)
    {
        uint8_t current = INVALID_NODE;
        uint8_t best = ROUTE_INF;

        for (int node = 1; node <= MAX_NODES; node++)
        {
            if (phase4Visited[node]) continue;
            if (phase4Distance[node] < best)
            {
                best = phase4Distance[node];
                current = node;
            }
        }

        if (current == INVALID_NODE) break;
        phase4Visited[current] = true;

        for (int neighbor = 1; neighbor <= MAX_NODES; neighbor++)
        {
            uint8_t edge = phase4Adjacency[current][neighbor];
            if (edge == ROUTE_INF) continue;
            if (phase4Distance[current] == ROUTE_INF) continue;

            uint16_t candidate = (uint16_t)phase4Distance[current] + (uint16_t)edge;
            if (candidate >= ROUTE_INF) continue;

            if (candidate < phase4Distance[neighbor])
            {
                phase4Distance[neighbor] = (uint8_t)candidate;
                phase4NextHop[neighbor] =
                    (current == NODE_ID) ? (uint8_t)neighbor : phase4NextHop[current];
            }
        }
    }
}

static void phase4StoreRoutes()
{
    for (int destination = 1; destination <= MAX_NODES; destination++)
    {
        RouteEntry &r = route_table[destination];

        r.destination = destination;
        r.primary_next_hop = INVALID_NODE;
        r.backup_next_hop = INVALID_NODE;
        r.primary_cost = ROUTE_INF;
        r.backup_cost = ROUTE_INF;
        r.seq_number = 0;
        r.primary_active = false;
        r.valid = false;

        if (destination == NODE_ID) continue;
        if (phase4Distance[destination] == ROUTE_INF) continue;

        uint8_t hop = phase4NextHop[destination];
        if (hop == INVALID_NODE) continue;

        r.primary_next_hop = hop;
        r.primary_cost = phase4Distance[destination];
        r.primary_active = true;
        r.valid = true;
    }
}

static void phase4RecalculateRoutes()
{
    phase4BuildAdjacency();
    phase4RunDijkstra();
    phase4StoreRoutes();
}

static uint8_t phase4GetNextHop(uint8_t destination)
{
    if (destination == NODE_ID || destination == 0 || destination > MAX_NODES)
        return INVALID_NODE;
    if (!route_table[destination].valid || !route_table[destination].primary_active)
        return INVALID_NODE;
    return route_table[destination].primary_next_hop;
}

// ============================================================
// PRINT HELPERS
// ============================================================

static void print_neighbor_table()
{
    Serial.println();
    Serial.println("========== NEIGHBOR TABLE ==========");

    bool found = false;
    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (!neighbor_table[i].active) continue;
        found = true;

        Serial.print("Node ");  Serial.print(neighbor_table[i].neighbor_id);
        Serial.print(" | PDR="); Serial.print(neighbor_table[i].pdr, 2);
        Serial.print(" | RSSI=");Serial.print(neighbor_table[i].rssi);
        Serial.print(" | jam="); Serial.print(neighbor_table[i].is_jammed ? "YES" : "NO");
        Serial.print(" | age="); Serial.print(millis() - neighbor_table[i].last_beacon_time);
        Serial.println("ms");
    }

    if (!found) Serial.println("No active neighbors");
    Serial.println("====================================");
}

static void printTopologyTable()
{
    Serial.println();
    Serial.println("========== TOPOLOGY TABLE ==========");

    bool found = false;
    for (int i = 0; i < MAX_NODES * MAX_NEIGHBORS; i++)
    {
        if (!topology[i].valid) continue;
        found = true;

        Serial.print(topology[i].node_a);
        Serial.print(" -> ");
        Serial.print(topology[i].node_b);
        Serial.print(" | cost=");
        Serial.print(topology[i].cost);
        Serial.print(" | age=");
        Serial.print(millis() - topology[i].last_update_time);
        Serial.println("ms");
    }

    if (!found) Serial.println("No advertised links");
    Serial.println("====================================");
}

static void phase4PrintAdjacency()
{
    Serial.println();
    Serial.println("========== ADJACENCY MATRIX ==========");
    Serial.print("    ");
    for (int i = 1; i <= MAX_NODES; i++) Serial.printf("%3d ", i);
    Serial.println();

    for (int i = 1; i <= MAX_NODES; i++)
    {
        Serial.printf("%3d ", i);
        for (int j = 1; j <= MAX_NODES; j++)
        {
            if (phase4Adjacency[i][j] == ROUTE_INF) Serial.print("INF ");
            else Serial.printf("%3d ", phase4Adjacency[i][j]);
        }
        Serial.println();
    }
    Serial.println("======================================");
}

static void phase4PrintRoutes()
{
    Serial.println();
    Serial.println("============= ROUTE TABLE ============");

    bool found = false;
    for (int d = 1; d <= MAX_NODES; d++)
    {
        if (d == NODE_ID || !route_table[d].valid) continue;
        found = true;

        Serial.print("Dest ");
        Serial.print(d);
        Serial.print(" | Next Hop=");
        Serial.print(route_table[d].primary_next_hop);
        Serial.print(" | Cost=");
        Serial.println(route_table[d].primary_cost);
    }

    if (!found) Serial.println("No reachable destinations");
    Serial.println("======================================");
}

// ============================================================
// RAW TX
// ============================================================

static int sendRawPacket(const uint8_t *packet, uint16_t length)
{
    LoRa.idle();
    LoRa.beginPacket();
    LoRa.write(packet, length);
    int result = LoRa.endPacket();
    lastRadioTx = millis();
    LoRa.receive();
    return result;
}

static uint16_t routingNextSequence()
{
    uint16_t s = nextSequenceValue++;
    if (nextSequenceValue == 0) nextSequenceValue = 1;
    return s;
}

// ============================================================
// BEACONS
// ============================================================

static void routingStartBeaconTimer()
{
    nextBeaconDue =
        millis() + BEACON_INITIAL_OFFSET_MS +
        ((uint32_t)(NODE_ID - 1) * 700UL) +
        random(0, BEACON_JITTER_MS + 1);
}

static void scheduleNextBeacon()
{
    nextBeaconDue =
        millis() + BEACON_INTERVAL_MS + random(0, BEACON_JITTER_MS + 1);
}

static void sendBeacon()
{
    myBeaconSequence++;

    uint8_t buffer[BEACON_MAX_SIZE];
    int pos = 0;

    buffer[pos++] = PACKET_BEACON;
    buffer[pos++] = PROTOCOL_VERSION;
    buffer[pos++] = NODE_ID;
    buffer[pos++] = (myBeaconSequence >> 8) & 0xFF;
    buffer[pos++] = myBeaconSequence & 0xFF;

    int countPosition = pos++;
    int count = 0;

    // Advertise active, non-jammed direct neighbors with their cost.
    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (!neighbor_table[i].active) continue;
        if (millis() - neighbor_table[i].last_beacon_time >= BEACON_TIMEOUT_MS) continue;
        if (pos + 2 > BEACON_MAX_SIZE) break;

        uint8_t cost = getNeighborCost(neighbor_table[i]);
        if (cost == ROUTE_INF) continue;

        buffer[pos++] = neighbor_table[i].neighbor_id;
        buffer[pos++] = cost;
        count++;
    }

    buffer[countPosition] = (uint8_t)count;

    int result = sendRawPacket(buffer, pos);

    Serial.print("[BEACON TX] Node ");
    Serial.print(NODE_ID);
    Serial.print(" | neighbors=");
    Serial.print(count);
    Serial.print(" | result=");
    Serial.println(result);
}

static void routingBeaconTask()
{
    if ((int32_t)(millis() - nextBeaconDue) >= 0)
    {
        if (millis() - lastRadioTx >= BEACON_GUARD_MS)
        {
            sendBeacon();
            scheduleNextBeacon();
        }
    }
}

static void processBeacon(uint8_t *packet, int length)
{
    if (length < BEACON_HEADER_SIZE) return;

    uint8_t sender = packet[2];
    if (sender == NODE_ID || sender == 0 || sender > MAX_NODES) return;

    uint16_t sequence = ((uint16_t)packet[3] << 8) | packet[4];
    uint8_t count = packet[5];

    // Any beacon proves the neighbor is alive.
    int index = addNeighbor(sender);
    if (index >= 0)
    {
        Neighbor &n = neighbor_table[index];

        n.last_beacon_time = millis();
        n.active = true;
        n.rssi = (int8_t)LoRa.packetRssi();

        // Jam hold-down: only forgive after the hold time, and then
        // give it a probationary PDR so one more failure re-jams it.
        if (n.is_jammed && millis() - n.jam_time >= JAM_HOLDDOWN_MS)
        {
            n.is_jammed = false;
            n.consecutive_misses = MISS_THRESHOLD - 1;
            n.pdr = 0.5f;

            Serial.print("[PDR RECOVERY] Node ");
            Serial.print(sender);
            Serial.println(" back in service (probation)");
            phase4RecalculateRoutes();
        }
    }

    // Duplicate / old beacon: liveness only. A big backwards jump
    // means the sender rebooted, so accept it.
    uint16_t behind = last_seq_from[sender] - sequence;
    if (sequence <= last_seq_from[sender] && behind < 1000) return;

    last_seq_from[sender] = sequence;

    // Parse the sender's advertised neighbors (its links to others).
    int pos = BEACON_HEADER_SIZE;

    for (int i = 0; i < count; i++)
    {
        if (pos + 2 > length) break;

        uint8_t neighborID = packet[pos++];
        uint8_t cost = packet[pos++];

        if (neighborID == 0 || neighborID > MAX_NODES || neighborID == sender) continue;
        if (cost == ROUTE_INF) continue;

        updateTopologyLink(sender, neighborID, cost, sequence);
    }

    phase4RecalculateRoutes();
}

// ============================================================
// DUPLICATE FILTER (relays)
// ============================================================

static bool packetAlreadySeen(uint8_t source, uint16_t sequence)
{
    uint32_t now = millis();

    for (int i = 0; i < SEEN_PACKET_CACHE_SIZE; i++)
    {
        if (!seenPackets[i].valid) continue;

        if (now - seenPackets[i].time > SEEN_PACKET_TIMEOUT_MS)
        {
            seenPackets[i].valid = false;
            continue;
        }

        if (seenPackets[i].source == source && seenPackets[i].sequence == sequence)
            return true;
    }
    return false;
}

static void rememberPacket(uint8_t source, uint16_t sequence)
{
    int slot = 0;
    uint32_t oldest = 0xFFFFFFFFUL;

    for (int i = 0; i < SEEN_PACKET_CACHE_SIZE; i++)
    {
        if (!seenPackets[i].valid) { slot = i; break; }
        if (seenPackets[i].time < oldest)
        {
            oldest = seenPackets[i].time;
            slot = i;
        }
    }

    seenPackets[slot].source = source;
    seenPackets[slot].sequence = sequence;
    seenPackets[slot].time = millis();
    seenPackets[slot].valid = true;
}

// ============================================================
// UNICAST SEND (originate) + RELAY (forward)
// ============================================================

// Originate a unicast packet toward `dst` using the CURRENT best route.
// Sets lastTxHop. Returns false if there is no route or TX failed.
static bool sendUnicast(uint8_t type, uint8_t dst,
                        const uint8_t *payload, uint16_t payloadLen)
{
    static uint8_t txBuf[MAX_PACKET_SIZE];

    lastTxHop = INVALID_NODE;

    if (payloadLen > MAX_PAYLOAD) return false;

    uint8_t hop = phase4GetNextHop(dst);
    lastTxHop = hop;
    if (hop == INVALID_NODE) return false;

    buildHeader(txBuf, type, NODE_ID, dst, NODE_ID, hop,
                DEFAULT_TTL, routingNextSequence());

    if (payloadLen > 0) memcpy(txBuf + HDR_SIZE, payload, payloadLen);

    return sendRawPacket(txBuf, HDR_SIZE + payloadLen) == 1;
}

// Relay any unicast packet (payload is never inspected, so encrypted
// messages and key chunks stay end-to-end private).
static bool forwardUnicast(uint8_t *pkt, int len)
{
    uint8_t type = pkt[0];
    uint8_t src  = pkt[2];
    uint8_t dst  = pkt[3];
    uint8_t ttl  = pkt[6];
    uint16_t seq = parseSequence(pkt);

    if (ttl <= 1)
    {
        Serial.println("[FWD] TTL expired");
        return false;
    }

    if (packetAlreadySeen(src, seq)) return false;
    rememberPacket(src, seq);

    uint8_t hop = phase4GetNextHop(dst);
    if (hop == INVALID_NODE)
    {
        Serial.print("[FWD] no route to ");
        Serial.println(dst);
        return false;
    }

    pkt[4] = NODE_ID;
    pkt[5] = hop;
    pkt[6] = ttl - 1;

    int result = sendRawPacket(pkt, len);

    Serial.print("[FWD] type=");
    Serial.print(type);
    Serial.print(" src=");
    Serial.print(src);
    Serial.print(" dst=");
    Serial.print(dst);
    Serial.print(" via=");
    Serial.print(hop);
    Serial.print(" ttl=");
    Serial.print(ttl - 1);
    Serial.print(" tx=");
    Serial.println(result);

    return result == 1;
}

#endif
