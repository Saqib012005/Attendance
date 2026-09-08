"""Classroom BLE mesh network and relay topology simulator for CampusGuard.

Simulates multi-hop propagation, packet collisions, backoff, and congestion for
student cohorts ranging from 10 to 200 devices in a standard classroom.
"""
import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .propagation import (
    DEFAULT_TEACHER_POS,
    ROOM_LENGTH,
    ROOM_WIDTH,
    Position,
    compute_path_loss,
)

RECEIVER_SENSITIVITY_DBM = -85.0  # Typical BLE receiver threshold
BLE_ADVERTISING_INTERVAL_MS = 100  # Default 100ms adv interval
MAX_RELAY_HOPS = 3                 # Standard classroom max hop depth
RELAY_QUOTA_PER_NODE = 4           # Maximum retransmissions per student device


@dataclass
class StudentNode:
    node_id: str
    position: Position
    is_authenticated: bool = True
    battery_level: float = 1.0       # 0.0 to 1.0
    received_direct_origin: bool = False
    received_via_relay: bool = False
    hop_depth: int = 0
    parent_id: Optional[str] = None
    relay_quota_remaining: int = RELAY_QUOTA_PER_NODE
    relay_history: List[str] = field(default_factory=list)


@dataclass
class MeshSimulationResult:
    node_count: int
    direct_reach_count: int
    relay_reach_count: int
    unreached_count: int
    coverage_pct: float
    avg_hop_depth: float
    max_hop_depth: int
    collision_rate: float
    duplicate_packet_count: int


def generate_classroom_cohort(
    count: int,
    seed: int = 42,
    teacher_pos: Optional[Position] = None,
) -> Tuple[Position, List[StudentNode]]:
    """Generate a realistic random distribution of students seated in the classroom."""
    rng = random.Random(seed)
    t_pos = teacher_pos or DEFAULT_TEACHER_POS
    nodes = []

    # Classroom seating area: x in [0.4, ROOM_WIDTH - 0.4], y in [1.5, ROOM_LENGTH - 0.4]
    min_x, max_x = 0.4, ROOM_WIDTH - 0.4
    min_y, max_y = 1.5, ROOM_LENGTH - 0.4

    for i in range(count):
        # Distribute students across desks with slight jitter
        x = rng.uniform(min_x, max_x)
        y = rng.uniform(min_y, max_y)
        z = rng.uniform(0.8, 1.2)
        pos = Position(x=x, y=y, z=z, zone="inside")
        nodes.append(StudentNode(node_id=f"student_{i:03d}", position=pos))

    return t_pos, nodes


def simulate_mesh_propagation(
    nodes: List[StudentNode],
    teacher_pos: Position,
    max_hops: int = MAX_RELAY_HOPS,
    collision_factor: float = 0.0015,  # Collision probability scaling per active node
    seed: int = 42,
) -> MeshSimulationResult:
    """Simulate session signal propagation from Teacher to students via direct + relay."""
    rng = random.Random(seed)
    n_count = len(nodes)
    node_map = {n.node_id: n for n in nodes}

    # Step 1: Teacher direct broadcast
    direct_reached: Set[str] = set()
    for n in nodes:
        rssi = compute_path_loss(tx_pos=teacher_pos, rx_pos=n.position, rng=rng)
        if rssi >= RECEIVER_SENSITIVITY_DBM:
            n.received_direct_origin = True
            n.hop_depth = 1
            n.parent_id = "teacher"
            direct_reached.add(n.node_id)

    # Step 2: Multi-hop relay propagation
    current_wave = list(direct_reached)
    all_reached: Set[str] = set(direct_reached)
    total_duplicates = 0
    total_transmissions = len(direct_reached)
    total_collisions = 0

    for hop in range(2, max_hops + 1):
        next_wave: Set[str] = set()
        active_relays = len(current_wave)
        
        # Collision probability rises quadratically with concurrent transmitters
        hop_collision_prob = min(0.60, collision_factor * active_relays * (active_relays - 1))

        for sender_id in current_wave:
            sender = node_map[sender_id]
            if sender.relay_quota_remaining <= 0:
                continue

            sender.relay_quota_remaining -= 1
            total_transmissions += 1

            for target in nodes:
                if target.node_id == sender_id or target.node_id in direct_reached:
                    continue

                # Check if transmission suffered collision
                if rng.random() < hop_collision_prob:
                    total_collisions += 1
                    continue

                rssi = compute_path_loss(tx_pos=sender.position, rx_pos=target.position, rng=rng)
                if rssi >= RECEIVER_SENSITIVITY_DBM:
                    if target.node_id in all_reached:
                        total_duplicates += 1
                    else:
                        target.received_via_relay = True
                        target.hop_depth = hop
                        target.parent_id = sender_id
                        target.relay_history = sender.relay_history + [sender_id]
                        all_reached.add(target.node_id)
                        next_wave.add(target.node_id)

        current_wave = list(next_wave)
        if not current_wave:
            break

    # Calculate aggregate summary
    direct_count = len(direct_reached)
    relay_count = len(all_reached) - direct_count
    unreached = n_count - len(all_reached)
    coverage = (len(all_reached) / n_count) * 100.0 if n_count > 0 else 0.0

    reached_hops = [node_map[nid].hop_depth for nid in all_reached]
    avg_hops = sum(reached_hops) / max(1, len(reached_hops))
    max_hops_obs = max(reached_hops) if reached_hops else 0
    coll_rate = (total_collisions / max(1, total_transmissions)) if total_transmissions > 0 else 0.0

    return MeshSimulationResult(
        node_count=n_count,
        direct_reach_count=direct_count,
        relay_reach_count=relay_count,
        unreached_count=unreached,
        coverage_pct=coverage,
        avg_hop_depth=avg_hops,
        max_hop_depth=max_hops_obs,
        collision_rate=coll_rate,
        duplicate_packet_count=total_duplicates,
    )
