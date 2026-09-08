"""Classroom RF propagation and spatial attenuation model for CampusGuard.

Models a 15x20 ft (4.57m x 6.10m, height 3.0m) classroom with physical walls,
windows, doors, and human body shadowing. Simulates realistic BLE RSSI
distributions for interior positions and adversarial exterior locations
(window proxy, corridor, adjacent room, different floor).
"""
import math
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Default classroom geometry in metres (15 ft x 20 ft)
ROOM_WIDTH = 4.57   # x-axis (15 ft)
ROOM_LENGTH = 6.10  # y-axis (20 ft)
ROOM_HEIGHT = 3.00  # z-axis

# Attenuation constants in dB
ATTENUATION_CONCRETE_WALL = 14.0
ATTENUATION_WINDOW_GLASS = 5.0
ATTENUATION_WOODEN_DOOR = 6.0
ATTENUATION_FLOOR_SLAB = 25.0
ATTENUATION_BODY_SHADOW = 4.0

# Path loss parameters at 2.4 GHz
PL_D0 = 40.0         # Path loss at d0 = 1.0 metre (dBm)
PATH_LOSS_EXP_LOS = 2.0
PATH_LOSS_EXP_NLOS = 3.0
SHADOW_SIGMA_LOS = 2.0
SHADOW_SIGMA_NLOS = 3.5

TX_POWER_TEACHER = 0.0   # 0 dBm default BLE broadcast
TX_POWER_ANCHOR = -4.0   # -4 dBm default fixed beacon broadcast


@dataclass(frozen=True)
class Position:
    x: float
    y: float
    z: float = 1.0  # approximate desk/handset height in metres
    zone: str = "inside"

    def distance_to(self, other: "Position") -> float:
        dx = self.x - other.x
        dy = self.y - other.y
        dz = self.z - other.z
        return max(0.1, math.sqrt(dx * dx + dy * dy + dz * dz))


# Standard positions for classroom calibration and testing
DEFAULT_TEACHER_POS = Position(x=2.28, y=1.0, z=1.2, zone="teacher_podium")

DEFAULT_ANCHORS = {
    "B1": Position(x=0.3, y=5.8, z=2.5, zone="front_left"),    # Near window/front
    "B2": Position(x=4.2, y=5.8, z=2.5, zone="front_right"),   # Front right
    "B3": Position(x=0.3, y=0.5, z=2.5, zone="back_left"),     # Back left
    "B4": Position(x=4.2, y=0.5, z=2.5, zone="back_right"),    # Near door/back
}

TEST_POSITIONS: Dict[str, Position] = {
    # Inside classroom positions
    "inside_front_center": Position(x=2.28, y=4.5, zone="inside"),
    "inside_center": Position(x=2.28, y=3.0, zone="inside"),
    "inside_back_center": Position(x=2.28, y=1.5, zone="inside"),
    "inside_window_edge": Position(x=0.5, y=4.0, zone="inside"),
    "inside_door_edge": Position(x=4.0, y=1.0, zone="inside"),
    "inside_corner_fl": Position(x=0.6, y=5.5, zone="inside"),
    "inside_corner_br": Position(x=4.0, y=0.6, zone="inside"),

    # Exterior adversarial positions
    "outside_window": Position(x=-1.0, y=4.0, zone="outside_window"),
    "outside_door": Position(x=5.5, y=1.0, zone="outside_door"),
    "corridor": Position(x=6.5, y=3.0, zone="corridor"),
    "adjacent_room": Position(x=-3.5, y=3.0, zone="adjacent_room"),
    "different_floor": Position(x=2.28, y=3.0, z=-2.5, zone="different_floor"),
}


def compute_path_loss(
    tx_pos: Position,
    rx_pos: Position,
    tx_power: float = 0.0,
    rng: Optional[random.Random] = None,
    obstacles: Optional[List[str]] = None,
    body_count: int = 0,
) -> float:
    """Compute received signal strength (RSSI in dBm) from transmitter to receiver."""
    d = tx_pos.distance_to(rx_pos)
    is_los = (tx_pos.zone.startswith("inside") and rx_pos.zone.startswith("inside"))
    
    n = PATH_LOSS_EXP_LOS if is_los else PATH_LOSS_EXP_NLOS
    sigma = SHADOW_SIGMA_LOS if is_los else SHADOW_SIGMA_NLOS
    
    pl = PL_D0 + 10.0 * n * math.log10(d)
    
    # Obstacle attenuation
    obs = obstacles or []
    for obstacle in obs:
        if obstacle == "concrete_wall":
            pl += ATTENUATION_CONCRETE_WALL
        elif obstacle == "window_glass":
            pl += ATTENUATION_WINDOW_GLASS
        elif obstacle == "wooden_door":
            pl += ATTENUATION_WOODEN_DOOR
        elif obstacle == "floor_slab":
            pl += ATTENUATION_FLOOR_SLAB

    # Extra zone-based physical barriers if rx is outside
    if rx_pos.zone == "outside_window":
        pl += ATTENUATION_WINDOW_GLASS
    elif rx_pos.zone == "outside_door":
        pl += ATTENUATION_WOODEN_DOOR
    elif rx_pos.zone == "adjacent_room":
        pl += ATTENUATION_CONCRETE_WALL
    elif rx_pos.zone == "corridor":
        pl += ATTENUATION_WOODEN_DOOR + 4.0
    elif rx_pos.zone == "different_floor":
        pl += ATTENUATION_FLOOR_SLAB

    # Human body shadowing
    if body_count > 0:
        pl += min(15.0, body_count * ATTENUATION_BODY_SHADOW)

    # Shadow fading noise
    noise = (rng.gauss(0.0, sigma) if rng else 0.0)
    rssi = tx_power - pl + noise
    return max(-110.0, min(-20.0, rssi))


def simulate_anchor_readings(
    rx_pos: Position,
    anchors: Optional[Dict[str, Position]] = None,
    sample_count: int = 5,
    rng: Optional[random.Random] = None,
    body_count: int = 0,
) -> Dict[str, Dict[str, float]]:
    """Simulate RSSI readings for all anchors observed from rx_pos.
    
    Returns dict mapping anchor_id to statistics: mean, std, min, max, count.
    """
    active_anchors = anchors or DEFAULT_ANCHORS
    results = {}
    r = rng or random.Random(42)

    for anchor_id, pos in active_anchors.items():
        samples = []
        for _ in range(sample_count):
            rssi = compute_path_loss(
                tx_pos=pos,
                rx_pos=rx_pos,
                tx_power=TX_POWER_ANCHOR,
                rng=r,
                body_count=body_count,
            )
            samples.append(rssi)
        
        mean_rssi = sum(samples) / len(samples)
        variance = sum((s - mean_rssi) ** 2 for s in samples) / max(1, len(samples) - 1)
        std_rssi = math.sqrt(variance)
        
        results[anchor_id] = {
            "mean_rssi": mean_rssi,
            "std_rssi": std_rssi,
            "min_rssi": min(samples),
            "max_rssi": max(samples),
            "sample_count": sample_count,
        }
    return results


def evaluate_fingerprint_match(
    observed_readings: Dict[str, float],
    calibrated_profiles: Dict[str, Tuple[float, float]],  # anchor -> (mean, std)
    tolerance_sigma: float = 3.0,
) -> float:
    """Evaluate Mahalanobis-like spatial match score between observed readings and profile.
    
    Returns a match score in [0.0, 1.0], where 1.0 is exact centroid match.
    """
    if not observed_readings or not calibrated_profiles:
        return 0.0

    common_anchors = set(observed_readings.keys()).intersection(calibrated_profiles.keys())
    if len(common_anchors) < 2:
        return 0.0

    total_sq_error = 0.0
    for a in common_anchors:
        obs = observed_readings[a]
        exp_mean, exp_std = calibrated_profiles[a]
        sigma = max(1.5, exp_std * tolerance_sigma)
        z = (obs - exp_mean) / sigma
        total_sq_error += z * z

    norm_error = total_sq_error / len(common_anchors)
    # Convert error to bounded similarity in [0, 1]
    match_score = math.exp(-0.5 * norm_error)
    return max(0.0, min(1.0, match_score))
