import math
import random
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

WIDTH = 1280
HEIGHT = 720
FPS = 30
DURATION_SEC = 18
TOTAL_FRAMES = FPS * DURATION_SEC

# Coordinates & Scale
ORIGIN_X = 220
ORIGIN_Y = 120
SCALE = 80 # pixels per metre

TEACHER = (2.28, 1.0)
ANCHORS = [
    (0.3, 5.8, "B1"),
    (4.2, 5.8, "B2"),
    (0.3, 0.5, "B3"),
    (4.2, 0.5, "B4"),
]

STUDENT_DESKS = []
for r in range(1, 5):
    for c in range(1, 5):
        STUDENT_DESKS.append((0.7 + c * 0.75, 1.8 + r * 0.85))

def to_screen(x, y):
    return (int(ORIGIN_X + x * SCALE), int(ORIGIN_Y + y * SCALE))

try:
    font_title = ImageFont.truetype("arial.ttf", 26)
    font_bold = ImageFont.truetype("arial.ttf", 18)
    font_regular = ImageFont.truetype("arial.ttf", 14)
    font_mono = ImageFont.truetype("consola.ttf", 14)
    font_mono_small = ImageFont.truetype("consola.ttf", 12)
except:
    font_title = font_bold = font_regular = font_mono = font_mono_small = ImageFont.load_default()

fourcc = cv2.VideoWriter_fourcc(*'mp4v')
video_writer = cv2.VideoWriter('Classroom_Simulation_Demo.mp4', fourcc, float(FPS), (WIDTH, HEIGHT))

gif_frames = []

print(f"Rendering {TOTAL_FRAMES} frames ({DURATION_SEC} seconds) of MP4 video...")

for f in range(TOTAL_FRAMES):
    t = f / FPS # time in seconds
    
    # Base Image
    img = Image.new("RGB", (WIDTH, HEIGHT), color=(9, 19, 31))
    draw = ImageDraw.Draw(img)
    
    # 1. Header Bar
    draw.rectangle([0, 0, WIDTH, 75], fill=(12, 24, 40))
    draw.line([0, 75, WIDTH, 75], fill=(0, 210, 211), width=2)
    
    # Brand
    draw.rounded_rectangle([25, 15, 65, 55], radius=10, fill=(0, 210, 211))
    draw.text((37, 20), "CG", fill=(0, 0, 0), font=font_bold)
    draw.text((80, 16), "CAMPUSGUARD ADVERSARIAL LAB", fill=(255, 255, 255), font=font_title)
    draw.text((80, 46), "15x20 ft Physical Classroom Spatial RF & Proxy Defense Simulation", fill=(131, 149, 167), font=font_regular)
    
    # Right Badges
    draw.rounded_rectangle([WIDTH - 380, 22, WIDTH - 220, 52], radius=15, outline=(0, 210, 211), width=1)
    draw.text((WIDTH - 365, 28), "BAYESIAN FUSION", fill=(0, 210, 211), font=font_bold)
    draw.rounded_rectangle([WIDTH - 200, 22, WIDTH - 30, 52], radius=15, outline=(29, 209, 161), width=1)
    draw.text((WIDTH - 185, 28), "15 GATES ACTIVE", fill=(29, 209, 161), font=font_bold)
    
    # 2. Main Classroom Canvas Bounds
    room_w = int(4.57 * SCALE)
    room_h = int(6.10 * SCALE)
    
    # Outside Zone Labels
    draw.rectangle([ORIGIN_X - 160, ORIGIN_Y, ORIGIN_X - 15, ORIGIN_Y + room_h], fill=(14, 28, 44))
    draw.text((ORIGIN_X - 150, ORIGIN_Y + 20), "[ADJACENT ROOM]", fill=(75, 101, 132), font=font_regular)
    draw.text((ORIGIN_X - 150, ORIGIN_Y + 45), "Wall Loss: -14 dB", fill=(255, 107, 107), font=font_mono_small)
    
    draw.rectangle([ORIGIN_X + room_w + 15, ORIGIN_Y, ORIGIN_X + room_w + 160, ORIGIN_Y + room_h], fill=(14, 28, 44))
    draw.text((ORIGIN_X + room_w + 25, ORIGIN_Y + 20), "[CORRIDOR HALL]", fill=(75, 101, 132), font=font_regular)
    draw.text((ORIGIN_X + room_w + 25, ORIGIN_Y + 45), "Door Loss: -6 dB", fill=(254, 202, 87), font=font_mono_small)
    
    # Room Interior
    draw.rectangle([ORIGIN_X, ORIGIN_Y, ORIGIN_X + room_w, ORIGIN_Y + room_h], fill=(16, 36, 58), outline=(0, 210, 211), width=2)
    
    # Thick Concrete Wall (Left)
    draw.line([ORIGIN_X, ORIGIN_Y, ORIGIN_X, ORIGIN_Y + room_h], fill=(231, 76, 60), width=6)
    
    # Wooden Door (Right)
    draw.line([ORIGIN_X + room_w, ORIGIN_Y + int(0.5 * SCALE), ORIGIN_X + room_w, ORIGIN_Y + int(1.8 * SCALE)], fill=(243, 156, 18), width=6)
    draw.text((ORIGIN_X + room_w + 5, ORIGIN_Y + int(1.0 * SCALE)), "DOOR", fill=(243, 156, 18), font=font_bold)
    
    # Window (Bottom)
    draw.line([ORIGIN_X + int(0.5 * SCALE), ORIGIN_Y + room_h, ORIGIN_X + int(4.0 * SCALE), ORIGIN_Y + room_h], fill=(52, 152, 219), width=5)
    draw.text((ORIGIN_X + int(1.8 * SCALE), ORIGIN_Y + room_h + 8), "GLASS WINDOW", fill=(52, 152, 219), font=font_regular)
    
    # Radio Wave Ripples from Teacher
    tx_scr, ty_scr = to_screen(TEACHER[0], TEACHER[1])
    for w in range(3):
        r_wave = int(((f * 4 + w * 70) % 280))
        alpha_val = max(0, 255 - int(r_wave * 0.9))
        draw.ellipse([tx_scr - r_wave, ty_scr - r_wave, tx_scr + r_wave, ty_scr + r_wave], outline=(0, 210, 211))
        
    # Teacher Podium
    draw.rectangle([tx_scr - 20, ty_scr - 14, tx_scr + 20, ty_scr + 14], fill=(0, 210, 211))
    draw.text((tx_scr - 18, ty_scr - 8), "TEACH", fill=(0, 0, 0), font=font_bold)
    
    # BLE Anchors
    for ax, ay, lbl in ANCHORS:
        asx, asy = to_screen(ax, ay)
        draw.ellipse([asx - 8, asy - 8, asx + 8, asy + 8], fill=(84, 160, 255))
        draw.text((asx + 10, asy - 6), f"Anchor {lbl}", fill=(131, 149, 167), font=font_regular)
        
    # Scenario State Logic
    current_test_name = ""
    status_text = ""
    rssi_text = "-49.1 dBm"
    verdict_text = "PRESENT"
    verdict_color = (29, 209, 161)
    confidence_text = "98.4%"
    log_lines = []
    
    # 0 - 3.5s: Baseline
    if t < 3.5:
        current_test_name = "BASELINE: Physical Classroom Geometry & Radio Anchors"
        rssi_text = "-49.1 dBm"
        verdict_text = "SCANNING"
        verdict_color = (0, 210, 211)
        confidence_text = "Active"
        log_lines = [
            "[SYSTEM] CampusGuard Physical Lab Initialized.",
            "[PHYSICS] 15x20ft Classroom loaded: concrete wall, wooden door.",
            "[RADIO] 4 BLE Anchors synced + Teacher 0 dBm transmitter active.",
            "[READY] Running automated proxy defense simulations..."
        ]
        for sx, sy in STUDENT_DESKS:
            ssx, ssy = to_screen(sx, sy)
            draw.ellipse([ssx - 6, ssy - 6, ssx + 6, ssy + 6], fill=(52, 73, 94))
            
    # 3.5 - 7.0s: Attack 1 (WhatsApp QR Forwarding)
    elif t < 7.0:
        current_test_name = "ATTACK #1: WhatsApp QR Screenshot Forwarding (Dorm Proxy)"
        rssi_text = "No Signal (0 dBm)"
        verdict_text = "REFUSED: EXPIRED"
        verdict_color = (255, 107, 107)
        confidence_text = "0.0%"
        
        # Desks
        for i, (sx, sy) in enumerate(STUDENT_DESKS):
            ssx, ssy = to_screen(sx, sy)
            col = (255, 107, 107) if i == 5 else (52, 73, 94)
            draw.ellipse([ssx - 6, ssy - 6, ssx + 6, ssy + 6], fill=col)
            
        # Draw Dorm Student
        dorm_x, dorm_y = ORIGIN_X - 100, ORIGIN_Y + 280
        draw.ellipse([dorm_x - 12, dorm_y - 12, dorm_x + 12, dorm_y + 12], fill=(255, 107, 107))
        draw.text((dorm_x - 55, dorm_y + 16), "Dorm Student (500m)", fill=(255, 107, 107), font=font_bold)
        
        # Flashing red transmission line
        src_sx, src_sy = to_screen(STUDENT_DESKS[5][0], STUDENT_DESKS[5][1])
        draw.line([src_sx, src_sy, dorm_x, dorm_y], fill=(255, 107, 107), width=3)
        draw.text((int((src_sx + dorm_x)/2) - 40, int((src_sy + dorm_y)/2) - 10), "WhatsApp Photo", fill=(254, 202, 87), font=font_mono_small)
        
        log_lines = [
            "[ATTACK #1] Student inside sends rolling QR photo to dorm via WhatsApp.",
            "[CLIENT] Absent student scans forwarded QR image at T+24s.",
            "[GATE ERROR] Challenge step expired: Seq #2 received vs Active #5.",
            "[VERDICT] REFUSED: challenge_expired (Attendance Blocked & Voided)!"
        ]

    # 7.0 - 10.5s: Attack 15 (Corridor Proxy)
    elif t < 10.5:
        current_test_name = "ATTACK #15: Corridor Through-The-Wall Proxy"
        rssi_text = "-70.1 dBm"
        verdict_text = "SECONDARY / FLAGGED"
        verdict_color = (254, 202, 87)
        confidence_text = "52.1%"
        
        for sx, sy in STUDENT_DESKS:
            ssx, ssy = to_screen(sx, sy)
            draw.ellipse([ssx - 6, ssy - 6, ssx + 6, ssy + 6], fill=(52, 73, 94))
            
        cor_x = ORIGIN_X + room_w + 70
        cor_y = ORIGIN_Y + int(1.2 * SCALE)
        draw.ellipse([cor_x - 10, cor_y - 10, cor_x + 10, cor_y + 10], fill=(254, 202, 87))
        draw.text((cor_x - 45, cor_y + 14), "Proxy In Corridor", fill=(254, 202, 87), font=font_bold)
        
        # Ray to teacher through door
        draw.line([tx_scr, ty_scr, cor_x, cor_y], fill=(254, 202, 87), width=2)
        
        log_lines = [
            "[ATTACK #15] Student standing in corridor behind closed wooden door.",
            "[RF LOSS] Wall & Door Attenuation detected: RSSI dropped by -20 dB.",
            "[GEOMETRY] Position outside classroom convex hull (Anchors B1-B4).",
            "[VERDICT] Degraded to SECONDARY -> Triggered Teacher Integrity Flag."
        ]

    # 10.5 - 14.0s: Attack 5 & 11 (Replay & Forgery)
    elif t < 14.0:
        current_test_name = "ATTACK #5 & #11: Proof Replay & HMAC Forgery Detection"
        rssi_text = "N/A (Corrupted)"
        verdict_text = "REFUSED: FORGED / REPLAY"
        verdict_color = (255, 107, 107)
        confidence_text = "0.0%"
        
        for sx, sy in STUDENT_DESKS:
            ssx, ssy = to_screen(sx, sy)
            draw.ellipse([ssx - 6, ssy - 6, ssx + 6, ssy + 6], fill=(52, 73, 94))
            
        log_lines = [
            "[ATTACK #5] Attacker replays captured proof packet for second student.",
            "[REPLAY LEDGER] (SessionID, DeviceKeyID) duplicate found -> REFUSED: replay_duplicate_proof.",
            "[ATTACK #11] Direct API submission with counterfeit HMAC nonce.",
            "[SECURITY GATE] Root secret recomputation mismatch -> REFUSED: challenge_forged (SUSPICIOUS)!"
        ]

    # 14.0 - 18.0s: Normal Flow & BLE Mesh 50 Nodes
    else:
        current_test_name = "NORMAL FLOW: Legitimate In-Room Attendance & BLE Mesh"
        rssi_text = "-49.1 dBm"
        verdict_text = "PRESENT"
        verdict_color = (29, 209, 161)
        confidence_text = "98.4%"
        
        # Draw student desks all green with mesh links
        for i, (sx, sy) in enumerate(STUDENT_DESKS):
            ssx, ssy = to_screen(sx, sy)
            draw.ellipse([ssx - 7, ssy - 7, ssx + 7, ssy + 7], fill=(29, 209, 161))
            # Mesh link to neighbor
            if i > 0:
                prev_sx, prev_sy = to_screen(STUDENT_DESKS[i-1][0], STUDENT_DESKS[i-1][1])
                draw.line([ssx, ssy, prev_sx, prev_sy], fill=(0, 210, 211), width=1)
                
        # Link from teacher to front row
        f_sx, f_sy = to_screen(STUDENT_DESKS[0][0], STUDENT_DESKS[0][1])
        draw.line([tx_scr, ty_scr, f_sx, f_sy], fill=(29, 209, 161), width=2)
        
        log_lines = [
            "[LEGITIMATE] Student seated at Desk Center (Line-of-Sight).",
            "[EVIDENCE] Fresh rolling QR (Seq #5) + Direct BLE (-49.1 dBm) + Biometric OK.",
            "[BLE MESH] 50/50 Classroom nodes reached via multi-hop relay (0% collision).",
            "[DECISION] Bayesian score: +8.45 nats -> VERDICT: PRESENT (98.4% Confidence)!"
        ]

    # 3. Right Sidebar UI Panels
    panel_x = ORIGIN_X + room_w + 190
    panel_w = WIDTH - panel_x - 25
    
    # Active Test Banner Panel
    draw.rounded_rectangle([panel_x, ORIGIN_Y, panel_x + panel_w, ORIGIN_Y + 110], radius=12, fill=(16, 30, 48), outline=(0, 210, 211), width=1)
    draw.text((panel_x + 15, ORIGIN_Y + 12), "CURRENT ACTIVE TEST SCENARIO", fill=(0, 210, 211), font=font_bold)
    draw.text((panel_x + 15, ORIGIN_Y + 40), current_test_name, fill=(255, 255, 255), font=font_bold)
    
    # Metrics Panel
    draw.rounded_rectangle([panel_x, ORIGIN_Y + 125, panel_x + panel_w, ORIGIN_Y + 235], radius=12, fill=(16, 30, 48), outline=(0, 210, 211), width=1)
    draw.text((panel_x + 15, ORIGIN_Y + 135), "LIVE TELEMETRY & DECISION GAUGE", fill=(0, 210, 211), font=font_bold)
    
    # Metric 1: RSSI
    draw.text((panel_x + 15, ORIGIN_Y + 165), "TARGET RSSI:", fill=(131, 149, 167), font=font_regular)
    draw.text((panel_x + 140, ORIGIN_Y + 165), rssi_text, fill=(255, 255, 255), font=font_bold)
    
    # Metric 2: Verdict
    draw.text((panel_x + 15, ORIGIN_Y + 190), "SECURITY VERDICT:", fill=(131, 149, 167), font=font_regular)
    draw.text((panel_x + 160, ORIGIN_Y + 188), verdict_text, fill=verdict_color, font=font_bold)
    
    # Metric 3: Confidence
    draw.text((panel_x + 15, ORIGIN_Y + 215), "FUSION CONFIDENCE:", fill=(131, 149, 167), font=font_regular)
    draw.text((panel_x + 180, ORIGIN_Y + 215), confidence_text, fill=(255, 255, 255), font=font_bold)
    
    # Terminal Log Panel
    draw.rounded_rectangle([panel_x, ORIGIN_Y + 250, panel_x + panel_w, ORIGIN_Y + room_h], radius=12, fill=(4, 9, 14), outline=(255, 255, 255), width=1)
    draw.text((panel_x + 15, ORIGIN_Y + 260), "CRYPTOGRAPHIC GATE TERMINAL", fill=(0, 210, 211), font=font_bold)
    
    y_log = ORIGIN_Y + 295
    for l in log_lines:
        c_line = (255, 107, 107) if "REFUSED" in l or "ERROR" in l else ((254, 202, 87) if "ATTACK" in l or "LOSS" in l else ((29, 209, 161) if "PRESENT" in l or "READY" in l else (0, 210, 211)))
        draw.text((panel_x + 15, y_log), l, fill=c_line, font=font_mono_small)
        y_log += 26
        
    # Convert PIL Image to OpenCV frame (BGR)
    cv_frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    video_writer.write(cv_frame)
    
    # Save every 5th frame for animated GIF
    if f % 5 == 0:
        gif_frames.append(img.resize((640, 360), Image.Resampling.LANCZOS))

video_writer.release()
print("MP4 Video successfully written to Classroom_Simulation_Demo.mp4!")

# Save GIF
if gif_frames:
    print("Saving animated GIF to Classroom_Simulation_Demo.gif...")
    gif_frames[0].save(
        'Classroom_Simulation_Demo.gif',
        save_all=True,
        append_images=gif_frames[1:],
        duration=int(1000 / (FPS / 5)),
        loop=0
    )
    print("GIF successfully saved!")
