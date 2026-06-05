#!/usr/bin/env python3
import sys
import time
import math
import subprocess
import shutil

def get_gradient_color(step, total_steps):
    frequency = 2 * math.pi / total_steps
    r = int(math.sin(frequency * step + 0) * 127 + 128)
    g = int(math.sin(frequency * step + 2) * 127 + 128)
    b = int(math.sin(frequency * step + 4) * 127 + 128)
    return f"\033[38;2;{r};{g};{b}m"

EAGLE_ART = [
    r"                             _                             ",
    r"                            / \                            ",
    r"                           /   \                           ",
    r" dynamic              _.._ |   | _.._              cyber   ",
    r" intelligence       .' .-'`|   |`'-. '.       orchestration",
    r"                   /  /    |   |    \  \                   ",
    r"                  |  |     /   \     |  |                  ",
    r"                  \  \   .'     '.   /  /                  ",
    r"                   '._'-'         '-'_.'                   ",
    r"                      `""--..___..--""`                     ",
    r"               ___                         ___             ",
    r"            .-'   `'-._               _.-'`   '-.          ",
    r"           /           '-._       _.-'           \         ",
    r"          /   _.._         '-._.-'         _.._   \        ",
    r"         |  .'    '-._       / \       _.-'    '.  |       ",
    r"         |  |         '-._  /   \  _.-'         |  |       ",
    r"         \  \             '/     \'             /  /       ",
    r"          \  '.           /       \           .'  /        ",
    r"           \   '-._      |  CORE   |      _.-'   /         ",
    r"            '-._   '-._  |  UNIT   |  _.-'   _.-'          ",
    r"                '-._   '-|    o    |-'   _.-'              ",
    r"                    '-._  \       /  _.-'                  ",
    r"                        '-.\     /.-'                      ",
    r"                            '._.'                          "
]

NOVA_TEXT = [
    r"  _   _    ___  _   _   _ ___     ",
    r" | \ | |  / _ \ \ \ / / / / _ \    ",
    r" |  \| | | | | | \ V / / / /_\ \   ",
    r" | |\  | | |_| |  \ / / /  ___  \  ",
    r" |_| \_|  \___/    V /_/_/_/   \_\ "
]

def start_background_audio():
    """Detects native CLI players and triggers the audio engine track asynchronously"""
    audio_file = "docs/assets/ascent_of_the_radiant_eagle.mp3"
    
    # Selection priority for lightweight players
    players = ["mpv", "ffplay", "play", "aplay"]
    chosen_player = None
    
    for p in players:
        if shutil.which(p):
            chosen_player = p
            break
            
    if not chosen_player:
        return None # Silently pass if no command-line player is found

    # Build audio command flags depending on the chosen engine
    if chosen_player == "mpv":
        cmd = ["mpv", "--no-video", "--volume=80", audio_file]
    elif chosen_player == "ffplay":
        cmd = ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", audio_file]
    else:
        cmd = [chosen_player, audio_file]

    # Run as a detached background process
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return process
    except Exception:
        return None

def animate_arrival():
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CLEAR = "\033[H\033[2J"
    
    sys.stdout.write(CLEAR)
    print(f"\033[1;32m[+] Git Clone Status: SUCCESSFUL\033[0m")
    print(f"\033[1;34m[+] Synchronizing Audio and Visual Streams...\033[0m\n")
    time.sleep(0.5)
    
    # Spin up background audio tracking
    audio_proc = start_background_audio()
    
    total_lines = len(EAGLE_ART)
    for idx, line in enumerate(EAGLE_ART):
        color = get_gradient_color(idx, total_lines)
        sys.stdout.write(color + line + RESET + "\n")
        sys.stdout.flush()
        time.sleep(0.04)
        
    print("\n" + " " * 20 + "-" * 25 + "\n")
    
    for i in range(len(NOVA_TEXT)):
        color = get_gradient_color(i + 10, len(NOVA_TEXT) + 10)
        print(" " * 15 + BOLD + color + NOVA_TEXT[i] + RESET)
        time.sleep(0.05)

    print("\n" + " " * 16 + "\033[1;36m-- QUANTUM INTELLIGENCE SYSTEM --\033[0m\n")
    
    # Keep the script tracking open for a bit if music is active
    if audio_proc:
        try:
            print("\033[0;35m[🎶 System Music Active: Ascent of the Radiant Eagle]\033[0m")
            print("\033[0;37mPress Ctrl+C at any time to enter terminal interface.\033[0m\n")
            audio_proc.wait()
        except KeyboardInterrupt:
            audio_proc.terminate()

if __name__ == "__main__":
    animate_arrival()
