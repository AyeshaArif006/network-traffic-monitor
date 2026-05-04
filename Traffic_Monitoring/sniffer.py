# ============================================================
# What this file does:
#   Captures network packets using Scapy
#   Saves them to a list AND a CSV file
#   Provides helper functions for the Flask app
# ============================================================


# ------------------------------------------------------------
# STEP 1: IMPORTS  (bring in tools we need)
# ------------------------------------------------------------

from scapy.all import sniff, IP, TCP, UDP, ICMP
# scapy  = a library that can capture real network packets
# IP     = lets us read IP packet info (like sender/receiver address)
# TCP    = lets us read TCP packet info (most web traffic uses TCP)
# UDP    = lets us read UDP packet info (used by DNS, video calls, etc.)
# ICMP   = lets us read ICMP packet info (used by "ping" command)

from datetime import datetime
# datetime = lets us get the current date and time

import threading
# threading = lets us run the sniffer in the BACKGROUND
# Without this, starting the sniffer would freeze the whole website

import csv
# csv = lets us save data to a .csv file

import os
# os = lets us check if a file exists and delete it


# ------------------------------------------------------------
# STEP 2: PORT MAP
# A dictionary that maps port numbers to service names.
# A "port" is like a door number on a computer.
# Example: Port 80 is always used for normal websites (HTTP)
# ------------------------------------------------------------

PORT_MAP = {
    80:   "HTTP",        # Normal websites
    443:  "HTTPS",       # Secure websites
    53:   "DNS",         # Domain name lookups (google.com → IP)
    22:   "SSH",         # Remote terminal access
    21:   "FTP",         # File transfer
    25:   "SMTP",        # Sending email
    110:  "POP3",        # Receiving email
    143:  "IMAP",        # Receiving email (newer method)
    3306: "MySQL",       # MySQL database
    5432: "PostgreSQL",  # PostgreSQL database
    8080: "HTTP-Alt",    # Alternate web server port
    67:   "DHCP",        # Automatic IP assignment
    68:   "DHCP",        # Automatic IP assignment (client side)
    123:  "NTP",         # Time synchronization
    3389: "RDP",         # Remote desktop
}


# ------------------------------------------------------------
# STEP 3: GLOBAL VARIABLES
# These are shared across all functions in this file.
# Think of them as the "memory" of the sniffer.
# ------------------------------------------------------------

# This list stores every packet we capture as a dictionary
captured_packets = []

# A Lock prevents two parts of the code from editing
# captured_packets at the exact same time (could cause errors)
packet_lock = threading.Lock()

# This flag tracks whether we are currently sniffing or not
is_sniffing = False

# This will hold the background thread once we start sniffing
sniffer_thread = None

# The name of the CSV file where we save packets
CSV_FILE = "packets.csv"


# ------------------------------------------------------------
# FUNCTION 1: get_service(port)
# Converts a port number into a human-readable service name.
# Example: get_service(80)   → "HTTP"
# Example: get_service(9999) → "Port-9999"
# ------------------------------------------------------------

def get_service(port):
    # .get(port, default) looks up the port in PORT_MAP
    # If not found, it returns the fallback: "Port-{number}"
    return PORT_MAP.get(port, f"Port-{port}")


# ------------------------------------------------------------
# FUNCTION 2: process_packet(pkt)
# Scapy calls this function automatically for EVERY packet.
# We extract useful info and save it.
# ------------------------------------------------------------

def process_packet(pkt):

    # --- Skip non-IP packets ---
    # We only care about internet (IP) traffic.
    # Bluetooth, ARP, etc. are ignored.
    if IP not in pkt:
        return  # "return" with no value = just stop here

    # --- Extract basic info (available in ALL IP packets) ---
    src_ip   = pkt[IP].src                        # Who sent the packet?
    dst_ip   = pkt[IP].dst                        # Who receives it?
    size     = len(pkt)                           # How big is it (bytes)?
    time_str = datetime.now().strftime("%H:%M:%S") # Current time as "HH:MM:SS"

    # --- Set default values in case it's not TCP/UDP/ICMP ---
    proto    = "OTHER"
    src_port = 0
    dst_port = 0
    service  = "Unknown"

    # --- Check what TYPE of packet it is and extract port info ---

    if TCP in pkt:
        # TCP packet (web browsing, SSH, email, etc.)
        proto    = "TCP"
        src_port = pkt[TCP].sport        # Source port number
        dst_port = pkt[TCP].dport        # Destination port number
        service  = get_service(dst_port) # Convert port to service name

    elif UDP in pkt:
        # UDP packet (DNS, video calls, online games, etc.)
        proto    = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        service  = get_service(dst_port)

    elif ICMP in pkt:
        # ICMP packet (ping command, network diagnostics)
        proto   = "ICMP"
        service = "ICMP"
        # ICMP doesn't use port numbers, so we leave them as 0

    # --- Bundle all the info into a dictionary ---
    # A dictionary is like a labeled container for data
    packet_data = {
        "time":     time_str,  # When was it captured?
        "src_ip":   src_ip,    # Sender IP address
        "dst_ip":   dst_ip,    # Receiver IP address
        "protocol": proto,     # TCP, UDP, ICMP, or OTHER
        "size":     size,      # Size in bytes
        "src_port": src_port,  # Sender port number
        "dst_port": dst_port,  # Receiver port number
        "service":  service,   # Human-readable service name
    }

    # --- Safely add packet to our shared list ---
    # "with packet_lock:" = lock the list while we edit it,
    # then automatically unlock when the block ends.
    # This prevents data corruption from two threads writing at once.
    with packet_lock:
        captured_packets.append(packet_data)

    # --- Also save this packet to the CSV file ---
    # Check if file already exists (so we only write the header once)
    file_exists = os.path.isfile(CSV_FILE)

    # Open the file in "append" mode ("a") so we ADD to it, not overwrite
    with open(CSV_FILE, "a", newline="") as f:
        # DictWriter writes a dictionary as a row in the CSV
        writer = csv.DictWriter(f, fieldnames=packet_data.keys())

        # Only write column names (header) if the file is brand new
        if not file_exists:
            writer.writeheader()

        # Write this packet as a new row
        writer.writerow(packet_data)


# ------------------------------------------------------------
# FUNCTION 3: start_sniffing()
# Starts capturing packets in the BACKGROUND.
# Called when the user clicks "Start" in the browser.
# ------------------------------------------------------------

def start_sniffing():

    # "global" means we want to modify these variables
    # that were defined outside this function
    global is_sniffing, sniffer_thread, captured_packets

    # Don't start again if already running
    if is_sniffing:
        return

    # Clear old packets from the previous session
    with packet_lock:
        captured_packets.clear()  # .clear() empties the list

    # Delete the old CSV file so we start fresh
    if os.path.isfile(CSV_FILE):
        os.remove(CSV_FILE)  # os.remove() deletes the file

    # Set the flag to True — sniffing is now ON
    is_sniffing = True

    # Define what the background thread will do
    def run():
        sniff(
            prn=process_packet,              # Call process_packet() for each packet
            store=False,                     # Don't store packets in Scapy's own memory
            stop_filter=lambda x: not is_sniffing
            # stop_filter = a tiny function that checks:
            # "should we stop?" → Yes, when is_sniffing becomes False
            # "lambda x: ..." is a one-line anonymous function
        )

    # Create a background thread to run sniffing
    # daemon=True means: automatically stop if the main program exits
    sniffer_thread = threading.Thread(target=run, daemon=True)
    sniffer_thread.start()  # Launch the thread!


# ------------------------------------------------------------
# FUNCTION 4: stop_sniffing()
# Stops the packet capture.
# Scapy's stop_filter will detect is_sniffing=False and stop.
# ------------------------------------------------------------

def stop_sniffing():
    global is_sniffing
    is_sniffing = False  # That's all it takes!


# ------------------------------------------------------------
# FUNCTION 5: get_packets()
# Returns a COPY of all captured packets.
# We return a copy so nothing can accidentally modify the original.
# ------------------------------------------------------------

def get_packets():
    with packet_lock:
        return list(captured_packets)  # list() creates a new copy


# ------------------------------------------------------------
# FUNCTION 6: get_stats()
# Calculates and returns statistics about captured packets.
# ------------------------------------------------------------

def get_stats():

    # Get a safe copy of the list first
    with packet_lock:
        pkts = list(captured_packets)

    # Count total packets
    total = len(pkts)

    # Count packets by protocol type
    # "sum(1 for p in pkts if condition)" = count items matching condition
    tcp_count  = sum(1 for p in pkts if p["protocol"] == "TCP")
    udp_count  = sum(1 for p in pkts if p["protocol"] == "UDP")
    icmp_count = sum(1 for p in pkts if p["protocol"] == "ICMP")

    # Calculate average packet size
    # Avoid dividing by zero if no packets captured yet
    if total > 0:
        avg_size = round(sum(p["size"] for p in pkts) / total, 2)
        # round(..., 2) = round to 2 decimal places
    else:
        avg_size = 0

    # Return all stats as a dictionary
    return {
        "total":    total,
        "tcp":      tcp_count,
        "udp":      udp_count,
        "icmp":     icmp_count,
        "avg_size": avg_size,
    }
