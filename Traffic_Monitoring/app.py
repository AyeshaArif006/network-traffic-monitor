# ============================================================
# What this file does:
#   - Creates a website using Flask
#   - Provides URLs (routes) that the browser can visit
#   - Connects the website to our sniffer.py
# ============================================================


# ------------------------------------------------------------
# STEP 1: IMPORTS  (bring in tools we need)
# ------------------------------------------------------------

from flask import Flask, render_template, jsonify, Response
# Flask           = the framework that creates our web server
# render_template = loads an HTML file and sends it to the browser
# jsonify         = converts a Python dict/list into JSON format
#                   (JSON is the language browsers and servers use to share data)
# Response        = lets us send a custom response (used for live streaming)

import sniffer
# Our own sniffer.py file — gives us access to all its functions
# Example: sniffer.start_sniffing(), sniffer.get_packets(), etc.

import json
# json.dumps() converts a Python object into a JSON text string
# Example: json.dumps({"a": 1}) → '{"a": 1}'

import time
# time.sleep(0.5) pauses the code for 0.5 seconds


# ------------------------------------------------------------
# STEP 2: Create the Flask app
# This one line creates our entire web application.
# __name__ is a special Python variable = name of this file.
# Flask uses it to find the "templates/" folder for HTML files.
# ------------------------------------------------------------

app = Flask(__name__)


# ------------------------------------------------------------
# HOW ROUTES WORK:
# @app.route("/something") is a "decorator".
# It tells Flask: "when someone visits /something, run this function".
# The function must return something to send back to the browser.
# ------------------------------------------------------------


# ------------------------------------------------------------
# ROUTE 1:  /
# The homepage. Returns the main HTML page.
# Visited when user opens http://localhost:5000/ in browser.
# ------------------------------------------------------------

@app.route("/")
def index():
    # render_template loads "index.html" from the "templates/" folder
    return render_template("index.html")


# ------------------------------------------------------------
# ROUTE 2:  /start
# Starts packet sniffing.
# The browser calls this when the user clicks the "Start" button.
# ------------------------------------------------------------

@app.route("/start")
def start():
    # Call the start function from our sniffer.py file
    sniffer.start_sniffing()

    # Send back a simple confirmation message as JSON
    # jsonify({"status": "started"}) → browser receives: {"status": "started"}
    return jsonify({"status": "started"})


# ------------------------------------------------------------
# ROUTE 3:  /stop
# Stops packet sniffing.
# The browser calls this when the user clicks the "Stop" button.
# ------------------------------------------------------------

@app.route("/stop")
def stop():
    sniffer.stop_sniffing()
    return jsonify({"status": "stopped"})


# ------------------------------------------------------------
# ROUTE 4:  /packets
# Returns ALL captured packets as a JSON list (one-time snapshot).
# The browser can call this to get the full list at any moment.
# ------------------------------------------------------------

@app.route("/packets")
def packets():
    # sniffer.get_packets() returns a Python list of dictionaries
    # jsonify() converts that into a JSON response for the browser
    return jsonify(sniffer.get_packets())


# ------------------------------------------------------------
# ROUTE 5:  /stats
# Returns statistics (counts, averages) as JSON.
# ------------------------------------------------------------

@app.route("/stats")
def stats():
    return jsonify(sniffer.get_stats())


# ------------------------------------------------------------
# ROUTE 6:  /stream  ← The most advanced route
#
# This uses "Server-Sent Events" (SSE) for REAL-TIME updates.
#
# Normal websites:  Browser ASKS → Server ANSWERS (one time)
# SSE (this route): Server PUSHES updates automatically!
#
# The browser connects once to /stream and just waits.
# Every 0.5 seconds, we send any NEW packets automatically.
# This is what makes the dashboard update in real time.
# ------------------------------------------------------------

@app.route("/stream")
def stream():

    # This inner function is called a "generator".
    # Normal functions use "return" and stop.
    # Generators use "yield" and KEEP RUNNING, sending data piece by piece.
    def generate():

        # Track how many packets we've already sent to the browser
        last_count = 0

        # Loop forever (until the browser disconnects)
        while True:

            # Get the current full list of all packets
            pkts = sniffer.get_packets()

            # Check if NEW packets arrived since last time we checked
            if len(pkts) > last_count:

                # Grab only the NEW packets using list slicing
                # pkts[5:] means "give me everything starting from index 5"
                new_pkts = pkts[last_count:]

                # Update our counter so next time we start from here
                last_count = len(pkts)

                # Convert the new packets list to a JSON text string
                data = json.dumps(new_pkts)

                # "yield" sends this data to the browser WITHOUT stopping
                # The "data: ...\n\n" format is REQUIRED by the SSE protocol
                # The browser knows to read lines that start with "data:"
                yield f"data: {data}\n\n"

            # Wait 0.5 seconds before checking for new packets again
            # Without this pause, the loop would run millions of times per second
            # and use 100% of your CPU!
            time.sleep(0.5)

    # Wrap the generator in a Response object
    # mimetype="text/event-stream" tells the browser:
    # "Keep this connection open, more data is coming!"
    return Response(generate(), mimetype="text/event-stream")


# ------------------------------------------------------------
# STEP 3: Run the app
#
# "if __name__ == '__main__'" means:
#   Only run this block if you execute THIS file directly.
#   (Not if another file imports it)
#
# To start the server, run:  python app.py
# Then open:  http://localhost:5000
# ------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=False,   # False = don't show internal errors to users (safer)
        threaded=True  # True  = handle multiple browser requests at the same time
                       # This is ESSENTIAL because /stream holds a connection open
                       # while other routes like /start and /stop also need to work
    )