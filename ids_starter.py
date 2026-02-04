# file: ids_starter.py
"""
Main entry point for the signature-based IDS.
"""
import threading
import signal
import os
import sys
import webbrowser
from threading import Timer
from capture import TEST_MODE, synthetic_record_generator, sniffer_thread
from detection import detector_loop
from dashboard import app, socketio, push_alert, blocked_ips

threads = []
running = True

def open_browser():
    """Opens the dashboard URL in the default web browser."""
    webbrowser.open_new("http://127.0.0.1:5000")

def shutdown(signum=None, frame=None):
    global running
    print("Shutting down IDS...")
    running = False
    for t in threads:
        try:
            if t.is_alive():
                t.join(timeout=1.0)
        except Exception:
            pass
    try:
        socketio.stop()
    except Exception:
        pass
    os._exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

def main():
    global TEST_MODE
    TEST_MODE = TEST_MODE or ("--test" in sys.argv)

    dt = threading.Thread(target=detector_loop, args=(push_alert,), daemon=True, name="detector")
    dt.start()
    threads.append(dt)

    if TEST_MODE:
        sg = threading.Thread(target=synthetic_record_generator, daemon=True, name="synthetic_gen")
        sg.start()
        threads.append(sg)
        print("TEST_MODE: Synthetic traffic generator running.")
    else:
        st = threading.Thread(target=sniffer_thread, daemon=True, name="sniffer")
        st.start()
        threads.append(st)
        print("Live sniffer running (requires root/admin).")
    Timer(1.5, open_browser).start()

    print("Starting IDS web dashboard at http://127.0.0.1:5000")
    try:
        # Note: socketio.run is blocking, so it must stay at the end
        socketio.run(app, host="0.0.0.0", port=5000)
    except Exception as e:
        print("Server error:", e)
        shutdown()

    # Emit initial blocked list so web clients get current state
    try:
        socketio.emit('blocked_list', list(blocked_ips))
    except Exception:
        pass

    print("Starting IDS web dashboard at http://127.0.0.1:5000")
    try:
        socketio.run(app, host="0.0.0.0", port=5000)
    except (KeyboardInterrupt, SystemExit):
        shutdown()
    except Exception as e:
        print("Server error:", e)
        shutdown()

if __name__ == "__main__":
    main()
