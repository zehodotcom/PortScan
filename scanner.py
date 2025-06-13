"""
This module contains the core scanning logic for the port scanner.
It includes functions for scanning individual ports and orchestrating
the full scan process using concurrent threads.
"""

# Import color constants and common ports information from other modules
from utils import COLOR_BRIGHT_GREEN, COLOR_BRIGHT_RED, COLOR_RESET
from common_ports import COMMON_PORTS_INFO
import socket
import sys
import time
import threading
import queue

# Define the number of threads for concurrent scanning.
# This value can be adjusted to optimize performance based on network conditions and system resources.
NUMBER_THREADS = 50


def scan_single_port(target_ip: str, port: int) -> bool:
    """
    Attempts to establish a TCP connection to a specific port on a given IP address.

    This function uses a non-blocking connect_ex() method to determine the port state
    without raising an exception on connection failure, which is ideal for port scanning.
    It prints the immediate result of the scan for a single port (only if open).

    Args:
        target_ip (str): The IP address of the target host (e.g., "127.0.0.1").
        port (int): The port number to scan (e.g., 80, 443).

    Returns:
        bool: True if the port is found to be open, False otherwise (closed/filtered).

    Exits:
        sys.exit() if a socket.gaierror (host resolution error) occurs,
        as these indicate critical network or host issues preventing any scan.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout for the connection attempt to prevent indefinite hanging.
        s.settimeout(0.5)

        # connect_ex() returns 0 on success, or an error code otherwise.
        connection_result = s.connect_ex((target_ip, port))

        service_info = COMMON_PORTS_INFO.get(port, "Unknown Service")

        if connection_result == 0:
            # We print immediately only for open ports to avoid overwhelming the console
            # during the concurrent scan. All results will be summarized at the end.
            print(
                f"{COLOR_BRIGHT_GREEN}Port {port} ({service_info}): Open{COLOR_RESET}"
            )
            return True
        else:
            return False

    except socket.gaierror:
        # If the hostname can't be resolved, it's a critical error for the whole scan.
        print(
            "Error: Hostname could not be resolved. Ensure the IP address is correct."
        )
        sys.exit(1)

    except socket.error as e:
        # For individual port errors (e.g., network transient issues),
        # print the error but don't exit the whole program.
        print(f"Connection error for port {port}: {e}")
        return False  # Treat as closed/filtered on error to continue the scan

    finally:
        s.close()


def port_scan_worker(
    target_ip: str, port_queue: queue.Queue, results_queue: queue.Queue
):
    """
    Worker function executed by each thread to scan ports.

    Continuously retrieves ports from the port_queue, scans them using scan_single_port,
    and puts the results (port, is_open) into the results_queue until the port_queue is empty.

    Args:
        target_ip (str): The IP address of the target host.
        port_queue (queue.Queue): A thread-safe queue containing ports to be scanned.
        results_queue (queue.Queue): A thread-safe queue to store the scan results (port, is_open).
    """
    while True:
        try:
            # Get a port from the queue. 'block=True' makes it wait until an item is available.
            # 'timeout=1' means it will wait for 1 second. If no item, it raises queue.Empty.
            port = port_queue.get(block=True, timeout=1)

            # Perform the scan for the retrieved port.
            is_open = scan_single_port(target_ip, port)

            # Put the result into the results queue.
            results_queue.put((port, is_open))

        except queue.Empty:
            # If the queue is empty after the timeout, all ports have likely been processed.
            # Break the loop to allow the worker thread to exit gracefully.
            break
        except Exception as e:
            # Catch any other unexpected errors during the scan of a single port
            # and still put a failure result or log it. This prevents a single thread from crashing.
            print(f"Error in port_scan_worker thread while scanning port {port}: {e}")
            results_queue.put((port, False))  # Assume closed on error for the summary
        finally:
            # Crucial: Mark the task as done, regardless of success or failure.
            # This allows port_queue.join() to track completion.
            port_queue.task_done()


def run_full_scan(target_ip: str, ports_arg: str | None = None):
    """
    Orchestrates the full port scanning process for common ports on a given IP using concurrent threads.

    Initializes the queues, launches worker threads, waits for all tasks to complete,
    and then compiles and prints the final scan summary, including all scanned port details.

    Args:
        target_ip (str): The IP address of the target host to scan.
    """
    ports_to_scan = sorted(list(COMMON_PORTS_INFO.keys()))

    print(
        f"Initiating concurrent port scan on {target_ip} with {NUMBER_THREADS} threads..."
    )

    start_time = time.time()

    # 1. Create the thread-safe queues
    # This queue will hold the ports that need to be scanned.
    port_queue = queue.Queue()
    # This queue will hold the results (port, is_open) from the worker threads.
    results_queue = queue.Queue()

    # 2. Fill the port_queue with all ports to scan
    for port in ports_to_scan:
        port_queue.put(port)

    # 3. Launch the worker threads
    threads = []
    for _ in range(NUMBER_THREADS):
        # Create a thread. The 'target' is the function it will execute.
        # 'args' are the arguments to pass to that function.
        thread = threading.Thread(
            target=port_scan_worker, args=(target_ip, port_queue, results_queue)
        )
        # Set the thread as a daemon. This means the program won't wait for these threads
        # to finish if the main program exits (e.g., due to an error), which helps in graceful shutdown.
        thread.daemon = True
        threads.append(thread)
        thread.start()  # Start the thread's execution

    # 4. Wait for all tasks in the port_queue to be completed
    # This blocks the main thread until all items in the queue have been retrieved
    # and their task_done() method has been called.
    port_queue.join()

    end_time = time.time()
    elapsed_time = end_time - start_time

    # 5. Collect and process results from results_queue
    all_scan_results = []  # List to store all (port, is_open) results

    # Retrieve all results from the results_queue
    while not results_queue.empty():
        port, is_open = results_queue.get()
        all_scan_results.append((port, is_open))
        results_queue.task_done()

    # Sort all results by port number for cleaner output
    all_scan_results.sort(key=lambda x: x[0])

    # --- Display ALL Scanned Port Details ---
    print("\n--- All Scanned Port Details ---")
    open_ports_count = 0
    closed_ports_count = 0
    for port, is_open in all_scan_results:
        service_info = COMMON_PORTS_INFO.get(port, "Unknown Service")
        if is_open:
            print(
                f"{COLOR_BRIGHT_GREEN}Port {port} ({service_info}): Open{COLOR_RESET}"
            )
            open_ports_count += 1
        else:
            print(
                f"{COLOR_BRIGHT_RED}Port {port} ({service_info}): Closed/Filtered{COLOR_RESET}"
            )
            closed_ports_count += 1
    # --- End of Displaying ALL Port Details ---

    print("\n--- Scan Summary ---")
    print(f"Scanned IP: {target_ip}")
    print(f"Open Ports: {open_ports_count}")
    print(f"Closed/Filtered Ports: {closed_ports_count}")
    print(f"Total Ports Scanned: {len(ports_to_scan)}")
    print(f"Scan Time: {elapsed_time:.2f} seconds")

    # It's good practice to ensure all result processing is done before main thread exits.
    # This call ensures all items put into results_queue have been processed by the main thread.
    results_queue.join()
