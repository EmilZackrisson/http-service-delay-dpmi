#!/usr/bin/env python3
"""
TCP Service Delay Analyzer

This program analyzes .cap files using capshow to calculate the delay
between TCP requests and their corresponding responses.
"""

import subprocess
import sys
import re
from typing import Dict, List, Tuple, Optional
from decimal import Decimal, getcontext
import csv
import argparse

# Set decimal precision to handle picosecond timestamps
getcontext().prec = 50

parser = argparse.ArgumentParser(
    prog="TCP Delay Analyzer"
)

parser.add_argument("filename")
parser.add_argument("-p", "--port", type=int, default=30003, help="TCP Port to filter for")
parser.add_argument("-o", "--outfile", help="filename for writing results as CSV")
parser.add_argument("-v", "--verbose", action='store_true')
parser.add_argument("--exp_id_len", type=int, default=5, help="The number of digits in expid")

debug = False

def debug_log(out):
    if debug:
        print(out)


def run_capshow(cap_file: str, port: int = 30003) -> str:
    """
    Run capshow command on the capture file.
    
    Args:
        cap_file: Path to the .cap file
        port: TCP port to filter (default: 30003)
    
    Returns:
        Output from capshow command
    """
    cmd = ["capshow", cap_file, f"--tp.port={port}", "-x"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        debug_log(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running capshow: {e}", file=sys.stderr)
        print(f"stderr: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: capshow command not found. Please ensure it's installed.", file=sys.stderr)
        sys.exit(1)


def extract_timestamp(header_line: str) -> Optional[Decimal]:
    """
    Extract timestamp from packet header line.
    Format: [packet_num]:direction:mp_id:TIMESTAMP:...
    
    Args:
        header_line: The packet header line
    
    Returns:
        Timestamp as Decimal (picosecond precision), or None if not found
    """
    parts = header_line.split(":")
    if len(parts) >= 4:
        try:
            return Decimal(parts[3])
        except (ValueError, ArithmeticError):
            return None
    return None

def extract_linksize(header_line:str) -> Optional[int]:
    """
    Extract link size from packet header line.
    Format: [packet_num]:direction:mp_id:TIMESTAMP:LINK...
    
    Args:
        header_line: The packet header line
    
    Returns:
        size as Integer, or None if not found
    """

    parts = header_line.split(":")
    if len(parts) >= 5:
        try:
            linksizepart = parts[4]
            linksizepart = linksizepart.lstrip("LINK(")
            linksizepart = linksizepart.rstrip(")")
            return int(linksizepart)
        except (ValueError):
            return None
    return None


def parse_TCP_headers(hex_lines: List[str]) -> Dict[str, str]:
    """
    Parse TCP headers from hexdump ASCII representation.
    
    Args:
        hex_lines: List of hexdump lines
    
    Returns:
        Dictionary of header name -> value
    """
    headers = {}
    
    # Build a one line string with all ASCII data
    full_line = ""
    for line in hex_lines:
        if len(line) < 10:
            continue

        first_pipe = line.find("|")
        if first_pipe == -1:
            # No pipe found
            return headers
        
        ascii_data = line[first_pipe:].strip("|")
        full_line += ascii_data

    # Look for semicolon-terminated metadata: expid;runid;keyid;counter;
    pattern = re.compile(r"(\d{5})\s*;\s*(\d+)\s*;\s*(\d{10})\s*;\s*(\d+)\s*;")

    match = pattern.findall(full_line)

    if len(match) == 0:
        return headers

    headers['exp_id'] = match[0][0]
    headers['run_id'] = match[0][1]
    headers['key_id'] = match[0][2]
    headers['counter'] = match[0][3]

    return headers


def extract_ips_ports(header_line: str) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[int]]:
    """
    Extract source and destination IP:port from capshow header line.
    Returns (src_ip, src_port, dst_ip, dst_port) or (None, None, None, None)
    """
    m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*-->\s*(\d+\.\d+\.\d+\.\d+):(\d+)", header_line)
    if m:
        return m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    return None, None, None, None


def parse_capshow_output(output: str, server_port: int = 30003) -> Tuple[List[Dict], List[Dict]]:
    """
    Parse capshow output to extract TCP requests and responses.

    Args:
        output: Raw output from capshow command
        server_port: TCP port used by the server (to determine direction)

    Returns:
        Tuple of (requests list, responses list)
    """
    requests = []
    responses = []

    lines = output.strip().split('\n')
    debug_log(f"Lines: {len(lines)}")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check if this is a packet header line
        if line.startswith('[') and ']:' in line:
            header_line = line
            timestamp = extract_timestamp(header_line)
            size = extract_linksize(header_line)
            src_ip, src_port, dst_ip, dst_port = extract_ips_ports(header_line)

            debug_log(f"Found header line with timestamp: {timestamp}")

            # Collect hex dump lines until we hit the next packet or end
            hex_lines = []
            i += 1
            while i < len(lines) and not "]:d" in lines[i]:
                if lines[i].startswith('[0') and ']' in lines[i]:
                    hex_lines.append(lines[i])
                i += 1

            # Parse headers from payload (handles semicolon-separated IDs)
            headers = parse_TCP_headers(hex_lines)
            if headers and timestamp is not None:
                # Determine direction using ports: if dst_port == server_port -> request (client->server)
                # if src_port == server_port -> response (server->client)
                if dst_port == server_port:
                    requests.append({
                        'timestamp': timestamp,
                        'headers': headers,
                        'size': size,
                        'raw_header': header_line,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port
                    })
                elif src_port == server_port:
                    responses.append({
                        'timestamp': timestamp,
                        'headers': headers,
                        'raw_header': header_line,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port
                    })
        else:
            i += 1

    return requests, responses


def match_request_response(requests: List[Dict], responses: List[Dict]) -> List[Dict]:
    """
    Match requests with their corresponding responses based on headers.
    
    Args:
        requests: List of parsed requests
        responses: List of parsed responses
    
    Returns:
        List of matched pairs with delay information
    """
    matches = []
    matched_requests = set()
    matched_responses = set()
    
    # Create a key for matching based on the four headers
    def make_key(headers: Dict[str, str]) -> Tuple[str, str, str, str]:
        return (
            headers.get('exp_id', ''),
            headers.get('key_id', ''),
            headers.get('run_id', ''),
            headers.get('counter', '')
        )
    
    # Group responses by their key for easier lookup
    response_map = {}
    for response in responses:
        key = make_key(response['headers'])
        if key not in response_map:
            response_map[key] = []
        response_map[key].append(response)
    
    # Match each request with its response
    for request in requests:
        key = make_key(request['headers'])
        
        if key in response_map and response_map[key]:
            # Find the first response after this request
            for response in response_map[key]:
                if response['timestamp'] >= request['timestamp']:
                    delay = response['timestamp'] - request['timestamp']
                    matches.append({
                        'exp_id': request['headers'].get('exp_id', 'N/A'),
                        'key_id': request['headers'].get('key_id', 'N/A'),
                        'run_id': request['headers'].get('run_id', 'N/A'),
                        'counter': request['headers'].get('counter', 'N/A'),
                        'request_time': request['timestamp'],
                        'response_time': response['timestamp'],
                        'delay': delay,
                        'size': request.get('size')
                    })
                    # Mark matched request/response and remove response so it's not matched again
                    matched_requests.add(id(request))
                    matched_responses.add(id(response))
                    response_map[key].remove(response)
                    break
    
    # Log unmatched requests and responses
    unmatched_requests = [r for r in requests if id(r) not in matched_requests]
    if unmatched_requests:
        print(f"Warning: {len(unmatched_requests)} request(s) without matching response:")
        for r in unmatched_requests:
            hdr = r.get('headers', {})
            print(f"  Request exp_id={hdr.get('exp_id','N/A')} run_id={hdr.get('run_id','N/A')} key_id={hdr.get('key_id','N/A')} counter={hdr.get('counter','N/A')} time={r.get('timestamp')} src={r.get('src_ip')}:{r.get('src_port')} dst={r.get('dst_ip')}:{r.get('dst_port')} size={r.get('size')}")

    unmatched_responses = [r for r in responses if id(r) not in matched_responses]
    if unmatched_responses:
        print(f"Warning: {len(unmatched_responses)} response(s) without matching request:")
        for r in unmatched_responses:
            hdr = r.get('headers', {})
            print(f"  Response exp_id={hdr.get('exp_id','N/A')} run_id={hdr.get('run_id','N/A')} key_id={hdr.get('key_id','N/A')} counter={hdr.get('counter','N/A')} time={r.get('timestamp')} src={r.get('src_ip')}:{r.get('src_port')} dst={r.get('dst_ip')}:{r.get('dst_port')}")

    return matches


def export_to_csv(file_name: str, matches: List[Dict]):
    with open(file_name, "w", newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')

        writer.writerow(["Experiment ID", "Key ID", "Run ID", "Counter", "Request Time", "Response Time", "Delay (s)", "Size"])

        for match in matches:
            writer.writerow([match['exp_id'], match['key_id'], match['run_id'], match['counter'], match['request_time'], match['response_time'], match['delay'], match['size']])


def main():
    """Main entry point."""

    args = parser.parse_args()
    
    cap_file = args.filename
    port = args.port
    csv_filename = args.outfile

    if args.verbose:
        global debug
        debug = True
    
    print(f"Analyzing {cap_file} on port {port}...")
    print()
    
    # Run capshow and parse output
    output = run_capshow(cap_file, port)
    requests, responses = parse_capshow_output(output, port)
    debug_log(requests)
    debug_log(responses)
    
    print(f"Found {len(requests)} TCP requests")
    print(f"Found {len(responses)} TCP responses")
    print()
    
    # Match requests with responses
    matches = match_request_response(requests, responses)
    
    if not matches:
        print("No matching request-response pairs found.")
        return
    
    # Display results
    print(f"{'Exp ID':<10} {'Key ID':<15} {'Run ID':<8} {'Counter':<8} {'Request Time':<18} {'Response Time':<18} {'Delay (s)':<20} {'Size' :<5}")
    print("-" * 115)
    
    total_delay = Decimal(0)
    for match in matches:
        print(f"{match['exp_id']:<10} {match['key_id']:<15} {match['run_id']:<8} {match['counter']:<8} "
              f"{match['request_time']:<18} {match['response_time']:<18} {match['delay']:<20} {match['size']:<5}")
        total_delay += match['delay']
    
    print("-" * 115)
    print(f"Total matches: {len(matches)}")
    print(f"Average delay: {total_delay / len(matches)} seconds")
    print(f"Min delay: {min(m['delay'] for m in matches)} seconds")
    print(f"Max delay: {max(m['delay'] for m in matches)} seconds")

    if csv_filename != None:
        export_to_csv(csv_filename, matches)


if __name__ == "__main__":
    main()
