#!/usr/bin/env python3
"""
HTTP Service Delay Analyzer

This program analyzes .cap files using capshow to calculate the delay
between HTTP requests and their corresponding responses.
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
    prog="HTTP Delay Analyzer"
)

parser.add_argument("filename")
parser.add_argument("-p", "--port", default=8001)
parser.add_argument("-o", "--outfile")
parser.add_argument("-v", "--verbose", action='store_true')

debug = False

def debug_log(out):
    if debug:
        print(out)


def run_capshow(cap_file: str, port: int = 8001) -> str:
    """
    Run capshow command on the capture file.
    
    Args:
        cap_file: Path to the .cap file
        port: TCP port to filter (default: 8001)
    
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


def parse_http_headers(hex_lines: List[str]) -> Dict[str, str]:
    """
    Parse HTTP headers from hexdump ASCII representation.
    
    Args:
        hex_lines: List of hexdump lines
    
    Returns:
        Dictionary of header name -> value
    """
    headers = {}
    
    # Combine all ASCII parts from hexdump
    ascii_text = ""
    for line in hex_lines:
        # Extract ASCII part (between last two | characters)
        match = re.search(r'\|([^|]*)\|$', line)
        if match:
            ascii_text += match.group(1)
    
    # Look for the headers we care about (case-insensitive)
    header_patterns = [
        (r'Counter:\s*(\d+)', 'counter'),
        (r'Exp_id:\s*(\d+)', 'exp_id'),
        (r'Key_id:\s*(\d+)', 'key_id'),
        (r'Run_id:\s*(\d+)', 'run_id'),
        (r'counter:\s*(\d+)', 'counter'),
        (r'exp_id:\s*(\d+)', 'exp_id'),
        (r'key_id:\s*(\d+)', 'key_id'),
        (r'run_id:\s*(\d+)', 'run_id'),
    ]
    
    for pattern, header_name in header_patterns:
        match = re.search(pattern, ascii_text, re.IGNORECASE)
        if match and header_name not in headers:
            headers[header_name] = match.group(1)
    
    return headers


def parse_capshow_output(output: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Parse capshow output to extract HTTP requests and responses.
    
    Args:
        output: Raw output from capshow command
    
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

            debug_log(f"Found header line with timestamp: {timestamp}")
            
            # Collect hex dump lines until we hit the next packet or end
            hex_lines = []
            i += 1
            while i < len(lines) and not "]:d" in lines[i]:
                if lines[i].startswith('[0') and ']' in lines[i]:
                    hex_lines.append(lines[i])
                i += 1
            
            # Check if this is an HTTP request or response
            ascii_combined = ''.join(hex_lines)
            
            if 'POST' in ascii_combined or 'GET' in ascii_combined:
                # This is a request
                headers = parse_http_headers(hex_lines)
                if headers and timestamp is not None:
                    requests.append({
                        'timestamp': timestamp,
                        'headers': headers,
                        'raw_header': header_line
                    })
            elif 'HTTP/1.1' in ascii_combined:
                # This is a response
                headers = parse_http_headers(hex_lines)
                if headers and timestamp is not None:
                    responses.append({
                        'timestamp': timestamp,
                        'headers': headers,
                        'raw_header': header_line
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
                        'delay': delay
                    })
                    # Remove this response so it's not matched again
                    response_map[key].remove(response)
                    break
    
    return matches

def export_to_csv(file_name: str, matches: List[Dict]):
    with open(file_name, "w", newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')

        writer.writerow(["Experiment ID", "Key ID", "Run ID", "Counter", "Request Time", "Response Time", "Delay (s)"])

        for match in matches:
            writer.writerow([match['exp_id'], match['key_id'], match['run_id'], match['counter'], match['request_time'], match['response_time'], match['delay']])


def main():
    """Main entry point."""
    # if len(sys.argv) < 2:
    #     print("Usage: python http_delay_analyzer.py <cap_file> [port]", file=sys.stderr)
    #     print("Example: python http_delay_analyzer.py trace-40588-1.cap 8001", file=sys.stderr)
    #     sys.exit(1)

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
    requests, responses = parse_capshow_output(output)
    debug_log(requests)
    debug_log(responses)
    
    print(f"Found {len(requests)} HTTP requests")
    print(f"Found {len(responses)} HTTP responses")
    print()
    
    # Match requests with responses
    matches = match_request_response(requests, responses)
    
    if not matches:
        print("No matching request-response pairs found.")
        return
    
    # Display results
    print(f"{'Exp ID':<10} {'Key ID':<15} {'Run ID':<8} {'Counter':<8} {'Request Time':<18} {'Response Time':<18} {'Delay (s)':<12}")
    print("-" * 115)
    
    total_delay = Decimal(0)
    for match in matches:
        print(f"{match['exp_id']:<10} {match['key_id']:<15} {match['run_id']:<8} {match['counter']:<8} "
              f"{match['request_time']:<18} {match['response_time']:<18} {match['delay']:<20}")
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
