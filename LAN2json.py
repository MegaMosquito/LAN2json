#!/usr/bin/env python
#coding: utf-8
"""

LAN2json.py LAN scanning tools that return JSON

This class provides a "scan()" function to perform Local Area Network (LAN)
scans using the popular "nmap" utility. Note that "nmap" must be run as root
in order to acquire this data (so your program may need to run as root).
The "nmap" utility will run as non-root but it will not give the required
MAC address data unless it has root privilege:

With root privilege nmap gives the MAC address and the manufacturer string:
 $ sudo nmap -sn -T5 192.168.123.0/24
Starting Nmap 7.40 ( https://nmap.org ) at 2019-06-01 14:07 PDT
Nmap scan report for 192.168.123.1
Host is up (0.0031s latency).
MAC Address: 3C:37:86:5E:EC:37 (Unknown)
Nmap scan report for 192.168.123.4
Host is up (0.0035s latency).
MAC Address: B8:27:EB:AC:14:3E (Raspberry Pi Foundation)
Nmap scan report for atomicpi.lan (192.168.123.163)
Host is up (0.015s latency).
MAC Address: 00:07:32:4B:E3:C6 (Aaeon Technology)
...

Without root privilege nmap gives only IP address and latency:
 $ nmap -sn -T5 192.168.123.0/24
Starting Nmap 7.40 ( https://nmap.org ) at 2019-06-01 14:07 PDT
Nmap scan report for 192.168.123.1
Host is up (0.0018s latency).
Nmap scan report for 192.168.123.4
Host is up (0.0064s latency).

This class also provides a "portscan" static method that performs a
sequential TCP port connection scan on a specified host (to discover all
of the TCP ports within a specified range on that host that have bound
and responsive "listener" processes).

There is also asmall main program wrapper so you can use it from the CLI.

Example CLI commands:
  $ sudo python LAN2json.py scan '192.168.123.0/24' '192.168.123.3' 'B8:27:EB:81:F4:79' '(Network Monitor Host)'
  $ sudo python LAN2json.py portscan '192.168.123.3' 1 65535

Static functions provided:
  portscan: find open TCP ports on a specific host
  scan: find IP and MAC addresses on the LAN

Attributes defined:
  TCP_PORT_MIN: The lowest usable TCP port (1, since 0 is "reserved")
  TCP_PORT_WELL_KNOWN_MAX: The highest numbered well-known TCP port
  TCP_PORT_REGISTERED_MIN: The lowest numbered registered TCP port
  TCP_PORT_REGISTERED_MAX: The highest numbered registered TCP port
  TCP_PORT_MAX: The highest possible TCP port number

Written by Glen Darling (mosquito@darlingevil.com) in December, 2018.

"""

import json
import os
import socket
import subprocess
import sys

class LAN2json:

  @staticmethod
  def scan(subnet_cidr, this_ip, this_mac, this_comment=''):

    """
    scan: synchronously run "nmap" in a subprocess to collect LAN hosts

    Use this function to scan the local area network (LAN) to detect LAN host
    IPv4 addresses, MAC addresses, and comment strings (as scanned from the
    network). The underlying nmap utility needs the subnet CIDR, so that is
    the first argument to this function.

    This function also takes arguments of the IP address, MAC address
    (and optionally a comment string) for the host where the command is
    being run. This is because nmap only returns the IP address for the
    local host. So providing these additional details enables the "scan"
    function to return a complete record even for the scanning host that
    is running the command.

    Args:
      subnet_cidr: string (subnet in CIDR format for this LAN)
      this_ip: string (the IPv4 address of this scanning host on the LAN)
      this_MAC: string (the MAC address of this scanning host)
      this_comment: string (optional comment field for this scanning host)

    Returns:
      a JSON array of records for each host discovered on the LAN.
      Fields and types for each record in the arry:
        "ip": string (IPv4 address where this host was found)
        "mac": string (colon-delimited MAC address of this host)
        "comment" string (detected interface manufacturer string)
    """

    # Root privilege is required or the `nmap` scan won't work correctly
    if os.geteuid() != 0:
      exit('Error: Root privilege is required for LAN2json.scan()! Exiting.')

    # Don't change these! (these are emitted by nmap, and used in egrep below)
    IP_PREFIX = 'Nmap scan report for '
    MAC_PREFIX = 'MAC Address: '

    # Run nmap on this subnet, then strip header, footer, and empty lines
    COMMAND = 'nmap -sn -T5 ' + subnet_cidr + ' | egrep -v "Starting Nmap|Nmap done|^$"'
    process = subprocess.Popen(['sh', '-c', COMMAND], stdout=subprocess.PIPE)
    hosts = []
    while True:
      try:
        # Each host has 3 lines of output (except this host has only 2)
        ip = process.stdout.readline().strip().decode('utf-8')[len(IP_PREFIX):]
        # Now fixup this: "map scan report for atomicpi.lan (192.168.123.163)"
        # Split string at whitespace, take only the last element
        ip = ip.split()[-1]
        # Remove () from the string
        ip = ip.replace('(','').replace(')','')
        latency = process.stdout.readline().strip().decode('utf-8')
        mac_and_comment = process.stdout.readline().strip().decode('utf-8')[len(MAC_PREFIX):]
        # Exit loop at end of input
        if ('' == ip + mac_and_comment):
          break
        # This host won't have the third line with MAC and comment
        mac = comment = ''
        if ('' != mac_and_comment):
          mac = mac_and_comment[:17]
          comment = mac_and_comment[18:]
        # For this host, add the provided MAC and constant comment
        if (this_ip == ip):
          mac = this_mac
          comment = this_comment
        # Package up the JSON and add to hosts array
        host = {}
        host['ip'] = ip
        host['mac'] = mac
        host['comment'] = comment
        hosts.append(host)
      except:
        # Exit loop on error
        break
    return hosts

  # Some convenient port number constants
  TCP_PORT_MIN = 1
  TCP_PORT_WELL_KNOWN_MAX = 1023
  TCP_PORT_REGISTERED_MIN = 1024
  TCP_PORT_REGISTERED_MAX = 49151
  TCP_PORT_MAX = 65535

  @staticmethod
  def portscan(ip, min=TCP_PORT_MIN, max=TCP_PORT_WELL_KNOWN_MAX):

    """
    portscan: synchronously scan for open TCP ports within a range

    Use this function to discover open TCP ports (i.e., those with listeners)
    within a specific range on a specified host. Since this scanning can be
    very slow, you may optionally specify a range of port numbers to scan.
    For example you might want to scan all of the well "known-port" numbers
    in range {1..1023}. On most hosts you require root privileges to
    bind a listener to these ports. Alternatively you could choose the
    IANA registered port range {1..49151} (i.e., from 2^10 to 2^14 + 2^15 − 1)
    but this larger range will take much longer to scan. If you can spare
    the time, you could also scan all possible TCP port numbers {0..65535}.
    
    If no range is specified, the default range of {1..1023} is used.

    This function is aware of the TCP port assignments in RFC1340, available
    at https://tools.ietf.org/html/rfc1340 and it will supply the "keyword"
    and "description" fields for thos ports that are provided in RFC1340,
    if any, for all open ports it discovers.

    Args:
      ip: string (IPv4 address of this host on the LAN)
      min: integer (optional lowest port nuber to scan -- default TCP_PORT_MIN)
      max: integer (optional highest port number to scan -- default TCP_PORT_WELL_KNOWN_MAX)

    Returns:
      a JSON array of records for each TCP ports with an active listener.
      Fields and types for each record in the array:
        "port": integer (the port number where a bound listener was found)
        "status": string (always "open")
        "known": boolean (True if RFC1340 has info about this port)
        "keyword": string (from RFC1340, may be "")
        "description": string (from RFC1340, may be "")
    """

    # Import the dictionary of TCP port numbers (only needed by this function)
    from rfc1340.known_tcp_ports import known_tcp_ports

    ports = []
    try:
      for port in range(min, max + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if (0 == result):
          if port in known_tcp_ports:
            port_info = known_tcp_ports[port]
            # print(json.dumps(port_info))
            port = { "port": port, "status": "open", "known": True, "keyword": port_info['keyword'], "description": port_info['description'] }
          else:
            port = { "port": port, "status": "open", "known": False, "keyword": "", "description": "" }
          ports.append(port)
        sock.close()
    except socket.gaierror:
      return { "error": "Unable to resolve host \"" + ip + "\"" }
    except socket.error:
      return { "error": "Unable to connect to host \"" + ip + "\"" }
    
    return ports

# Test shell (only executes if this module is run stand-alone)
if __name__ == '__main__':

  error = {"error": "incorrect CLI arguments"}

  try:

    # If no arguments provided, or first argument is "scan"
    if (1 == len(sys.argv) or "scan" == sys.argv[1]):

      # No args?
      if (1 == len(sys.argv) or (2 == len(sys.argv) and "scan" == sys.argv[1])):

        # Run scan with these hard-coded values (from my dev environment)
        hosts = LAN2json.scan('192.168.123.0/24', '192.168.123.3', 'B8:27:EB:81:F4:79', '(Network Monitor Host)')

      # If 5 or 6 arguments, pass all of them to the scan function
      elif (len(sys.argv) >= 5):

        if (6 == len(sys.argv)):
          # Comment field provided
          hosts = LAN2json.scan(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        else:
          # No comment field provided
          hosts = LAN2json.scan(sys.argv[2], sys.argv[3], sys.argv[4])

      else:
        hosts = error

      print(json.dumps(hosts))

    # Note that the portscan function requires at least an IP address argument
    elif ("portscan" == sys.argv[1] and len(sys.argv) >= 3):

      # Just an IP address provided?
      if (3 == len(sys.argv)):
        ports = LAN2json.portscan(sys.argv[2])

      # Or IP address and min, max provided?
      elif (5 == len(sys.argv)):

        try:
          min = int(sys.argv[3])
          max = int(sys.argv[4])
          ports = LAN2json.portscan(sys.argv[2], min, max)

        except:
          ports = error

      else:
        ports = error

      print(json.dumps(ports))

    else:

      print(json.dumps(error))

  except KeyboardInterrupt:
    sys.exit()

