# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.
from struct import unpack
from socket import inet_ntoa
from elasticsearch import Elasticsearch, helpers
from multiprocessing.pool import ThreadPool
import time, datetime, socket, sys, json, socket, logging, logging.handlers, getopt, parser_modules

logging.basicConfig(level = "DEBUG") # Set the logging level

# Timestamp variable
now = datetime.datetime.utcnow()

### Packed Integer Parsers ###
class name_lookups(object):
    """DNS lookup class"""
    import socket, time
    from site_category import site_categories

    dns_cache = {} # Name cache

    # Multicast per http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    special_ips = {
        "255.255.255.255":"Broadcast",
        "127.0.0.1":"Localhost",
        "224.0.0.0":"Multicast",
        "224.0.0.1":"All Hosts Multicast",
        "224.0.0.2":"All Routers Multicast",
        "224.0.0.4":"DVMRP Multicast",
        "224.0.0.5":"OSPF Router Multicast",
        "224.0.0.6":"OSPF Designated Router Multicast",
        "224.0.0.9":"RIPv2 Multicast",
        "224.0.0.10":"EIGRP Multicast",
        "224.0.0.12":"DHCP Server / Relay",
        "224.0.0.13":"PIMv2 Multicast",
        "224.0.0.14":"RSVP Encapsulation Multicast",
        "224.0.0.18":"VRRP Multicast",
        "224.0.0.19":"IS-IS Multicast",
        "224.0.0.20":"IS-IS Multicast",
        "224.0.0.21":"IS-IS Multicast",
        "224.0.0.22":"IGMPv3 Multicast",
        "224.0.0.102":"HSRPv2 Multicast",
        "224.0.0.252":"Link-local Multicast Name Resolution",
        "224.0.0.252":"Teredo Multicast"
        }
    
    # Add special IPs to dns_cache
    for key in special_ips:
        dns_cache[key] = {}
        dns_cache[key]["FQDN"] = special_ips[key]
        dns_cache[key]["Domain"] = special_ips[key]
        dns_cache[key]["Content"] = "Uncategorized"

        second_level_domains = {
                "co.id", # Indonesia
                "co.in", # India
                "co.jp", # Japan
                "co.nz", # New Zealand
                "co.uk", # United Kingdom
                "co.za", # South Africa
                "com.ar", # Argentina
                "com.au", # Australia
                "com.bn", # Brunei
                "com.br", # Brazil
                "com.cn", # People's Republic of China
                "com.gh", # Ghana
                "com.hk", # Hong Kong
                "com.mx", # Mexico
                "com.sg", # Singapore
                "edu.au", # Australia
                "net.au", # Australia
                "net.il", # Israel
                "org.au" # Australia
        }

    def __init__(self):
        return

    def ip_names(
        self,
        ip_version, # type: int
        ip_addr # type: str
        ):
        """
        DNS reverse lookups for SRC and DST IP addresses
        
        Args:
            ip_version (int): Internet Protocol version
            ip_addr (str): IP address for lookup

        Returns:
            dict: {Content, Domain, Expires, FQDN}
        """               
        if ip_addr not in self.dns_cache: # Not already cached
            
            # Record cache
            self.dns_cache[ip_addr] = {}
            self.dns_cache[ip_addr]["Expires"] = int(self.time.time())+1800
            
            # Run reverse lookup
            try:
                ip_lookup = str(self.socket.getfqdn(ip_addr))
            except Exception as lookup_message: # DNS lookup failed
                print(lookup_message)
                return False
            
            # Successful lookup
            if ip_lookup != ip_addr:                
                
                # Update the local cache with the FQDN
                self.dns_cache[ip_addr]["FQDN"] = ip_lookup
                
                # Parse the FQDN for the Domain
                if "." in ip_lookup:
                    fqdn_exploded = ip_lookup.split('.') # Blow it up

                    # Grab TLD and second-level domain
                    domain = str(fqdn_exploded[-2]) + "." + str(fqdn_exploded[-1])
                    
                    # Check for .co.uk, .com.jp, etc...
                    if domain in self.second_level_domains:
                        domain = str(fqdn_exploded[-3]) + "." + str(domain) 
                
                # Use IP, no domain record available
                else:
                    domain = ip_lookup
                
                self.dns_cache[ip_addr]["Domain"] = domain # Domain

                if self.dns_cache[ip_addr]["Domain"] in self.site_categories: # Documented site with Content
                    self.dns_cache[ip_addr]["Content"] = self.site_categories[self.dns_cache[ip_addr]["Domain"]]
                else:
                    self.dns_cache[ip_addr]["Content"] = "Uncategorized" # Default content; Normalize graphs
            
            # No DNS record, use IP instead
            else:
                # Use defaults to normalize graphs
                self.dns_cache[ip_addr]["FQDN"] = ip_addr
                self.dns_cache[ip_addr]["Domain"] = ip_addr
                self.dns_cache[ip_addr]["Content"] = "Uncategorized"
        
        return self.dns_cache[ip_addr]

### Packed Integer Parsers ###
class int_parse(object):
    from struct import unpack

    def __init__(self):
        return
    
    def integer_unpack(
        self,
        packed_data, # type: struct
        pointer, # type: int
        field_size # type: int
        ):
        """
        Unpack an Integer
        
        Args:
            packed_data (struct): Packed data
            pointer (int): Current unpack location
            field_size (int): Length of data to unpack

        Returns:
            str: IPv4 address
        """
        if field_size == 1:
            return self.unpack('!B',packed_data[pointer:pointer+field_size])[0]
        elif field_size == 2:
            return self.unpack('!H',packed_data[pointer:pointer+field_size])[0]	
        elif field_size == 4:
            return self.unpack('!I',packed_data[pointer:pointer+field_size])[0]
        elif field_size == 8:
            return self.unpack('!Q',packed_data[pointer:pointer+field_size])[0]
        else:
            return False

### Packed IP Parsers (Netflow v5, Netflow v9, IPFIX) ###
class ip_parse(object):
    import socket
    
    # Windows socket.inet_ntop support via win_inet_pton
    try:
        import win_inet_pton
    except ImportError:
        pass
    
    def __init__(self):
        return

    # Unpack IPv4
    def parse_ipv4(
        self,
        packed_data, # type: struct
        pointer, # type: int
        field_size # type: int
        ):
        """
        Unpack an IPv4 address
        
        Args:
            packed_data (struct): Packed data
            pointer (int): Current unpack location
            field_size (int): Length of data to unpack

        Returns:
            str: IPv4 address
        """
        payload = self.socket.inet_ntoa(packed_data[pointer:pointer+field_size])
        return payload

    # Unpack IPv6
    def parse_ipv6(
        self,
        packed_data, # type: struct
        pointer, # type: int
        field_size # type: int
        ):
        """
        Unpack an IPv6 address
        
        Args:
            packed_data (struct): Packed data
            pointer (int): Current unpack location
            field_size (int): Length of data to unpack

        Returns:
            str: IPv4 address
        """
        payload = self.socket.inet_ntop(self.socket.AF_INET6,packed_data[pointer:pointer+field_size])
        return payload


### Generic MAC Address Parsers ###
class mac_address(object):
    import struct
    
    def __init__(self):
        
        # See the following for MAC OUI information:
        # http://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
        # https://tools.ietf.org/html/rfc7042
        mac_oui = {
        "005056": {"Vendor":"VMware",               "Type":"Virtualization"},
        "00005E": {"Vendor":"IANA",                 "Type":"Unicast"},
        "01000C": {"Vendor":"Cisco",                "Type":"Logical"},
        "01005E": {"Vendor":"IANA",                 "Type":"Multicast"},
        "0180C2": {"Vendor":"IEEE",                 "Type":"Logical"},
        "0A0027": {"Vendor":"Oracle",               "Type":"Virtualization"},
        "2C0E3D": {"Vendor":"Samsung",              "Type":"Physical"},
        "333300": {"Vendor":"IPv6",                 "Type":"Virtualization"},
        "48F8B3": {"Vendor":"Linksys",              "Type":"Physical"},
        "5855CA": {"Vendor":"Apple",                "Type":"Physical"},
        "74C63B": {"Vendor":"AzureWave Technology", "Type":"Physical"},
        "74D435": {"Vendor":"Giga-Byte Technology", "Type":"Physical"},
        "FFFFFF": {"Vendor":"Broadcast",            "Type":"Logical"}
        }

    # MAC passed as Python list, 6 elements
    def mac_parse(
        self,
        mac # type: list
        ):
        """
        Parse MAC addresses passed as Python list(6) that has already been unpacked

        Args:
            mac (list): List with (6) elements

        Returns:
            tuple: (MAC Address:str, MAC OUI:str)
        """
        mac_list = []
        for mac_item in mac:
            mac_item_hex = hex(mac_item).replace('0x','') # Strip leading characters
            if len(mac_item_hex) == 1:
                mac_item_hex = str("0" + mac_item_hex) # Handle leading zeros and double-0's
            mac_list.append(mac_item_hex)
        parsed_mac = (':'.join(mac_list)).upper() # Format MAC as 00:11:22:33:44:AA
        parsed_mac_oui = (''.join(mac_list[0:3])).upper() # MAC OUI as 001122
        return (parsed_mac,parsed_mac_oui)

    # MAC passed as packed bytes
    def mac_packed_parse(
        self,
        packed_data, # type: "XDR Data"
        pointer, # type: int
        field_size # type: int
        ):
        """
        Parse MAC addresses passed as packed bytes that first need to be unpacked
         
        Args:
            packed_data (xdr): Packed XDR data
            pointer (int): Current location for unpacking
            field_size (int): Size of the packed data

        Returns:
            tuple: (MAC Address:str, MAC OUI:str)
        """
        mac_list = []
        mac_objects = self.struct.unpack('!%dB' % field_size,packed_data[pointer:pointer+field_size])
        for mac_item in mac_objects:
            mac_item_hex = hex(mac_item).replace('0x','') # Strip leading characters
            if len(mac_item_hex) == 1:
                mac_item_hex = str("0" + mac_item_hex) # Handle leading zeros and double-0's
            mac_list.append(mac_item_hex)
        parsed_mac = (':'.join(mac_list)).upper() # Format MAC as 00:11:22:33:44:AA
        parsed_mac_oui = (''.join(mac_list[0:3])).upper() # MAC OUI as 001122
        return (parsed_mac,parsed_mac_oui)
    
    # MAC OUI formatted "001122"
    def mac_oui(
        self,
        mac_oui_num # type: int
        ):
        """
        Get MAC OUI (vendor,type) based on an OUI number formatted as '0011AA'
         
        Args:
            mac_oui_num (str): MAC OUI string eg 0011AA

        Returns:
            tuple: (Vendor, Type)
        """
        try:
            return (self.mac_oui[mac_oui_num]["Vendor"],self.mac_oui[mac_oui_num]["Type"])
        except NameError,KeyError:
            return False

### Generic ICMP Parsers ###
class icmp_parse(object):

    def __init__(self):

        # ICMP Types and corresponding Codes
        self.icmp_table = {
        0: {"Type":"Echo Reply","Codes": {0: "No Code"}}, 
        1: {"Type":"Unassigned"},
        2: {"Type":"Unassigned"},
        3: {
            "Type":"Destination Unreachable",
            "Codes": {
                0: "Net Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed and Don't Fragment was Set",
                5: "Source Route Failed",
                6: "Destination Network Unknown",
                7: "Destination Host Unknown",
                8: "Source Host Isolated",
                9: "Communication with Destination Network is Administratively Prohibited",
                10: "Communication with Destination Host is Administratively Prohibited",
                11: "Destination Network Unreachable for Type of Service",
                12: "Destination Host Unreachable for Type of Service",
                13: "Communication Administratively Prohibited ",
                14: "Host Precedence Violation",
                15: "Precedence cutoff in effect"
            }
        },
        4: {"Type":"Source Quench","Codes": {0: "No Code"}},
        5: {
            "Type":"Redirect",
            "Codes": {
                0: "Redirect Datagram for the Network",
                0: "Redirect Datagram for the Host",
                0: "Redirect Datagram for the Type of Service and Network",
                0: "Redirect Datagram for the Type of Service and Host"
            }
        },
        6: {
            "Type":"Alternate Host Address",
            "Codes": {
                0: "Alternate Address for Host"
            }
        }, 
        7: {"Type":"Unassigned"},
        8: {"Type":"Echo","Codes": {0: "No Code"}},
        9: {"Type":"Router Advertisement","Codes": {0: "No Code"}},
        10: {"Type":"Router Selection","Codes": {0: "No Code"}},
        11: {
            "Type":"Time Exceeded",
            "Codes": {
                0: "Time to Live exceeded in Transit",
                1: "Fragment Reassembly Time Exceeded"
            }
        }, 
        12: {
            "Type":"Parameter Problem",
            "Codes": {
                0: "Pointer indicates the error",
                1: "Missing a Required Option",
                2: "Bad Length"
            }
        },
        13: {"Type":"Timestamp","Codes": {0: "No Code"}},
        14: {"Type":"Timestamp Reply","Codes": {0: "No Code"}},
        15: {"Type":"Information Request","Codes": {0: "No Code"}},
        16: {"Type":"Information Reply","Codes": {0: "No Code"}},
        17: {"Type":"Address Mask Request","Codes": {0: "No Code"}},
        18: {"Type":"Address Mask Reply","Codes": {0: "No Code"}},
        19: {"Type":"Reserved"},
        20: {"Type":"Reserved"},
        21: {"Type":"Reserved"},
        22: {"Type":"Reserved"},
        23: {"Type":"Reserved"},
        24: {"Type":"Reserved"},
        25: {"Type":"Reserved"},
        26: {"Type":"Reserved"},
        27: {"Type":"Reserved"},
        28: {"Type":"Reserved"},
        29: {"Type":"Reserved"},
        30: {"Type":"Traceroute"},
        31: {"Type":"Datagram Conversion Error"},
        32: {"Type":"Mobile Host Redirect"},
        33: {"Type":"IPv6 Where-Are-You"},
        34: {"Type":"IPv6 I-Am-Here"},
        35: {"Type":"Mobile Registration Request"},
        36: {"Type":"Mobile Registration Reply"},
        37: {"Type":"Domain Name Request"},
        38: {"Type":"Domain Name Reply"},
        39: {"Type":"SKIP"},
        40: {"Type":"Photuris"}
        }

    # Parse human ICMP Type and Code from integers
    def icmp_human_type_code(
        self,
        icmp_reported # type: int
        ):
        """
        Parse ICMP integer to get the human ICMP Type and Code 

        Args:
            icmp_reported (int): Exported ICMP code [(256 * ICMP Type)+ICMP Code]

        Returns:
            tuple: (ICMP Type: str, ICMP Code: str)
        """
        icmp_num_type = icmp_reported//256 # ICMP Type
        icmp_num_code = icmp_reported%256 # ICMP Code

        try:
            icmp_parsed_type = self.icmp_table[icmp_num_type]["Type"]

            try:
                icmp_parsed_code = self.icmp_table[icmp_num_type]["Codes"][icmp_num_code]
            except (NameError,KeyError):
                icmp_parsed_code = "No Code"

            return (icmp_parsed_type,icmp_parsed_code) # Return human ICMP Type and Code
        
        # Failed to parse ICMP Type / Code, just return original Type and Code numbers
        except (NameError,KeyError):
            return (icmp_num_type,icmp_num_code)

    def icmp_num_type_code(
        self,
        icmp_reported # type: int
        ):
        """
        Parse ICMP integer to get the numeric ICMP Type and Code
        
        Args:
            icmp_reported (int): Exported ICMP code [(256 * ICMP Type)+ICMP Code]

        Returns:
            tuple: (ICMP Type: int, ICMP Code: int)
        
        """
        icmp_num_type = icmp_reported//256 # ICMP Type
        icmp_num_code = icmp_reported%256 # ICMP Code
        
        return (icmp_num_type,icmp_num_code)

### Generic HTTP Parsers ###
class http_parse(object):

    def __init__(self):
        return

    def http_code_category(
        self,
        http_code # type: int
        ):
        """
        Reconcile an HTTP code to it's overall category eg 404 - Client Error
        
        Args:
            http_code (int): HTTP code eg 405

        Returns:
            str: HTTP Code Category eg "Client Error"
        
        """
        if http_code in range(100,200):
            return "Informational"
        elif http_code in range(200,300):
            return "Success"
        elif http_code in range(300,400):
            return "Redirection"
        elif http_code in range(400,500):
            return "Client Error"
        elif http_code in range(500,600):
            return "Server Error"
        else:
            return "Other"
    
    def http_code_parsed(
        self,
        http_code # type: int
        ):
        """
        Parse HTTP codes to HTTP code names
        
        Args:
            http_code (int): HTTP code number eg "404"

        Returns:
            str: Parsed HTTP code eg "Not Found"
        
        """
        if http_code == 200:
            return "OK"
        elif http_code == 201:
            return "Created"
        elif http_code == 202:
            return "Accepted"
        elif http_code == 100:
            return "Continue"
        elif http_code == 101:
            return "Switching Protocols"
        elif http_code == 102:
            return "Processing"
        elif http_code == 203:
            return "Non-Authoritative Information"
        elif http_code == 204:
            return "No Content"
        elif http_code == 205:
            return "Reset Content"
        elif http_code == 206:
            return "Partial Content"
        elif http_code == 207:
            return "Multi-Status"
        elif http_code == 208:
            return "Already Reported"
        elif http_code == 226:
            return "IM Used"
        elif http_code == 300:
            return "Multiple Choices"
        elif http_code == 301:
            return "Moved Permanently"
        elif http_code == 302:
            return "Found"
        elif http_code == 303:
            return "See Other"
        elif http_code == 304:
            return "Not Modified"
        elif http_code == 305:
            return "Use Proxy"
        elif http_code == 306:
            return "Switch Proxy"
        elif http_code == 307:
            return "Temporary Redirect"
        elif http_code == 308:
            return "Permanent Redirect"
        elif http_code == 400:
            return "Bad Request"
        elif http_code == 401:
            return "Unauthorized"
        elif http_code == 402:
            return "Payment Required"
        elif http_code == 403:
            return "Forbidden"
        elif http_code == 404:
            return "Not Found"
        elif http_code == 405:
            return "Method Not Allowed"
        elif http_code == 406:
            return "Not Acceptable"
        elif http_code == 407:
            return "Proxy Authentication Required"
        elif http_code == 408:
            return "Request Time-Out"
        elif http_code == 409:
            return "Conflict"
        elif http_code == 410:
            return "Gone"
        elif http_code == 411:
            return "Length Required"
        elif http_code == 412:
            return "Precondition Failed"
        elif http_code == 413:
            return "Payload Too Large"
        elif http_code == 414:
            return "URI Too Long"
        elif http_code == 415:
            return "Unsupported Media Type"
        elif http_code == 416:
            return "Range Not Satisfiable"
        elif http_code == 417:
            return "Expectation Failed"
        elif http_code == 418:
            return "Teapot"
        elif http_code == 421:
            return "Misdirected Request"
        elif http_code == 422:
            return "Unprocessable Entity"
        elif http_code == 423:
            return "Locked"
        elif http_code == 424:
            return "Failed Dependency"
        elif http_code == 426:
            return "Upgrade Required"
        elif http_code == 428:
            return "Precondition Required"
        elif http_code == 429:
            return "Too Many Requests"
        elif http_code == 431:
            return "Request Header Fields Too Large"
        elif http_code == 451:
            return "Unavailable For Legal Reasons"
        elif http_code == 500:
            return "Internal Server Error"
        elif http_code == 501:
            return "Not Implemented"
        elif http_code == 502:
            return "Bad Gateway"
        elif http_code == 503:
            return "Service Unavailable"
        elif http_code == 504:
            return "Gateway Time-Out"
        elif http_code == 505:
            return "HTTP Version Not Supported"
        elif http_code == 506:
            return "Variant Also Negotiates"
        elif http_code == 507:
            return "Insufficient Storage"
        elif http_code == 508:
            return "Loop Detected"
        elif http_code == 510:
            return "Not Extended"
        elif http_code == 511:
            return "Network Authentication Required"
        else:
            return "Other"

### Netflow v5 parsers ###
class netflow_v5_parse(object):

    def __init__(self):
        return

    def header_parse(self, packet):
        packet_keys = [
            "netflow_version", 
            "flow_count",
            "sys_uptime",
            "unix_secs",
            "unix_nsecs",
            "flow_seq",
            "engine_type",
            "engine_id"]
        
        packet_values = unpack('!HHIIIIBB', packet[0:22])
        
        # v5 packet fields and values
        packet_contents = dict(zip(packet_keys, packet_values))

        # Timestamp for flow received
        now = datetime.datetime.utcnow()
        packet_contents["time"] = now

        logging.info("Packet header info: " + str(packet_contents))

        # Check the Netflow version
        if packet_contents["netflow_version"] == 5:
            return packet_contents
        else:
            logging.warning("Received a non-v5 Netflow packet - SKIPPING")
            return False
    
    def flow_parse(self, raw_flow_cache):
        global now
        parsed_flow_data = {
            "_index": str("flow-" + now.strftime("%Y-%m-%d")),
            "_type": "Flow",
            "_source": {
                "Flow Type": "Netflow v5",
                "IP Protocol Version": 4,
                "Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z"
                }
            }
        (
            ip_source,
            ip_destination,
            next_hop,
            parsed_flow_data["_source"]["Input Interface"],
            parsed_flow_data["_source"]["Output Interface"],
            parsed_flow_data["_source"]["Packets In"],
            parsed_flow_data["_source"]["Bytes In"],
            parsed_flow_data["_source"]["System Uptime Start"],
            parsed_flow_data["_source"]["System Uptime Stop"],
            parsed_flow_data["_source"]["Source Port"],
            parsed_flow_data["_source"]["Destination Port"],
            pad,
            parsed_flow_data["_source"]["TCP Flags"],
            parsed_flow_data["_source"]["Protocol Number"],
            parsed_flow_data["_source"]["Type of Service"],
            parsed_flow_data["_source"]["Source AS"],
            parsed_flow_data["_source"]["Destination AS"],
            parsed_flow_data["_source"]["Source Mask"],
            parsed_flow_data["_source"]["Destination Mask"]
        ) = unpack('!4s4s4shhIIIIHHcBBBhhBB', raw_flow_cache)

        # Get IPv4 addresses in dotted decimal format
        parsed_flow_data["_source"]["IPv4 Source"] = inet_ntoa(ip_source)
        parsed_flow_data["_source"]["IPv4 Destination"] = inet_ntoa(ip_destination)
        parsed_flow_data["_source"]["IPv4 Next Hop"] = inet_ntoa(next_hop)
        
        logging.debug("Current flow data: " + str(parsed_flow_data))
        return parsed_flow_data

    def flow_pool(self, raw_flow_cache):
        pool = ThreadPool()
        results = pool.map(self.flow_parse, raw_flow_cache)
        pool.close()
        pool.join()
        return results

### Netflow v9 Parsers ###
class netflowv9_parse(object):
    from struct import unpack
    from collections import OrderedDict
    from field_types import v9_fields
    #import logging
    
    def __init__(self):
        return

    # Parsing template flowset
    def template_flowset_parse(
        self,
        packed_data, # type: struct
        sensor, # type: str
        pointer, # type: int
        length # type: int
        ):
        """
        Unpacks a Netflow v9 template.
        
        Args:
            packed_data (struct): Packed data
            sensor (str): Netflow v9 sensor
            pointer (int): Current unpack location
            length (int): Length of data to unpack

        Returns:
            dict: {"Sensor": str, "Template ID": int, "Length": int, "Type": int, "Definitions": ordered dict}
        """
        cache = {}
        while pointer < length:
            (template_id, template_field_count) = self.unpack('!HH',packed_data[pointer:pointer+4])
            pointer += 4 # Advance the field
            
            #self.logging.info("Template number " + str(template_id) + ", field count " + str(template_field_count) + ", position " + str(pointer))

            hashed_id = hash(str(sensor)+str(template_id))
            cache[hashed_id] = {}
            cache[hashed_id]["Sensor"] = str(sensor)
            cache[hashed_id]["Template ID"] = template_id
            cache[hashed_id]["Length"] = template_field_count # Field count
            cache[hashed_id]["Type"] = "Flow Data"
            cache[hashed_id]["Definitions"] = self.OrderedDict()

            for _ in range(0,template_field_count): # Iterate through each line in the template
                (element, element_length) = self.unpack('!HH',packed_data[pointer:pointer+4])
                
                if element in self.v9_fields: # Fields we know about and support
                    cache[hashed_id]["Definitions"][element] = element_length
                
                else: # Proprietary or undocumented field
                    cache[hashed_id]["Definitions"][element] = 0
                    #self.logging.warning("Unsupported field " + str(element) + " in template ID " + str(template_id) + " from " + str(sensor))
                
                pointer += 4 # Advance the field

            #self.logging.debug(str(cache[hashed_id]))
            
        return cache

    # Parsing option template
    def option_template_parse(
        self,
        packed_data, # type: struct
        sensor, # type: str
        pointer # type: int
        ):	
        """
        Unpack a Netflow v9 option template
        
        Args:
            packed_data (struct): Packed data
            sensor (str): Netflow v9 sensor
            pointer (int): Current unpack location

        Returns:
            dict[Hashed ID]: {Sensor: str, Template ID: int, Type: str, Scope Fields: dict, Option Fields: dict}
        
        """
        (option_template_id,option_scope_length,option_length) = self.unpack('!HHH',packed_data[pointer:pointer+6])
        pointer += 6 # Move ahead 6 bytes
        
        cache = {}
        hashed_id = hash(str(sensor)+str(option_template_id)) # Hash for individual sensor and template ID
        cache[hashed_id] = {}
        cache[hashed_id]["Sensor"] = str(sensor)
        cache[hashed_id]["Template ID"] = option_template_id
        cache[hashed_id]["Type"] = "Options Template"
        cache[hashed_id]["Scope Fields"] = self.OrderedDict()
        cache[hashed_id]["Option Fields"] = self.OrderedDict()

        for x in range(pointer,pointer+option_scope_length,4):
            (scope_field_type,scope_field_length) = self.unpack('!HH',packed_data[x:x+4])
            cache[hashed_id]["Scope Fields"][scope_field_type] = scope_field_length
        
        pointer += option_scope_length

        for x in range(pointer,pointer+option_length,4):
            (option_field_type,option_field_length) = self.unpack('!HH',packed_data[x:x+4])
            cache[hashed_id]["Option Fields"][option_field_type] = option_field_length
        
        pointer += option_length
        return cache

### Protocol and Port Parsers ###
class ports_and_protocols(object):
    # Field types, defined ports, etc
    from defined_ports import registered_ports,other_ports
    from protocol_numbers import protocol_type

    def __init__(self):
        return

    # Tag "Traffic Category" by Protocol classification ("Routing", "ICMP", etc.)
    def protocol_traffic_category(
        self,
        protocol_number # type: int
        ):
        """
        Reconcile protocol numbers to a Category eg 89 to "Routing"
        
        Args:
            protocol_number (int): Traffic type eg 89 to "Routing"

        Returns:
            str: Traffic Category eg "Routing"
        
        """
        try:
            return self.protocol_type[protocol_number]["Category"]
        except (NameError,KeyError):
            return "Other"
    
    # Tag traffic by SRC and DST port
    def port_traffic_classifier(
        self,
        src_port, # type: int
        dst_port # type: int
        ):
        """
        Reconcile port numbers to services eg TCP/80 to HTTP, and services to categories eg HTTP to Web
        Args:
            src_port (int): Port number eg "443"
            dst_port (int): Port number eg "443"
        Returns:
            dict: ["Traffic":"HTTP","Traffic Category":"Web"], default value is "Other" for each.
        """
        for evaluated_port in [src_port,dst_port]:
            
            # Evaluate source and destination ports
            if evaluated_port in self.registered_ports:
                traffic = {}
                traffic["Traffic"] = self.registered_ports[evaluated_port]["Name"]

                if "Category" in self.registered_ports[evaluated_port]:
                    traffic["Traffic Category"] = self.registered_ports[evaluated_port]["Category"]
                else:
                    traffic["Traffic Category"] = "Other"
                break # Done parsing ports

            elif evaluated_port in self.other_ports:
                traffic = {}
                traffic["Traffic"] = self.other_ports[evaluated_port]["Name"]

                if "Category" in self.other_ports[evaluated_port]:
                    traffic["Traffic Category"] = self.other_ports[evaluated_port]["Category"]
                else:
                    traffic["Traffic Category"] = "Other"
                break # Done parsing ports

            else:
                pass

        try: # Set as "Other" if not already set
            traffic
        except (NameError,KeyError):
            traffic = {}
            traffic["Traffic"] = "Other"
            traffic["Traffic Category"] = "Other"            

        return traffic
