from copy import deepcopy
import sys
from datetime import datetime
import time
import dns.name
import dns.message
import dns.query
import dns.flags
import dns
import dns.resolver


# This is my custom time class to keep track of time in a light weight way
class TimeStamps:
    def __init__(self, hour = 0, min = 0, sec = 0):
        self.hour = hour
        self.min = min
        self.sec = sec

    def print_time(self):
        line = str(self.hour) + ":" + str(self.min) + ":" + str(self.sec)
        print(line)

    def to_seconds(self):
        return (self.hour * 3600) + (self.min * 60) + self.sec

    def get_time(self):
        line = str(self.hour) + ":" + str(self.min) + ":" + str(self.sec)
        return line


# Will return the most current serial number from a SOA record
# The server_root argument is synomous with the @ command of dig
# An exception will be thrown if an unexpected result occurs
# NOTE: update to your local (or the node's) resolver ip
def get_serial(target, server_root):

    #name_server = '8.8.8.8' aka server_root # @ part of dig
    # target = "."
    server_root = "192.168.25.253" # NOTE: update to your local (or the node's) resolver ip
    ADDITIONAL_RDCLASS = 65535

    domain = dns.name.from_text(target)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    request = dns.message.make_query(domain, dns.rdatatype.SOA) # use_edns = 0? for below code
    request.use_edns(options=[dns.edns.GenericOption(dns.edns.NSID, b'')]) # seems to work...

    try:
        # response = dns.query.udp(request, server_root, timeout=2.0) # timeout 2 seconds, throws timeout exception (try around it), .4
        response = dns.query.udp(request, server_root, timeout=2.0)
        nsid = "BLANK"
        for opt in response.options:
            if opt.otype == dns.edns.NSID:
                nsid = opt.data
                nsid = nsid.decode("utf-8") + " nsid"
                # print(nsid) # got em


        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                # print("SERIAL", int(rrset[0].serial)) # got em
                return int(rrset[0].serial), nsid
            # if rrset.rdtype == dns.rdatatype.SOA and rrset.name == dns.name.root: # makes sure its the root that owns the record
            
    except Exception as e:
        print("[Domain Analyzer][Error] %s" % e)
        return -1, -1


def main(argv):
    gap_time = 10

    # hit the other addresses
    roots = [("verisign(a)-v4", "198.41.0.4"),
            ("USC-v4", "199.9.14.201"),
            ("CogentCom-v4", "192.33.4.12"),
            ("UM-v4", "199.7.91.13"),
            ("NASA-v4", "192.203.230.10"),
            ("ISC-v4", "192.5.5.241"),
            ("US_DD(NIC)-v4", "192.112.36.4"),
            ("Army-v4", "198.97.190.53"),
            ("Netnod-v4", "192.36.148.17"),
            ("verisign(j)-v4", "192.58.128.30"),
            ("RIPE-v4", "193.0.14.129"),
            ("ICANN-v4", "199.7.83.42"),
            ("WIDE-v4", "202.12.27.33"), 
            ("verisign(a)-v6", "2001:503:ba3e::2:30"),
            ("USC-v6", "2001:500:200::b"),
            ("CogentCom-v6", "2001:500:2::c"),
            ("UM-v6", "2001:500:2d::d"),
            ("NASA-v6", "2001:500:a8::e"),
            ("ISC-v6", "2001:500:2f::f"),
            ("US_DD(NIC)-v6", "2001:500:12::d0d"),
            ("Army-v6", "2001:500:1::53"),
            ("Netnod-v6", "2001:7fe::53"),
            ("verisign(j)-v6", "2001:503:c27::2:30"),
            ("RIPE-v6", "2001:7fd::1"),
            ("ICANN-v6", "2001:500:9f::42"),
            ("WIDE-v6", "2001:dc3::35")]

    iter = 0

    serial_map = {}
    nsid_map = {}
    
    flagger = 1
    while flagger:
        iter += 1
        target_address = "example.com_byu_imaal_lab" + str(iter)

        for s in roots:
            previous_serial, nsid = get_serial(target_address, s[1])
            serial_map[s[0]] =  previous_serial
            nsid_map[s[0]] = (previous_serial, nsid)

        print(serial_map.values())

        first = list(serial_map.values())[0]
        trip_wire = 0
        for a in serial_map.values():
            if a != first and a != -1: # bug-> -1 throws everything off
                trip_wire = 1

        old_serials = deepcopy(serial_map)
        # print(trip_wire)
        if trip_wire:
            time.sleep(60)
            trip_wire = 0

            for s in roots:
                previous_serial, nsid = get_serial(target_address, s[1])
                serial_map[s[0]] =  previous_serial
                nsid_map[s[0]] = (previous_serial, nsid)

                if serial_map[s[0]] == old_serials[s[0]] and serial_map[s[0]]:
                    if serial_map[s[0]] != -1:
                        with open("origin_results.txt", 'a') as the_file:
                            first = s[0] + " TIMEOUT " + str(serial_map[s[0]]) + "\n"
                            the_file.write(first)
                    else:
                        with open("origin_results.txt", 'a') as the_file:
                            first = s[0] + " NO update " + str(serial_map[s[0]]) + "\n"
                            the_file.write(first)
                else:
                    with open("origin_results.txt", 'a') as the_file:
                        first = s[0] + " updated " + str(serial_map[s[0]]) + "\n"
                        the_file.write(first)


if __name__ == "__main__":
    main(sys.argv[1:])