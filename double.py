from pydoc import resolve
import sys
from datetime import datetime
import time
import dns.name
import dns.message
import dns.query
import dns.flags
import dns
import dns.resolver
import subprocess


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


def createTimeStamp():
    x = datetime.now().time()

    hour = x.strftime("%H")
    minute = x.strftime("%M")
    second = x.strftime("%S")

    result = TimeStamps(int(hour), int(minute), int(second))

    return result


def checkIfTime(time_a, time_b, flex_max, flex_min):
    delta = deltaTimeStamp(time_a, time_b)
    #print(delta)
    if delta >= flex_min and delta <= flex_max:
        #print("hit")
        return True
    else:
        return False


def negCheckIfTime(time_a, time_b, flex_min):
    delta = deltaTimeStamp(time_a, time_b)
    if delta <= flex_min:
        # print("hit (neg)")
        return True
    else:
        return False


def next_target(time_list, current_time):
    # print(time_list)
    times = []
    for i in time_list:
        x = str(i)
        x = x.strip()
        #print(x)
        result = x.split(":")
        final = TimeStamps(int(result[0]), int(result[1]), float(result[2]))

        times.append(final)

    # current_time.print_time()
    time_till = []
    for t in times:
        delta = deltaTimeStamp(current_time, t)
        # t.print_time()
        # print(delta, "!!!")
        time_till.append(delta)

    smallest = 99999999999999
    iter = -1
    small_iter = -1
    all_neg_flag = 1
    for t in time_till:
        iter += 1
        # print(iter)
        if t >= 0:
            all_neg_flag = 0
            if t < smallest:
                smallest = t
                small_iter = iter

    # if all the times are before the current time 
    if all_neg_flag:
        iter = -1
        for t in time_till:
            iter += 1
            if t < smallest:
                smallest = t
                small_iter = iter


    # print(small_iter, smallest, time_till[small_iter])
    #times[small_iter].print_time()
    return times[small_iter]


# current, target to get time till
def deltaTimeStamp(time_a, time_b):
    total_a_seconds = time_a.to_seconds()
    total_b_seconds = time_b.to_seconds()

    # z = y - x
    return total_b_seconds - total_a_seconds


def get_serial(target, server_root):

    #name_server = '8.8.8.8' aka server_root # @ part of dig
    # target = "."
    server_root = "192.168.86.1"
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


def measure(root_name, target_address, server_root, serial_map, nsid_map):
    file_name = str(root_name) + ".txt"
    previous_serial = serial_map[root_name]
    current_serial, nsid = get_serial(target_address, server_root)
    if current_serial != previous_serial or current_serial == -1:
        # print(iter)
        if current_serial == -1:
            with open(file_name, 'a') as the_file:
                first = str(datetime.now().time()) + " TIMED OUT" + " " + nsid + "\n"
                the_file.write(first)
            
        else:
            # print(file_name)
            with open(file_name, 'a') as the_file:
                first = str(datetime.now().time()) + " " + str(current_serial) + " " + nsid + "\n"
                the_file.write(first)
            
            serial_map[root_name] = current_serial
            nsid_map[root_name] = (nsid, current_serial)

    
def good_time(current, target):
    current_hour = current.hour
    target_hour = target.hour

    if current_hour < target_hour:
        return True
    elif target_hour == 0 and current_hour == 23:
        return True
    else:
        return False
    

def switch_resolver(resolver):
    if resolver == "BIND":
        reso = subprocess.Popen(["sh", "start_bind.sh"])
    else:
        reso = subprocess.Popen(["sh", "start_unbound.sh"])


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
    
    # init
    for s in roots:
        previous_serial, nsid = get_serial(target_address, s[1])
        serial_map[s[0]] =  previous_serial

    old_serials = serial_map


    flagger = 1
    while flagger:
        resolver_flag = "BIND"
        switch_resolver(resolver_flag)

        iter += 1
        target_address = "example.com_byu_imaal_lab" + str(iter)

        for s in roots:
            previous_serial, nsid = get_serial(target_address, s[1])
            serial_map[s[0]] = previous_serial
            nsid_map[s[0]] = (previous_serial, nsid)

        
        for s in roots:
            if serial_map[s[0]] != old_serials[s[0]] and serial_map[s[0]] != -1 and old_serials[s[0]] != -1:
                # at this point we know a serial has updated
                # we can send another unique bad request and see what the serial is
                # if the serial is different and not -1, then report incomplete update
                # else report complete update
                iter += 1
                target_address = "example.com_byu_imaal_lab" + str(iter)
                new_serial, nsid = get_serial(target_address, s[1])

                if new_serial != -1 and new_serial != serial_map[s[0]]:
                    with open("double_results_bind.txt", 'a') as the_file:
                        first = s[0] + " INCOMPLETE update " + str(serial_map[s[0]])
                        the_file.write(first)

                else:
                    with open("double_results_bind.txt", 'a') as the_file:
                        first = s[0] + " COMPLETE update " + str(serial_map[s[0]])
                        the_file.write(first)


        # this is where we can call our scripts to test and then switch
        resolver_flag = "UNBOUND"
        switch_resolver(resolver_flag)

        for s in roots:
            if serial_map[s[0]] != old_serials[s[0]] and serial_map[s[0]] != -1 and old_serials[s[0]] != -1:
                # at this point we know a serial has updated
                # we can send another unique bad request and see what the serial is
                # if the serial is different and not -1, then report incomplete update
                # else report complete update
                iter += 1
                target_address = "example.com_byu_imaal_lab" + str(iter)
                new_serial, nsid = get_serial(target_address, s[1])

                if new_serial != -1 and new_serial != serial_map[s[0]]:
                    with open("double_results_unbound.txt", 'a') as the_file:
                        first = s[0] + " INCOMPLETE update " + str(serial_map[s[0]])
                        the_file.write(first)

                else:
                    with open("double_results_unbound.txt", 'a') as the_file:
                        first = s[0] + " COMPLETE update " + str(serial_map[s[0]])
                        the_file.write(first)



        old_serials = serial_map
        time.sleep(gap_time)

if __name__ == "__main__":
    main(sys.argv[1:])