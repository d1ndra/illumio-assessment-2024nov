import csv
import argparse

from collections import defaultdict

proto_info = {'0': 'hopopt', '1': 'icmp', '2': 'igmp', '3': 'ggp', '4': 'ipv4', '5': 'st', '6': 'tcp', '7': 'cbt', '8': 'egp', '9': 'igp', '10': 'bbn-rcc-mon', '11': 'nvp-ii', '12': 'pup', '13': 'argus', '14': 'emcon', '15': 'xnet', '16': 'chaos', '17': 'udp', '18': 'mux', '19': 'dcn-meas', '20': 'hmp', '21': 'prm', '22': 'xns-idp', '23': 'trunk-1', '24': 'trunk-2', '25': 'leaf-1', '26': 'leaf-2', '27': 'rdp', '28': 'irtp', '29': 'iso-tp4', '30': 'netblt', '31': 'mfe-nsp', '32': 'merit-inp', '33': 'dccp', '34': '3pc', '35': 'idpr', '36': 'xtp', '37': 'ddp', '38': 'idpr-cmtp', '39': 'tp++', '40': 'il', '41': 'ipv6', '42': 'sdrp', '43': 'ipv6-route', '44': 'ipv6-frag', '45': 'idrp', '46': 'rsvp', '47': 'gre', '48': 'dsr', '49': 'bna', '50': 'esp', '51': 'ah', '52': 'i-nlsp', '53': 'swipe', '54': 'narp', '55': 'min-ipv4', '56': 'tlsp', '57': 'skip', '58': 'ipv6-icmp', '59': 'ipv6-nonxt', '60': 'ipv6-opts', '62': 'cftp', '64': 'sat-expak', '65': 'kryptolan', '66': 'rvd', '67': 'ippc', '69': 'sat-mon', '70': 'visa', '71': 'ipcv', '72': 'cpnx', '73': 'cphb', '74': 'wsn', '75': 'pvp', '76': 'br-sat-mon', '77': 'sun-nd', '78': 'wb-mon', '79': 'wb-expak', '80': 'iso-ip', '81': 'vmtp', '82': 'secure-vmtp', '83': 'vines', '84': 'iptm', '85': 'nsfnet-igp', '86': 'dgp', '87': 'tcf', '88': 'eigrp', '89': 'ospfigp', '90': 'sprite-rpc', '91': 'larp', '92': 'mtp', '93': 'ax.25', '94': 'ipip', '95': 'micp', '96': 'scc-sp', '97': 'etherip', '98': 'encap', '100': 'gmtp', '101': 'ifmp', '102': 'pnni', '103': 'pim', '104': 'aris', '105': 'scps', '106': 'qnx', '107': 'a/n', '108': 'ipcomp', '109': 'snp', '110': 'compaq-peer', '111': 'ipx-in-ip', '112': 'vrrp', '113': 'pgm', '115': 'l2tp', '116': 'ddx', '117': 'iatp', '118': 'stp', '119': 'srp', '120': 'uti', '121': 'smp', '122': 'sm', '123': 'ptp', '124': 'isis', '125': 'fire', '126': 'crtp', '127': 'crudp', '128': 'sscopmce', '129': 'iplt', '130': 'sps', '131': 'pipe', '132': 'sctp', '133': 'fc', '134': 'rsvp-e2e-ignore', '135': 'mobility', '136': 'udplite', '137': 'mpls-in-ip', '138': 'manet', '139': 'hip', '140': 'shim6', '141': 'wesp', '142': 'rohc', '143': 'ethernet', '144': 'aggfrag', '145': 'nsh', '146': 'homa', '255': 'reserved'}

def get_lookup_info(fname):
    with open(fname) as csvfile:
        csvreader = csv.reader(csvfile)
        lookup_info = {}
        for i,row_info in enumerate(csvreader):
            if not i or not row_info or len(row_info) < 3:
                continue
            dstport = row_info[0].strip()
            prot = row_info[1].strip()
            tag = row_info[2].strip()
            if dstport and prot and tag:
                lookup_info[dstport + ',' +prot] = tag.lower()
    return lookup_info

# 0: version
# 1: a/c id
# 2: interface_id
# 3: src addr
# 4: dst addr
# 5: srcport
# 6: dstport
# 7: protocol
# 8: packets
# 9: bytes transferred
# 10: start time
# 11: end time
# 12: accept/reject
# 13: log status

def process_line(logline, lookup_info, tag_count, port_proto_count):
    logline = logline.split()
    if len(logline) < 8:
        return
    version = logline[0].strip()
    if version != '2':
        return
    dst_port = logline[6].strip()
    protocol = proto_info.get(logline[7])
    if not version or not dst_port or not protocol:
        return
    port_proto = dst_port + ',' + protocol
    tag = lookup_info.get(port_proto)
    if not tag:
        tag = "Untagged"
    tag_count[tag] += 1
    port_proto_count[port_proto] += 1


def write_output(outputfile, tag_count, port_proto_count):
    with open(outputfile, 'w') as f_o:
        if tag_count:
            f_o.write("Tag Counts:\n")
            f_o.write("Tag,Count\n")
            for tag, count in tag_count.items():
                f_o.write("{},{}\n".format(tag, count))
        f_o.write('\n\n')
        if port_proto_count:
            f_o.write("Port/Protocol Combination Counts:\n")
            f_o.write("Port,Protocol,Count \n")
            for port_proto, count in port_proto_count.items():
                f_o.write("{},{}\n".format(port_proto, count))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-logfile')
    parser.add_argument('-lookupfile')
    parser.add_argument('-outputfile')

    args = parser.parse_args()
    logfile = args.logfile
    if not logfile:
        raise Exception("No logfile provided")
    lookup_file = args.lookupfile if args.lookupfile else 'lookup.csv'
    outputfile = args.outputfile if args.outputfile else 'output.txt'
    return logfile, lookup_file, outputfile


if __name__ == '__main__':

    logfile, lookup_file, outputfile = parse_args()

    lookup_info = get_lookup_info(lookup_file)
    tag_count = defaultdict(int)
    port_proto_count = defaultdict(int)

    with open(logfile) as f_logfile:
        for logline in f_logfile:
            process_line(logline, lookup_info, tag_count, port_proto_count)
    
    write_output(outputfile, tag_count, port_proto_count)
