#!/usr/bin/python3

import sys
from subprocess import PIPE, Popen
import re

def cmdline(command):
    process = Popen(
            args=command,
            stdout=PIPE,
            shell=True,
            universal_newlines=True
        )
    return process.communicate()[0]

pcap_file = sys.argv[1]
output_file_name = pcap_file.split('.')[0]+'_streams.txt'
output_file = open(output_file_name,'w')
 

cmd = 'tshark -r %s -qz conv,tcp' % pcap_file
summary = cmdline(cmd)

lines = summary.split('\n')[5:-1]

src_ips = []
src_ports = []
dst_ips = []
dst_ports = []
for line in lines:
        columns = line.split()
        src_ip, src_port = columns[0].split(':')
        dst_ip, dst_port = columns[1].split(':')

        src_ips.append(src_ip)
        src_ports.append(src_port)
        dst_ips.append(dst_ip)
        dst_ports.append(dst_port)

for src_ip, src_port, dst_ip, dst_port in zip(src_ips, src_ports, dst_ips, dst_ports):
    filter = 'ip.src == %s and tcp.srcport == %s and ip.dst == %s and tcp.dstport == %s' % (src_ip, src_port, dst_ip, dst_port)

    cmd = 'tshark -r %s -Y "%s"' % (pcap_file, filter)
    output = cmdline(cmd)

    pattern = r'\d+\s+\d+\.\d+\s+.*\n'
    stream = ''.join(re.findall(pattern, output))

    output_file.write(stream)

output_file.close()
