#!/usr/bin/python3

import sys
from subprocess import PIPE, Popen

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
count = 0 
while True:
    cmd = 'tshark -r %s -z follow,tcp,ascii,%s' %(pcap_file,count)
    stream = cmdline(cmd)
    stream = stream.split('===================================================================\n')[1]
    stream += '\n -------------------- \n'
    if 'Node 0: :0' not in stream:
        output_file.write(stream)
    else:
        break
    count += 1

output_file.close()
