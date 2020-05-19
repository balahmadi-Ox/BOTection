
# coding: utf-8

# In[ ]:


"""
BOTection - Network Flow Reassembly
Created by balahmadi @balahmadi_OX

@author: balahmadi - 2020
"""
#1. Network Flow Reassembly: Convert PCAPs to Bro/Zeek Logs 
#Prerequisites: Bro/Zeek installed

import os
directory = os.getcwd()

def ensure_dir(file_dir):
    if not os.path.exists(file_dir):
        try:
            print('Attempting to create directory in the path specified...')
            os.makedirs(file_dir)
            print("Directory created successfully...")
            return 1
        except:
            IOError
            print("Directory COULD NOT be created in the location specified.")
            sys.exit(0)
            return 0
    else:
        print("Directory specified already exists....moving on...")
    return 1


def generateLogs(pcap,dirr):
    ensure_dir(out + dirr + '/' + pcap)
    os.chdir(d)
    cmd = "export PATH=/usr/local/bro/bin:$PATH; bro -r " + pcap
    os.system(cmd)
    os.system("mv *.log " +  out + dirr + "/" + pcap )
    os.chdir(directory)

out = directory + '/Data/Processed/'
directories = ['Malicious','Benign','Mixed','Malicious_to_inject']
for dirr in directories:
    d =  directory + '/Data/PCAP/' + dirr
    for f in os.listdir(d):
        if f.endswith('.pcap'):
            generateLogs(f,dirr)

