
# coding: utf-8

# In[ ]:


"""
BOTection - Connection State Extraction
Created by balahmadi @balahmadi_OX

@author: balahmadi - 2020
"""

#2. Connection State Extraction: Extract the features (e.g. conn_state}), 
# producing a key-value store of state transitions and their frequency.

import numpy as np
import pandas as pd
import dill as pickle
from collections import defaultdict
import csv  # imports the csv module
import sys  # imports the sys module
import os
import timeit
import random
import copy
DATAPATH_Mal = './Data/Processed/Malicious/'
DATAPATH_Benign = './Data/Processed/Benign/'
DATAPATH_Mixed = './Data/Processed/Mixed/'
DATAPATH_Injected = './Data/Processed/Malicious_to_inject/'
OUTPATH = '/Data/Features/'
DATAPATH = './Data/Processed/'

Directory = os.getcwd()


# In[ ]:


def validIP(address):  # Check if value is an ip address
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True


# In[ ]:


def readLogs_Mixed(fil,f_type ):
    
    n_flows = [10,15,20,25,30,35]
    cols = ['ts','uid','orig_h','id.orig_p','resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents']
    data = pd.read_csv(DATAPATH_Mixed + fil + '/conn.log' , sep = '\t', skiprows=8, names = cols)
    data.drop(data.tail(1).index,inplace=True) 
    newCol = data[['proto','service','conn_state']].apply(
             lambda x: '|'.join(map(str, x)), axis=1)
    data['state_proto_service'] = newCol
    
    unique_IPs = list(set(data['orig_h']))
    cleaned_unique_IPs = []
    for address in unique_IPs:
        if validIP(address):
            cleaned_unique_IPs.append(address)
    
    for ip in cleaned_unique_IPs:
        if ip in MalIP:
            result = data[(data.resp_h ==ip) | (data.orig_h ==ip)]
            for n in n_flows:
                dictmatrix_conn = defaultdict(lambda: defaultdict(float))
                dictmatrix_sig = defaultdict(lambda: defaultdict(float))
                
                list_df = [result[i:i+n] for i in range(0,result.shape[0],1)]
               
                count = 1
                for item in list_df:
                    conn = list(item['conn_state'])
                    sig = list(item['state_proto_service'])
                    if len(conn) ==n:
                        for ind1 in range(0,len(sig)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_sig.keys() and (sig[ind1],sig[ind2]) in dictmatrix_sig[count].keys():
                                dictmatrix_sig[count][(sig[ind1],sig[ind2])]=dictmatrix_sig[count][(sig[ind1],sig[ind2])] + 1
                            else:

                                dictmatrix_sig[count][(sig[ind1],sig[ind2])] = 1

                        for ind1 in range(0,len(conn)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_conn.keys() and (conn[ind1],conn[ind2]) in dictmatrix_conn[count].keys():
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])]=dictmatrix_conn[count][(conn[ind1],conn[ind2])] + 1
                            else:
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])] = 1
                    
                        count = count + 1
                if dictmatrix_conn:
                    ensure_dir('./Data/Features/Mixed/Malicious/conn_state/'+ str(n) + '/'  + fil + '/' + ip + '/')
                    ensure_dir('./Data/Features/Mixed/Malicious/state_proto_service/' + str(n) + '/' + fil + '/' + ip + '/' )

                    with open('./Data/Features/Mixed/Malicious/conn_state/' + str(n) + '/' + fil + '/'+ ip + '/' + ip +'.pickle', 'a') as handle:
                         pickle.dump(dictmatrix_conn, handle, protocol=pickle.HIGHEST_PROTOCOL)

                    with open('./Data/Features/Mixed/Malicious/state_proto_service/' + str(n) + '/' + fil + '/'  +ip + '/'+ ip +'.pickle', 'a') as handle:
                         pickle.dump(dictmatrix_sig, handle, protocol=pickle.HIGHEST_PROTOCOL)  
    
        else:
            results = data[(data.resp_h ==ip) | (data.orig_h ==ip)]
            for n in n_flows:
                dictmatrix_conn = defaultdict(lambda: defaultdict(float))
                dictmatrix_sig = defaultdict(lambda: defaultdict(float))

                list_df = [results[i:i+n] for i in range(0,results.shape[0],1)]
                count = 1
                for item in list_df:
                    conn = list(item['conn_state'])
                    sig = list(item['state_proto_service'])
                    if len(conn) ==n:
                        for ind1 in range(0,len(sig)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_sig.keys() and (sig[ind1],sig[ind2]) in dictmatrix_sig[count].keys():
                                dictmatrix_sig[count][(sig[ind1],sig[ind2])]=dictmatrix_sig[count][(sig[ind1],sig[ind2])] + 1
                            else:
                                dictmatrix_sig[count][(sig[ind1],sig[ind2])] = 1

                        for ind1 in range(0,len(conn)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_conn.keys() and (conn[ind1],conn[ind2]) in dictmatrix_conn[count].keys():
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])]=dictmatrix_conn[count][(conn[ind1],conn[ind2])] + 1
                            else:
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])] = 1
                        count = count + 1
                
                if dictmatrix_conn:
                    ensure_dir('./Data/Features/Mixed/Benign/conn_state/'   + str(n) + '/' + fil + '/')
                    ensure_dir('./Data/Features/Mixed/Benign/state_proto_service/'   + str(n) + '/' + fil + '/' )    
                    with open('./Data/Features/Mixed/Benign/conn_state/'  + str(n) + '/'+ fil + '/'+ ip +'.pickle', 'a') as handle:
                         pickle.dump(dictmatrix_conn, handle, protocol=pickle.HIGHEST_PROTOCOL)

                    with open('./Data/Features/Mixed/Benign/state_proto_service/'  +str(n) + '/'+ fil + '/'+ ip +'.pickle', 'a') as handle:
                         pickle.dump(dictmatrix_sig, handle, protocol=pickle.HIGHEST_PROTOCOL) 


# In[49]:


def readLogs(fil,f_type ):
    
    n_flows = [10,15,20,25,30,35]
    
    cols = ['ts','uid','orig_h','id.orig_p','resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents']
    data = pd.read_csv(DATAPATH + "/" +f_type +"/" + fil + '/conn.log' , sep = '\t', skiprows=8, names = cols)
    data.drop(data.tail(1).index,inplace=True) 

    newCol = data[['proto','service','conn_state']].apply(
             lambda x: '|'.join(map(str, x)), axis=1)
    data['state_proto_service'] = newCol
    
    unique_IPs = list(set(data['orig_h']))
    cleaned_unique_IPs = []
    for address in unique_IPs:
        if validIP(address):
            cleaned_unique_IPs.append(address)

    if f_type == 'Malicious':
        for ip in cleaned_unique_IPs:
            result = data[(data.resp_h ==ip) | (data.orig_h ==ip)]
            for n in n_flows:
                dictmatrix_conn = defaultdict(lambda: defaultdict(float))
                dictmatrix_sig = defaultdict(lambda: defaultdict(float))

                
                list_df = [result[i:i+n] for i in range(0,result.shape[0],1)]
                count = 1
                for item in list_df:
                    conn = list(item['conn_state'])
                    sig = list(item['state_proto_service'])
                   
                    if len(conn) ==n:
                        
                        for ind1 in range(0,len(sig)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_sig.keys() and (sig[ind1],sig[ind2]) in dictmatrix_sig[count].keys():
                                dictmatrix_sig[count][(sig[ind1],sig[ind2])]=dictmatrix_sig[count][(sig[ind1],sig[ind2])] + 1
                            else:

                                dictmatrix_sig[count][(sig[ind1],sig[ind2])] = 1

                        for ind1 in range(0,len(conn)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_conn.keys() and (conn[ind1],conn[ind2]) in dictmatrix_conn[count].keys():
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])]=dictmatrix_conn[count][(conn[ind1],conn[ind2])] + 1
                            else:
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])] = 1

                        count = count + 1
                if dictmatrix_conn:
                    ensure_dir('./Data/Features/Malicious/conn_state/'   + str(n) + '/' + fil + '/' + ip + '/')
                    ensure_dir('./Data/Features/Malicious/state_proto_service/'  + str(n) + '/'  + fil + '/' + ip + '/')
                
                    with open('./Data/Features/Malicious/conn_state/'  + str(n) + '/' + fil +  '/'+ ip + '/' + ip +'.pickle', 'a') as handle:
                        pickle.dump(dictmatrix_conn, handle, protocol=pickle.HIGHEST_PROTOCOL)

                    with open('./Data/Features/Malicious/state_proto_service/'  + str(n) + '/' + fil +  '/' +ip + '/'+ ip +'.pickle', 'a') as handle:
                        pickle.dump(dictmatrix_sig, handle, protocol=pickle.HIGHEST_PROTOCOL)  
    
    else:
        print(fil)
        print(cleaned_unique_IPs)
        for ip in cleaned_unique_IPs:
            
            result = data[(data.resp_h ==ip) | (data.orig_h ==ip)]
     
            for n in n_flows:
                dictmatrix_conn = defaultdict(lambda: defaultdict(float))
                dictmatrix_sig = defaultdict(lambda: defaultdict(float))

                list_df = [result[i:i+n] for i in range(0,result.shape[0],1)]
                count = 1              
                for item in list_df:
                    conn = list(item['conn_state'])
                    sig = list(item['state_proto_service'])
                    
                    if len(conn) ==n:
                        
                        for ind1 in range(0,len(sig)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_sig.keys() and (sig[ind1],sig[ind2]) in dictmatrix_sig[count].keys():
                                dictmatrix_sig[count][(sig[ind1],sig[ind2])]=dictmatrix_sig[count][(sig[ind1],sig[ind2])] + 1
                            else:
                                dictmatrix_sig[count][(sig[ind1],sig[ind2])] = 1

                        for ind1 in range(0,len(conn)-1):
                            ind2 = ind1 + 1
                            if count in dictmatrix_conn.keys() and (conn[ind1],conn[ind2]) in dictmatrix_conn[count].keys():
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])]=dictmatrix_conn[count][(conn[ind1],conn[ind2])] + 1
                            else:
                                dictmatrix_conn[count][(conn[ind1],conn[ind2])] = 1
                    
                        count = count + 1
                         
                if dictmatrix_conn: 

                    ensure_dir('./Data/Features/Benign/conn_state/'  + str(n) + '/' + fil + '/' )
                    ensure_dir('./Data/Features/Benign/state_proto_service/' + str(n) + '/'  + fil + '/' )
                    with open('./Data/Features/Benign/conn_state/'  + str(n) + '/'+ fil + '/'+ ip +'.pickle', 'a') as handle:
                        pickle.dump(dictmatrix_conn, handle, protocol=pickle.HIGHEST_PROTOCOL)

                    with open('./Data/Features/Benign/state_proto_service/'  +str(n) + '/'+ fil + '/'+ ip +'.pickle', 'a') as handle:
                        pickle.dump(dictmatrix_sig, handle, protocol=pickle.HIGHEST_PROTOCOL)  

def ensure_dir(file_dir):
    if not os.path.exists(file_dir):
        try:
            print('Attempting to create directory in the path specified...')
            os.makedirs(file_dir)
            #print("Directory created successfully...")
            return 1
        except:
            IOError
            #print("Directory COULD NOT be created in the location specified.")
            sys.exit(0)
            return 0
   
    return 1


# In[5]:


def readLogs_inject(fil):
    n= 15
    injected_k = [1,2,3,4,5,6,7,8,9,10,11,12,13,14]
    cols = ['ts','uid','orig_h','id.orig_p','resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents']
    data = pd.read_csv(DATAPATH_Injected + "/" +"/" + fil + '/conn.log', sep = '\t', skiprows=8, names = cols)
    data.drop(data.tail(1).index,inplace=True) 
    newCol = data[['proto','service','conn_state']].apply(
             lambda x: '|'.join(map(str, x)), axis=1)
    data['signature'] = newCol
    
    unique_IPs = list(set(data['orig_h']))
    cleaned_unique_IPs = []
    for address in unique_IPs:
        if validIP(address):
            cleaned_unique_IPs.append(address)
    
    for k in injected_k:     
        for ip in cleaned_unique_IPs:
            states = ['S0','SF','RSTOS0','RSTRH','SH','SHR','OTH']
            
            result = data[(data.resp_h ==ip) | (data.orig_h ==ip)]

            dictmatrix_conn = defaultdict(lambda: defaultdict(float))
            dictmatrix_sig = defaultdict(lambda: defaultdict(float))
            dictmatrix_history = defaultdict(lambda: defaultdict(float))
            
            list_df = [result[i:i+n+1] for i in range(0,result.shape[0],1)]
            count = 1
            for item in list_df:
                conn = list(item['conn_state'])
                
                if len(conn) == n:
                   
                    visited = []
                    indices = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14]
                    for i in range(0,k):
                        ri = random.choice(indices)
                        if ri not in visited:
                            visited.append(ri)
                            indices.remove(ri)
                            temp_states = copy.copy(states)
                            s_i = conn[ri]
                            if s_i in temp_states:
                                temp_states.remove(s_i)
                            rs = random.choice(temp_states)
                            conn.insert(ri,rs)
                    conn = conn[0:n]

                for ind1 in range(0,len(conn)-1):
                    ind2 = ind1 + 1
                    if count in dictmatrix_conn.keys() and (conn[ind1],conn[ind2]) in dictmatrix_conn[count].keys():
                        dictmatrix_conn[count][(conn[ind1],conn[ind2])]=dictmatrix_conn[count][(conn[ind1],conn[ind2])] + 1
                    else:
                        dictmatrix_conn[count][(conn[ind1],conn[ind2])] = 1
                count = count + 1
            ensure_dir('./Data/Features/Malicious_to_inject/Malicious/conn_state/' + str(k) + '/')
            with open('./Data/Features/Malicious_to_inject/Malicious/conn_state/' + str(k) + '/'+ ip +'.pickle', 'a') as handle:
                 pickle.dump(dictmatrix_conn, handle, protocol=pickle.HIGHEST_PROTOCOL)




# In[53]:


for f in os.listdir(DATAPATH_Benign):
    if not os.path.exists(Directory + OUTPATH + "/Benign/" +f) and f.endswith('.pcap'):
        if 'conn.log' in os.listdir(DATAPATH + "/Benign/" + f ):
            readLogs(f, 'Benign')
print('Done Encoding Benign files')

for f in os.listdir(DATAPATH_Mal):
    if not os.path.exists(Directory + OUTPATH + "/Malicious/" + f) and f.endswith('.pcap'):
        readLogs(f, 'Malicious')
print('Done Encoding Malicious files')

MalIP = []
BenignIPs = []
for f in os.listdir(DATAPATH_Mixed):
    if not os.path.exists(Directory + OUTPATH + "/Mixed/" + f) and f.endswith('.pcap'):
        readLogs_Mixed(f, 'Mixed')
print('Done Encoding Mixed (malicious, benign) files')

for f in os.listdir(DATAPATH_Injected):
    if not os.path.exists(Directory + OUTPATH + "/Malicious_to_inject/" + f) and f.endswith('.pcap'):
        readLogs_inject(f)
print('Done Encoding Malicious injected with Benign States')

