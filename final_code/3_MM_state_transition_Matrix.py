
# coding: utf-8

# In[ ]:


"""
BOTection - Markov Chain Modelling
Created by balahmadi @balahmadi_OX

@author: balahmadi - 2020
"""

#3. Markov Chain Modelling:
# Use the state transition frequency (obtained as output from Encoding.py) to build Markov Chain models and produce a feature vector for each sub-log. 

import os
from collections import defaultdict
import dill as pickle
import pandas as pd
import csv

def Markov_chain_modelling(n):
    frames2 = []
    frames3 = []
    frames = []
    fls = ['Malicious','Benign']
    for ff in fls:
        if ff == 'Malicious':
            for sample in os.listdir('./Data/Features/Malicious/' + typ + "/" + str(n)):
                if sample != '.DS_Store':
                    for ip in os.listdir('./Data/Features/Malicious/' + typ + "/" + str(n) +'/' + sample):
                        countdict = defaultdict(int) 
                        if ip != '.DS_Store':
                            with open('./Data/Features/Malicious/' + typ + "/" + str(n) +'/' + sample +'/' + ip + '/' + ip + '.pickle','rb') as f:
                                dic = pickle.load(f)

                            df = pd.DataFrame.from_dict(dic, orient='index')
                            if len(df.index) > 0:
                                state_1 = list(df.columns.get_level_values(0))
                                state_2 = list(df.columns.get_level_values(1))

                                for i in state_1:
                                    temp = df.iloc[:, df.columns.get_level_values(0)==i]
                                    temp["sum"] = temp.sum(axis=1)
                                    df['sum']= temp['sum']
                                    df.loc[:, df.columns.get_level_values(0)==i] = df.iloc[:, df.columns.get_level_values(0)==i].div(df['sum'], axis = 0)

                                mx = df.copy()

                                mx['Flows'] = mx.index
                                mx['filename'] = [sample] * len(mx)
                                if sample in family:
                                    mx['Family'] = [family[sample]] * len(mx)
                                else:
                                    mx['Family'] = ['Missing'] * len(mx)
                                mx['Class'] = [ff] * len(mx)

                                mx = mx.set_index(['Family','Flows','Class'], append=True)
                                mx.fillna(0, inplace = True)
                                frames.append(mx)
                           
        else:
             for sample in os.listdir('./Data/Features/Benign/' + typ + "/" + str(n)):
                if sample != '.DS_Store':
                    for ip in os.listdir('./Data/Features/Benign/' + typ + "/" + str(n) +'/' + sample):
                       
                        countdict = defaultdict(int) 
                
                        with open('./Data/Features/Benign/' + typ + "/" + str(n) +'/' + sample +'/' + ip ,'rb') as f:
                            dic = pickle.load(f)
                        

                        df = pd.DataFrame.from_dict(dic, orient='index')
                        
                        if len(df.index) > 0:
                            
                            state_1 = list(df.columns.get_level_values(0))
                            state_2 = list(df.columns.get_level_values(1))

                            for i in state_1:
                                temp = df.iloc[:, df.columns.get_level_values(0)==i]
                                temp["sum"] = temp.sum(axis=1)
                                df['sum']= temp['sum']
                                df.loc[:, df.columns.get_level_values(0)==i] = df.iloc[:, df.columns.get_level_values(0)==i].div(df['sum'], axis = 0)

                            mx = df.copy()

                            mx['Flows'] = mx.index
                            mx['filename'] = [sample] * len(mx)
                            mx['Family'] = [sample] * len(mx)
                            mx['Class'] = [ff] * len(mx)

                            mx = mx.set_index(['Family','Flows','Class'], append=True)
                            mx.fillna(0, inplace = True)

                            if not mx.empty:
                                frames2.append(mx)

            
            
    mx_bot = pd.concat(frames)
    mx_bot = mx_bot.reset_index()
    mx_bot.fillna(0, inplace = True)
    
    mx_b = pd.concat(frames2)
    mx_b = mx_b.reset_index()
    mx_b.fillna(0, inplace = True)
   
   
    frames3.append(mx_b)
    frames3.append(mx_bot)
    mx = pd.concat(frames3)
    mx.fillna(0, inplace = True)
    mx.reset_index()
    
    return mx

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


n_flows = [10,15,20,25,30,35]
typ = "conn_state" #or state_proto_service

family = {}
with open('./Data/families.csv') as files:
    reader = csv.reader(files)
    for row in reader:
        family[row[0]] = row[1]
        
        
for n in n_flows:
    MM_mx = Markov_chain_modelling (n)
    to_drop=["level_0","sum"]
    MM_mx.drop(to_drop, axis=1, inplace = True)
    ensure_dir("./Data/MM_StateTransition/")

    with open("./Data/MM_StateTransition/dataset_" + str(n), "wb") as dill_file:
        pickle.dump(MM_mx, dill_file)

