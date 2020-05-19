
# coding: utf-8

# In[8]:


"""
BOTection - MultiClass Classifier
Created by balahmadi @balahmadi_OX

@author: balahmadi - 2020
"""

# 4. Multi-Class Classification (Family Classification Detection) to classify n-flows to a Malware Family
#   Train a RF multi-class classifier to classify n-flows to its malware family.


import pandas as pd
import numpy as np
import math
from sklearn.decomposition import PCA
import sklearn.metrics as metrics
from sklearn.model_selection import cross_val_predict
from sklearn.ensemble import RandomForestClassifier as RF
from sklearn.preprocessing import scale
import dill as pickle 
from sklearn.model_selection import train_test_split
import sys  
import os
import csv 

n_flows = [10,15,35,30,25,20,10]

for n in n_flows:
    
    with open("./Data/MM_StateTransition/dataset_" + str(n), "rb") as f:
        dataset = pickle.load(f)
   
    malDataset = dataset.loc[dataset.Class =='Malicious']
    malDataset.dropna(axis=1, how='any')  
    to_drop=["Family","Class"]
    
    y = malDataset['Family']
    X = malDataset.drop(to_drop, axis=1)
    col_names=malDataset.columns    
    X_train, X_test, y_train, y_test = train_test_split( X, y, test_size=0.33, random_state=42, stratify=y)
   
    X_train=X_train.as_matrix().astype(np.float)
    X_test=X_test.as_matrix().astype(np.float)
   
    # Binarize the output
    y_train = pd.factorize(y_train)
    y_test = pd.factorize(y_test)
   
    class_Names=y_test[1]
                               
    y_train = y_train[0]
    y_test = y_test[0]
    
    print ('-------------- Results: n = ' + str(n) + ' ---------------')

    
    print ('-------------- Precision - Recall - F1 Score Report ---------------')
    classifier = RF(n_estimators=101, max_features=None, class_weight ='balanced')
    model = classifier.fit(X_train,y_train)
    y_pred = model.predict(X_test)
    print (metrics.classification_report(y_test, y_pred, target_names = class_Names , digits=4))

    print ('-------------- Precision - Recall - F1 Score Report (Cross Validation) ---------------')
    # When applying cross-validation
    y_pred = cross_val_predict(RF(n_estimators=101, max_features=None, class_weight ='balanced'), X, y, cv=10)
    print (metrics.classification_report(y, y_pred, target_names =  class_Names , digits=4))

