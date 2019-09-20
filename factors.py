import re
import json
import pandas as pd
from fuzzywuzzy import fuzz
import pickle
from fuzzywuzzy import process
import os


#Loading teh factors from the previous parsers
f=open('factors','rb')
factor_map=pickle.load(f)


def create_factor_map():
    #Create a set from factor map
    for key in factor_map:
        try:
            factor_map[key].remove('')
        except:
            pass
        factor_map[key]= set(factor_map[key])
    return(factor_map)


###Function to map the keys with each other
def map_keys(input_dict):
    poss_factors={}
    threshhold=90
    for val in factor_map.keys():
        poss_factors[val]=set()
        
    for key in input_dict:
        for factor in factor_map:
            if key in factor_map[factor]:
                poss_factors[factor].add(key)
            else:
                for fac_keys in factor_map[factor]:
                    if fuzz.token_sort_ratio(fac_keys,key)>threshhold:
                        poss_factors[factor].add(key)
    poss_factors_copy=poss_factors.copy()
    for factors in poss_factors:
        if len(poss_factors[factors])<3:
            del(poss_factors_copy[factors])
            
    return poss_factors_copy
                
def get_factor_suggestion(input_dict):
    factor_map=create_factor_map()
    return map_keys(input_dict)


def get_factors_df(input_dict):
    facs=get_factor_suggestion(input_dict)
    max_len=0
    for key in facs:
        facs[key]=list(facs[key])
        if len(facs[key])>max_len:
            max_len=len(facs[key])
    for key in facs:
        if len(facs[key])<max_len:
            while(len(facs[key])<max_len):
                facs[key].append('')

    return(pd.DataFrame(facs))