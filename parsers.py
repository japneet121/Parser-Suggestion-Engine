import re
import json
import pandas as pd
from fuzzywuzzy import fuzz
import pickle
from fuzzywuzzy import process
import os

# Loading teh parsers
f=open('parsers','rb')
#print(type(f))
parsers=pickle.load(f)


def map_parsers(input_dict):
    poss_parsers={}
    poss_parsers_count={}
    threshhold=90
    for val in parsers.keys():
        poss_parsers[val]=set()
        
    for key in input_dict:
        for field in parsers:
            if key in parsers[field]:
                poss_parsers[field].add(key)
            else:
                for fac_keys in parsers[field]:
                    if fuzz.token_sort_ratio(fac_keys,key)>threshhold:
                        poss_parsers[field].add(key)
    poss_parsers_copy=poss_parsers.copy()
    for parser in poss_parsers:
        poss_parsers_count[parser]=len(poss_parsers[parser])
        if len(poss_parsers[parser])<1:
            
            del(poss_parsers_copy[parser])
            
    return (poss_parsers_copy,poss_parsers_count)


def get_parser_suggestions(input_dict):
    pars,pars_count=map_parsers(input_dict)
    pars_count=sorted(pars_count.items(), key=lambda item: item[1], reverse=True)
    i=0
    parsers=[]
    while((pars_count[i][1]/len(input_dict))>.45):
        parsers.append(pars_count[i][0])
        i+=1
    return parsers

def get_parser_suggestion_html(input_dict):
    parsers=get_parser_suggestions(input_dict)
    return ", ".join(parsers[:2])