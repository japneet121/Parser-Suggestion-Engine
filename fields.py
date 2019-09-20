import re
import json
import pandas as pd
from fuzzywuzzy import fuzz
import pickle
from fuzzywuzzy import process
import os

#Load the fields from the old parsers
f=open('/Users/japneet/git/parser_gatekeeper/fields','rb')
field_map=pickle.load(f)

#Load the factor map file from the old parsers
f=open('factors','rb')
factor_map=pickle.load(f)


#Load the regex map regex map
f=open('field_map_regex','rb')
field_map_regex=pickle.load(f)



field_mapping={
    "reg_ipv4":"IP Address",
    "reg_ipv6":"IP Address",
    "reg_url":"URL",
    "reg_mac":"MAC",
    "reg_email":"User",
    "reg_win_file_path":"FilePath",
    "reg_lin_filepath":"FilePath"
    
}
'''
Function returning the suggestions on teh basis on field values regexes
'''
def getSuggestionsFromValues(input_dict):
    suggestions=[]
    IPV6 = "((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?"
    IPV4 = "(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])"
    IP = "(?:"+IPV6+"|"+IPV4+"})"
    CISCOMAC = "(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})"
    WINDOWSMAC = "(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})"
    COMMONMAC = "(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})"
    BADMAC = "(?:(?:[A-Fa-f0-9]:){5}[A-Fa-f0-9])"
    HOSTNAME = "(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)"
    IPORHOST = "(?:"+HOSTNAME+"|"+IP+")"
    URL="^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)[a-z0-9A-Z]+([\-\.]{1}[a-z0-9A-Z]+)*\.[a-zA-Z]{2,5}(:[0-9]{1,5})?(\/.*)?$"
    EMAIL="^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9A-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    WIN_FILEPATH="^(?:[a-zA-Z]\:|\\\\[\w\.]+\\\\[\w.$]+)\\\\(?:[\w]+\\\\)*\w([\w.])+$"
    LIN_FILEPATH="^\/{1}(((\/{1}\.{1})?[a-zA-Z0-9 -_]+\/?)+(\.{1}[a-zA-Z0-9]{2,4})?)$"
    reg_dict={
        "reg_mac":re.compile("(?:"+CISCOMAC+"|"+WINDOWSMAC+"|"+COMMONMAC+"|"+BADMAC+")"),
        "reg_ipv4":re.compile(IPV4),
        "reg_ipv6":re.compile(IPV6),
        "reg_url":re.compile(URL),
        "reg_email":re.compile(EMAIL),
        "reg_win_file_path":re.compile(WIN_FILEPATH),
        "reg_lin_filepath":re.compile(LIN_FILEPATH)
        }
    for key in input_dict:
        for reg_key in reg_dict:
            print(reg_key,key)
            print(reg_dict[reg_key])
            if(reg_dict[reg_key].search(input_dict[key])):
                suggestions.append({"input_field":key,"previous_field":reg_key,"field_type_suggested":field_mapping[reg_key]})
        
    
    return suggestions


'''
Funciton returning the suggestions on the basis on the regex matching criteria
'''
def getSuggestionsFromKeysRegex(input_dict):
    suggestions=[]
    for field_name in input_dict.keys():
        for field_type in field_map_regex:
            #print(field_type)
            for values in field_map_regex[field_type]:
                #values=values.lower()
                if values.search(field_name):
                    #print(values)
                    suggestions.append({"input_field":field_name,"previous_field":values,"field_type_suggested":field_type})

    return suggestions

'''
Function returning the values on the basis of exact key matching and key splitting
'''
def getSuggestionsFromKeys(input_dict):
    suggestions=[]
    for field_name in input_dict.keys():
        for field_type in field_map:
            #print(field_type)
            for values in set(field_map[field_type]):
                #print(values)
                values=values.lower()
                if values==field_name:
                    suggestions.append({"input_field":field_name,"previous_field":values,"field_type_suggested":field_type})
                elif len(values.split(' '))>1:
                    for word in values.split(' '):
                        if values ==word:
                            suggestions.append({"input_field":field_name,"previous_field":values,"field_type_suggested":field_type})
                elif len(values.split('_'))>1:
                    for word in values.split('_'):
                        if values ==word:
                            suggestions.append({"input_field":field_name,"previous_field":values,"field_type_suggested":field_type}) 
    return suggestions

'''
Function returning the suggestions on the basis of fuzzy matching the keys
'''
def getFuzzyMatch(input_dict,threshhold=90):
    suggestions=[]
    choices=input_dict.keys()
    for word in choices:
        for field_type in field_map:
            #print(field_type)
            for values in set(field_map[field_type]):
                #print(fuzz.token_set_ratio(word,values))
                if fuzz.token_sort_ratio(word,values)>threshhold:
                    suggestions.append({"input_field":word,"previous_field":values,"field_type_suggested":field_type})
    return(suggestions)


def get_field_suggestions(input_dict):
    suggestions=[]
    suggestions.extend(getSuggestionsFromKeys(input_dict))
    suggestions.extend(getSuggestionsFromValues(input_dict))
    suggestions.extend(getSuggestionsFromKeysRegex(input_dict))
    suggestions.extend(getFuzzyMatch(input_dict))
    #print(suggestions)
    df=pd.DataFrame(suggestions)
    df=df.drop_duplicates('input_field')
    df.columns=["Input Fields","Previous Fields/Regex","Suggested Field Type"]
    return(df)

