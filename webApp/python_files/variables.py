#imports
from flask import flash
import sys
import pandas as pd
import numpy as np
from flask import session

import json

import csv
import os
# sys.path.append("../cowplusonlinebeta.github.io")
# import cowplus

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import openconfig
config = openconfig.read_config()

directory_descriptions = config["UPLOAD_FOLDER"] + '/descriptions'

monadic_reqcol = ["stateabb", "ccode", "year"]
dyadic_reqcol = ["stateabb1", "ccode1", "stateabb2", "ccode2", "year"]

def debug(label, variable):
    print("\n>>> (DEBUG) " + label + " : " + str(variable) + "\n")
    return

def column_check(dataframe, reqcol):
    if not set(reqcol).issubset(set(dataframe.columns)):
       return False
    return True

def remove_items(test_list, item):
    # using list comprehension to perform the task
    res = [i for i in test_list if i != item]
    return res

def delete_item(test_list, index):
    # using list comprehension to perform the task
    del test_list[index]
    return test_list

#variable ids - name + filename
def createVarIDsDict(username):
    directory_uploaded = os.path.join(config["UPLOAD_FOLDER"], username)
    all_dictionary = {}
    secondstep_dictionary = {}
    i = 0
    for filename in os.listdir(directory_descriptions):
        f = os.path.join(directory_descriptions, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.columns.tolist().copy()
            temp_list = remove_items(temp_list, "stateabb")
            temp_list = remove_items(temp_list, "stateabb1")
            temp_list = remove_items(temp_list, "stateabb2")
            temp_list = remove_items(temp_list, "ccode1")
            temp_list = remove_items(temp_list, "ccode2")
            temp_list = remove_items(temp_list, "ccode")
            temp_list = remove_items(temp_list, "year")
            for j in range(len(temp_list)):
                temp_list[j] = temp_list[j]+filename[:-4]
            all_dictionary[i] = {'vars' : temp_list}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars' : temp_list}
            i = i+1
    for filename in os.listdir(directory_uploaded):
        f = os.path.join(directory_uploaded, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.columns.tolist().copy()
            temp_list = remove_items(temp_list, "stateabb")
            temp_list = remove_items(temp_list, "stateabb1")
            temp_list = remove_items(temp_list, "stateabb2")
            temp_list = remove_items(temp_list, "ccode1")
            temp_list = remove_items(temp_list, "ccode2")
            temp_list = remove_items(temp_list, "ccode")
            temp_list = remove_items(temp_list, "year")
            for j in range(len(temp_list)):
                temp_list[j] = temp_list[j]+filename[:-4]
            all_dictionary[i] = {'vars' : temp_list}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars' : temp_list}
            i = i+1
    return all_dictionary, secondstep_dictionary

#variable name; variable type; variable preloaded/uploaded
def createVarDict(username):
    directory_uploaded = os.path.join(config["UPLOAD_FOLDER"], username)
    all_dictionary = {}
    secondstep_dictionary = {}
    i = 0
    var_names = []
    var_types = []
    var_pvus = []
    for filename in os.listdir(directory_descriptions):
        f = os.path.join(directory_descriptions, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.columns.tolist().copy()
            temp_list = remove_items(temp_list, "stateabb")
            temp_list = remove_items(temp_list, "stateabb1")
            temp_list = remove_items(temp_list, "stateabb2")
            temp_list = remove_items(temp_list, "ccode1")
            temp_list = remove_items(temp_list, "ccode2")
            temp_list = remove_items(temp_list, "ccode")
            temp_list = remove_items(temp_list, "year")
            for j in range(len(temp_list)):
                var_names.append(temp_list[j])
                var_pvus.append("Preloaded Datasets")
            if(column_check(temp_file, monadic_reqcol)):
                for j in range(len(temp_list)):
                    var_types.append("Country-Year Data")
            elif(column_check(temp_file, dyadic_reqcol)):
                for j in range(len(temp_list)):
                    var_types.append("Dyad-Year Data")
            all_dictionary[i] = {'vars_name' : var_names, 'vars_type' : var_types, 'vars_pvu' : var_pvus}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars_name' : var_names, 'vars_type' : var_types, 'vars_pvu' : var_pvus}
            var_names = []
            var_types = []
            var_pvus = []
            i = i+1
    for filename in os.listdir(directory_uploaded):
        f = os.path.join(directory_uploaded, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.columns.tolist().copy()
            temp_list = remove_items(temp_list, "stateabb")
            temp_list = remove_items(temp_list, "stateabb1")
            temp_list = remove_items(temp_list, "stateabb2")
            temp_list = remove_items(temp_list, "ccode1")
            temp_list = remove_items(temp_list, "ccode2")
            temp_list = remove_items(temp_list, "ccode")
            temp_list = remove_items(temp_list, "year")
            for j in range(len(temp_list)):
                var_names.append(temp_list[j])
                var_pvus.append("Uploaded Datasets")
            if(column_check(temp_file, monadic_reqcol)):
                for j in range(len(temp_list)):
                    var_types.append("Country-Year Data")
            elif(column_check(temp_file, dyadic_reqcol)):
                for j in range(len(temp_list)):
                    var_types.append("Dyad-Year Data")
            all_dictionary[i] = {'vars_name' : var_names, 'vars_type' : var_types, 'vars_pvu' : var_pvus}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars_name' : var_names, 'vars_type' : var_types, 'vars_pvu' : var_pvus}
            var_names = []
            var_types = []
            var_pvus = []
            i = i+1
    return all_dictionary, secondstep_dictionary

#variable descriptions
def createVarDescripDict(username):
    directory_uploaded = os.path.join(config["UPLOAD_FOLDER"], username)
    all_dictionary = {}
    secondstep_dictionary = {}
    i = 0
    for filename in os.listdir(directory_descriptions):
        f = os.path.join(directory_descriptions, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.iloc[0].tolist().copy()
            temp_list = [x for x in temp_list if str(x) != 'nan'] #since descriptions for stateabb, ccode, year, etc. are all nans, they are not included in temp_list
            all_dictionary[i] = {'vars' : temp_list}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars' : temp_list}
            i = i+1
    for filename in os.listdir(directory_uploaded):
        f = os.path.join(directory_uploaded, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.iloc[0].tolist().copy()
            temp_columns = temp_file.columns.tolist().copy()
            if(column_check(temp_file, monadic_reqcol)):
                idx_state = temp_columns.index("stateabb")
                idx_ccode = temp_columns.index("ccode")
                idx_year_m = temp_columns.index("year")
                temp_list = delete_item(temp_list, idx_state)
                if(idx_ccode > idx_state):
                    idx_ccode = idx_ccode - 1
                temp_list = delete_item(temp_list, idx_ccode)
                if(idx_year_m > idx_state):
                    idx_year_m = idx_year_m - 1
                if(idx_year_m > idx_ccode):
                    idx_year_m = idx_year_m - 1
                temp_list = delete_item(temp_list, idx_year_m)
            elif (column_check(temp_file,dyadic_reqcol)):
                idx_state_one = temp_columns.index("stateabb1")
                idx_state_two = temp_columns.index("stateabb2")
                idx_ccode_one = temp_columns.index("ccode1")
                idx_ccode_two = temp_columns.index("ccode2")
                idx_year_d = temp_columns.index("year")
                temp_list = delete_item(temp_list, idx_state_one) # state one
                #state two
                if(idx_state_two > idx_state_one):
                    idx_state_two = idx_state_two - 1
                temp_list = delete_item(temp_list, idx_state_two)
                #ccode one
                if(idx_ccode_one > idx_state_one):
                    idx_ccode_one = idx_ccode_one - 1
                if(idx_ccode_one > idx_state_two):
                    idx_ccode_one = idx_ccode_one - 1
                temp_list = delete_item(temp_list, idx_ccode_one)
                #ccode 2
                if(idx_ccode_two > idx_state_one):
                    idx_ccode_two = idx_ccode_two - 1
                if(idx_ccode_two > idx_state_two):
                    idx_ccode_two = idx_ccode_two - 1
                if(idx_ccode_two > idx_ccode_one):
                    idx_ccode_two = idx_ccode_two - 1
                temp_list = delete_item(temp_list, idx_ccode_two)
                #year
                if(idx_year_d > idx_state_one):
                    idx_year_d = idx_year_d - 1
                if(idx_year_d > idx_state_two):
                    idx_year_d = idx_year_d - 1
                if(idx_year_d > idx_ccode_one):
                    idx_year_d = idx_year_d - 1
                if(idx_year_d > idx_ccode_two):
                    idx_year_d = idx_year_d - 1
                temp_list = delete_item(temp_list, idx_year_d)
            #find index of stateabb, ccode, year, etc in temp_file.columns
            #set int variable = to index
            #remove index position in temp_list.iloc[0]
            #if index position of new thing to be removed < removed; index stays same; else: index-1
            all_dictionary[i] = {'vars' : temp_list}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars' : temp_list}
            i = i+1
    return all_dictionary, secondstep_dictionary
    df = pd.DataFrame.from_dict(dictionary, orient='index',columns=['vars'])
    return df.to_json(orient="values")

#which dataset does each variable belong to
def createVarDatasetDict(username):
    directory_uploaded = os.path.join(config["UPLOAD_FOLDER"], username)
    all_dictionary = {}
    secondstep_dictionary = {}
    i = 0
    for filename in os.listdir(directory_descriptions):
        f = os.path.join(directory_descriptions, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.columns.tolist().copy()
            temp_list = remove_items(temp_list, "stateabb")
            temp_list = remove_items(temp_list, "stateabb1")
            temp_list = remove_items(temp_list, "stateabb2")
            temp_list = remove_items(temp_list, "ccode1")
            temp_list = remove_items(temp_list, "ccode2")
            temp_list = remove_items(temp_list, "ccode")
            temp_list = remove_items(temp_list, "year")
            for j in range(len(temp_list)):
                temp_list[j] = filename[:-4]
            all_dictionary[i] = {'vars' : temp_list}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars' : temp_list}
            i = i+1
    for filename in os.listdir(directory_uploaded):
        f = os.path.join(directory_uploaded, filename)
        # checking if it is a file
        if os.path.isfile(f):
            temp_file = pd.read_csv(f, sep=",")
            temp_list = temp_file.columns.tolist().copy()
            temp_list = remove_items(temp_list, "stateabb")
            temp_list = remove_items(temp_list, "stateabb1")
            temp_list = remove_items(temp_list, "stateabb2")
            temp_list = remove_items(temp_list, "ccode1")
            temp_list = remove_items(temp_list, "ccode2")
            temp_list = remove_items(temp_list, "ccode")
            temp_list = remove_items(temp_list, "year")
            for j in range(len(temp_list)):
                temp_list[j] = filename[:-4]
            all_dictionary[i] = {'vars' : temp_list}
            if(column_check(temp_file, monadic_reqcol)):
                secondstep_dictionary[i] = {'vars' : temp_list}
            i = i+1
    return all_dictionary, secondstep_dictionary
    df = pd.DataFrame.from_dict(dictionary, orient='index',columns=['vars'])
    return df.to_json(orient="values")
'''
def createVarIDs_JS(username):
    a, m = createVarIDsDict(username)
    adf = pd.DataFrame.from_dict(a, orient='index',columns=['vars'])
    mdf = pd.DataFrame.from_dict(m, orient = 'index', columns = ['vars'])
    return adf.to_json(orient="values"), mdf.to_json(orient="values")

def createVar_JS(username):
    a, m = createVarDict(username)
    adf = pd.DataFrame.from_dict(a)
    mdf = pd.DataFrame.from_dict(m)
    return adf.to_json(orient="values"), mdf.to_json(orient="values")

def createVarDescrip_JS(username):
    a, m = createVarDescripDict(username)
    adf = pd.DataFrame.from_dict(a, orient='index',columns=['vars'])
    mdf = pd.DataFrame.from_dict(m, orient = 'index', columns = ['vars'])
    return adf.to_json(orient="values"), mdf.to_json(orient="values")

def createVarDataset_JS(username):
    a, m = createVarDatasetDict(username)
    adf = pd.DataFrame.from_dict(a, orient='index',columns=['vars'])
    mdf = pd.DataFrame.from_dict(m, orient = 'index', columns = ['vars'])
    return adf.to_json(orient="values"), mdf.to_json(orient="values")
'''
def convert_to_serializable(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(i) for i in obj]
    return obj

def createVarGeneric(username, var_type):
    json_path = os.path.join(config["UPLOAD_FOLDER"], username, "temp")
    a_filepath = os.path.join(json_path, f"{username}_{var_type}_a.json")
    m_filepath = os.path.join(json_path, f"{username}_{var_type}_m.json")
    debug("needs_refresh", "True")
    if var_type == "IDs":
        a, m = createVarIDsDict(username)
    elif var_type == "Var":
        a, m = createVarDict(username)
    elif var_type == "Descrip":
        a, m = createVarDescripDict(username)
    elif var_type == "Dataset":
        a, m = createVarDatasetDict(username)
    else:
        raise ValueError("Invalid var_type. Expected 'IDs', 'Var', 'Descrip', or 'Dataset'.")
    
    a_ser = convert_to_serializable(a)
    m_ser = convert_to_serializable(m)

    debug("a_ser " + str(var_type), a_ser)
    debug("m_ser " + str(var_type), a_ser)  
        
    if var_type == "Var":
        adf = pd.DataFrame.from_dict(a)
        mdf = pd.DataFrame.from_dict(m)
    else:
        adf = pd.DataFrame.from_dict(a, orient='index', columns=['vars'])
        mdf = pd.DataFrame.from_dict(m, orient='index', columns=['vars'])
    return adf.to_json(orient="values"), mdf.to_json(orient="values")