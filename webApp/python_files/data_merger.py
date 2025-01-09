#imports

import sys
import pandas as pd
import numpy as np

import csv
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import openconfig
config = openconfig.read_config()

directory_preloaded = config["UPLOAD_FOLDER"] + '/preloaded_datasets'
username = "test_profile"
directory_uploaded = "Bigger Chungus"
# ignore the vscode yellow error
# import cowplus

# Change to the "datafiles_csv" folder
# os.chdir('C:\cowplus_online\cowplusonlinebeta.github.io\datafiles_csv\preloaded_datasets')

# diplo_ex = pd.read_csv('COW_Diplomatic_Exchange_Dyadic.csv')[1:]
# diplo_ex.name = 'diplo_ex'
# alliance = pd.read_csv('COW_Alliance_2022_Non_Directed_Dyadic.csv')[1:]
# alliance.name = 'alliance'
# direct_contiguity = pd.read_csv('COW_Direct_Contiguity_Directed_Dyadic.csv')[1:]
# direct_contiguity.name = 'direct_contiguity'
# igo = pd.read_csv('COW_IGO_2022_Non_Directed_Dyadic.csv')[1:]
# igo.name = 'igo'
# major_powers = pd.read_csv('COW_Major_Powers_2022.csv')[1:]
# major_powers.name = 'major_powers'
# mids = pd.read_csv('COW_MIDs_2022_Non_Directed_Dyadic.csv')[1:]
# mids.name = 'mids'
# nmc = pd.read_csv('COW_National_Military_Capabilities.csv')[1:]
# nmc.name = 'nmc'
# wrp = pd.read_csv('COW_World_Religions.csv')[1:]
# wrp.name = 'wrp'
# trade = pd.read_csv('COW_Trade_Dyadic.csv')[1:]
# trade.name = 'trade'

# os.chdir('C:\cowplus_online\cowplusonlinebeta.github.io\datafiles_csv')

# data_dict = {
#     'diplo_ex': diplo_ex,
#     'alliance': alliance,
#     'direct_contiguity': direct_contiguity,
#     'igo': igo,
#     'major_powers': major_powers,
#     'mids': mids,
#     'nmc': nmc,
#     'wrp': wrp,
#     'trade': trade
# }

dyadic_data = ['diplo_ex', 'alliance', 'igo', 'mids', 'trade', 'direct_contiguity']
monadic_data = ['nmc', 'wrp', 'major_powers']

# return from variablesChooser()
# variables_chosen = ['defense','neutrality','nonaggression','entente','dr_at_1','dr_at_2','de','joint_igo_membership','joint_igo_membership_count', 'conttype', 'mid_count','mid_onset_m','mid_ongoing_m','onset_other','ongoing_other','main_disno','dyindex,strtday_m','strtmnth_m','strtyr_m','endday_m','endmnth_m','endyear_m','outcome_m','settlmnt_m','fatlev_m','highact_m', 'flow1','flow2','smoothflow1']
def check(col, data):
    return col in data

monadic_reqcol = ["stateabb", "ccode", "year"]
dyadic_reqcol = ["stateabb1", "ccode1", "stateabb2", "ccode2", "year"]

#checks that columns are correctly added for merging
def column_check(dataframe, reqcol):
    if not set(reqcol).issubset(set(dataframe.columns)):
       return False
    return True

#finds longest data file
def find_largest(files):
    length = len(files[0])
    data_file = files[0]
    for i in range(len(files)):
        if (len(files[i]) > length):
            length = len(files[i])
            data_file = files[i]
    return data_file

#removes items from a list
def remove_items(test_list, item):
 
    res = list(filter((item).__ne__, test_list))
 
    return res

def createNewDataList(files_chosen_raw, variables_chosen, username):
    directory_uploaded = os.path.join(config["UPLOAD_FOLDER"], username)
    files_chosen = []
    # if a file is in the list of files chosen by the user, add it to the array files_chosen
    for name in files_chosen_raw:
        f = os.path.join(directory_preloaded, name +'.csv')
        # checking if it is a file
        if os.path.isfile(f):
            files_chosen.append(pd.read_csv(f)[1:])
        else:
            f = os.path.join(directory_uploaded, name + '.csv')
            if os.path.isfile(f):
                files_chosen.append(pd.read_csv(f)[1:])
    print("data_merger> dc:",str(files_chosen))
    print("data_merger> vc:",str(variables_chosen))

    # find the largest data file out of the files chosen by the user
    largest_file = find_largest(files_chosen)

    #determine if data is is monadic or dyadic
    if(column_check(files_chosen[0], monadic_reqcol)):
        datatype = "monadic"
    elif(column_check(files_chosen[0], dyadic_reqcol)):
        datatype = "dyadic"
    
    # if data is monadic
    if(datatype == "monadic"):
        # add event ids to each of the files chosen (unique because there should not be duplicates in the preloaded / uploaded data)
        for file_df in files_chosen:
            file_df["eventID"] = file_df["stateabb"].astype(str) + "_" + file_df["ccode"].astype(str) + "_" + file_df["year"].astype(str)
        cols_monadic = ["eventID"]
        df = largest_file[cols_monadic]
        df.drop_duplicates(subset = cols_monadic)
        for data_file in files_chosen: 
            for var in variables_chosen: 
                if check(var, data_file) == True:
                    cols_monadic.append(var)
                    data_list_temp = data_file[cols_monadic]
                    df = df.merge(data_list_temp, how = "outer", on = "eventID", suffixes= (None, "_x"))
                cols_monadic = ["eventID"]
            cols_monadic = ["eventID"]
        splitEvent= list(map(list, zip(*df["eventID"].str.split("_"))))
        df.insert(1, "year", splitEvent[2])
        df.insert(1, "ccode", splitEvent[1])
        df.insert(1, "stateabb", splitEvent[0])

        df['ccode'] = pd.to_numeric(df['ccode'], errors='coerce')
        if df['ccode'].isna().any():
            print('There are empty ccode values! Please correct them. The empty values have been replaced with 0.', 'error')
        df['ccode'] = df['ccode'].fillna(0)

        df.ccode = df.ccode.astype(int)
        df.year = df.year.astype(int)
        df = df.sort_values(by=["ccode", "year"])
    if(datatype == "dyadic"):
        for data_file in files_chosen:
            data_file["eventID"] = data_file["stateabb1"].astype(str) + "_" + data_file["ccode1"].astype(str) + "_" + data_file["stateabb2"].astype(str) + "_" + data_file["ccode2"].astype(str) + "_" + data_file["year"].astype(str)
        cols_dyadic = ["eventID"]
        df = largest_file[cols_dyadic]
        df.drop_duplicates(subset = cols_dyadic)
        for data_file in files_chosen: 
            cols_dyadic = ["eventID"]
            for var in variables_chosen: 
                cols_dyadic = ["eventID"]
                if check(var, data_file) == True:
                    cols_dyadic.append(var)
                    data_list_temp = data_file[cols_dyadic]
                    print(cols_dyadic)
                    df = df.merge(data_list_temp, how = "outer", on = "eventID", suffixes= (None, "_x"))
                df = df.drop_duplicates(subset = cols_dyadic)
        splitEvent= list(map(list, zip(*df["eventID"].str.split("_"))))
        df.insert(1, "year", splitEvent[4])
        df.insert(1, "ccode2", splitEvent[3])
        df.insert(1, "stateabb2", splitEvent[2])
        df.insert(1, "ccode1", splitEvent[1])
        df.insert(1, "stateabb1", splitEvent[0])
        df.year = df.year.astype(int)
        df['ccode1'] = pd.to_numeric(df['ccode1'], errors='coerce')
        if df['ccode1'].isna().any():
            print('There are empty ccode values! Please correct them. The empty values have been replaced with 0.', 'error')
        df['ccode1'] = df['ccode1'].fillna(0)
        df['ccode2'] = pd.to_numeric(df['ccode2'], errors='coerce')
        if df['ccode2'].isna().any():
            print('There are empty ccode2 values! Please correct them. The empty values have been replaced with 0.', 'error')
        df['ccode2'] = df['ccode2'].fillna(0)
        df.ccode2 = df.ccode2.astype(int)
        df.ccode1 = df.ccode1.astype(int)
        df = df.sort_values(by=["ccode1", "ccode2", "year"])
    print(df.columns.tolist())
    df.fillna(".", inplace=True)
    df.insert(0, 'id', range(1, 1 + len(df)))
    return df

def createNewDataListSecondStep(data_frame, fcrss, vcss, fcr, vc, username):
    directory_uploaded = os.path.join(config["UPLOAD_FOLDER"], username)
    df = data_frame.copy(deep = True)
    print(df.columns.tolist())
    files_chosen = []
    
    for name in fcrss:
        f = os.path.join(directory_preloaded, name +'.csv')
        print(f)
        # checking if it is a file
        if os.path.isfile(f):
            files_chosen.append(pd.read_csv(f)[1:])
        else:
            f = os.path.join(directory_uploaded, name + '.csv')
            print(f)
            if os.path.isfile(f):
                files_chosen.append(pd.read_csv(f)[1:])
    print("data_merger> dc:",str(files_chosen))
    print("data_merger> vc:",str(vcss))
    datatype = "monadic"
    #creates eventIDs for files_chosen
    for file_df in files_chosen:
            file_df["eventID"] = file_df["stateabb"].astype(str) + "_" + file_df["ccode"].astype(str) + "_" + file_df["year"].astype(str)
    cols_monadic = ["eventID"]
    df["eventID_state1"] = df["stateabb1"].astype(str) + "_" + df["ccode1"].astype(str) + "_" + df["year"].astype(str)
    df["eventID_state2"] = df["stateabb2"].astype(str) + "_" + df["ccode2"].astype(str) + "_" + df["year"].astype(str)
    for data_file in files_chosen: 
        for var in vcss: 
            if check(var, data_file) == True:
                cols_monadic.append(var)
                data_list_temp = data_file[cols_monadic]
                print(cols_monadic)
                df = df.merge(data_list_temp, how = "left", left_on = "eventID_state1", right_on = "eventID", suffixes= ("_1", "_2"))
                df = df.drop(["eventID"], axis = 1)
                df = df.merge(data_list_temp, how = "left", left_on = "eventID_state2", right_on = "eventID", suffixes= ("_1", "_2"))
                df = df.drop(["eventID"], axis = 1)
            cols_monadic = ["eventID"]
        cols_monadic = ["eventID"]
    df.fillna(".", inplace=True)
    return df
