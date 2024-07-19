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

os.chdir(config["UPLOAD_FOLDER"])
monadic_reqcol = ["stateabb", "ccode", "year"]
dyadic_reqcol = ["stateabb1", "ccode1", "stateabb2", "ccode2", "year"]
def column_check(dataframe, reqcol):
    if not set(reqcol).issubset(set(dataframe.columns)):
       return False
    return True

def verify_files(files):
    monadic_files = []
    dyadic_files = []
    good_files = []
    bad_files = []
    for file in files:
        temp_file = pd.read_csv(file.filename)
        if(column_check(temp_file, monadic_reqcol)):
            monadic_files.append(file.filename)
            good_files.append(file.filename)
            continue
        elif(column_check(temp_file, dyadic_reqcol)):
            dyadic_files.append(file.filename)
            good_files.append(file.filename)
            continue
        else:
            bad_files.append(file.filename)
    return monadic_files, dyadic_files, good_files, bad_files
