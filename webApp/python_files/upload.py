#imports

import sys
import pandas as pd
import numpy as np

import csv
import os
import time

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import openconfig
config = openconfig.read_config()

os.chdir(config["UPLOAD_FOLDER"])
monadic_reqcol = ["stateabb", "ccode", "year"]
dyadic_reqcol = ["stateabb1", "ccode1", "stateabb2", "ccode2", "year"]
def column_check(column_string, reqcol):
    columns = column_string.split(',')
    
    # Check if all required columns are present in the list
    if all(x in columns for x in reqcol):
        return True
    return False

def verify_files(first_line, file):
    monadic_files = []
    dyadic_files = []
    good_files = []
    bad_files = []
    # not a temp file
    temp_file = first_line
    if(column_check(temp_file, monadic_reqcol)):
        monadic_files.append(file.filename)
        good_files.append(file.filename)
    elif(column_check(temp_file, dyadic_reqcol)):
        dyadic_files.append(file.filename)
        good_files.append(file.filename)
    else:
        bad_files.append(file.filename)
    return monadic_files, dyadic_files, good_files, bad_files
