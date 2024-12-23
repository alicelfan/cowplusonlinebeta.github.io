import os
import pandas as pd

def merge_csv_files(directory, output_file):
    merged_df = None

    for filename in os.listdir(directory):
        if filename.endswith('.csv'):
            file_path = os.path.join(directory, filename)
            
            # drop both id and stateabb columns (upon request)
            df = pd.read_csv(file_path).drop(['id', 'stateabb'], axis=1)
            
            # merge with existing
            if merged_df is None:
                merged_df = df
            else:
                merged_df = pd.merge(merged_df, df, on=['ccode', 'year'], how='outer')

    # create new id column
    merged_df.insert(0, 'id', range(1, 1 + len(merged_df)))

    merged_df.to_csv(output_file, index=False)
    print(f"Output at {output_file}")

csv_directory = os.getcwd()
output_csv_file = 'merged.csv'

merge_csv_files(csv_directory, output_csv_file)