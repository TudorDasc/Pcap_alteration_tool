import os
import pandas as pd

from zat.log_to_dataframe import LogToDataFrame

log_to_df = LogToDataFrame()

def read_cache(filename, read_initial_func, use_cache=True):
    name, ext = os.path.splitext(filename)

    # uncomment the lines below if we want to use the cache version of files
    # filename_cache = name+".parquet"
    #
    # if use_cache and os.path.exists(filename_cache):
    #     print(f"using cached version of {filename} at {filename_cache}")
    #     cache_df = pd.read_parquet(filename_cache)
    #     return cache_df

    # get_df_from_eve expects double quotes
    print(f"reading {filename}")
    df = read_initial_func(f"{filename}")

    # if use_cache:
    #     print(f"storing cached version at {filename_cache}")
    #     df.to_parquet(filename_cache)

    return df


def read_eve(filename, use_cache=True):
    return read_cache(filename, get_df_from_eve, use_cache)


def read_zeek(filename, use_cache=True):
    return read_cache(filename, log_to_df.create_dataframe, use_cache)


def get_df_from_eve(filename):
    df = pd.read_json(filename)
    return df
