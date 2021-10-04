#!/usr/bin/env python3
# This script reads csv metadata files and output the figure according to this metadata,
# also output a merged version of csv

import argparse
import nest_asyncio
# Monkey patches for fix the re-entering of asyncio problem
nest_asyncio.apply()

from multiprocessing import Pool, cpu_count
from src.meta.merge import Merger
from src.meta.grouper import MetaGrouper
from src.sharks.sharkReader import SharkReader
from src.sharks.sharkConfig import SharkConfigFactory

DEBUG = 1
save_metadata = False

argparser = argparse.ArgumentParser(description="Reads the metadata csv files and merge them into one")
argparser.add_argument("-i", "--input", help="Input metadata csv folder")
argparser.add_argument("-o", "--output", help="The output meta data file.", default="./merged_metaname")

def get_filelist(input_filename, output_filename):
    from os import listdir
    from os.path import isfile, join, isdir
    output_file = output_filename + ".csv"
    if isdir(input_filename):
        input_filelist = [join(input_filename, f) for f in listdir(input_filename) \
            if isfile(join(input_filename, f) and f.endswith('.meta.csv'))]
        return input_filelist, output_file
    elif isfile(input_filename):
        return input_filename, output_file
    else:
        print("Unidentified input_filename!")
        raise NotImplementedError

def process_filelist(filelist)->Merger:
    merger = Merger()

    total_files = len(filelist)
    for i,filename in enumerate(filelist):
        merger.add_a_metafile(filename)
        print("Progress: ", i, "/", str(total_files), "r")

if __name__ == "__main__":
    args = argparser.parse_args()
    input_filelist, output_filename = get_filelist(args.input, args.output)

    merger = process_filelist(input_filelist)
    merger.saveMeta(output_filename)
    print("Finished merging!")