import argparse # Default for parsing command-line arguments
import configparser # Python module for parsing .ini like configuration files
from datetime import datetime # Date/Time manipulation
import pwd, grp # To access Group and User database in UNIX systems
from fnmatch import fnmatch # Matching filenames in UNIX systems which are different from REGEX
import hashlib # SHA-1 hashing
from math import ceil
import os 
import re
import sys # Accessing command-line arguments
import zlib # Data compression


argparser = argparse.ArgumentParser(description="Content Tracker")
sub_parsers = argparser.add_subparsers(title="Commands", dest="command") 
sub_parsers.required = True

def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)
    match args.command:
        case "add"          : cmd_add(args)
        case "cat-file"     : cmd_cat_file(args)
        case "check-ignore" : cmd_check_ignore(args)
        case "checkout"     : cmd_checkout(args)
        case "commit"       : cmd_commit(args)
        case "hash-object"  : cmd_hash_object(args)
        case "init"         : cmd_init(args)
        case "log"          : cmd_log(args)
        case "ls-files"     : cmd_ls_files(args)
        case "ls-tree"      : cmd_ls_tree(args)
        case "rev-parse"    : cmd_rev_parse(args)
        case "rm"           : cmd_rm(args)
        case "show-ref"     : cmd_show_ref(args)
        case "status"       : cmd_status(args)
        case "tag"          : cmd_tag(args)
        case _              : print("Bad command")


