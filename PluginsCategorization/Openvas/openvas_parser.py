"""Download plugins from Openvas website and creates a dataset"""
import datetime
#import os
import re
import csv
from openvas_downloader import download_file, decompress_plugin_file




#Regex that extract important fields to make dataset

OID = re.compile(r'script_oid\(\".*?\.(?P<oid>\d+)\"\)')
CVSS = re.compile(r'name\:.*?\"cvss_base\"\,.*?value\:.*?\"(?P<cvss>.*?)\"')
FAMILY = re.compile(r'script\_family\(\"(?P<script_family>.*?)\"\)')
SOLUTION = re.compile(r'script\_tag\(name.*?\"solution\".*?value.*?\:(?P<solution>.*)')
TAG_SOL = re.compile(r'tag\_solution.?\=.*?\"(?P<tag_solution>.*)')
OIDS = []
VENDORCSV = []



def rename_file(filename):
    """Rename a filename"""
    filename = filename + '_' + str(datetime.datetime.now().time()) + '.tar.bz2'
    return filename

def read_vendor_reference_csv(filename):
    """ Read vendor references from file and saves into list"""
    reference_regex_csv = []
    with open(filename, 'rb') as vendors:
        reader = csv.reader(vendors)
        next(reader, None)  # skip the headers
        for row in reader:
            reference_regex_csv.append(row[2])
    return reference_regex_csv

def get_block_of_text(start, end, file_object):
    """Get just the block of text that we need it to create the dataset"""
    recording_mode = False
    for line in file_object:
        if not recording_mode:
            if line.decode().replace(' ', '').rstrip().startswith(start):
                recording_mode = True
        elif line.decode().rstrip().replace(' ', '').rstrip().startswith(end):
            recording_mode = False
        else:
            yield line

def main():
    """ Main function """
    vendor_list = read_vendor_reference_csv('../VendorReferences.csv')
    openvasfile = rename_file('OpenvasPlugins/PluginsOpenvas')
    openvasdestfile = './' + openvasfile.replace('.tar.bz2', "")
    configs = 'OpenvasConfigs/openvasconfig.ini'
    download_file(openvasfile, configs)
    decompress_plugin_file(openvasdestfile, openvasfile)
    print(vendor_list)
    # for root, subdirs, files in os.walk(openvasdestfile):
    #     print(subdirs)
    # #Files walking
    #     for f in files:
    #         list_file_path = os.path.join(root, f)
    #         with open(list_file_path,'rb') as list_file:
    #             f_content = list_file.read()

main()
#with open('./OpenvasPlugins/PluginsOpenvas_11:18:41.777440/aas_detect.nasl','rb') as f:
#    hi = get_block_of_text("if(description)", "include(", f)
#    for g in hi:
#        print(g)
