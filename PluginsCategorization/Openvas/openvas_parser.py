from openvas_downloader import download_file,decompress_plugin_file
import datetime
import os
import re
import csv



#Regex that extract important fields to make dataset

oid = re.compile(r'script_oid\(\".*?\.(?P<oid>\d+)\"\)')
solutiontype = re.compile(r'script\_tag\(name\:.*?"solution\_type\"\,.*?value\:.*?"(?P<solution>.*?)\"\)')
cvss = re.compile(r'name\:.*?\"cvss_base\"\,.*?value\:.*?\"(?P<cvss>.*?)\"')
scriptfamily = re.compile(r'script\_family\(\"(?P<script_family>.*?)\"\)')
solution = re.compile(r'script\_tag\(name.*?\"solution\".*?value.*?\:(?P<solution>.*)')
tag_solution = re.compile(r'tag\_solution.?\=.*?\"(?P<tag_solution>.*)')
oids = []
vendorcsv = []



def rename_file(filename):
    filename = filename + '_' + str(datetime.datetime.now().time()) + '.tar.bz2'
    return filename

def read_vendor_reference_csv(fileName):
    reference_regex_csv = []
    with open(fileName,'rb') as VR:
        reader = csv.reader(VR)
        next(reader, None)  # skip the headers
        for row in reader:
            reference_regex_csv.append(row[2])
    return reference_regex_csv

def loof_for_vendor_reference(filename,content):
    vendor_references = []
    content = content.upper()
    for i in filename:
        i = str(i)
        vr = re.compile(i)
        vendor_ref = vr.findall(content)
        if vendor_ref:
            for i in vendor_ref:
                if type(i) is str:
                    vendor_references.append(i)
                if type(i) is tuple:
                    i = list(set(i))
                    i = filter(None,i)
                    for l in i:
                        vendor_references.append(l)
    vendor_references=' '.join(vendor_references)
    return vendor_references

def get_block_of_text(start, end, file_object):
    inRecordingMode = False
    for line in file_object:
        if not inRecordingMode:
            if line.decode().replace(' ','').rstrip().startswith(start):
                inRecordingMode = True
        elif line.decode().rstrip().replace(' ','').rstrip().startswith(end):
            inRecordingMode = False
        else:
            yield line

def main():
    openvasfile = rename_file('OpenvasPlugins/PluginsOpenvas')
    openvasdestfile = './' + openvasfile.replace('.tar.bz2',"")
    configs = 'OpenvasConfigs/openvasconfig.ini'
    download_file(openvasfile,configs)
    decompress_plugin_file(openvasdestfile,openvasfile)
    # for root, subdirs, files in os.walk(openvasdestfile):
    #     print(subdirs)
    # #Files walking   
    #     for f in files: 
    #         list_file_path = os.path.join(root, f)
    #         with open(list_file_path,'rb') as list_file:
    #             f_content = list_file.read()
                
main()
# with open('OpenvasPlugins/OpenvasPlugins/PluginsOpenvas_19:38:20.414675/aas_detect.nasl','rb') as f:
#     hi = get_block_of_text("if(description)", "include(", f)
#     for g in hi:
#         print(g)