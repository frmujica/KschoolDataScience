"""Download plugins from Openvas website and creates a dataset"""
import os
import re
import csv
from openvas_downloader import download_file, decompress_plugin_file

#Regex that extract important fields to make dataset

OID = re.compile(r'script_oid\(\".*?\.(?P<oid>\d+)\"\)')
CVSS = re.compile(r'name\:.*?\"cvss_base\"\,.*?value\:.*?\"(?P<cvss>.*?)\"')
FAMILY = re.compile(r'script\_family\(\"(?P<script_family>.*?)\"\)')
SOLUTION = re.compile(r'script\_tag\(name.*?\"solution\".*?value.*?\:(?P<solution>.*)')
TAG_SOL = re.compile(r'tag\_solution.?\=.*?\"(?P<tag_solution>.*)')
SCRIPTCATEGORY = re.compile(r'script\_category\((?P<script_category>.*?)\)')
SCRIPTNAME = re.compile(r'script\_name\(.*?(\"|\')(?P<script_name>.*?)(\"|\').*?\)')
SCRIPTNAME_ALTERNATIVE = re.compile(r'name.*?\=.*?(\"|\')(?P<script_name>.*?)(\"|\')')
OIDS = []
VENDORCSV = []

def read_vendor_reference_csv(filename):
    """ Read vendor references from file and saves into list this function is useful
    to enrich vulnerability data"""
    reference_regex_csv = []
    with open(filename, 'r') as vendors:
        reader = csv.reader(vendors)
        next(reader, None)  # skip the headers
        for row in reader:
            reference_regex_csv.append(row[2])
    return reference_regex_csv

# def get_block_of_text(start, end, file_object):
#     """Get just the block of text that we need it to create the dataset"""
#     recording_mode = False
#     print(file_object)
#     for line in file_object:
#         if not recording_mode:
#             if line.replace(' ', '').rstrip().startswith(start):
#                 recording_mode = True
#         elif line.rstrip().replace(' ', '').rstrip().startswith(end):
#             recording_mode = False
#         else:
#             yield line

def block_of_text_in_clear(blockoftextobject):
    """Convert block of text object in clear text"""
    for text in blockoftextobject:
        print(text)
        #return text

def look_for_data(filecontent, filename):
    """Function that look for OID first and then look for other fields"""
    plugin_data = "None"
    lookforoid = OID.search(filecontent.decode("ISO-8859-1"))
    if lookforoid:
        plugin_data = generate_dataset(filecontent, lookforoid.group('oid'), filename)
    return plugin_data

def write_dataset(filename, outputlist):
    """Write dataset into csv file"""
    csv_headers = ['oid', 'plugin_name', 'plugin_file', 'script_category', 'text']
    with open(filename, 'w') as outcsv:
        writer = csv.writer(outcsv)
        writer.writerow(csv_headers)
        #Write data to file
        for list_object in outputlist:
            outcsv.write(list_object + "\n")

def generate_dataset(filecontent, oid, filename):
    """Function to create "final" dataset"""
    #vendor_reference = "DOES NOT APPLY"
    filecontent = filecontent.decode("ISO-8859-1")
    start = "if (description)".replace(' ', '').rstrip()
    end = "exit(0)"
    start_index = filecontent.replace(' ', '').rstrip().index(start)
    end_index = filecontent.index(end)
    text = filecontent[start_index:end_index]
    text = text.replace('if (description)'.replace(' ', '').strip(), '').replace('{', '')
    text = text.replace('if (description)', '').replace('{', '')
    #print("Filename is " + filename)
    #print(text)
    #text = re.search(r'^if.\(description\).*^include\(', filecontent, re.MULTILINE | re.DOTALL)
    #print(text.group(0))
    look_for_script_category = SCRIPTCATEGORY.search(filecontent)
    look_for_script_name = SCRIPTNAME.search(filecontent)
    look_for_script_name_alt = SCRIPTNAME_ALTERNATIVE.search(filecontent)
    if look_for_script_category:
        script_category = look_for_script_category.group('script_category')
    if look_for_script_name:
        scriptname = look_for_script_name.group('script_name')
        plugin_name = scriptname
        #Missing vendor references
    if look_for_script_name_alt:
        scriptname = look_for_script_name_alt.group('script_name')
        plugin_name = scriptname
        #Missing vendor references
    plugin_name = plugin_name.replace(',', ' ')
    plugin_name = plugin_name.replace('\"', '')
    csvdata = '\"' + str(oid) + '\"' +  ',' + '\"' + str(plugin_name) + '\"' + ',' + '\"' + str(filename) + '\"' + ',' + '\"' + str(script_category) + '\"' + ',' + '\"' + str(text) + '\"'
    return csvdata

def walk_directories(directory, outputfile):
    """Function to walk for every single file on specific directory"""
    oids_list = []
    print("Waling in root directory")
    for root, subdirs, files in os.walk(directory):
        print("Walking in those subdirectories: %s" % subdirs)
        #Files walking
        for file in files:
            list_file_path = os.path.join(root, file)
            with open(list_file_path, 'rb') as list_file:
                f_content = list_file.read()
                oids_list.append(look_for_data(f_content, file))
    write_dataset(outputfile, oids_list)

def main():
    """ Main function """
    #vendor_list = read_vendor_reference_csv('../VendorReferences.csv')
    openvasfile = 'OpenvasPlugins/PluginsOpenvas.tar.bz2'
    openvasdestfile = openvasfile.replace('.tar.bz2', "")
    configs = 'OpenvasConfigs/OpenvasConfig.ini'
    ouputcsvfile = 'DatasetInput/OpenvasLookup.csv'
    download_file(openvasfile, configs)
    decompress_plugin_file(openvasdestfile, openvasfile)
    #print(vendor_list)
    walk_directories(openvasdestfile, ouputcsvfile)
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
