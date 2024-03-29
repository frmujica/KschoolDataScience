"""Download plugins from Openvas website and creates a dataset"""
import os
import re
import csv
import json
from openvas_downloader import download_file, decompress_plugin_file

#Regex that extract important fields to make dataset

OID = re.compile(r'script_oid\(\".*?\.(?P<oid>\d+)\"\)')
CVSS = re.compile(r'name\:.*?\"cvss_base\"\,.*?value\:.*?\"(?P<cvss>.*?)\"')
FAMILY = re.compile(r'script\_family\(\"(?P<script_family>.*?)\"\)')
SOLUTION = re.compile(r'script\_tag\(name.*?\"solution\".*?value.*?\:(?P<solution>.*)')
TAG_SOL = re.compile(r'tag\_solution.?\=.*?\"(?P<tag_solution>.*)')
SCRIPTCATEGORY = re.compile(r'script\_category\((?P<script_category>.*?)\)')
SCRIPTFAMILY = re.compile(r'script\_family\((?P<script_family>.*?)\)')
SCRIPTNAME = re.compile(r'script\_name\(.*?(\"|\')(?P<script_name>.*?)(\"|\').*?\)')
SCRIPTNAME_ALTERNATIVE = re.compile(r'name.*?\=.*?(\"|\')(?P<script_name>.*?)(\"|\')')
CREATION_DATE = re.compile(
    r'creation_date\"\,.*?value\:\"(?P<creation_date>\d+\-\d+\-\d+\s+\d+\:\d+\:\d+)')
LAST_MODIFICATION = re.compile(
    r'last_modification\"\,.*?value\:\".*?(?P<last_modification>\d+\-\d+\-\d+\s+\d+\:\d+\:\d+)')
CVE = re.compile(r'(?P<cve_data>CVE\-\d+\-\d+)')
CVSS = re.compile(r'\"cvss_base\".*value\:.*?\"(?P<cvss_base>.*?)\"')
CVSS_VECTOR = re.compile(r'\"cvss_base\_vector\"\,.*?value.*?\:.*?\"(?P<cvss_vector>.*?)\"')
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

def look_for_data(filecontent, filename):
    """Function that look for OID first and then look for other fields"""
    plugin_data = "None"
    lookforoid = OID.search(filecontent.decode("ISO-8859-1"))
    if lookforoid:
        plugin_data = generate_dataset(filecontent, lookforoid.group('oid'), filename)
    return plugin_data

def write_dataset_json(filename, outputlist):
    """Write dataset into json file"""
    with open(filename, "w") as outjson:
        for obj in outputlist:
            outjson.write(json.dumps(obj) + "\n")

def get_block_of_text(start, end, filecontent):
    """" Function that looks for a block of text """
    start = start.replace(' ', '').strip()
    end = end.replace(' ', '').strip()
    start_index = filecontent.replace(' ', '').strip().index(start)
    end_index = filecontent.index(end)
    text = filecontent[start_index + 100:end_index]
    return text

def clean_text(text):
    """Clean rubish from text"""
    text = text.replace('if(description)'.replace(' ', '').strip(), '').replace('{', '')
    text = text.replace('if(description)', '').replace('{', '')
    text = re.sub(r'\#+', '', text)
    text = re.sub(r'.*?51.*?Franklin.*?St.*', '', text)
    text = re.sub(r'MA 02110-1301 USA', '', text)
    text = re.sub(r'^\n+', '', text)
    text = text.strip()
    return text

def generate_dataset(filecontent, oid, filename):
    """Function to create "final" dataset"""
    #vendor_reference = "DOES NOT APPLY"
    filecontent = filecontent.decode("ISO-8859-1")
    #last_modification = "None"
    text = get_block_of_text("if (description)", "exit(0);", filecontent)
    text = clean_text(text)
    cve = CVE.findall(filecontent)
    if CREATION_DATE.search(filecontent):
        creation_date = CREATION_DATE.search(filecontent).group('creation_date')
    if LAST_MODIFICATION.search(filecontent):
        last_modification = LAST_MODIFICATION.search(filecontent).group('last_modification')
    if SCRIPTCATEGORY.search(filecontent):
        script_category = SCRIPTCATEGORY.search(filecontent).group('script_category')
        script_category = script_category.replace('\"', '').strip()
    if SCRIPTFAMILY.search(filecontent):
        script_family = SCRIPTFAMILY.search(filecontent).group('script_family')
        script_family = script_family.replace('\"', '').strip()
    if SCRIPTNAME.search(filecontent):
        scriptname = SCRIPTNAME.search(filecontent).group('script_name')
        plugin_name = scriptname
        #Missing vendor references
    if SCRIPTNAME_ALTERNATIVE.search(filecontent):
        scriptname = SCRIPTNAME_ALTERNATIVE.search(filecontent).group('script_name')
        plugin_name = scriptname
        #Missing vendor references
    if CVSS.search(filecontent):
        cvss = CVSS.search(filecontent).group('cvss_base')
        cvss = cvss.strip()
    if CVSS_VECTOR.search(filecontent):
        cvss_vector = CVSS_VECTOR.search(filecontent).group('cvss_vector')
        cvss_vector = cvss_vector.strip()
    plugin_name = plugin_name.replace(',', ' ')
    plugin_name = plugin_name.replace('\"', '')
    jsondata = {"oid": oid, "creation_date": creation_date,
                "last_modification_date":last_modification,
                "plugin_name": plugin_name, "filename": filename,
                "script_category": script_category, "script_family": script_family,
                "cve": cve,
                "cvss": cvss, "cvss_vector": cvss_vector,
                "text": text}
    return jsondata

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
    write_dataset_json(outputfile, oids_list)

def main():
    """ Main function """
    #vendor_list = read_vendor_reference_csv('../VendorReferences.csv')
    openvasfile = 'OpenvasPlugins/PluginsOpenvas.tar.bz2'
    openvasdestfile = openvasfile.replace('.tar.bz2', "")
    configs = 'OpenvasConfigs/OpenvasConfig.ini'
    ouputcsvfile = 'DatasetInput/OpenvasLookup.json'
    download_file(openvasfile, configs)
    decompress_plugin_file(openvasdestfile, openvasfile)
    walk_directories(openvasdestfile, ouputcsvfile)

main()
