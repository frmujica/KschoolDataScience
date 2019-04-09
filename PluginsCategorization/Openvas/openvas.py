from openvasplugindownloader import DownloadFile,DecompressPluginFile
import datetime
import os
import re
import csv



#Regex for extracting important fields

OID = re.compile(r'script_oid\(\".*?\.(?P<oid>\d+)\"\)')
SolutionType = re.compile(r'script\_tag\(name\:.*?"solution\_type\"\,.*?value\:.*?"(?P<solution>.*?)\"\)')
CVSS = re.compile(r'name\:.*?\"cvss_base\"\,.*?value\:.*?\"(?P<cvss>.*?)\"')
ScriptFamily = re.compile(r'script\_family\(\"(?P<script_family>.*?)\"\)')
Solution = re.compile(r'script\_tag\(name.*?\"solution\".*?value.*?\:(?P<solution>.*)')
TagSolution = re.compile(r'tag\_solution.?\=.*?\"(?P<tag_solution>.*)')
OIDs = []
VendorCSV = []



def NameofFile(Filename):
    Filename = Filename + '_' + str(datetime.datetime.now().time()) + '.tar.bz2'
    return Filename

def ReadVendorReferencesCSV(FileName):
    ReferenceRegexCSV = []
    with open(FileName,'rb') as VR:
        reader = csv.reader(VR)
        next(reader, None)  # skip the headers
        for row in reader:
            ReferenceRegexCSV.append(row[2])
    return ReferenceRegexCSV

def LookVendorReference(FileName,Content):
    VendorReferences = []
    Content = Content.upper()
    for i in FileName:
        i = str(i)
        VR = re.compile(i)
        VendorRef = VR.findall(Content)
        if VendorRef:
            for i in VendorRef:
                if type(i) is str:
                    VendorReferences.append(i)
                if type(i) is tuple:
                    i = list(set(i))
                    i = filter(None,i)
                    for l in i:
                        VendorReferences.append(l)
    VendorReference=' '.join(VendorReferences)
#    del VendorReferences[:]
    return VendorReference


def main():
    openvasfile = NameofFile('OpenvasPlugins/PluginsOpenvas')
    openvasdestfile = 'OpenvasPlugins' + '/' + openvasfile.replace('.tar.bz2',"")
    configs = 'OpenvasConfigs/openvasconfig.ini'
    DownloadFile(openvasfile,configs)
    DecompressPluginFile(openvasdestfile,openvasfile)
    for root, subdirs, files in os.walk(openvasdestfile):
    #Files walking   
        for f in files: 
            list_file_path = os.path.join(root, f)
            with open(list_file_path,'rb') as list_file:
                f_content = list_file.read()
                print(f_content)

main()