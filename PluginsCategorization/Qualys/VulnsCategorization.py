import sys
import xml.etree.ElementTree as ET
import csv
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import getpass
import configparser

#We declared all the global variables we are going to need after in our code. Basically we clasify all the vulnerabilities into 9 categories, and we left "to clasify" category for all of those vulnerabilities that we could not clasify automatically with this code.

SolutionPatch = "Update or patch installation"
Eol = "End of life Platform"
Info = "Informational"
Workaround = "Workaround"
NoPatch = "No solution or patch available"
PolicyCompliance = "Policy compliance"
UselessService = "Unsecure or useless service"
ConfigurationChanges = "Configuration changes"
Ssltls = "SSL/TLS hardening"
ToClassify = "To classify"

#The next two functions are going to be optional, the main goal is to download the Knowledge base, aKa KB, from Qualys API and save into file that we define in the variable "plugins_output_file", then the code is going to proccess this file for categorizing Qualys plugins.

def GetAPIConfigValues(ConfigFile):
    Config = configparser.ConfigParser()
    Config.read(ConfigFile)
    return Config

def GetQualysApiValues(ConfigFile):
    Config = GetAPIConfigValues(ConfigFile)
    BaseUrl = Config['QualysAPIDownload']['URL']
    Username = Config['QualysAPIDownload']['User']
    Password = Config['QualysAPIDownload']['Password']
    if Password == '':
        Password = getpass.getpass() # Ask for API password if does not exist in configuration file
    Headers = {'X-Requested-With': 'Python3'}
    return (BaseUrl,Username,Password,Headers)

def GetPlugins(PluginsOutputFile,ConfigFile):
    url_base,username,password,headers = GetQualysApiValues(ConfigFile)
    endpoint = url_base + '/api/2.0/fo/knowledge_base/vuln/'
    parameter = {'action' : 'list'}
    r = requests.get(endpoint,auth=(username,password),params=parameter,headers=headers,verify=False)
    with open(PluginsOutputFile,'w') as f:
        f.write(r.text)

#These function are going to read the plugins that we have got from the KB, then will apply one of that 9 categories and save into a csv file. This file we normally use in Splunk&reg;  as a lookup to enrich data from vulnerabilities results and make some reports. 

def WriteLookup(FileName,List):
    CsvHeaders = ["ID", "SolutionCategory", "VendorReference", "PluginName","Diagnosis","Consequence","Solution"]
    with open(FileName, 'w') as outcsv:
        writer = csv.writer(outcsv)
        writer.writerow(CsvHeaders)
    # Write data to file
        for r in List:
            outcsv.write(r + "\n")
        outcsv.close()

def ReadVendorReferencesCSV(FileName):
    ReferenceRegexCSV = []
    with open(FileName,'r') as VR:
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
    VendorReference = VendorReference.split()
    return VendorReference

def CleanVendorReferenceList(VRList):
    VRTemp = []
    for v in VRList:
        if type(v) is str:
            VRTemp.append(v)
        if type(v) is list:
            for i in v:
                VRTemp.append(i)
    VRTemp = [elem for elem in VRTemp if elem != "AND"]
    VRTemp = [elem for elem in VRTemp if elem != "TO"]
    VRTemp = sorted(set(VRTemp),key=VRTemp.index)
    VRTemp = filter(None,VRTemp)
    VendorReference = ' '.join(VRTemp)
    return VendorReference
            
def CompressCSV(FileName):
    import gzip
    import shutil
    FileNameCompressed = FileName + '.gz'
    with open(FileName, 'rb') as f_in, gzip.open(FileNameCompressed, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
        
def GenerateClasifiedPlugin(PluginsInputFile,ReferenceRegexCSV,OutputFile):
    tree = ET.parse(PluginsInputFile)
    root = tree.getroot()
    QIDs = []
    VRID = []
    for kb in root:
        for response in kb:
            for vulnlist in response.findall('VULN'):
                PATCH = ToClassify
                QID = vulnlist.find('QID').text
                PATCHABLE = vulnlist.find('PATCHABLE').text
                TITLE = vulnlist.find('TITLE').text
                VendorRefName = LookVendorReference(ReferenceRegexCSV,TITLE)
                TITLE = TITLE.replace(',',' ')
                VRID.append(VendorRefName)
                VULN_TYPE = vulnlist.find('VULN_TYPE').text
                SOLUTIONELEMENT = vulnlist.find('SOLUTION')
                if SOLUTIONELEMENT is not None:
                    SOLUTION = SOLUTIONELEMENT.text
                    SOLUTION = SOLUTION.replace('\"','').replace(',','')
                else:
                    SOLUTION = "None"
                DIAGNOSISELEMENT = vulnlist.find('DIAGNOSIS')
                if DIAGNOSISELEMENT is not None:
                    DIAGNOSIS = DIAGNOSISELEMENT.text
                    DIAGNOSIS = DIAGNOSIS.replace('\"','')
                    DIAGNOSIS = DIAGNOSIS.replace(',','')
                else:
                    DIAGNOSIS = "None"
                CONSEQUENCEELEMENT = vulnlist.find('CONSEQUENCE')
                if CONSEQUENCEELEMENT is not None:
                    CONSEQUENCE = CONSEQUENCEELEMENT.text
                    CONSEQUENCE = CONSEQUENCE.replace('\"','')
                    CONSEQUENCE = CONSEQUENCE.replace(',','')
                else:
                    CONSEQUENCE = "None"
                VENDOR_REFERENCE_ID = vulnlist.findall('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/ID')
                if VENDOR_REFERENCE_ID is None:
                    VENDOR_REFERENCE_ID = "None"
                else:
                    for vr in vulnlist.findall('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE'):
                        id = vr.find('ID').text
                        id = id.upper()
                        id = id.replace(',',' ')
                        id = id.replace('\"','')
                        id = id.split()
                        VRID.append(id)
                VENDOR_REFERENCE = CleanVendorReferenceList(VRID)
                VRID.clear()
                if TITLE.find('EOL') != -1:
                    PATCH = Eol
                if PATCHABLE == '0' and SOLUTIONELEMENT is not None:
                    SOLUTION = SOLUTION.lower()
                    if TITLE.find('EOL') != -1:
                        PATCH = Eol
                    elif (SOLUTION.find('not released patch') != -1 
                        or SOLUTION.find('no fix available') != -1 
                        or SOLUTION.find('not released a patch') != -1 
                        or SOLUTION.find('no official fix') != -1 
                        or SOLUTION.find('not released the patch') != -1 
                        or SOLUTION.find('no solution') != -1 
                        or SOLUTION.find('not released') != -1 
                        or SOLUTION.find('hasn\'t released') != -1 
                        or SOLUTION.find('no vendor advisory') != -1 
                        or SOLUTION.find('not issued a fix') != -1 
                        or SOLUTION.find('no vendor supplied patches') != -1 
                        or SOLUTION.find('vendor has not confirmed the vulnerability') != -1
                        or SOLUTION.find('vendor has not confirmed vulnerability') != -1
                        or SOLUTION.find('vendor hasn\'t confirmed') != -1
                        or SOLUTION.find('no patch') != -1
                        or SOLUTION.find('no vendor-supplied') != -1
                        or SOLUTION.find('no patches')!=-1
                        or SOLUTION.find('any vendor supplied') != -1
                        or SOLUTION.find('any fixes') != -1
                        or SOLUTION.find('no known patches') != -1
                        or SOLUTION.find('any vendor-supplied') != -1
                        or SOLUTION.find('has not confirmed this issue') != -1
                        or SOLUTION.find('has not released') != -1
                        #or SOLUTION.find('') != -1
                        #or SOLUTION.find('') != -1
                        #or SOLUTION.find('') != -1
                        #or SOLUTION.find('') != -1
                        ):
                        if SOLUTION.find('workaround:<br>') != -1:
                            PATCH = Workaround
                        elif SOLUTION.find('workaround:') != -1:
                            PATCH = Workaround
                        elif SOLUTION.find('workarounds:<br>') != -1:
                            PATCH = Workaround
                        else:
                            PATCH = NoPatch
                    elif VULN_TYPE == "Information Gathered":
                        PATCH = Info
                    elif (SOLUTION.find('workaround') != -1):
                        PATCH = Workaround
                    else:
                        PATCH = ConfigurationChanges
                if (PATCHABLE == '1' and PATCH != Eol):
                    PATCH = SolutionPatch
                if VULN_TYPE == "Information Gathered":
                    PATCH = Info
                else:
                    PATH = ToClassify
                TITLE = TITLE.replace('\"','')
                LookupData = '\"' + QID + '\"' + ',' + '\"' + PATCH + '\"' + ',' + '\"' + str(VENDOR_REFERENCE) + '\"' + ',' + '\"' + TITLE.replace('\"','') + '\"' + ',' + '\"' + DIAGNOSIS + '\"' + ',' + '\"' + CONSEQUENCE + '\"' + ',' + '\"' + SOLUTION + '\"'
                QIDs.append(LookupData)
    WriteLookup(OutputFile,QIDs)
    CompressCSV(OutputFile)


#Finally, we call all the functions we created before into a main function that will receive an argument. If we want to download the KB from Qualys API we must introduce the URL and credentials

def VulnsCategorizationMain(DownloadFlag,PluginsFile,OutputFile,PluginsQualysConfig,VendorReferences):
    References = []
    DownloadFlag = DownloadFlag.lower()
    if (DownloadFlag == 'yes' or DownloadFlag =='y'):
        print('Connecting to API and downloading the latest knowledge base from Qualys')
        GetPlugins(PluginsFile,PluginsQualysConfig)
        for r in ReadVendorReferencesCSV(VendorReferences):
            References.append(r)
        GenerateClasifiedPlugin(PluginsFile,References,OutputFile)
        print('File %s was created' % OutputFile)
    elif(DownloadFlag == 'no' or DownloadFlag == 'n' ):
        print('Using the knowledge base in your localfiles')
        for r in ReadVendorReferencesCSV('../VendorReferences.csv'):
            References.append(r)
        GenerateClasifiedPlugin(PluginsFile,References,OutputFile)
        print('File %s was created' % OutputFile)
    else:
        print('Please enter a valid value')