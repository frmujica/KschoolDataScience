import requests
import configparser
import tarfile

def GetOpenvasConfigValues(ConfigFile):
    Config = configparser.ConfigParser()
    Config.read(ConfigFile)
    return Config

def GetOpenvasValues(ConfigFile):
    Config = GetOpenvasConfigValues(ConfigFile)
    BaseUrl = Config['Openvas']['URL']
    return (BaseUrl)

def DownloadFile(PluginsOutputFile,ConfigFile):
    url = GetOpenvasValues(ConfigFile)
    r = requests.get(url)
    if r.status_code == 200:
        print('Response OK, downloading file')
        with open(PluginsOutputFile, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)
        print('File download has been completed')

def DecompressPluginFile(dirpath,PluginsFile):
    print('Descompressing file %s',(PluginsFile)) # Must be the absolute file path 
    tar = tarfile.open(PluginsFile)
    tar.extractall(path=dirpath)
    tar.close()