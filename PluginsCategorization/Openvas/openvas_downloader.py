import requests
import configparser
import tarfile

def get_openvas_config_values(configfile):
    config = configparser.ConfigParser()
    config.read(configfile)
    return config

def get_openvas_values(configfile):
    config = get_openvas_config_values(configfile)
    base_url = config['Openvas']['URL']
    return (base_url)

def download_file(plugins_output_file,configfile):
    url = get_openvas_values(configfile)
    r = requests.get(url)
    if r.status_code == 200:
        print('Response OK, downloading file from openvas web')
        with open(plugins_output_file, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)
        print('File download has been completed')

def decompress_plugin_file(dirpath,plugins_file):
    print('Descompressing file %s',(plugins_file)) # Must be the absolute file path 
    tar = tarfile.open(plugins_file)
    tar.extractall(path=dirpath)
    tar.close()