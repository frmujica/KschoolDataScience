"""Openvas Downloader"""
import configparser
import tarfile
import requests

def get_openvas_config_values(configfile):
    """Read the configuration file and return its values"""
    config = configparser.ConfigParser()
    config.read(configfile)
    return config

def get_openvas_values(configfile):
    """Read the URL and return its base, this function was desinged for APIS"""
    config = get_openvas_config_values(configfile)
    base_url = config['Openvas']['URL']
    return base_url

def download_file(plugins_output_file, configfile):
    """Download the file from the website"""
    url = get_openvas_values(configfile)
    response = requests.get(url)
    if response.status_code == 200:
        print('Response OK, downloading file from openvas web')
        with open(plugins_output_file, 'wb') as file_directory:
            for chunk in response.iter_content(chunk_size=128):
                file_directory.write(chunk)
        print('File download has been completed')

def decompress_plugin_file(dirpath, plugins_file):
    """Descompress the file"""
    print('Descompressing file %s' % plugins_file) # Must be the absolute file path
    tar = tarfile.open(plugins_file)
    tar.extractall(path=dirpath)
    tar.close()
    print("Descompress has been completed")
