from cmath import log
import hashlib
import os
import pyudev
import psutil
from tinydb import TinyDB, Query
import logging

db = TinyDB("db.json")

logging.basicConfig(filename='info.log',
                    format='%(levelname)s %(asctime)s :: %(message)s',
                    level=logging.INFO)

def check(dir):
    '''
    This function is responsible to find malicious files.

    Parameters:
    dir: Directory of the file.

    Returns:
    error: A boolean value that is set to true if the user doesn't want to remove the file.

    '''

    directory = dir

    File = Query()
    error = False
    # iterate over files in all directories
    for root, dirs, files in os.walk(directory):
        for file in files:
            hashed_file = hash_file(os.path.join(root, file))
            results = db.search(File.hash == hashed_file)
            if results:
                logging.info('Malicious file found (' + file + ').')
                error = take_action(os.path.join(root, file), file)
                if error:
                    return error
    return error

def take_action(dir, file):
    '''
    This function lets the user choose whether to remove the malicious file or to eject usb.

    Parameters:
    dir: Directory of the file.
    file: File name.

    Returns:
    error: A boolean value that is set to true if the user doesn't want to remove the file.

    '''

    print("Threat detected in file: " + file)
    while True:
        answer = input(
            "Do you want to remove the malicious file " + file + "? Y/N\n")
        logging.info('User entered ' + answer)
        if answer.lower() == 'y':
            os.remove(dir)
            logging.info('(' + file + ')' + " removed.")
            print("malicious file removed")
            error = False
            return error
        elif answer.lower() == 'n':
            error = True
            return error
        else:
            print("Wrong input")

def hash_file(dir):
    '''
    This function is responsible for hashing files.

    Parameter:
    dir: Directory of file to be hashed.

    Returns:
    hashed_file.hexadigest(): The hexadecimal string of the file hash.

    '''

    hashed_file = hashlib.sha256()
    with open(dir, 'rb') as data:
        for byte_block in iter(lambda: data.read(4096),b""):
            hashed_file.update(byte_block)
    return hashed_file.hexdigest()

def usb_insertion_monitor():
    '''This function is responsible for detecting when a usb is inserted.'''

    logging.info('Monitoring usb.')
    context = pyudev.Context()

    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by('usb')
    monitor.start()
    for device in iter(monitor.poll, None):
        if device.action == 'add':
            flag = True
            while flag:
                for p in psutil.disk_partitions(False):
                    if 'media' in p.mountpoint:
                        print(p.mountpoint)
                        logging.info('usb connected at: ' + p.mountpoint + '.')
                        # Checks if the usb is safe
                        error = check(p.mountpoint)
                        flag = False
                        if error:
                            eject_usb(p.mountpoint)

def eject_usb(mountpoint):
    '''
    This function ejects the usb from the computer.
    
    Parameters:
    mountpoint: Path where the usb is mounted

    '''

    cmd = "eject " + mountpoint
    os.system(cmd)
    print("Device was successfully ejected ")
    logging.info('usb at ' + mountpoint + ' is ejected.')

usb_insertion_monitor()