import hashlib
import os
import pyudev
import psutil
from tinydb import TinyDB, Query

db = TinyDB("db.json")
def check(dir):
  # assign directory
  directory = dir

  File = Query()

  # iterate over files in
  # that directory
  for filename in os.listdir(directory):
      f = os.path.join(directory, filename)
      # checking if it is a file
      if os.path.isfile(f):

          # first get all lines from file
          with open(f, 'r') as fi:
              lines = fi.readlines()

          # remove spaces
          lines = [line.replace(' ', '') for line in lines]
          lines = [line.lower() for line in lines]

          # finally, write lines in the file
          with open(f, 'w') as fi:
              fi.writelines(lines)

          open_file = open(f, "rb")
          read_file = open_file.read()
          hashed_file = hashlib.sha256()
          hashed_file.update(read_file)
          results = db.search(File.hash == hashed_file.hexdigest())
          if results:
              print("virus in", filename) 


context = pyudev.Context()
while True:
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by('usb')
    monitor.start()
    for device in iter(monitor.poll, None):
        if device.action == 'add':
            for p in psutil.disk_partitions(False):
                if 'media' in p.mountpoint:
                    print(p.mountpoint)
                    check(p.mountpoint)