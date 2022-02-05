import hashlib
import os
from tinydb import TinyDB, Query

db = TinyDB("db.json")

directory = './hash_compare/'

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

        file = open(f, "rb")
        read_file = file.read()
        hashed_file = hashlib.sha256()
        hashed_file.update(read_file)
        db.insert({'hash':hashed_file.hexdigest()})