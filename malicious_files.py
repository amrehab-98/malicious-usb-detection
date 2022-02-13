import hashlib
import os
from tinydb import TinyDB, Query

db = TinyDB("db.json")

directory = './hash_compare/'

File = Query()
def update_db(directory):
    '''
    This functions is responsible for adding malicious files hashes to the database.

    Parameters:
    directory: Path of the directory that contains malicious files.
    '''

    for root, dirs, files in os.walk(directory):
        for file in files:
            with open(os.path.join(root, file), 'rb') as data:
                hashed_file = hashlib.sha256()
                for byte_block in iter(lambda: data.read(4096),b""):
                    hashed_file.update(byte_block)

            results = db.search(File.hash == hashed_file.hexdigest()) 
            if not results:       
                db.insert({'hash':hashed_file.hexdigest()})

update_db(directory)