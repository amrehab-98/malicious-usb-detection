# Malicious USB DETECTION
## Installing Dependencies
After making sure python3 and pip3 are installed.
```bash
foo@bar:~$ pip3 install pyudev
foo@bar:~$ pip3 install psutil
foo@bar:~$ pip3 install tinydb
```
## Adding to the database
Add files you want to mark as malicious to the hash_compare directory in the main project directory.

```bash
foo@bar:~$ python3 malicious_files.py
```
## Run the program
Run this command to keep the program running in the terminal
```bash
foo@bar:~$ python3 hash_sec.py
```
## Scenario
While the program is runnning insert the USB to be scanned.
The program will scan the USB and notify the user if there were any malicious files found. The user then chooses whether to delete the files or not.
If the user chooses not to delete the malicious files the USB will be ejected automatically.