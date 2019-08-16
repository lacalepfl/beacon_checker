# Unicorn beacon checker

Script to verify the data of a unicorn beacon output.

The script:
  - implemented with python 3
  - need 4 files:
    - the seed file
    - the file with values
    - the image file
    - the encrypted image file


A example of file is given

The seeds file, the image file and the encrypted image file can all be downloaded the links on the website archives page
The values file can be a copy-paste of the website page
What is important for the file with the value is:
  - It contains the 4 value: Beacon value, Witness, Commitment, n
  - One line for each value, formated as: the name, then a colon and a space, then the value in the hexadecimal format as given on the site
    - dummy example: Beacon value: 1c3f337c5ba0e2359bcb2b2798dd83c4013d530578057f89

Another possibility is to download the zip file with the files ready to be used.


running:
python3 checker.py seedsfile valuefile imagefile encryptedimagefile

