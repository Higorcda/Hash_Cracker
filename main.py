
from optparse import OptionParser
from hashlib import sha1, sha224, sha256, sha384, sha512, md5
from threading import Thread
from os.path import exists, isfile, basename
from time import sleep
from sys import exit

valid_hash_formats = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5']

hash_functions = {}

for hash_format in valid_hash_formats:
    hash_functions[hash_format] = locals()[hash_format]

parser = OptionParser('''\n
Arguments

(-d, --decrypt): Hashes
(-f, --default-format): Default Format - Valid: SHA1, SHA224, SHA256, SHA384, SHA512, MD5
(-w, --wordlist): Wordlist
''')

arguments = [
    { 'argument': ['-d', '--decrypt'], 'dest': 'decrypt', 'type': 'string', 'help': 'Hashes' },
    { 'argument': ['-f', '--default-format'], 'dest': 'default_format', 'type': 'string', 'help': 'Default Hash Format' },
    { 'argument': ['-w', '--wordlist'], 'dest': 'wordlist', 'type': 'string', 'help': 'Wordlist' }
]

for argument in arguments:
    parser.add_option(argument['argument'][0], argument['argument'][1], dest = argument['dest'], type = argument['type'], help = argument['help'])

(options, args) = parser.parse_args()

(decrypt, default_format, wordlist) = (options.decrypt, options.default_format, options.wordlist)

errors = []

if (decrypt is None):
    errors.append('Enter the Decrypt Argument (%s, %s)' % (arguments[0]['argument'][0], arguments[0]['argument'][1]))

if ((default_format is not None) and (default_format not in valid_hash_formats)):
    errors.append('Invalid Hash Format (%s) - Valid: %s' % (default_format, (', '.join(valid_hash_formats))))

if (wordlist is None):
    errors.append('Enter the Wordlist Argument (%s, %s)' % (arguments[2]['argument'][0], arguments[2]['argument'][1]))

elif (exists(wordlist) is False):
    errors.append('Wordlist File (%s) does not exists' % (basename(wordlist)))

elif (isfile(wordlist) is False):
    errors.append('Invalid Wordlist FIle (%s)' % (basename(wordlist)))

if (len(errors) > 0):
    for error in errors:

        print('Error: %s' % (error))

    exit()

hashes = []

if (':' in decrypt):
    for _hash_ in decrypt.split(':'): hashes.append(_hash_)

elif ((exists(decrypt) is True) and (isfile(decrypt) is True)):
    with open(decrypt, 'r', encoding = 'latin-1') as read:

        for _hash_ in read.readlines(): hashes.append(_hash_.strip('\n'))

else:
    hashes.append(decrypt)

wordlist_lines = []

with open(wordlist, 'r', encoding = 'latin-1') as read:
    for line in read.readlines():

        wordlist_lines.append(line.strip('\n'))

wordlist = wordlist_lines

class crack:

    def start(self, _hash_, thread_identifier):

        self._hash_ = _hash_.lower()

        main_status = False

        for content in wordlist:
            (status, hash_format, value) = self._try_(content.encode('utf-8'))

            if ((status is False) and (hash_format is None) and (value is None)): continue

            print('[Thread: %d][Hash: %s][Format: %s] Value: %s' % (thread_identifier, self._hash_, hash_format.upper(), value.decode()))

            main_status = True

        if (main_status is False):
            print('[Thread: %d][Hash: %s] No value found...')

    def _try_(self, content):

        hashed_content = None 

        if (default_format is not None):
            
            hashed_content = hash_functions[default_format](content).hexdigest().lower()

            if (hashed_content != self._hash_): return (False, None, None)
                
            return (True, default_format, content)

        for hash_format in valid_hash_formats:
            hashed_content = hash_functions[hash_format](content).hexdigest().lower()

            if (hashed_content != self._hash_): continue 

            return (True, hash_format, content)
        
        return (False, None, None)

if (__name__ == '__main__'):

    print('\nCracker Running...\n\n%s\n' % ('-' * 80))

    crack = crack()

    thread_identifier = 1

    for _hash_ in hashes:
        Thread(target = crack.start, args = (_hash_, thread_identifier,)).start()

        thread_identifier += 1

        sleep(10)