#!/usr/bin/env python3

# Methodology provided by Martin Bos (pure_hate) - https://www.trustedsec.com/team/martin-bos/
# Original script created by Larry Spohn (spoonman) - https://www.trustedsec.com/team/larry-spohn/
# Python refactoring and general fixing, Justin Bollinger (bandrel) - https://www.trustedsec.com/team/justin-bollinger/
# Hashview integration by Justin Bollinger (bandrel) and Claude Sonnet 4.5 
#   special thanks to hans for all his hard work on hashview and creating APIs for us to use 

import subprocess
import sys
import os
import random
import re
import json
import binascii
import shutil
import readline
import glob

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# python2/3 compatability
try:
    input = raw_input
except NameError:
    
    pass

hate_path = os.path.dirname(os.path.realpath(__file__))
if not os.path.isfile(hate_path + '/config.json'):
    print('Initializing config.json from config.json.example')
    shutil.copy(hate_path + '/config.json.example',hate_path + '/config.json')

with open(hate_path + '/config.json') as config:
    config_parser = json.load(config)

with open(hate_path + '/config.json.example') as defaults:
    default_config = json.load(defaults)

hcatPath = config_parser['hcatPath']
hcatBin = config_parser['hcatBin']
hcatTuning = config_parser['hcatTuning']
hcatWordlists = config_parser['hcatWordlists']
hcatOptimizedWordlists = config_parser['hcatOptimizedWordlists']
hcatRules = []

try:
    maxruntime = config_parser['bandrelmaxruntime']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    maxruntime = default_config['bandrelmaxruntime']

try:
    bandrelbasewords = config_parser['bandrel_common_basedwords']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    bandrelbasewords = default_config['bandrel_common_basedwords']

try:

    pipal_count = config_parser['pipal_count']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    pipal_count = default_config['pipal_count']

try:
    pipalPath = config_parser['pipalPath']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    pipalPath = default_config['pipalPath']

try:
    hcatDictionaryWordlist = config_parser['hcatDictionaryWordlist']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatDictionaryWordlist = default_config['hcatDictionaryWordlist']
try:
    hcatHybridlist = config_parser['hcatHybridlist']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatHybridlist = default_config[e.args[0]]
try:
    hcatCombinationWordlist = config_parser['hcatCombinationWordlist']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatCombinationWordlist = default_config[e.args[0]]
try:
    hcatMiddleCombinatorMasks = config_parser['hcatMiddleCombinatorMasks']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatMiddleCombinatorMasks = default_config[e.args[0]]
try:
    hcatMiddleBaseList = config_parser['hcatMiddleBaseList']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatMiddleBaseList = default_config[e.args[0]]
try:
    hcatThoroughCombinatorMasks = config_parser['hcatThoroughCombinatorMasks']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatThoroughCombinatorMasks = default_config[e.args[0]]
try:
    hcatThoroughBaseList = config_parser['hcatThoroughBaseList']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatThoroughBaseList = default_config[e.args[0]]
try:
    hcatPrinceBaseList = config_parser['hcatPrinceBaseList']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatPrinceBaseList = default_config[e.args[0]]
try:
    hcatGoodMeasureBaseList = config_parser['hcatGoodMeasureBaseList']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatGoodMeasureBaseList = default_config[e.args[0]]

try:
    hashview_url = config_parser['hashview_url']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hashview_url = default_config.get('hashview_url', 'https://localhost:8443')

try:
    hashview_api_key = config_parser['hashview_api_key']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hashview_api_key = default_config.get('hashview_api_key', '')


hcatExpanderBin = "expander.bin"
hcatCombinatorBin = "combinator.bin"
hcatPrinceBin = "pp64.bin"

def verify_wordlist_dir(directory, wordlist):
    if os.path.isfile(wordlist):
        return wordlist
    elif os.path.isfile(directory + '/' + wordlist):
        return directory + '/' + wordlist
    else:
        print('Invalid path for {0}. Please check configuration and try again.'.format(wordlist))
        quit(1)

# hashcat biniary checks for systems that install hashcat binary in different location than the rest of the hashcat files
if hcatPath:
    candidate = hcatPath.rstrip('/') + '/' + hcatBin
    if os.path.isfile(candidate):
        hcatBin = candidate
    elif os.path.isfile(hcatBin):
        pass
    else:
        print('Invalid path for hashcat binary. Please check configuration and try again.')
        quit(1)
else:
    # No hcatPath set, just use hcatBin (should be in PATH)
    if shutil.which(hcatBin) is None:
        print('Hashcat binary not found in PATH. Please check configuration and try again.')
        quit(1)

# Verify hashcat-utils binaries exist and work
hashcat_utils_path = hate_path + '/hashcat-utils/bin'
required_binaries = [
    (hcatExpanderBin, 'expander'),
    (hcatCombinatorBin, 'combinator'),
]

for binary, name in required_binaries:
    binary_path = hashcat_utils_path + '/' + binary
    if not os.path.isfile(binary_path):
        print(f'Error: {name} binary not found at {binary_path}')
        print('Please ensure hashcat-utils is properly installed.')
        quit(1)
    # Check if binary is executable
    if not os.access(binary_path, os.X_OK):
        print(f'Error: {name} binary at {binary_path} is not executable')
        print('Try running: chmod +x {0}'.format(binary_path))
        quit(1)
    # Test binary execution
    try:
        test_result = subprocess.run(
            [binary_path], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=2
        )
        # Binary should show usage and exit with error code (that's expected)
        # If we get here without exception, the binary is executable
    except subprocess.TimeoutExpired:
        # Timeout is fine - means binary is running
        pass
    except Exception as e:
        print(f'Error: {name} binary at {binary_path} failed to execute: {e}')
        print('The binary may be compiled for the wrong architecture.')
        print('Try recompiling hashcat-utils for your system.')
        quit(1)

# Verify princeprocessor binary
prince_path = hate_path + '/princeprocessor/' + hcatPrinceBin
if not os.path.isfile(prince_path):
    print(f'Warning: PRINCE binary not found at {prince_path}')
    print('PRINCE attacks will not be available.')
elif not os.access(prince_path, os.X_OK):
    print(f'Warning: PRINCE binary at {prince_path} is not executable')
    print('Try running: chmod +x {0}'.format(prince_path))

#verify and convert wordlists to fully qualified paths
hcatMiddleBaseList = verify_wordlist_dir(hcatWordlists, hcatMiddleBaseList)
hcatThoroughBaseList = verify_wordlist_dir(hcatWordlists, hcatThoroughBaseList)
hcatPrinceBaseList = verify_wordlist_dir(hcatWordlists, hcatPrinceBaseList)
hcatGoodMeasureBaseList = verify_wordlist_dir(hcatWordlists, hcatGoodMeasureBaseList)
for x in range(len(hcatDictionaryWordlist)):
    hcatDictionaryWordlist[x] = verify_wordlist_dir(hcatWordlists, hcatDictionaryWordlist[x])
for x in range(len(hcatHybridlist)):
    hcatHybridlist[x] = verify_wordlist_dir(hcatWordlists, hcatHybridlist[x])
hcatCombinationWordlist[0] = verify_wordlist_dir(hcatWordlists, hcatCombinationWordlist[0])
hcatCombinationWordlist[1] = verify_wordlist_dir(hcatWordlists, hcatCombinationWordlist[1])


hcatHashCount = 0
hcatHashCracked = 0
hcatBruteCount = 0
hcatDictionaryCount = 0
hcatMaskCount = 0
hcatFingerprintCount = 0
hcatCombinationCount = 0
hcatHybridCount = 0
hcatExtraCount = 0
hcatRecycleCount = 0
hcatProcess = 0
debug_mode = True


# Sanitize filename for use as hashcat session name
def generate_session_id():
    """Sanitize the hashfile name for use as a hashcat session name
    
    Hashcat session names can only contain alphanumeric characters, hyphens, and underscores.
    This function removes the file extension and replaces problematic characters.
    """
    # Get just the filename without path
    filename = os.path.basename(hcatHashFile)
    # Remove extension
    name_without_ext = os.path.splitext(filename)[0]
    # Replace any non-alphanumeric chars (except - and _) with underscore
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', name_without_ext)
    return sanitized


# Help
def usage():
    print("usage: python hate_crack.py <hash_file> <hash_type>")
    print("\nThe <hash_type> is attained by running \"{hcatBin} --help\"\n".format(hcatBin=hcatBin))
    print("Example Hashes: http://hashcat.net/wiki/doku.php?id=example_hashes\n")


def ascii_art():
    print(r"""

  ___ ___         __             _________                       __    
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    < 
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
                          Version 1.09
  """)


# File selector with tab autocomplete
def select_file_with_autocomplete(prompt, default=None, allow_multiple=False):
    """
    Interactive file selector with tab autocomplete functionality.
    
    Args:
        prompt: The prompt to display to the user
        default: Optional default value if user presses Enter
        allow_multiple: If True, allows comma-separated file list
    
    Returns:
        String path or list of paths (if allow_multiple=True)
    """
    def path_completer(text, state):
        """Tab completion function for file paths"""
        if not text:
            text = './'
        
        # Expand ~ to home directory
        text = os.path.expanduser(text)
        
        # Handle both absolute and relative paths
        if text.startswith('/') or text.startswith('./') or text.startswith('../') or text.startswith('~'):
            matches = glob.glob(text + '*')
        else:
            matches = glob.glob('./' + text + '*')
            matches = [m[2:] if m.startswith('./') else m for m in matches]
        
        # Add trailing slash for directories
        matches = [m + '/' if os.path.isdir(m) else m for m in matches]
        
        try:
            return matches[state]
        except IndexError:
            return None
    
    # Configure readline for tab completion
    readline.set_completer_delims(' \t\n;')
    # Disable the "Display all X possibilities?" prompt
    try:
        readline.parse_and_bind("set completion-query-items -1")
    except:
        pass
    try:
        readline.parse_and_bind("tab: complete")
    except:
        pass
    try:
        readline.parse_and_bind("bind ^I rl_complete")
    except:
        pass
    readline.set_completer(path_completer)
    
    # Build prompt
    full_prompt = f"\n{prompt}"
    if default:
        full_prompt += f" (default: {default})"
    full_prompt += ": "
    
    result = input(full_prompt).strip()
    
    # Handle default
    if not result and default:
        return default
    
    # Handle multiple files
    if allow_multiple and ',' in result:
        files = [f.strip() for f in result.split(',')]
        return [os.path.expanduser(f) for f in files if f]
    
    return os.path.expanduser(result) if result else None


# Counts the number of lines in a file
def lineCount(file):
    try:
        with open(file) as outFile:
            count = 0
            for line in outFile:
                count = count + 1
        return count
    except:
        return 0

# Brute Force Attack
def hcatBruteForce(hcatHashType, hcatHashFile, hcatMinLen, hcatMaxLen):
    global hcatBruteCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcbin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out --increment --increment-min={min} "
        "--increment-max={max} -a 3 ?a?a?a?a?a?a?a?a?a?a?a?a?a?a {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcbin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            min=hcatMinLen,
            max=hcatMaxLen,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatBruteCount = lineCount(hcatHashFile + ".out")


# Dictionary Attack
def hcatDictionary(hcatHashType, hcatHashFile):
    global hcatDictionaryCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hcatHashType} {hash_file} --session {session_name} -o {hash_file}.out {optimized_wordlists}/* "
        "-r {hcatPath}/rules/best66.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            optimized_wordlists=hcatOptimizedWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()


    for wordlist in hcatDictionaryWordlist:
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hcatHashType} {hash_file} --session {session_name} -o {hash_file}.out {hcatWordlist} "
            "-r {hcatPath}/rules/d3ad0ne.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatPath=hcatPath,
                hcatBin=hcatBin,
                hcatHashType=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                hcatWordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()


        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hcatHashType} {hash_file} --session {session_name} -o {hash_file}.out {hcatWordlist} "
            "-r {hcatPath}/rules/T0XlC.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatPath=hcatPath,
                hcatBin=hcatBin,
                hcatHashType=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                hcatWordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

    hcatDictionaryCount = lineCount(hcatHashFile + ".out") - hcatBruteCount


# Quick Dictionary Attack (Optional Chained Rules)
def hcatQuickDictionary(hcatHashType, hcatHashFile, hcatChains, wordlists):
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hcatHashType} {hash_file} --session {session_name} -o {hash_file}.out "
        "'{wordlists}' {chains} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            wordlists=wordlists,
            chains=hcatChains,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()



# Top Mask Attack
def hcatTopMask(hcatHashType, hcatHashFile, hcatTargetTime):
    global hcatMaskCount
    global hcatProcess
    subprocess.Popen(
        "cat {hash_file}.out | cut -d : -f 2 > {hash_file}.working".format(
            hash_file=hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hate_path}/PACK/statsgen.py {hash_file}.working -o {hash_file}.masks".format(
            hash_file=hcatHashFile,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatProcess = subprocess.Popen(
        "{hate_path}/PACK/maskgen.py {hash_file}.masks --targettime {target_time} --optindex -q --pps 14000000000 "
        "--minlength=7 -o {hash_file}.hcmask".format(
            hash_file=hcatHashFile,
            target_time=hcatTargetTime,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 3 {hash_file}.hcmask {tuning} "
        "--potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatMaskCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Fingerprint Attack
def hcatFingerprint(hcatHashType, hcatHashFile):
    global hcatFingerprintCount
    global hcatProcess
    crackedBefore = lineCount(hcatHashFile + ".out")
    crackedAfter = 0
    while crackedBefore != crackedAfter:
        crackedBefore = lineCount(hcatHashFile + ".out")
        subprocess.Popen("cat {hash_file}.out | cut -d : -f 2 > {hash_file}.working".format(
            hash_file=hcatHashFile), shell=True).wait()
        hcatProcess = subprocess.Popen(
            "{hate_path}/hashcat-utils/bin/{expander_bin} < {hash_file}.working | sort -u > {hash_file}.expanded".format(
                expander_bin=hcatExpanderBin,
                hash_file=hcatHashFile,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 {hash_file}.expanded "
            "{hash_file}.expanded {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()
        crackedAfter = lineCount(hcatHashFile + ".out")
    hcatFingerprintCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Combinator Attack
def hcatCombination(hcatHashType, hcatHashFile):
    global hcatCombinationCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 {left} "
        "{right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            word_lists=hcatWordlists,
            left=hcatCombinationWordlist[0],
            right=hcatCombinationWordlist[1],
            tuning=hcatTuning,
            hate_path=hate_path),
        shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatCombinationCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Hybrid Attack
def hcatHybrid(hcatHashType, hcatHashFile, wordlists=None):
    global hcatHybridCount
    global hcatProcess
    
    # Use provided wordlists or fall back to config default
    if wordlists is None:
        wordlists = hcatHybridlist
    
    # Ensure wordlists is a list
    if not isinstance(wordlists, list):
        wordlists = [wordlists]
    
    for wordlist in wordlists:
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 6 -1 ?s?d {wordlist} ?1?1 "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 6 -1 ?s?d {wordlist} ?1?1?1 "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 6 -1 ?s?d {wordlist} "
            "?1?1?1?1 {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 7 -1 ?s?d ?1?1 {wordlist} "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 7 -1 ?s?d ?1?1?1 {wordlist} "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 7 -1 ?s?d ?1?1?1?1 {wordlist} "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatHybridCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# YOLO Combination Attack
def hcatYoloCombination(hcatHashType, hcatHashFile):
    global hcatProcess
    try:
        while 1:
            hcatLeft = random.choice(os.listdir(hcatOptimizedWordlists))
            hcatRight = random.choice(os.listdir(hcatOptimizedWordlists))
            hcatProcess = subprocess.Popen(
                "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 {optimized_lists}/{left} "
                "{optimized_lists}/{right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=generate_session_id(),
                    word_lists=hcatWordlists,
                    optimized_lists=hcatOptimizedWordlists,
                    tuning=hcatTuning,
                    left=hcatLeft,
                    right=hcatRight,
                    hate_path=hate_path), shell=True)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print('Killing PID {0}...'.format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
    except KeyboardInterrupt:
        pass

# Bandrel methodlogy
def hcatBandrel(hcatHashType, hcatHashFile):
    global hcatProcess
    basewords = []
    while True:
        company_name = input('What is the company name (Enter multiples comma separated)? ')
        if company_name:
            break
    for name in company_name.split(','):
        basewords.append(name)
    for word in bandrelbasewords.split(','):
        basewords.append(word)
    for name in basewords:
        mask1 = '-1{0}{1}'.format(name[0].lower(),name[0].upper())
        mask2 = ' ?1{0}'.format(name[1:])
        for x in range(6):
            mask2 += '?a'
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} -a 3 --session {session_name} -o {hash_file}.out "
            "{tuning} --potfile-path={hate_path}/hashcat.pot --runtime {maxruntime} -i {hcmask1} {hash_file} {hcmask2}".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                tuning=hcatTuning,
                hcmask1=mask1,
                hcmask2=mask2,
                maxruntime=maxruntime,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()
    print('Checking passwords against pipal for top {0} passwords and basewords'.format(pipal_count))
    pipal_basewords = pipal()
    for word in pipal_basewords:
        mask1 = '-1={0}{1}'.format(word[0].lower(),word[0].upper())
        mask2 = ' ?1{0}'.format(word[1:])
        for x in range(6):
            mask2 += '?a'
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} -a 3 --session {session_name} -o {hash_file}.out "
            "{tuning} --potfile-path={hate_path}/hashcat.pot --runtime {maxruntime} -i {hcmask1} {hash_file} {hcmask2}".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=generate_session_id(),
                tuning=hcatTuning,
                hcmask1=mask1,
                hcmask2=mask2,
                maxruntime=maxruntime,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

# Middle fast Combinator Attack
def hcatMiddleCombinator(hcatHashType, hcatHashFile):
    global hcatProcess
    masks = hcatMiddleCombinatorMasks
    # Added support for multiple character masks
    new_masks = []
    for mask in masks:
        tmp = []
        if len(mask) > 1:
            for character in mask:
                tmp.append(character)
            new_masks.append('$' + '$'.join(tmp))
        else:
            new_masks.append('$'+mask)
    masks = new_masks

    try:
        for x in range(len(masks)):
            hcatProcess = subprocess.Popen(
                "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 -j '${middle_mask}' {left} "
                "{right} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=generate_session_id(),
                    left=hcatMiddleBaseList,
                    right=hcatMiddleBaseList,
                    tuning=hcatTuning,
                    middle_mask=masks[x],
                    hate_path=hate_path),
                shell=True)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print('Killing PID {0}...'.format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
    except KeyboardInterrupt:
        pass

# Middle thorough Combinator Attack
def hcatThoroughCombinator(hcatHashType, hcatHashFile):
    global hcatProcess
    masks = hcatThoroughCombinatorMasks
    # Added support for multiple character masks
    new_masks = []
    for mask in masks:
        tmp = []
        if len(mask) > 1:
            for character in mask:
                tmp.append(character)
            new_masks.append('$' + '$'.join(tmp))
        else:
            new_masks.append('$'+mask)
    masks = new_masks

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 {left} "
        "{right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            left=hcatThoroughBaseList,
            right=hcatThoroughBaseList,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path),
        shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    try:
        for x in range(len(masks)):
            hcatProcess = subprocess.Popen(
                "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 "
                "-j '${middle_mask}' {left} {right} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=generate_session_id(),
                    left=hcatThoroughBaseList,
                    right=hcatThoroughBaseList,
                    word_lists=hcatWordlists,
                    tuning=hcatTuning,
                    middle_mask=masks[x],
                    hate_path=hate_path),
                    shell=True)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print('Killing PID {0}...'.format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
    except KeyboardInterrupt:
        pass
    try:
        for x in range(len(masks)):
            hcatProcess = subprocess.Popen(
              "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 "
              "-k '${end_mask}' {left} {right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=generate_session_id(),
                    left=hcatThoroughBaseList,
                    right=hcatThoroughBaseList,
                    word_lists=hcatWordlists,
                    tuning=hcatTuning,
                    end_mask=masks[x],
                    hate_path=hate_path),
                    shell=True)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print('Killing PID {0}...'.format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
    except KeyboardInterrupt:
        pass
    try:
        for x in range(len(masks)):
            hcatProcess = subprocess.Popen(
              "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 "
              "-j '${middle_mask}' -k '${end_mask}' {left} {right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=generate_session_id(),
                    left=hcatThoroughBaseList,
                    right=hcatThoroughBaseList,
                    word_lists=hcatWordlists,
                    tuning=hcatTuning,
                    middle_mask=masks[x],
                    end_mask=masks[x],
                    hate_path=hate_path),
                    shell=True)
            hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

# Pathwell Mask Brute Force Attack
def hcatPathwellBruteForce(hcatHashType, hcatHashFile):
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 3 {hate_path}/masks/pathwell.hcmask "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()


# PRINCE Attack
def hcatPrince(hcatHashType, hcatHashFile):
    global hcatProcess
    hcatHashCracked = lineCount(hcatHashFile + ".out")
    hcatProcess = subprocess.Popen(
        "{hate_path}/princeprocessor/{prince_bin} --case-permute --elem-cnt-min=1 --elem-cnt-max=16 -c < "
        "{hcatPrinceBaseList} | {hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out "
        "-r {hate_path}/princeprocessor/rules/prince_optimized.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            prince_bin=hcatPrinceBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            hcatPrinceBaseList=hcatPrinceBaseList,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

# Extra - Good Measure
def hcatGoodMeasure(hcatHashType, hcatHashFile):
    global hcatExtraCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -r {hcatPath}/rules/combinator.rule "
        "-r {hcatPath}/rules/InsidePro-PasswordsPro.rule {hcatGoodMeasureBaseList} {tuning} "
        "--potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            hcatGoodMeasureBaseList=hcatGoodMeasureBaseList,
            session_name=generate_session_id(),
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatExtraCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# LanMan to NT Attack
def hcatLMtoNT():
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m 3000 {hash_file}.lm > {hash_file}.lm.cracked".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m 3000 {hash_file}.lm --session {session_name} -o {hash_file}.lm.cracked -1 ?u?d?s --increment -a 3 ?1?1?1?1?1?1?1 "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        hcatProcess.kill()

    subprocess.Popen("cat {hash_file}.lm.cracked | cut -d : -f 2 > {hash_file}.working".format(
        hash_file=hcatHashFile), shell=True).wait()
    converted = convert_hex("{hash_file}.working".format(hash_file=hcatHashFile))
    with open("{hash_file}.working".format(hash_file=hcatHashFile),mode='w') as working:
        working.writelines('\n'.join(converted))
    hcatProcess = subprocess.Popen(
        "{hate_path}/hashcat-utils/bin/{combine_bin} {hash_file}.working {hash_file}.working | sort -u > {hash_file}.combined".format(
            combine_bin=hcatCombinatorBin,
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatProcess = subprocess.Popen(
        "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m 1000 {hash_file}.nt > {hash_file}.nt.out".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m 1000 {hash_file}.nt --session {session_name} -o {hash_file}.nt.out {hash_file}.combined "
        "-r {hate_path}/rules/toggles-lm-ntlm.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            session_name=generate_session_id(),
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

    # toggle-lm-ntlm.rule by Didier Stevens https://blog.didierstevens.com/2016/07/16/tool-to-generate-hashcat-toggle-rules/


# Recycle Cracked Passwords
def hcatRecycle(hcatHashType, hcatHashFile, hcatNewPasswords):
    global hcatProcess
    working_file = hcatHashFile + '.working'
    if hcatNewPasswords > 0:
        hcatProcess = subprocess.Popen("cat {hash_file}.out | cut -d : -f 2 > {working_file}".format(
            hash_file=hcatHashFile, working_file=working_file), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        converted = convert_hex(working_file)

        # Overwrite working file with updated converted words
        with open(working_file, 'w') as f:
            f.write("\n".join(converted))
        for rule in hcatRules:
            hcatProcess = subprocess.Popen(
                "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out {hash_file}.working "
                "-r {hcatPath}/rules/{rule} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                    rule=rule,
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=generate_session_id(),
                    hcatPath=hcatPath,
                    tuning=hcatTuning,
                    hate_path=hate_path), shell=True)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                hcatProcess.kill()

def check_potfile():
    print("Checking POT file for already cracked hashes...")
    subprocess.Popen(
        "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m {hash_type} {hash_file} > {hash_file}.out".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            hate_path=hate_path), shell=True)
    hcatHashCracked = lineCount(hcatHashFile + ".out")
    if hcatHashCracked > 0:
        print("Found %d hashes already cracked.\nCopied hashes to %s.out" % (hcatHashCracked, hcatHashFile))
    else:
        print("No hashes found in POT file.")

# creating the combined output for pwdformat + cleartext
def combine_ntlm_output():
    hashes = {}
    check_potfile()
    with open(hcatHashFile + ".out", "r") as hcatCrackedFile:
        for crackedLine in hcatCrackedFile:
            hash, password = crackedLine.split(':')
            hashes[hash] = password.rstrip()
    with open(hcatHashFileOrig + ".out", "w+") as hcatCombinedHashes:
        with open(hcatHashFileOrig, "r") as hcatOrigFile:
            for origLine in hcatOrigFile:
                if origLine.split(':')[3] in hashes:
                    password = hashes[origLine.split(':')[3]]
                    hcatCombinedHashes.write(origLine.strip()+password+'\n')

# Cleanup Temp Files
def cleanup():
    global pwdump_format
    global hcatHashFileOrig
    try:
        if hcatHashType == "1000" and pwdump_format:
            print("\nComparing cracked hashes to original file...")
            combine_ntlm_output()
        print("\nCracked passwords combined with original hashes in %s" % (hcatHashFileOrig + ".out"))
        print('\nCleaning up temporary files...')
        if os.path.exists(hcatHashFile + ".masks"):
            os.remove(hcatHashFile + ".masks")
        if os.path.exists(hcatHashFile + ".working"):
            os.remove(hcatHashFile + ".working")
        if os.path.exists(hcatHashFile + ".expanded"):
            os.remove(hcatHashFile + ".expanded")
        if os.path.exists(hcatHashFileOrig + ".combined"):
            os.remove(hcatHashFileOrig + ".combined")
        if os.path.exists(hcatHashFileOrig + ".lm"):
            os.remove(hcatHashFileOrig + ".lm")
        if os.path.exists(hcatHashFileOrig + ".lm.cracked"):
            os.remove(hcatHashFileOrig + ".lm.cracked")
        if os.path.exists(hcatHashFileOrig + ".working"):
            os.remove(hcatHashFileOrig + ".working")
        if os.path.exists(hcatHashFileOrig + ".passwords"):
            os.remove(hcatHashFileOrig + ".passwords")
    except KeyboardInterrupt:
        #incase someone mashes the Control+C it will still cleanup
        cleanup()

# Hashview Integration
class HashviewAPI:
    """Upload files to Hashview API"""
    
    FILE_FORMATS = {
        'pwdump': 0,
        'netntlm': 1,
        'kerberos': 2,
        'shadow': 3,
        'user:hash': 4,
        'hash_only': 5,
    }
    
    def __init__(self, base_url, api_key, debug=False):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.debug = debug
        self.session = requests.Session()
        self.session.cookies.set('uuid', api_key)
        # Disable SSL certificate verification for self-signed certificates
        self.session.verify = False
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def upload_wordlist(self, file_path, wordlist_name=None):
        if wordlist_name is None:
            wordlist_name = os.path.basename(file_path)
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        url = f"{self.base_url}/v1/wordlists/add/{wordlist_name}"
        headers = {'Content-Type': 'text/plain'}
        
        print(f"Uploading wordlist: {os.path.basename(file_path)} -> {wordlist_name}")
        response = self.session.post(url, data=file_content, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def upload_hashfile(self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None):
        if hashfile_name is None:
            hashfile_name = os.path.basename(file_path)
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        url = (
            f"{self.base_url}/v1/hashfiles/upload/"
            f"{customer_id}/{file_format}/{hash_type}/{hashfile_name}"
        )
        
        headers = {'Content-Type': 'text/plain'}
        
        print(f"Uploading hashfile: {os.path.basename(file_path)} -> {hashfile_name}")
        response = self.session.post(url, data=file_content, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def upload_cracked_hashes(self, file_path, hash_type='1000'):
        # Read file - API expects plaintext format: hash:plaintext
        print(f"Importing cracked hashes: {os.path.basename(file_path)}")
        print(f"  Reading hash:plaintext pairs...")
        
        valid_lines = []
        line_count = 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if '31d6cfe0d16ae931b73c59d7e0c089c0' in line:
                    continue
                if not line or ':' not in line:
                    continue
                
                parts = line.split(':', 1)
                if len(parts) != 2:
                     break #might need to add encoding into HEX conversion here
                    
                hash_value = parts[0].strip()
                plaintext = parts[1].strip()
                
                # Keep format as-is: hash:plaintext
                valid_lines.append(f"{hash_value}:{plaintext}")
                line_count += 1
        
        # Join all lines into a single string with newline separators
        converted_content = '\n'.join(valid_lines)
        
        print(f"  Processed {line_count} hash:plaintext pairs")
        
        url = f"{self.base_url}/v1/hashes/import/{hash_type}"
        
        # API expects plain text body with hash:plaintext format
        headers = {'Content-Type': 'text/plain'}
        
        print(f"\n  === REQUEST DETAILS ===")
        print(f"  URL: {url}")
        print(f"  Method: POST")
        print(f"  Headers: {headers}")
        print(f"  Cookies: {dict(self.session.cookies)}")
        print(f"  Hash type: {hash_type}")
        print(f"  Content preview (first 500 chars):")
        print(converted_content[:500])
        print(f"\n  Uploading...")
        
        response = self.session.post(url, data=converted_content, headers=headers)
        
        # Debug: print response details
        print(f"\n  === RESPONSE DETAILS ===")
        print(f"  Status code: {response.status_code}")
        print(f"  Response headers: {dict(response.headers)}")
        print(f"  Response content: {response.text[:500]}")
        
        response.raise_for_status()
        
        # Check if response is JSON error
        try:
            json_response = response.json()
            if 'type' in json_response and json_response['type'] == 'Error':
                raise Exception(f"Hashview API Error: {json_response.get('msg', 'Unknown error')}")
            return json_response
        except (json.JSONDecodeError, ValueError) as e:
            # Not valid JSON
            raise Exception(f"Invalid API response: {response.text[:200]}")
    
    def display_customers_multicolumn(self, customers):
        """Display customers in multiple columns to minimize scrolling
        
        Args:
            customers: List of customer dictionaries
        """
        if not customers:
            print("\nNo customers found.")
            return
        
        # Get terminal width, default to 120 if can't determine
        try:
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 120
        
        # Each entry is "ID: Name" - calculate column width
        # Find max ID width
        max_id_len = max(len(str(c.get('id', ''))) for c in customers)
        # Add formatting: "ID: Name  " (ID + ": " + some name space + padding)
        # Use reasonable name width (30 chars) for column sizing
        col_width = max_id_len + 2 + 30 + 2  # ID + ": " + name + padding
        
        # Calculate number of columns that fit
        num_cols = max(1, terminal_width // col_width)
        
        print("\n" + "="*terminal_width)
        print("Available Customers:")
        print("="*terminal_width)
        
        # Organize customers into columns
        num_customers = len(customers)
        rows = (num_customers + num_cols - 1) // num_cols  # Ceiling division
        
        for row in range(rows):
            line_parts = []
            for col in range(num_cols):
                idx = row + col * rows
                if idx < num_customers:
                    customer = customers[idx]
                    cust_id = customer.get('id', 'N/A')
                    cust_name = customer.get('name', 'N/A')
                    # Truncate name to fit column width
                    name_width = col_width - max_id_len - 2 - 2
                    if len(str(cust_name)) > name_width:
                        cust_name = str(cust_name)[:name_width-3] + "..."
                    entry = f"{cust_id}: {cust_name}"
                    line_parts.append(entry.ljust(col_width))
            print("".join(line_parts).rstrip())
        
        print("="*terminal_width)
        print(f"Total: {len(customers)} customer(s)")
    
    def list_customers(self):
        url = f"{self.base_url}/v1/customers"
        
        print("Fetching customer list...")
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        
        # Parse the 'users' JSON string into a list
        if 'users' in data:
            customers = json.loads(data['users'])
            return {'customers': customers}
        
        return data
    
    def list_hashfiles(self):
        """Get all hashfiles from Hashview"""
        url = f"{self.base_url}/v1/hashfiles"
        
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        
        # Parse hashfiles - may be JSON string
        if 'hashfiles' in data:
            if isinstance(data['hashfiles'], str):
                hashfiles = json.loads(data['hashfiles'])
            else:
                hashfiles = data['hashfiles']
            return hashfiles
        
        return []
    
    def get_customer_hashfiles(self, customer_id):
        """Get hashfiles for a specific customer"""
        all_hashfiles = self.list_hashfiles()
        # Filter by customer_id - handle both int and string comparisons
        return [hf for hf in all_hashfiles if int(hf.get('customer_id', 0)) == customer_id]
    
    def create_customer(self, name):
        url = f"{self.base_url}/v1/customers/add"
        headers = {'Content-Type': 'application/json'}
        data = {"name": name}
        
        print(f"Creating customer: {name}")
        response = self.session.post(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def create_job(self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=True):
        url = f"{self.base_url}/v1/jobs/add"
        headers = {'Content-Type': 'application/json'}
        # Only send the minimum required fields - server has issues with notification parameters
        data = {
            "name": name,
            "hashfile_id": hashfile_id,
            "customer_id": customer_id,
            # Note: notify_email and notify_pushover cause server errors - do not send them
        }
        
        print(f"Creating job: {name}")
        response = self.session.post(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def start_job(self, job_id):
        url = f"{self.base_url}/v1/jobs/start/{job_id}"
        
        print(f"Starting job ID: {job_id}")
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()
    
    def list_jobs(self, customer_id=None):
        # The API doesn't have a filter by customer endpoint, get all jobs
        url = f"{self.base_url}/v1/jobs"
        
        if customer_id:
            print(f"Fetching jobs for customer ID {customer_id}...")
        else:
            print("Fetching all jobs...")
        
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        
        # Parse the response - may return 'jobs' as JSON string
        if 'jobs' in data and isinstance(data['jobs'], str):
            jobs = json.loads(data['jobs'])
            # Filter by customer_id if provided
            if customer_id:
                jobs = [job for job in jobs if job.get('customer_id') == customer_id]
            return {'jobs': jobs}
        
        return data
    
    def download_left_hashes(self, customer_id, hashfile_id, output_file=None):
        # Use the proper API v1 endpoint for downloading hashfiles (left only)
        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}"
        
        print(f"Downloading left hashes...")
        print(f"  Customer ID: {customer_id}")
        print(f"  Hashfile ID: {hashfile_id}")
        
        response = self.session.get(url)
        
        # Check if we got HTML (login page) instead of hash data
        if response.content.startswith(b'<!DOCTYPE') or response.content.startswith(b'<html'):
            raise Exception("Authentication failed - received HTML login page instead of hash data.")
        
        response.raise_for_status()
        
        # Check if response is JSON error message
        try:
            json_response = response.json()
            if 'type' in json_response and json_response['type'] == 'Error':
                raise Exception(f"Hashview API Error: {json_response.get('msg', 'Unknown error')}")
        except (json.JSONDecodeError, ValueError):
            # Not JSON, assume it's the actual hash file content
            pass
        
        # If no output file specified, generate one
        if output_file is None:
            output_file = f"left_{customer_id}_{hashfile_id}.txt"
        
        # Write the content to file
        with open(output_file, 'wb') as f:
            f.write(response.content)
        
        file_size = len(response.content)
        # Wrap output to 100 columns
        import textwrap
        message = f"✓ Downloaded {file_size} bytes to {output_file}"
        wrapped = textwrap.fill(message, width=100, subsequent_indent="  ")
        print(wrapped)
        
        return {'output_file': output_file, 'size': file_size}
    
    def list_wordlists(self):
        """Get all available wordlists"""
        url = f"{self.base_url}/v1/wordlists"
        
        print("Fetching wordlists...")
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        
        # Parse the response - may return 'wordlists' as JSON string
        if 'wordlists' in data:
            if isinstance(data['wordlists'], str):
                wordlists = json.loads(data['wordlists'])
                return {'wordlists': wordlists}
            return data
        
        return data
    
    def upload_wordlist(self, wordlist_path, wordlist_name=None):
        """Upload a wordlist to Hashview"""
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
        
        # Use filename if no name provided
        if not wordlist_name:
            wordlist_name = os.path.basename(wordlist_path)
        
        url = f"{self.base_url}/v1/wordlists/add/{wordlist_name}"
        
        print(f"Uploading wordlist: {wordlist_name}")
        print(f"  File: {wordlist_path}")
        
        with open(wordlist_path, 'rb') as f:
            response = self.session.post(url, data=f, headers={'Content-Type': 'text/plain'})
        
        response.raise_for_status()
        result = response.json()
        
        if result.get('type') == 'Error':
            raise Exception(result.get('msg', 'Unknown error'))
        
        return result


def hashview_api():
    """Download/Upload data to Hashview API"""
    global hcatHashFile, hcatHashType
    
    if not REQUESTS_AVAILABLE:
        print("\nError: 'requests' module not found.")
        print("Install it with: pip install requests")
        return
    
    print("\n" + "="*60)
    print("Hashview Integration")
    print("="*60)
    
    # Get Hashview connection details from config
    if not hashview_api_key:
        print("\nError: Hashview API key not configured.")
        print("Please set 'hashview_api_key' in config.json")
        return
    
    print(f"\nConnecting to Hashview at: {hashview_url}")
    
    try:
        api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)
        
        while True:
            print("\n" + "="*60)
            print("What would you like to do?")
            print("="*60)
            print("\t(1) Upload Cracked Hashes from current session")
            # print("\t(2) Create Job")
            print("\t(3) List Customers")
            print("\t(4) Create Customer")
            print("\t(5) Download Left Hashes")
            print("\t(99) Back to Main Menu")
            
            choice = input("\nSelect an option: ")
            
            if choice == '1':
                # Upload cracked hashes
                print("\n" + "-"*60)
                print("Upload Cracked Hashes")
                print("-"*60)
                
                # Check if we're in an active session
                cracked_file = None
                session_file = None
                try:
                    if 'hcatHashFile' in globals() and hcatHashFile:
                        potential_file = hcatHashFile + ".out"
                        if os.path.exists(potential_file):
                            session_file = potential_file
                            print(f"Found session file: {session_file}")
                    elif 'hcatHashFile' in globals() and hcatHashFile:
                        potential_file = hcatHashFile + "nt.out"
                        if os.path.exists(potential_file):
                            session_file = potential_file
                            print(f"Found session file: {session_file}")
                except:
                    pass
                
                # Prompt for file
                if session_file:
                    use_session = input(f"Use this file? (Y/n): ").strip().lower()
                    if use_session != 'n':
                        cracked_file = session_file
                
                if not cracked_file:
                    cracked_file = select_file_with_autocomplete(
                        f"Enter path to cracked hashes file (.out format) [hash type: {hcatHashType}] (TAB to autocomplete)"
                    )
                    if cracked_file:
                        cracked_file = cracked_file.strip()
                
                # Validate file exists
                if not os.path.exists(cracked_file):
                    print(f"✗ Error: File not found: {cracked_file}")
                    continue
                
                # Show file info
                file_size = os.path.getsize(cracked_file)
                with open(cracked_file, 'r') as f:
                    line_count = sum(1 for _ in f)
                print(f"File: {cracked_file}")
                print(f"Size: {file_size} bytes")
                print(f"Lines: {line_count}")
                
                # Use the same hash type from main menu
                hash_type = hcatHashType
                
                # Upload
                print(f"\nUploading to Hashview (hash type: {hash_type})...")
                try:
                    result = api_harness.upload_cracked_hashes(cracked_file, hash_type)
                    print(f"\n✓ Success: {result.get('msg', 'Cracked hashes uploaded')}")
                    if 'count' in result:
                        print(f"  Imported: {result['count']} hashes")
                except Exception as e:
                    print(f"\n✗ Error: {str(e)}")
                    import traceback
                    print("\nFull error details:")
                    traceback.print_exc()
            
            # elif choice == '2':
            #     # Upload hashfile and create job
            #     hashfile_path = select_file_with_autocomplete(
            #         "Enter path to hashfile (TAB to autocomplete)"
            #     )
            #     if not hashfile_path or not os.path.exists(hashfile_path):
            #         print(f"Error: File not found: {hashfile_path}")
            #         continue
                
            #     customer_id = int(input("Enter customer ID: "))
            #     hash_type = int(input(f"Enter hash type (default: {hcatHashType}): ") or hcatHashType)
                
            #     print("\nFile formats:")
            #     print("  0 = pwdump, 1 = NetNTLM, 2 = kerberos")
            #     print("  3 = shadow, 4 = user:hash, 5 = hash_only")
            #     file_format = int(input("Enter file format (default: 5): ") or 5)
                
            #     hashfile_name = input(f"Enter hashfile name (default: {os.path.basename(hashfile_path)}): ") or None
                
            #     try:
            #         result = api_harness.upload_hashfile(
            #             hashfile_path, customer_id, hash_type, file_format, hashfile_name
            #         )
            #         print(f"\n✓ Success: {result.get('msg', 'Hashfile uploaded')}")
            #         if 'hashfile_id' in result:
            #             print(f"  Hashfile ID: {result['hashfile_id']}")
            #             # Hash count is not returned by the upload API, so we don't display it
            #             if 'hash_count' in result:
            #                 print(f"  Hash count: {result['hash_count']}")
            #             if 'instacracked' in result:
            #                 print(f"  Insta-cracked: {result['instacracked']}")
                        
            #             # Offer to create a job
            #             create_job = input("\nWould you like to create a job for this hashfile? (Y/n): ") or "Y"
            #             if create_job.upper() == 'Y':
            #                 job_name = input("Enter job name: ")
            #                 limit_recovered = input("Limit to recovered hashes only? (y/N): ").upper() == 'Y'
            #                 notify_email = input("Send email notifications? (Y/n): ").upper() != 'N'
                            
            #                 # Ask if user wants to upload a custom wordlist for this job
            #                 upload_wordlist = input("\nUpload a custom wordlist to Hashview? (y/N): ").upper() == 'Y'
            #                 uploaded_wordlist_id = None
                            
            #                 if upload_wordlist:
            #                     print("\n" + "="*60)
            #                     print("WORDLIST UPLOAD")
            #                     print("="*60)
            #                     print("Select a wordlist file to upload to Hashview.")
            #                     print("After upload, you'll need to:")
            #                     print("  1. Create a task in Hashview using this wordlist")
            #                     print("  2. Manually add the task to this job via web interface")
            #                     print("\nPress TAB to autocomplete file paths.")
            #                     print("="*60)
                                
            #                     wordlist_path = select_file_with_autocomplete(
            #                         "Enter path to wordlist file"
            #                     )
                                
            #                     if wordlist_path and os.path.isfile(wordlist_path):
            #                         # Ask for wordlist name
            #                         default_name = os.path.basename(wordlist_path)
            #                         wordlist_name = input(f"\nEnter wordlist name (default: {default_name}): ").strip() or default_name
                                    
            #                         try:
            #                             # Upload the wordlist
            #                             upload_result = api_harness.upload_wordlist(wordlist_path, wordlist_name)
            #                             print(f"\n✓ Success: {upload_result.get('msg', 'Wordlist uploaded')}")
            #                             if 'wordlist_id' in upload_result:
            #                                 uploaded_wordlist_id = upload_result['wordlist_id']
            #                                 print(f"  Wordlist ID: {uploaded_wordlist_id}")
            #                                 print(f"  Wordlist Name: {wordlist_name}")
            #                         except Exception as e:
            #                             print(f"\n✗ Error uploading wordlist: {str(e)}")
            #                             print("Continuing with job creation...")
            #                     else:
            #                         print("\n✗ No valid wordlist file selected.")
            #                         print("Continuing with job creation...")
                            
            #                 try:
            #                     job_result = api_harness.create_job(
            #                         job_name, result['hashfile_id'], customer_id,
            #                         limit_recovered, notify_email
            #                     )
            #                     print(f"\n✓ Success: {job_result.get('msg', 'Job created')}")
            #                     if 'job_id' in job_result:
            #                         print(f"  Job ID: {job_result['job_id']}")
            #                         print(f"\nNote: Job created with automatically assigned tasks based on")
            #                         print(f"      historical effectiveness for hash type {hash_type}.")
                                    
            #                         if uploaded_wordlist_id:
            #                             print(f"\n{'='*60}")
            #                             print("NEXT STEPS - Configure Task in Hashview Web Interface:")
            #                             print(f"{'='*60}")
            #                             print(f"1. Go to: {hashview_url}")
            #                             print(f"2. Navigate to Tasks → Create New Task")
            #                             print(f"3. Configure task with:")
            #                             print(f"   - Wordlist ID: {uploaded_wordlist_id} ({wordlist_name})")
            #                             print(f"   - Rule: (select appropriate rule)")
            #                             print(f"   - Attack mode: 0 (dictionary)")
            #                             print(f"4. Go to Jobs → Job ID {job_result['job_id']}")
            #                             print(f"5. Add the new task to this job")
            #                             print(f"{'='*60}")
                                    
            #                         # Offer to start the job
            #                         start_now = input("\nStart the job now? (Y/n): ") or "Y"
            #                         if start_now.upper() == 'Y':
            #                             start_result = api_harness.start_job(job_result['job_id'])
            #                             print(f"\n✓ Success: {start_result.get('msg', 'Job started')}")
            #                 except Exception as e:
            #                     print(f"\n✗ Error creating job: {str(e)}")
            #     except Exception as e:
            #         print(f"\n✗ Error uploading hashfile: {str(e)}")
            
            elif choice == '3':
                # List customers
                try:
                    result = api_harness.list_customers()
                    if 'customers' in result and result['customers']:
                        api_harness.display_customers_multicolumn(result['customers'])
                    else:
                        print("\nNo customers found.")
                except Exception as e:
                    print(f"\n✗ Error fetching customers: {str(e)}")
            
            elif choice == '4':
                # Create customer
                customer_name = input("\nEnter customer name: ")
                try:
                    result = api_harness.create_customer(customer_name)
                    print(f"\n✓ Success: {result.get('msg', 'Customer created')}")
                    if 'customer_id' in result:
                        print(f"  Customer ID: {result['customer_id']}")
                except Exception as e:
                    print(f"\n✗ Error creating customer: {str(e)}")
            
            elif choice == '5':
                # Download left hashes
                try:
                    # First, list customers to help user select
                    result = api_harness.list_customers()
                    if 'customers' in result and result['customers']:
                        api_harness.display_customers_multicolumn(result['customers'])
                    
                    # Get customer ID and hashfile ID directly
                    customer_id = int(input("\nEnter customer ID: "))
                    
                    # List hashfiles for the customer
                    try:
                        customer_hashfiles = api_harness.get_customer_hashfiles(customer_id)
                        
                        if customer_hashfiles:
                            print("\n" + "="*100)
                            print(f"Hashfiles for Customer ID {customer_id}:")
                            print("="*100)
                            print(f"{'ID':<10} {'Name':<88}")
                            print("-" * 100)
                            for hf in customer_hashfiles:
                                hf_id = hf.get('id', 'N/A')
                                hf_name = hf.get('name', 'N/A')
                                # Truncate long names to fit within 100 columns
                                if len(str(hf_name)) > 88:
                                    hf_name = str(hf_name)[:85] + "..."
                                print(f"{hf_id:<10} {hf_name:<88}")
                            print("="*100)
                            print(f"Total: {len(customer_hashfiles)} hashfile(s)")
                        else:
                            print(f"\nNo hashfiles found for customer ID {customer_id}")
                    except Exception as e:
                        print(f"\nWarning: Could not list hashfiles: {e}")
                        print("You may need to manually find the hashfile ID in the web interface.")
                    
                    hashfile_id = int(input("\nEnter hashfile ID: "))
                    
                    # Set output filename automatically
                    output_file = f"left_{customer_id}_{hashfile_id}.txt"

                    # Download the left hashes
                    download_result = api_harness.download_left_hashes(
                        customer_id, hashfile_id, output_file
                    )
                    print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
                    print(f"  File: {download_result['output_file']}")
                    
                    # Ask if user wants to switch to this hashfile
                    switch = input("\nSwitch to this hashfile for cracking? (Y/n): ").strip().lower()
                    if switch != 'n':
                        hcatHashFile = download_result['output_file']
                        print(f"✓ Switched to hashfile: {hcatHashFile}")
                        print("\nReturning to main menu to start cracking...")
                        return  # Exit hashview menu and return to main menu
                        
                except ValueError:
                    print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                except Exception as e:
                    print(f"\n✗ Error downloading hashes: {str(e)}")
            
            elif choice == '99':
                break
            else:
                print("Invalid option. Please try again.")
    
    except KeyboardInterrupt:
        print("\n\nHashview upload canceled.")
    except Exception as e:
        print(f"\nError connecting to Hashview: {str(e)}")


# Quick Dictionary Attack with Optional Chained Rules
def quick_crack():
    # Rules Attack
    wordlist_choice = None
    rule_choice = None
    selected_hcatRules = []

    wordlist_files =  sorted(os.listdir(hcatWordlists))
    print("\nWordlists:")
    for i, file in enumerate(wordlist_files, start=1):
        print(f"{i}. {file}")

    # Setup tab completion for file paths
    def path_completer(text, state):
        """Tab completion function for file paths"""
        if not text:
            # If empty, complete from current directory
            text = './'
        
        # Expand ~ to home directory
        text = os.path.expanduser(text)
        
        # Handle both absolute and relative paths
        if text.startswith('/') or text.startswith('./') or text.startswith('../') or text.startswith('~'):
            # Path-based completion
            matches = glob.glob(text + '*')
        else:
            # Complete from current directory
            matches = glob.glob('./' + text + '*')
            # Remove the ./ prefix for cleaner display
            matches = [m[2:] if m.startswith('./') else m for m in matches]
        
        # Add trailing slash for directories
        matches = [m + '/' if os.path.isdir(m) else m for m in matches]
        
        try:
            return matches[state]
        except IndexError:
            return None
    
    # Configure readline for tab completion
    readline.set_completer_delims(' \t\n;')
    # Disable the "Display all X possibilities?" prompt
    try:
        readline.parse_and_bind("set completion-query-items -1")
    except:
        pass
    # Try both GNU readline and libedit (macOS) key bindings
    try:
        readline.parse_and_bind("tab: complete")
    except:
        pass
    try:
        readline.parse_and_bind("bind ^I rl_complete")
    except:
        pass
    readline.set_completer(path_completer)

    while wordlist_choice is None:
        try:
            raw_choice = input("\nEnter path of wordlist or wordlist directory (tab to autocomplete).\n"
                            "Press Enter for default optimized wordlists [{0}]: ".format(hcatOptimizedWordlists))
            if raw_choice == '':
                wordlist_choice = hcatOptimizedWordlists
            elif os.path.exists(raw_choice):
                wordlist_choice = raw_choice
            elif 1 <= int(raw_choice) <= len(wordlist_files):
                if os.path.exists(hcatWordlists + '/' + wordlist_files[int(raw_choice) - 1]):
                    wordlist_choice = hcatWordlists + '/' + wordlist_files[int(raw_choice) - 1]
                    print(wordlist_choice)
            else:
                wordlist_choice = None
                print('Please enter a valid wordlist or wordlist directory.')
        except ValueError:
            print("Please enter a valid number.")

    rule_files =  sorted(os.listdir(hcatPath + '/rules'))
    print("\nWhich rule(s) would you like to run?")
    print('0. To run without any rules')
    for i, file in enumerate(rule_files, start=1):
        print(f"{i}. {file}")
    print('99. YOLO...run all of the rules')

    while rule_choice is None:
        raw_choice = input('Enter Comma separated list of rules you would like to run. To run rules chained use the + symbol.\n'
                            'For example 1+1 will run {0} chained twice and 1,2 would run {0} and then {1} sequentially.\n'
                            'Choose wisely: '.format(rule_files[0], rule_files[1]))
        if raw_choice != '':
            rule_choice = raw_choice.split(',')

    if '99' in rule_choice:
        for rule in rule_files:
            selected_hcatRules.append('-r {hcatPath}/rules/{selected_rule}'.format(selected_rule=rule, hcatPath=hcatPath))
    elif '0' in rule_choice:
        selected_hcatRules = ['']
    else:
        for choice in rule_choice:
            if '+' in choice:
                combined_choice = ''
                choices = choice.split('+')
                for rule in choices:
                    try:
                        combined_choice = '{0} {1}'.format(combined_choice, '-r {hcatPath}/rules/{selected_rule}'.format(selected_rule=rule_files[int(rule) - 1],
                                                                                                                         hcatPath=hcatPath))
                    except:
                        continue
                selected_hcatRules.append(combined_choice)
            else:
                try:
                    selected_hcatRules.append('-r {hcatPath}/rules/{selected_rule}'.format(selected_rule=rule_files[int(choice) - 1],hcatPath=hcatPath))
                except IndexError:
                    continue

    #Run Quick Crack with each selected rule
    for chain in selected_hcatRules:
         hcatQuickDictionary(hcatHashType, hcatHashFile, chain, wordlist_choice)


# Extensive Pure_Hate Methodology
def extensive_crack():
    # Brute Force Attack
    hcatBruteForce(hcatHashType, hcatHashFile, "1", "7")

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatBruteCount)

    # Dictionary Attack
    hcatDictionary(hcatHashType, hcatHashFile)

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatDictionaryCount)

    # Top Mask Attack
    hcatTargetTime = 4 * 60 * 60  # 4 Hours
    hcatTopMask(hcatHashType, hcatHashFile, hcatTargetTime)

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatMaskCount)

    # Fingerprint Attack
    hcatFingerprint(hcatHashType, hcatHashFile)

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatFingerprintCount)

    # Combination Attack
    hcatCombination(hcatHashType, hcatHashFile)

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatCombinationCount)

    # Hybrid Attack
    hcatHybrid(hcatHashType, hcatHashFile)

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatHybridCount)

    # Extra - Just For Good Measure
    hcatGoodMeasure(hcatHashType, hcatHashFile)

    # Recycle Cracked Passwords
    hcatRecycle(hcatHashType, hcatHashFile, hcatExtraCount)


# Brute Force
def brute_force_crack():
    hcatMinLen = int(input("\nEnter the minimum password length to brute force (1): ") or 1)
    hcatMaxLen = int(input("\nEnter the maximum password length to brute force (7): ") or 7)
    hcatBruteForce(hcatHashType, hcatHashFile, hcatMinLen, hcatMaxLen)


# Top Mask
def top_mask_crack():
    hcatTargetTime = int(input("\nEnter a target time for completion in hours (4): ") or 4)
    hcatTargetTime = hcatTargetTime * 60 * 60
    hcatTopMask(hcatHashType, hcatHashFile, hcatTargetTime)


# Fingerprint
def fingerprint_crack():
    hcatFingerprint(hcatHashType, hcatHashFile)


# Combinator
def combinator_crack():
    hcatCombination(hcatHashType, hcatHashFile)


# Hybrid
def hybrid_crack():
    """Interactive hybrid attack with dynamic wordlist selection"""
    print("\n" + "="*60)
    print("HYBRID ATTACK")
    print("="*60)
    print("This attack combines wordlists with masks to generate candidates.")
    print("Examples:")
    print("  - Mode 6: wordlist + mask (e.g., 'password' + '123')")
    print("  - Mode 7: mask + wordlist (e.g., '123' + 'password')")
    print("="*60)
    
    # Ask if user wants to use config default or select custom wordlist(s)
    use_default = input("\nUse default hybrid wordlist from config? (Y/n): ").strip().lower()
    
    if use_default != 'n':
        # Use config default
        print(f"\nUsing default wordlist(s) from config:")
        if isinstance(hcatHybridlist, list):
            for wl in hcatHybridlist:
                print(f"  - {wl}")
            wordlists = hcatHybridlist
        else:
            print(f"  - {hcatHybridlist}")
            wordlists = [hcatHybridlist]
    else:
        # Let user select wordlist(s)
        print("\nSelect wordlist(s) for hybrid attack.")
        print("You can enter:")
        print("  - A single file path")
        print("  - Multiple paths separated by commas")
        print("  - Press TAB to autocomplete file paths")
        
        selection = select_file_with_autocomplete(
            "Enter wordlist file(s) (comma-separated for multiple)",
            allow_multiple=True
        )
        
        if not selection:
            print("No wordlist selected. Aborting hybrid attack.")
            return
        
        # Convert to list if single file
        if isinstance(selection, str):
            wordlists = [selection]
        else:
            wordlists = selection
        
        # Validate all files exist
        valid_wordlists = []
        for wl in wordlists:
            if os.path.isfile(wl):
                valid_wordlists.append(wl)
                print(f"✓ Found: {wl}")
            else:
                print(f"✗ Not found: {wl}")
        
        if not valid_wordlists:
            print("\nNo valid wordlists found. Aborting hybrid attack.")
            return
        
        wordlists = valid_wordlists
    
    # Confirm before starting
    print(f"\nStarting hybrid attack with {len(wordlists)} wordlist(s)...")
    print(f"Hash type: {hcatHashType}")
    print(f"Hash file: {hcatHashFile}")
    
    # Run the attack with selected wordlist(s)
    hcatHybrid(hcatHashType, hcatHashFile, wordlists)


# Pathwell Top 100 Bruteforce Mask
def pathwell_crack():
    # Bruteforce Mask Attack
    hcatPathwellBruteForce(hcatHashType, hcatHashFile)


# PRINCE Attack
def prince_attack():
    hcatPrince(hcatHashType, hcatHashFile)


# YOLO Combination
def yolo_combination():
    hcatYoloCombination(hcatHashType, hcatHashFile)

# Thorough Combinator
def thorough_combinator():
    hcatThoroughCombinator(hcatHashType, hcatHashFile)

# Middle Combinator
def middle_combinator():
    hcatMiddleCombinator(hcatHashType, hcatHashFile)

# Bandrel Methodology
def bandrel_method():
    hcatBandrel(hcatHashType, hcatHashFile)


# convert hex words for recycling
def convert_hex(working_file):
    processed_words = []
    regex = r'^\$HEX\[(\S+)\]'
    with open(working_file, 'r') as f:
        for line in f:
            match = re.search(regex, line.rstrip('\n'))
            if match:
                try:
                    processed_words.append(binascii.unhexlify(match.group(1)).decode('iso-8859-9'))
                except UnicodeDecodeError:
                    pass
            else:
                processed_words.append(line.rstrip('\n'))

    return processed_words

# Display Cracked Hashes
def show_results():
    if os.path.isfile(hcatHashFile + ".out"):
        with open(hcatHashFile + ".out") as hcatOutput:
            for cracked_hash in hcatOutput:
                print(cracked_hash.strip())
    else:
        print("No hashes were cracked :(")

# Analyze Hashes with Pipal
def pipal():
    hcatHashFilePipal = hcatHashFile
    if hcatHashType == "1000":
        combine_ntlm_output()
        hcatHashFilePipal = hcatHashFileOrig

    if os.path.isfile(pipalPath):
        if os.path.isfile(hcatHashFilePipal + ".out"):
            pipalFile = open(hcatHashFilePipal + ".passwords", 'w')
            with open(hcatHashFilePipal + ".out") as hcatOutput:
                for cracked_hash in hcatOutput:
                    password = cracked_hash.split(':')
                    clearTextPass = password[-1]
                    match = re.search(r'^\$HEX\[(\S+)\]', clearTextPass)
                    if match:
                        clearTextPass = binascii.unhexlify(match.group(1)).decode('iso-8859-9')
                    pipalFile.write(clearTextPass)
                pipalFile.close()

            pipalProcess = subprocess.Popen(
                "{pipal_path} {pipal_file} -t {pipal_count} --output {pipal_out}".format(
                    pipal_path=pipalPath,
                    pipal_file=hcatHashFilePipal + ".passwords",
                    pipal_out=hcatHashFilePipal + ".pipal",
                    pipal_count=pipal_count),
                shell=True)
            try:
                pipalProcess.wait()
            except KeyboardInterrupt:
                print('Killing PID {0}...'.format(str(pipalProcess.pid)))
                pipalProcess.kill()
            print("Pipal file is at " + hcatHashFilePipal + ".pipal\n")
            with open(hcatHashFilePipal + ".pipal") as pipalfile:
                pipal_content = pipalfile.readlines()
                raw_pipal = '\n'.join(pipal_content)
                raw_pipal = re.sub('\n+', '\n', raw_pipal)
                raw_regex = r'Top [0-9]+ base words\n'
                for word in range(pipal_count):
                    raw_regex += r'(\S+).*\n'
                basewords_re = re.compile(raw_regex)
                results = re.search(basewords_re,raw_pipal)
                top_basewords = []
                if results:
                    for i in range(1, results.lastindex + 1):
                        top_basewords.append(results.group(i))
                    return top_basewords
                else:
                    return []
        else:
            print("No hashes were cracked :(")
            return []
    else:
        print("The path to pipal.rb is either not set, or is incorrect.")
        return



# Exports output to excel file
def export_excel():

    # Check for openyxl dependancy for export
    try:
        import openpyxl
    except:
        sys.stderr.write('You must install openpyxl first using \'pip install openpyxl\' or \'pip3 install openpyxl\'\n')
        return

    if hcatHashType == "1000":
        combine_ntlm_output()
        output = openpyxl.Workbook()
        current_ws = output.create_sheet(title='hate_crack output', index=0)
        current_row = 2
        current_ws['A1'] = 'Username'
        current_ws['B1'] = 'SID'
        current_ws['C1'] = 'LM Hash'
        current_ws['D1'] = 'NTLM Hash'
        current_ws['E1'] = 'Clear-Text Password'
        with open(hcatHashFileOrig+'.out') as input_file:
            for line in input_file:
                matches = re.match(r'(^[^:]+):([0-9]+):([a-z0-9A-Z]{32}):([a-z0-9A-Z]{32}):::(.*)',line.rstrip('\r\n'))
                if not matches:
                    continue
                username = matches.group(1)
                sid = matches.group(2)
                lm = matches.group(3)
                ntlm = matches.group(4)
                try:
                    clear_text = matches.group(5)
                    match = re.search(r'^\$HEX\[(\S+)\]', clear_text)
                    if match:
                        clear_text = binascii.unhexlify(match.group(1)).decode('iso-8859-9')
                except:
                    clear_text = ''
                current_ws['A' + str(current_row)] = username
                current_ws['B' + str(current_row)] = sid
                current_ws['C' + str(current_row)] = lm
                current_ws['D' + str(current_row)] = ntlm
                current_ws['E' + str(current_row)] = clear_text
                current_row += 1
            output.save(hcatHashFile+'.xlsx')
            print("Output exported succesfully to {0}".format(hcatHashFile+'.xlsx'))
    else:
        sys.stderr.write('Excel output only supported for pwdformat for NTLM hashes')
        return


# Show README
def show_readme():
    with open(hate_path + "/readme.md") as hcatReadme:
        print(hcatReadme.read())


# Exit Program
def quit_hc():
    cleanup()
    sys.exit(0)


# The Main Guts
def main():
    global pwdump_format
    global hcatHashFile
    global hcatHashType
    global hcatHashFileOrig
    global lmHashesFound
    global debug_mode

    # Parse command line arguments
    args = sys.argv[1:]
    
    try:
        hcatHashFile = args[0]
        hcatHashType = args[1]

    except IndexError:
        # No arguments provided - show menu
        ascii_art()
        print("\n" + "="*60)
        print("No hash file provided. What would you like to do?")
        print("="*60)
        print("\t(1) Download hashes from Hashview")
        print("\t(2) Show usage information")
        print("\t(3) Exit")
        
        choice = input("\nSelect an option: ")
        
        if choice == '1':
            # Download from Hashview
            if not REQUESTS_AVAILABLE:
                print("\nError: 'requests' module not found.")
                print("Install it with: pip install requests")
                sys.exit(1)
            
            if not hashview_api_key:
                print("\nError: Hashview API key not configured.")
                print("Please set 'hashview_api_key' in config.json")
                sys.exit(1)
            
            try:
                api_harness = HashviewAPI(hashview_url, hashview_api_key)
                
                # List customers
                result = api_harness.list_customers()
                if 'customers' in result and result['customers']:
                    api_harness.display_customers_multicolumn(result['customers'])
                
                # Get customer ID
                customer_id = int(input("\nEnter customer ID: "))
                
                # List hashfiles for the customer
                try:
                    customer_hashfiles = api_harness.get_customer_hashfiles(customer_id)
                    
                    if customer_hashfiles:
                        print("\n" + "="*100)
                        print(f"Hashfiles for Customer ID {customer_id}:")
                        print("="*100)
                        print(f"{'ID':<10} {'Name':<88}")
                        print("-" * 100)
                        for hf in customer_hashfiles:
                            hf_id = hf.get('id', 'N/A')
                            hf_name = hf.get('name', 'N/A')
                            # Truncate long names to fit within 100 columns
                            if len(str(hf_name)) > 88:
                                hf_name = str(hf_name)[:85] + "..."
                            print(f"{hf_id:<10} {hf_name:<88}")
                        print("="*100)
                        print(f"Total: {len(customer_hashfiles)} hashfile(s)")
                    else:
                        print(f"\nNo hashfiles found for customer ID {customer_id}")
                except Exception as e:
                    print(f"\nWarning: Could not list hashfiles: {e}")
                    print("You may need to manually find the hashfile ID in the web interface.")
                
                # Prompt directly for hashfile ID
                hashfile_id = int(input("\nEnter hashfile ID: "))
                
                # Get hash type
                # print("\nEnter hash type (e.g., 1000 for NTLM, 0 for MD5)")
                # print("See hashcat --help for hash type reference")
                # hcatHashType = input("Hash type: ")
                hcatHashType = "1000" # Default to NTLM for simplicity
                
                # Set output filename automatically
                output_file = f"left_{customer_id}_{hashfile_id}.txt"
                
                # Download the left hashes
                download_result = api_harness.download_left_hashes(
                    customer_id, hashfile_id, output_file
                )
                print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
                print(f"  File: {download_result['output_file']}")
                
                # Set the hash file for processing
                hcatHashFile = download_result['output_file']
                
                print(f"\nNow starting hate_crack with:")
                print(f"  Hash file: {hcatHashFile}")
                print(f"  Hash type: {hcatHashType}")
                    
            except ValueError:
                print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                sys.exit(1)
            except Exception as e:
                print(f"\n✗ Error downloading hashes: {str(e)}")
                sys.exit(1)
        elif choice == '2':
            usage()
            sys.exit(0)
        else:
            sys.exit(0)

    hcatHashFileOrig = hcatHashFile
    ascii_art()

    # Get Initial Input Hash Count
    hcatHashCount = lineCount(hcatHashFile)

    # If LM or NT Mode Selected and pwdump Format Detected, Prompt For LM to NT Attack
    if hcatHashType == "1000":
        lmHashesFound = False
        pwdump_format = False
        hcatHashFileLine = open(hcatHashFile, "r").readline()
        if re.search(r"[a-f0-9A-F]{32}:[a-f0-9A-F]{32}:::", hcatHashFileLine):
            pwdump_format = True
            print("PWDUMP format detected...")
            print("Parsing NT hashes...")
            subprocess.Popen(
                "cat {hash_file} | cut -d : -f 4 |sort -u > {hash_file}.nt".format(hash_file=hcatHashFile),
                             shell=True).wait()
            print("Parsing LM hashes...")
            subprocess.Popen("cat {hash_file} | cut -d : -f 3 |sort -u > {hash_file}.lm".format(hash_file=hcatHashFile),
                             shell=True).wait()
            if ((lineCount(hcatHashFile + ".lm") == 1) and (
                        hcatHashFileLine.split(":")[2].lower() != "aad3b435b51404eeaad3b435b51404ee")) or (
                        lineCount(hcatHashFile + ".lm") > 1):
                lmHashesFound = True
                lmChoice = input("LM hashes identified. Would you like to brute force the LM hashes first? (Y) ") or "Y"
                if lmChoice.upper() == 'Y':
                    hcatLMtoNT()
            hcatHashFileOrig = hcatHashFile
            hcatHashFile = hcatHashFile + ".nt"
        elif re.search(r"^[a-f0-9A-F]{32}$", hcatHashFileLine):
            pwdump_format = False
            print("PWDUMP format was not detected...")
            print("Hash only detected")
        elif re.search(r"^.+:[a-f0-9A-F]{32}$", hcatHashFileLine):
            pwdump_format = False
            print("PWDUMP format was not detected...")
            print("username with Hash detected")
            subprocess.Popen(
                "cat {hash_file} | cut -d : -f 2 |sort -u > {hash_file}.nt".format(hash_file=hcatHashFile),
                             shell=True).wait()
            hcatHashFileOrig = hcatHashFile
            hcatHashFile = hcatHashFile + ".nt"
        else:
            print("unknown format....does it have usernames?")
            exit(1)
    # Check POT File for Already Cracked Hashes
    if not os.path.isfile(hcatHashFile + ".out"):
        hcatOutput = open(hcatHashFile + ".out", "w+")
        hcatOutput.close()
        print("Checking POT file for already cracked hashes...")
        subprocess.Popen(
            "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m {hash_type} {hash_file} > {hash_file}.out".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                hate_path=hate_path), shell=True).wait()
        hcatHashCracked = lineCount(hcatHashFile + ".out")
        if hcatHashCracked > 0:
            print("Found %d hashes already cracked.\nCopied hashes to %s.out" % (hcatHashCracked, hcatHashFile))
        else:
            print("No hashes found in POT file.")

    # Display Options
    try:
        while 1:
            print("\n\t(1) Quick Crack")
            print("\t(2) Extensive Pure_Hate Methodology Crack")
            print("\t(3) Brute Force Attack")
            print("\t(4) Top Mask Attack")
            print("\t(5) Fingerprint Attack")
            print("\t(6) Combinator Attack")
            print("\t(7) Hybrid Attack")
            print("\t(8) Pathwell Top 100 Mask Brute Force Crack")
            print("\t(9) PRINCE Attack")
            print("\t(10) YOLO Combinator Attack")
            print("\t(11) Middle Combinator Attack")
            print("\t(12) Thorough Combinator Attack")
            print("\t(13) Bandrel Methodology")
            print("\n\t(94) Hashview")
            print("\t(95) Analyze hashes with Pipal")
            print("\t(96) Export Output to Excel Format")
            print("\t(97) Display Cracked Hashes")
            print("\t(98) Display README")
            print("\t(99) Quit")
            options = {"1": quick_crack,
                       "2": extensive_crack,
                       "3": brute_force_crack,
                       "4": top_mask_crack,
                       "5": fingerprint_crack,
                       "6": combinator_crack,
                       "7": hybrid_crack,
                       "8": pathwell_crack,
                       "9": prince_attack,
                       "10": yolo_combination,
                       "11": middle_combinator,
                       "12": thorough_combinator,
                       "13": bandrel_method,
                       "94": hashview_api,
                       "95": pipal,
                       "96": export_excel,
                       "97": show_results,
                       "98": show_readme,
                       "99": quit_hc
                       }
            try:
                task = input("\nSelect a task: ")
                options[task]()
            except KeyError:
                pass
    except KeyboardInterrupt:
        quit_hc()

# Boilerplate
if __name__ == '__main__':
    main()
