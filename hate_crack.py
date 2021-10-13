#!/usr/bin/env python

# Methodology provided by Martin Bos (pure_hate) - https://www.trustedsec.com/team/martin-bos/
# Original script created by Larry Spohn (spoonman) - https://www.trustedsec.com/team/larry-spohn/
# Python refactoring and general fixing, Justin Bollinger (bandrel) - https://www.trustedsec.com/team/justin-bollinger/

import subprocess
import sys
import os
import random
import re
import json
import binascii
import shutil

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
    hcatRules = config_parser['hcatRules']
except KeyError as e:
    print('{0} is not defined in config.json using defaults from config.json.example'.format(e))
    hcatRules = default_config['hcatRules']

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


if sys.platform == 'darwin':
    hcatExpanderBin = "expander.app"
    hcatCombinatorBin = "combinator.app"
    hcatPrinceBin = "pp64.app"
else:
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
if os.path.isfile(hcatBin):
    pass
elif os.path.isfile(hcatPath.rstrip('/') + '/' + hcatBin):
    hcatBin = hcatPath.rstrip('/') + '/' + hcatBin
else:
    print('Invalid path for hashcat binary. Please check configuration and try again.')
    quit(1)

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
            session_name=os.path.basename(hcatHashFile),
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
        "-r {hcatPath}/rules/best64.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            session_name=os.path.basename(hcatHashFile),
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
                session_name=os.path.basename(hcatHashFile),
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
                session_name=os.path.basename(hcatHashFile),
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
            session_name=os.path.basename(hcatHashFile),
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
    hcatProcess = subprocess.Popen(
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
            session_name=os.path.basename(hcatHashFile),
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
        hcatProcess = subprocess.Popen("cat {hash_file}.out | cut -d : -f 2 > {hash_file}.working".format(
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
                session_name=os.path.basename(hcatHashFile),
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
            session_name=os.path.basename(hcatHashFile),
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
def hcatHybrid(hcatHashType, hcatHashFile):
    global hcatHybridCount
    global hcatProcess
    for wordlist in hcatHybridlist:
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 6 -1 ?s?d {wordlist} ?1?1 "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} -o {hash_file}.out -a 6 -1 ?s?d {wordlist} ?1?1?1 "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} -o {hash_file}.out -a 6 -1 ?s?d {wordlist} "
            "?1?1?1?1 {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} -o {hash_file}.out -a 7 -1 ?s?d ?1?1 {wordlist} "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} -o {hash_file}.out -a 7 -1 ?s?d ?1?1?1 {wordlist} "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
                wordlist=wordlist,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print('Killing PID {0}...'.format(str(hcatProcess.pid)))
            hcatProcess.kill()

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} -o {hash_file}.out -a 7 -1 ?s?d ?1?1?1?1 {wordlist} "
            "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
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
                    session_name=os.path.basename(hcatHashFile),
                    word_lists=hcatWordlists,
                    optimized_lists=hcatOptimizedWordlists,
                    tuning=hcatTuning,
                    left=hcatLeft,
                    right=hcatRight,
                    hate_path=hate_path), shell=True)
            hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

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
                session_name=os.path.basename(hcatHashFile),
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
                session_name=os.path.basename(hcatHashFile),
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
                    session_name=os.path.basename(hcatHashFile),
                    left=hcatMiddleBaseList,
                    right=hcatMiddleBaseList,
                    tuning=hcatTuning,
                    middle_mask=masks[x],
                    hate_path=hate_path),
                shell=True)
            hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()

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

    try:
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 {left} "
            "{right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                session_name=os.path.basename(hcatHashFile),
                left=hcatThoroughBaseList,
                right=hcatThoroughBaseList,
                word_lists=hcatWordlists,
                tuning=hcatTuning,
                hate_path=hate_path),
            shell=True)
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
                    session_name=os.path.basename(hcatHashFile),
                    left=hcatThoroughBaseList,
                    right=hcatThoroughBaseList,
                    word_lists=hcatWordlists,
                    tuning=hcatTuning,
                    middle_mask=masks[x],
                    hate_path=hate_path),
                    shell=True)
            hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()
    try:
        for x in range(len(masks)):
            hcatProcess = subprocess.Popen(
              "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 "
              "-k '${end_mask}' {left} {right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=os.path.basename(hcatHashFile),
                    left=hcatThoroughBaseList,
                    right=hcatThoroughBaseList,
                    word_lists=hcatWordlists,
                    tuning=hcatTuning,
                    end_mask=masks[x],
                    hate_path=hate_path),
                    shell=True)
            hcatProcess.wait()
    except KeyboardInterrupt:
        print('Killing PID {0}...'.format(str(hcatProcess.pid)))
        hcatProcess.kill()
    try:
        for x in range(len(masks)):
            hcatProcess = subprocess.Popen(
              "{hcatBin} -m {hash_type} {hash_file} --session {session_name} -o {hash_file}.out -a 1 "
              "-j '${middle_mask}' -k '${end_mask}' {left} {right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                    hcatBin=hcatBin,
                    hash_type=hcatHashType,
                    hash_file=hcatHashFile,
                    session_name=os.path.basename(hcatHashFile),
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
            session_name=os.path.basename(hcatHashFile),
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
            session_name=os.path.basename(hcatHashFile),
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
            session_name=os.path.basename(hcatHashFile),
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
            session_name=os.path.basename(hcatHashFile),
            tuning=hcatTuning,
            hate_path=hate_path), shell=True)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        hcatProcess.kill()

    hcatProcess = subprocess.Popen("cat {hash_file}.lm.cracked | cut -d : -f 2 > {hash_file}.working".format(
        hash_file=hcatHashFile), shell=True).wait()
    converted = convert_hex("{hash_file}.working".format(hash_file=hcatHashFile))
    with open("{hash_file}.working".format(hash_file=hcatHashFile),mode='w') as working:
        working.writelines(converted)
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
            session_name=os.path.basename(hcatHashFile),
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
                    session_name=os.path.basename(hcatHashFile),
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
        "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m {hash_type} {hash_file} > {hate_path}/{hash_file}.out".format(
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
    try:
        if hcatHashType == "1000":
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

# Quick Dictionary Attack with Optional Chained Rules
def quick_crack():
    # Rules Attack
    wordlist_choice = None
    rule_choice = None
    selected_hcatRules = []
    while wordlist_choice is None:
        raw_choice = input("\nEnter path of wordlist or wordlist directory.\n"
                           "Press Enter for default optimized wordlists [{0}]:".format(hcatOptimizedWordlists))
        if raw_choice == '':
            wordlist_choice = hcatOptimizedWordlists
        else:
            if os.path.exists(raw_choice):
                wordlist_choice = raw_choice

    print("\nWhich rule(s) would you like to run?")
    rule_number = 1
    print('(0) To run without any rules')
    for rule in hcatRules:
        print('({0}) {1}'.format(rule_number, rule))
        rule_number += 1
    print('(99) YOLO...run all of the rules')

    while rule_choice is None:
        raw_choice = input('Enter Comma separated list of rules you would like to run. To run rules chained use the + symbol.\n'
                            'For example 1+1 will run {0} chained twice and 1,2 would run {0} and then {1} sequentially.\n'
                            'Choose wisely: '.format(hcatRules[0], hcatRules[1]))
        if raw_choice != '':
            rule_choice = raw_choice.split(',')

    if '99' in rule_choice:
        for rule in hcatRules:
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
                        combined_choice = '{0} {1}'.format(combined_choice, '-r {hcatPath}/rules/{selected_rule}'.format(selected_rule=hcatRules[int(rule) - 1],
                                                                                                                         hcatPath=hcatPath))
                    except:
                        continue
                selected_hcatRules.append(combined_choice)
            else:
                try:
                    selected_hcatRules.append('-r {hcatPath}/rules/{selected_rule}'.format(selected_rule=hcatRules[int(choice) - 1],hcatPath=hcatPath))
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
    hcatHybrid(hcatHashType, hcatHashFile)


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
                for i in range(1, results.lastindex + 1):
                    top_basewords.append(results.group(i))
                return(top_basewords)
        else:
         print("No hashes were cracked :(")
    else:
        print("The path to pipal.rb is either not set, or is incorrect.")



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
    global hcatHashFile
    global hcatHashType
    global hcatHashFileOrig
    global lmHashesFound

    hcatHashFileOrig = ""

    try:
        hcatHashFile = sys.argv[1]
        hcatHashType = sys.argv[2]

    except IndexError:
        usage()
        sys.exit()

    ascii_art()

    # Get Initial Input Hash Count
    hcatHashCount = lineCount(hcatHashFile)

    # If LM or NT Mode Selected and pwdump Format Detected, Prompt For LM to NT Attack
    if hcatHashType == "1000":
        lmHashesFound = False
        hcatHashFileLine = open(hcatHashFile, "r").readline()
        if re.search(r"[a-z0-9A-Z]{32}:[a-z0-9A-Z]{32}:.*::", hcatHashFileLine):
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
            print("\n\t(95) Analyze hashes with Pipal")
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
