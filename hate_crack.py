#!/usr/bin/env python

# Methodology provided by Martin Bos (pure_hate) - https://www.trustedsec.com/team-members/martin-bos/
# Original script created by Larry Spohn (spoonman) - https://www.trustedsec.com/team-members/larry-spohn/
# Python refactoring and general fixing, Justin Bollinger (bandrel) - https://www.trustedsec.com/team-members/justin-bollinger/

import subprocess
import sys
import os
import signal
import time
import random
import re
import json
import binascii

# python2/3 compatability
try:
    input = raw_input
except NameError:
    pass


hate_path = os.path.dirname(os.path.realpath(__file__))
with open(hate_path + '/config.json') as config:
    config_parser = json.load(config)

    hcatPath = config_parser['hcatPath']
    hcatBin = config_parser['hcatBin']
    hcatTuning = config_parser['hcatTuning']
    hcatWordlists = config_parser['hcatWordlists']
    hcatOptimizedWordlists = config_parser['hcatOptimizedWordlists']
    hcatExpanderBin = config_parser['hcatExpanderBin']
    hcatCombinatorBin = config_parser['hcatCombinatorBin']
    hcatPrinceBin = config_parser['hcatPrinceBin']

# hashcat biniary checks for systems that install hashcat binary in different location than the rest of the hashcat files
if os.path.isfile(hcatBin):
    pass
elif os.path.isfile(hcatPath.rstrip('/') + '/' + hcatBin):
    hcatBin = hcatPath.rstrip('/') + '/' + hcatBin
else:
    print('Invalid path for hashcat biniary. Please check configuration and try again.')
    quit(1)

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
                         Public Release
                          Version 1.01
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
        "{hcbin} -m {hash_type} {hash_file} --remove -o {hash_file}.out --increment --increment-min={min} "
        "--increment-max={max} -a 3 ?a?a?a?a?a?a?a?a?a?a?a?a?a?a {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcbin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            min=hcatMinLen,
            max=hcatMaxLen,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatBruteCount = lineCount(hcatHashFile + ".out")


# Dictionary Attack
def hcatDictionary(hcatHashType, hcatHashFile):
    global hcatDictionaryCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatPath} -m {hcatHashType} {hash_file} --remove -o {hash_file}.out {optimized_wordlists}/* "
        "-r {hcatPath}/rules/best64.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            optimized_wordlists=hcatOptimizedWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hcatHashType} {hash_file} --remove -o {hash_file}.out {hcatWordlists}/rockyou.txt "
        "-r {hcatPath}/rules/d3ad0ne.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            hcatWordlists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hcatHashType} {hash_file} --remove -o {hash_file}.out {hcatWordlists}/rockyou.txt "
        "-r {hcatPath}/rules/T0XlC.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            hcatWordlists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatDictionaryCount = lineCount(hcatHashFile + ".out") - hcatBruteCount


# Quick Dictionary Attack (Optional Chained Rules)
def hcatQuickDictionary(hcatHashType, hcatHashFile, hcatChains):
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hcatHashType} {hash_file} --remove -o {hash_file}.out {optimized_wordlists}/* {chains} "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hcatHashType=hcatHashType,
            hash_file=hcatHashFile,
            optimized_wordlists=hcatOptimizedWordlists,
            chains=hcatChains,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()


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
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hate_path}/PACK/maskgen.py {hash_file}.masks --targettime {target_time} --optindex -q --pps 14000000000 "
        "--minlength=7 -o {hash_file}.hcmask".format(
            hash_file=hcatHashFile,
            target_time=hcatTargetTime,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 3 {hash_file}.hcmask {tuning} "
        "--potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
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
                hate_path=hate_path), shell=True).wait()
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 1 {hash_file}.expanded "
            "{hash_file}.expanded {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True).wait()
        crackedAfter = lineCount(hcatHashFile + ".out")
    hcatFingerprintCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Combinator Attack
def hcatCombination(hcatHashType, hcatHashFile):
    global hcatCombinationCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 1 {word_lists}/rockyou.txt "
        "{word_lists}/rockyou.txt {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path),
        shell=True).wait()
    hcatCombinationCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Hybrid Attack
def hcatHybrid(hcatHashType, hcatHashFile):
    global hcatHybridCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 6 -1 ?s?d {word_lists}/rockyou.txt ?1?1 "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 6 -1 ?s?d {word_lists}/rockyou.txt ?1?1?1 "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 6 -1 ?s?d {word_lists}/rockyou.txt "
        "?1?1?1?1 {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 7 -1 ?s?d ?1?1 {word_lists}/rockyou.txt "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 7 -1 ?s?d ?1?1?1 {word_lists}/rockyou.txt "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 7 -1 ?s?d ?1?1?1?1 {word_lists}/rockyou.txt "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatHybridCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# YOLO Combination Attack
def hcatYoloCombination(hcatHashType, hcatHashFile):
    global hcatProcess
    while 1:
        hcatLeft = random.choice(os.listdir(hcatOptimizedWordlists))
        hcatRight = random.choice(os.listdir(hcatOptimizedWordlists))
        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 1 {optimized_lists}/{left} "
            "{optimized_lists}/{right} {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                word_lists=hcatWordlists,
                optimized_lists=hcatOptimizedWordlists,
                tuning=hcatTuning,
                left=hcatLeft,
                right=hcatRight,
                hate_path=hate_path), shell=True).wait()

# Holden Combinator Attack
def hcatHoldenCombinator(hcatHashType, hcatHashFile):
    global hcatProcess
    numbers = [0,1,2,3,4,5,6,7,8,9]
    special = [" ","-","_","+",",","!","#","$","\"","%","&","\'","(",")","*",",",".","/",":",";","<","=",">","?","@","[","\\","]","^","`","{","|","}","~"]
    for x in range(len(numbers)):
        print numbers[x],

    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 1 -j '$9' {word_lists}/rockyou.txt "
        "{word_lists}/rockyou.txt {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path),
        shell=True).wait()


# Pathwell Mask Brute Force Attack
def hcatPathwellBruteForce(hcatHashType, hcatHashFile):
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -a 3 {hate_path}/masks/pathwell.hcmask "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()


# PRINCE Attack
def hcatPrince(hcatHashType, hcatHashFile):
    global hcatProcess
    hcatHashCracked = lineCount(hcatHashFile + ".out")
    hcatProcess = subprocess.Popen(
        "{hate_path}/princeprocessor/{prince_bin} --case-permute --elem-cnt-min=1 --elem-cnt-max=16 -c < "
        "{word_lists}/rockyou.txt | {hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out "
        "-r {hate_path}/princeprocessor/rules/prince_optimized.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            prince_bin=hcatPrinceBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            optimized_lists=hcatOptimizedWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()


# Extra - Good Measure
def hcatGoodMeasure(hcatHashType, hcatHashFile):
    global hcatExtraCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out -r {hcatPath}/rules/combinator.rule "
        "-r {hcatPath}/rules/InsidePro-PasswordsPro.rule {word_lists}/rockyou.txt {tuning} "
        "--potfile-path={hate_path}/hashcat.pot".format(
            hcatPath=hcatPath,
            hcatBin=hcatBin,
            hash_type=hcatHashType,
            hash_file=hcatHashFile,
            word_lists=hcatWordlists,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatExtraCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# LanMan to NT Attack
def hcatLMtoNT():
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m 3000 {hash_file}.lm > {hash_file}.lm.cracked".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m 3000 {hash_file}.lm --remove -o {hash_file}.lm.cracked -1 ?u?d?s --increment -a 3 ?1?1?1?1?1?1?1 "
        "{tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen("cat {hash_file}.lm.cracked | cut -d : -f 2 > {hash_file}.working".format(
        hash_file=hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hate_path}/hashcat-utils/bin/{combine_bin} {hash_file}.working {hash_file}.working | sort -u > "
        "{hash_file}.combined".format(
            combine_bin=hcatCombinatorBin,
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()

    hcatProcess = subprocess.Popen(
        "{hcatBin} --show --potfile-path={hate_path}/hashcat.pot -m 1000 {hash_file}.nt > {hash_file}.nt.out".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "{hcatBin} -m 1000 {hash_file}.nt --remove -o {hash_file}.nt.out {hash_file}.combined "
        "-r {hate_path}/rules/toggles-lm-ntlm.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
            hcatBin=hcatBin,
            hash_file=hcatHashFile,
            tuning=hcatTuning,
            hate_path=hate_path), shell=True).wait()
    # toggle-lm-ntlm.rule by Didier Stevens https://blog.didierstevens.com/2016/07/16/tool-to-generate-hashcat-toggle-rules/


# Recycle Cracked Passwords
def hcatRecycle(hcatHashType, hcatHashFile, hcatNewPasswords):
    global hcatProcess
    working_file = hcatHashFile + '.working'
    if hcatNewPasswords > 0:
        hcatProcess = subprocess.Popen("cat {hash_file}.out | cut -d : -f 2 > {working_file}".format(
            hash_file=hcatHashFile, working_file=working_file), shell=True).wait()
        converted = convert_hex(working_file)

        # Overwrite working file with updated converted words
        with open(working_file, 'w') as f:
            f.write("\n".join(converted))

        hcatProcess = subprocess.Popen(
            "{hcatBin} -m {hash_type} {hash_file} --remove -o {hash_file}.out {hash_file}.working "
            "-r {hcatPath}/rules/d3ad0ne.rule {tuning} --potfile-path={hate_path}/hashcat.pot".format(
                hcatBin=hcatBin,
                hash_type=hcatHashType,
                hash_file=hcatHashFile,
                hcatPath=hcatPath,
                tuning=hcatTuning,
                hate_path=hate_path), shell=True).wait()

# Cleanup Temp Files
def cleanup():
    if hcatHashType == "1000":
        print("\nComparing cracked hashes to original file...")
        with open(hcatHashFileOrig + ".out", "w+") as hcatCombinedHashes:
            with open(hcatHashFile + ".out", "r") as hcatCrackedFile:
                for crackedLine in hcatCrackedFile:
                    with open(hcatHashFileOrig, "r") as hcatOrigFile:
                        for origLine in hcatOrigFile:
                            if crackedLine.split(":")[0] == origLine.split(":")[3]:
                                hcatCombinedHashes.write(origLine.strip() + crackedLine.split(":")[1])
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


# CTRL-C Function
def signal_handler(signal, frame):
    global hcatHashFile
    global hcatBin
    global hcatProcess

    print("Killing %s..." % hcatBin)
    processGroup = os.getpgid(hcatProcess)
    hcatProcess = subprocess.Popen("kill -%d" % processGroup, shell=True).wait()
    time.sleep(5)


# Quick Dictionary Attack with Optional Chained Best64 Rules
def quick_crack():
    hcatChainsInput = int(input("\nHow many times would you like to chain the best64.rule? (1): ") or 1)
    hcatChains = "-r {hcatPath}/rules/best64.rule ".format(hcatPath=hcatPath)
    if hcatChainsInput > 1:
        for n in range(1, hcatChainsInput):
            hcatChains += "-r {hcatPath}/rules/best64.rule ".format(hcatPath=hcatPath)

    hcatQuickDictionary(hcatHashType, hcatHashFile, hcatChains)


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
    if not os.path.isfile(hcatWordlists + '/rockyou.txt'):
        print("rockyou.txt not found in {0}  Please verify and try again").format(hcatWordlists)
        return
    hcatPrince(hcatHashType, hcatHashFile)


# YOLO Combination
def yolo_combination():
    hcatYoloCombination(hcatHashType, hcatHashFile)

# Holden Combinator
def holden_combinator():
    hcatHoldenCombinator(hcatHashType, hcatHashFile)


# convert hex words for recycling
def convert_hex(working_file):
    processed_words = []
    regex = r'^\$HEX\[(\S+)\]'
    with open(working_file, 'r') as f:
        for line in f:
            match = re.search(regex, line.rstrip('\n'))
            if match:
                processed_words.append(binascii.unhexlify(match.group(1)).decode('utf-8'))
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

    # Catch CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Get Initial Input Hash Count
    hcatHashCount = lineCount(hcatHashFile)

    # If LM or NT Mode Selected and pwdump Format Detected, Prompt For LM to NT Attack
    if hcatHashType == "1000":
        lmHashesFound = False
        hcatHashFileLine = open(hcatHashFile, "r").readline()
        if re.search(r"[a-z0-9]{32}:[a-z0-9]{32}:::$", hcatHashFileLine):
            print("PWDUMP format detected...")
            print("Parsing NT hashes...")
            subprocess.Popen(
                "cat {hash_file} | cut -d : -f 4 |sort -u > {hash_file}.nt".format(hash_file=hcatHashFile),
                             shell=True).wait()
            print("Parsing LM hashes...")
            subprocess.Popen("cat {hash_file} | cut -d : -f 3 |sort -u > {hash_file}.lm".format(hash_file=hcatHashFile),
                             shell=True).wait()
            if ((lineCount(hcatHashFile + ".lm") == 1) and (
                        hcatHashFileLine.split(":")[2] != "aad3b435b51404eeaad3b435b51404ee")) or (
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
	print("\t(11) Holden Combinator Attack")
        print("\n\t(97) Display Cracked Hashes")
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
		   "11": holden_combinator,
                   "97": show_results,
                   "98": show_readme,
                   "99": quit_hc
                   }
        try:
            task = input("\nSelect a task: ")
            options[task]()
        except KeyError:
            pass
# Boilerplate
if __name__ == '__main__':
    main()
