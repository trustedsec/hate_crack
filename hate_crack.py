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
    print("\nThe <hash_type> is attained by running \"%s/%s --help\"\n" % (hcatPath, hcatBin))
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
                          Version 1.00
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
        "%s/%s -m %s %s --remove -o %s.out --increment --increment-min=%s --increment-max=%s -a 3 ?a?a?a?a?a?a?a?a?a?a?a?a?a?a %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatMinLen, hcatMaxLen, hcatTuning, hate_path),
        shell=True).wait()
    hcatBruteCount = lineCount(hcatHashFile + ".out")


# Dictionary Attack
def hcatDictionary(hcatHashType, hcatHashFile):
    global hcatDictionaryCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out %s/* -r %s/rules/best64.rule %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatOptimizedWordlists, hcatPath, hcatTuning,
            hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out %s/rockyou.txt -r %s/rules/d3ad0ne.rule %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatPath, hcatTuning,
            hate_path),
        shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out %s/rockyou.txt -r %s/rules/T0XlC.rule %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatPath, hcatTuning,
            hate_path),
        shell=True).wait()
    hcatDictionaryCount = lineCount(hcatHashFile + ".out") - hcatBruteCount


# Quick Dictionary Attack (Optional Chained Rules)
def hcatQuickDictionary(hcatHashType, hcatHashFile, hcatChains):
    global hcatProcess
    hcatProcess = subprocess.Popen("%s/%s -m %s %s --remove -o %s.out %s/* %s %s --potfile-path=%s/hashcat.pot" % (
        hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatOptimizedWordlists, hcatChains, hcatTuning,
        hate_path), shell=True).wait()


# Top Mask Attack
def hcatTopMask(hcatHashType, hcatHashFile, hcatTargetTime):
    global hcatMaskCount
    global hcatProcess
    hcatProcess = subprocess.Popen("cat %s.out | cut -d : -f 2 > %s.working" % (hcatHashFile, hcatHashFile),
                                   shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/PACK/statsgen.py %s.working -o %s.masks" % (hate_path, hcatHashFile, hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/PACK/maskgen.py %s.masks --targettime %s --optindex -q --pps 14000000000 --minlength=7 -o %s.hcmask" % (
            hate_path, hcatHashFile, hcatTargetTime, hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 3 %s.hcmask %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatHashFile, hcatTuning, hate_path),
        shell=True).wait()
    hcatMaskCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Fingerprint Attack
def hcatFingerprint(hcatHashType, hcatHashFile):
    global hcatFingerprintCount
    global hcatProcess
    crackedBefore = lineCount(hcatHashFile + ".out")
    crackedAfter = 0
    while crackedBefore != crackedAfter:
        crackedBefore = lineCount(hcatHashFile + ".out")
        hcatProcess = subprocess.Popen("cat %s.out | cut -d : -f 2 > %s.working" % (hcatHashFile, hcatHashFile),
                                       shell=True).wait()
        hcatProcess = subprocess.Popen("%s/hashcat-utils/bin/%s < %s.working | sort -u > %s.expanded" % (
            hate_path, hcatExpanderBin, hcatHashFile, hcatHashFile), shell=True).wait()
        hcatProcess = subprocess.Popen(
            "%s/%s -m %s %s --remove -o %s.out -a 1 %s.expanded %s.expanded %s --potfile-path=%s/hashcat.pot" % (
                hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatHashFile, hcatHashFile, hcatTuning,
                hate_path), shell=True).wait()
        crackedAfter = lineCount(hcatHashFile + ".out")
    hcatFingerprintCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Combinator Attack
def hcatCombination(hcatHashType, hcatHashFile):
    global hcatCombinationCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 1 %s/rockyou.txt %s/rockyou.txt %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatWordlists, hcatTuning,
            hate_path), shell=True).wait()
    hcatCombinationCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Hybrid Attack
def hcatHybrid(hcatHashType, hcatHashFile):
    global hcatHybridCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 6 -1 ?s?d %s/rockyou.txt ?1?1 %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatTuning, hate_path),
        shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 6 -1 ?s?d %s/rockyou.txt ?1?1?1 %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatTuning, hate_path),
        shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 6 -1 ?s?d %s/rockyou.txt ?1?1?1?1 %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatTuning, hate_path),
        shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 7 -1 ?s?d ?1?1 %s/rockyou.txt %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatTuning, hate_path),
        shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 7 -1 ?s?d ?1?1?1 %s/rockyou.txt %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatTuning, hate_path),
        shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 7 -1 ?s?d ?1?1?1?1 %s/rockyou.txt %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatWordlists, hcatTuning, hate_path),
        shell=True).wait()
    hcatHybridCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# YOLO Combination Attack
def hcatYoloCombination(hcatHashType, hcatHashFile):
    global hcatProcess
    while 1:
        hcatLeft = random.choice(os.listdir(hcatOptimizedWordlists))
        hcatRight = random.choice(os.listdir(hcatOptimizedWordlists))
        hcatProcess = subprocess.Popen(
            "%s/%s -m %s %s --remove -o %s.out -a 1 %s/%s %s/%s %s --potfile-path=%s/hashcat.pot" % (
                hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatOptimizedWordlists, hcatLeft,
                hcatOptimizedWordlists, hcatRight, hcatTuning, hate_path), shell=True).wait()


# Pathwell Mask Brute Force Attack
def hcatPathwellBruteForce(hcatHashType, hcatHashFile):
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -a 3 %s/masks/pathwell.hcmask %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hate_path, hcatTuning, hate_path),
        shell=True).wait()


# PRINCE Attack
def hcatPrince(hcatHashType, hcatHashFile):
    global hcatProcess
    hcatHashCracked = lineCount(hcatHashFile + ".out")
    hcatProcess = subprocess.Popen(
        "%s/princeprocessor/%s --case-permute --elem-cnt-min=1 --elem-cnt-max=16 -c < %s/rockyou.txt |%s/%s -m %s %s --remove -o %s.out -r %s/princeprocessor/rules/prince_optimized.rule %s --potfile-path=%s/hashcat.pot" % (
            hate_path, hcatPrinceBin, hcatWordlists, hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile,
            hate_path,
            hcatTuning, hate_path), shell=True).wait()


# Extra - Good Measure
def hcatGoodMeasure(hcatHashType, hcatHashFile):
    global hcatExtraCount
    global hcatProcess
    hcatProcess = subprocess.Popen(
        "%s/%s -m %s %s --remove -o %s.out -r %s/rules/combinator.rule -r %s/rules/InsidePro-PasswordsPro.rule %s/rockyou.txt %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatPath, hcatPath, hcatWordlists, hcatTuning,
            hate_path), shell=True).wait()
    hcatExtraCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# LanMan to NT Attack
def hcatLMtoNT():
    global hcatProcess
    hcatProcess = subprocess.Popen("%s/%s --show --potfile-path=%s/hashcat.pot -m 3000 %s.lm >%s.lm.cracked" % (
        hcatPath, hcatBin, hate_path, hcatHashFile, hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m 3000 %s.lm --remove -o %s.lm.cracked -1 ?u?d?s --increment -a 3 ?1?1?1?1?1?1?1 %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashFile, hcatHashFile, hcatTuning, hate_path), shell=True).wait()
    hcatProcess = subprocess.Popen("cat %s.lm.cracked | cut -d : -f 2 > %s.working" % (hcatHashFile, hcatHashFile),
                                   shell=True).wait()
    hcatProcess = subprocess.Popen("%s/hashcat-utils/bin/%s %s.working %s.working | sort -u > %s.combined" % (
        hate_path, hcatCombinatorBin, hcatHashFile, hcatHashFile, hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen("%s/%s --show --potfile-path=%s/hashcat.pot -m 1000 %s.nt >%s.nt.out" % (
        hcatPath, hcatBin, hate_path, hcatHashFile, hcatHashFile), shell=True).wait()
    hcatProcess = subprocess.Popen(
        "%s/%s -m 1000 %s.nt --remove -o %s.nt.out %s.combined -r %s/rules/toggles-lm-ntlm.rule %s --potfile-path=%s/hashcat.pot" % (
            hcatPath, hcatBin, hcatHashFile, hcatHashFile, hcatHashFile, hate_path, hcatTuning, hate_path),
        shell=True).wait()
    # toggle-lm-ntlm.rule by Didier Stevens https://blog.didierstevens.com/2016/07/16/tool-to-generate-hashcat-toggle-rules/


# Recycle Cracked Passwords
def hcatRecycle(hcatHashType, hcatHashFile, hcatNewPasswords):
    global hcatProcess
    if hcatNewPasswords > 0:
        hcatProcess = subprocess.Popen("cat %s.out | cut -d : -f 2 > %s.working" % (hcatHashFile, hcatHashFile),
                                       shell=True).wait()
        hcatProcess = subprocess.Popen(
            "%s/%s -m %s %s --remove -o %s.out %s.working -r %s/rules/d3ad0ne.rule %s --potfile-path=%s/hashcat.pot" % (
                hcatPath, hcatBin, hcatHashType, hcatHashFile, hcatHashFile, hcatHashFile, hcatPath, hcatTuning,
                hate_path),
            shell=True).wait()


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
    hcatChains = "-r %s/rules/best64.rule " % hcatPath
    if hcatChainsInput > 1:
        for n in range(1, hcatChainsInput):
            hcatChains += "-r %s/rules/best64.rule " % hcatPath

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
            subprocess.Popen("cat %s | cut -d : -f 4 |sort -u > %s.nt" % (hcatHashFile, hcatHashFile),
                             shell=True).wait()
            print("Parsing LM hashes...")
            subprocess.Popen("cat %s | cut -d : -f 3 |sort -u > %s.lm" % (hcatHashFile, hcatHashFile),
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
        subprocess.Popen("%s/%s --show --potfile-path=%s/hashcat.pot -m %s %s >%s.out" % (
            hcatPath, hcatBin, hate_path, hcatHashType, hcatHashFile, hcatHashFile), shell=True).wait()
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
