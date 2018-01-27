#!/usr/bin/python
# PolicyGen - Analyze and Generate password masks according to a password policy
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.2
#
# Copyright (C) 2013 Peter Kacherginsky
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.

import sys, string, random
import datetime
from optparse import OptionParser, OptionGroup
import itertools

VERSION = "0.0.2"


class PolicyGen:
    def __init__(self):
        self.output_file = None

        self.minlength = 8
        self.maxlength = 8
        self.mindigit = None
        self.minlower = None
        self.minupper = None
        self.minspecial = None
        self.maxdigit = None
        self.maxlower = None
        self.maxupper = None
        self.maxspecial = None

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

    def getcomplexity(self, mask):
        """ Return mask complexity. """
        count = 1
        for char in mask[1:].split("?"):
            if char == "l":
                count *= 26
            elif char == "u":
                count *= 26
            elif char == "d":
                count *= 10
            elif char == "s":
                count *= 33
            elif char == "a":
                count *= 95
            else:
                print
            "[!] Error, unknown mask ?%s in a mask %s" % (char, mask)

        return count

    def generate_masks(self, noncompliant):
        """ Generate all possible password masks matching the policy """

        total_count = 0
        sample_count = 0

        # NOTE: It is better to collect total complexity
        #       not to lose precision when dividing by pps
        total_complexity = 0
        sample_complexity = 0

        # TODO: Randomize or even statistically arrange matching masks
        for length in xrange(self.minlength, self.maxlength + 1):
            print
            "[*] Generating %d character password masks." % length
            total_length_count = 0
            sample_length_count = 0

            total_length_complexity = 0
            sample_length_complexity = 0

            for masklist in itertools.product(['?d', '?l', '?u', '?s'], repeat=length):

                mask = ''.join(masklist)

                lowercount = 0
                uppercount = 0
                digitcount = 0
                specialcount = 0

                mask_complexity = self.getcomplexity(mask)

                total_length_count += 1
                total_length_complexity += mask_complexity

                # Count charachter types in a mask
                for char in mask[1:].split("?"):
                    if char == "l":
                        lowercount += 1
                    elif char == "u":
                        uppercount += 1
                    elif char == "d":
                        digitcount += 1
                    elif char == "s":
                        specialcount += 1

                # Filter according to password policy
                # NOTE: Perform exact opposite (XOR) operation if noncompliant
                #       flag was set when calling the function.
                if ((self.minlower == None or lowercount >= self.minlower) and \
                            (self.maxlower == None or lowercount <= self.maxlower) and \
                            (self.minupper == None or uppercount >= self.minupper) and \
                            (self.maxupper == None or uppercount <= self.maxupper) and \
                            (self.mindigit == None or digitcount >= self.mindigit) and \
                            (self.maxdigit == None or digitcount <= self.maxdigit) and \
                            (self.minspecial == None or specialcount >= self.minspecial) and \
                            (self.maxspecial == None or specialcount <= self.maxspecial)) ^ noncompliant:

                    sample_length_count += 1
                    sample_length_complexity += mask_complexity

                    if self.showmasks:
                        mask_time = mask_complexity / self.pps
                        time_human = ">1 year" if mask_time > 60 * 60 * 24 * 365 else str(
                            datetime.timedelta(seconds=mask_time))
                        print
                        "[{:>2}] {:<30} [l:{:>2} u:{:>2} d:{:>2} s:{:>2}] [{:>8}]  ".format(length, mask, lowercount,
                                                                                            uppercount, digitcount,
                                                                                            specialcount, time_human)

                    if self.output_file:
                        self.output_file.write("%s\n" % mask)

            total_count += total_length_count
            sample_count += sample_length_count

            total_complexity += total_length_complexity
            sample_complexity += sample_length_complexity

        total_time = total_complexity / self.pps
        total_time_human = ">1 year" if total_time > 60 * 60 * 24 * 365 else str(datetime.timedelta(seconds=total_time))
        print
        "[*] Total Masks:  %d Time: %s" % (total_count, total_time_human)

        sample_time = sample_complexity / self.pps
        sample_time_human = ">1 year" if sample_time > 60 * 60 * 24 * 365 else str(
            datetime.timedelta(seconds=sample_time))
        print
        "[*] Policy Masks: %d Time: %s" % (sample_count, sample_time_human)


if __name__ == "__main__":

    header = "                       _ \n"
    header += "     PolicyGen %s  | |\n" % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    # parse command line arguments
    parser = OptionParser("%prog [options]\n\nType --help for more options", version="%prog " + VERSION)
    parser.add_option("-o", "--outputmasks", dest="output_masks", help="Save masks to a file", metavar="masks.hcmask")
    parser.add_option("--pps", dest="pps", help="Passwords per Second", type="int", metavar="1000000000")
    parser.add_option("--showmasks", dest="showmasks", help="Show matching masks", action="store_true", default=False)
    parser.add_option("--noncompliant", dest="noncompliant", help="Generate masks for noncompliant passwords",
                      action="store_true", default=False)

    group = OptionGroup(parser, "Password Policy",
                        "Define the minimum (or maximum) password strength policy that you would like to test")
    group.add_option("--minlength", dest="minlength", type="int", metavar="8", default=8,
                     help="Minimum password length")
    group.add_option("--maxlength", dest="maxlength", type="int", metavar="8", default=8,
                     help="Maximum password length")
    group.add_option("--mindigit", dest="mindigit", type="int", metavar="1", help="Minimum number of digits")
    group.add_option("--minlower", dest="minlower", type="int", metavar="1",
                     help="Minimum number of lower-case characters")
    group.add_option("--minupper", dest="minupper", type="int", metavar="1",
                     help="Minimum number of upper-case characters")
    group.add_option("--minspecial", dest="minspecial", type="int", metavar="1",
                     help="Minimum number of special characters")
    group.add_option("--maxdigit", dest="maxdigit", type="int", metavar="3", help="Maximum number of digits")
    group.add_option("--maxlower", dest="maxlower", type="int", metavar="3",
                     help="Maximum number of lower-case characters")
    group.add_option("--maxupper", dest="maxupper", type="int", metavar="3",
                     help="Maximum number of upper-case characters")
    group.add_option("--maxspecial", dest="maxspecial", type="int", metavar="3",
                     help="Maximum number of special characters")
    parser.add_option_group(group)

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")

    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print
        header

    policygen = PolicyGen()

    # Settings    
    if options.output_masks:
        print
        "[*] Saving generated masks to [%s]" % options.output_masks
        policygen.output_file = open(options.output_masks, 'w')

    # Password policy
    if options.minlength != None: policygen.minlength = options.minlength
    if options.maxlength != None: policygen.maxlength = options.maxlength
    if options.mindigit != None: policygen.mindigit = options.mindigit
    if options.minlower != None: policygen.minlower = options.minlower
    if options.minupper != None: policygen.minupper = options.minupper
    if options.minspecial != None: policygen.minspecial = options.minspecial
    if options.maxdigit != None: policygen.maxdigits = options.maxdigit
    if options.maxlower != None: policygen.maxlower = options.maxlower
    if options.maxupper != None: policygen.maxupper = options.maxupper
    if options.maxspecial != None: policygen.maxspecial = options.maxspecial

    # Misc
    if options.pps: policygen.pps = options.pps
    if options.showmasks: policygen.showmasks = options.showmasks

    print
    "[*] Using {:,d} keys/sec for calculations.".format(policygen.pps)

    # Print current password policy
    print
    "[*] Password policy:"
    print
    "    Pass Lengths: min:%d max:%d" % (policygen.minlength, policygen.maxlength)
    print
    "    Min strength: l:%s u:%s d:%s s:%s" % (
        policygen.minlower, policygen.minupper, policygen.mindigit, policygen.minspecial)
    print
    "    Max strength: l:%s u:%s d:%s s:%s" % (
        policygen.maxlower, policygen.maxupper, policygen.maxdigit, policygen.maxspecial)

    print
    "[*] Generating [%s] masks." % ("compliant" if not options.noncompliant else "non-compliant")
    policygen.generate_masks(options.noncompliant)
