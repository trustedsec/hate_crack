#!/usr/bin/python
# MaskGen - Generate Password Masks
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.3
#
# Copyright (C) 2013 Peter Kacherginsky
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.

import sys
import csv
import datetime
from operator import itemgetter
from optparse import OptionParser, OptionGroup

VERSION = "0.0.3"


class MaskGen:
    def __init__(self):
        # Masks collections with meta data
        self.masks = dict()

        self.target_time = None
        self.output_file = None

        self.minlength = None
        self.maxlength = None
        self.mintime = None
        self.maxtime = None
        self.mincomplexity = None
        self.maxcomplexity = None
        self.minoccurrence = None
        self.maxoccurrence = None

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

        # Counter for total masks coverage
        self.total_occurrence = 0

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

    def loadmasks(self, filename):
        """ Load masks and apply filters. """
        maskReader = csv.reader(open(args[0], 'r'), delimiter=',', quotechar='"')

        for (mask, occurrence) in maskReader:

            if mask == "": continue

            mask_occurrence = int(occurrence)
            mask_length = len(mask) / 2
            mask_complexity = self.getcomplexity(mask)
            mask_time = mask_complexity / self.pps

            self.total_occurrence += mask_occurrence

            # Apply filters based on occurrence, length, complexity and time
            if (self.minoccurrence == None or mask_occurrence >= self.minoccurrence) and \
                    (self.maxoccurrence == None or mask_occurrence <= self.maxoccurrence) and \
                    (self.mincomplexity == None or mask_complexity <= self.mincomplexity) and \
                    (self.maxcomplexity == None or mask_complexity <= self.maxcomplexity) and \
                    (self.mintime == None or mask_time <= self.mintime) and \
                    (self.maxtime == None or mask_time <= self.maxtime) and \
                    (self.maxlength == None or mask_length <= self.maxlength) and \
                    (self.minlength == None or mask_length >= self.minlength):
                self.masks[mask] = dict()
                self.masks[mask]['length'] = mask_length
                self.masks[mask]['occurrence'] = mask_occurrence
                self.masks[mask]['complexity'] = 1 - mask_complexity
                self.masks[mask]['time'] = mask_time
                self.masks[mask]['optindex'] = 1 - mask_complexity / mask_occurrence

    def generate_masks(self, sorting_mode):
        """ Generate optimal password masks sorted by occurrence, complexity or optindex """
        sample_count = 0
        sample_time = 0
        sample_occurrence = 0

        # TODO Group by time here 1 minutes, 1 hour, 1 day, 1 month, 1 year....
        #      Group by length   1,2,3,4,5,6,7,8,9,10....
        #      Group by occurrence 10%, 20%, 30%, 40%, 50%....

        if self.showmasks: print
        "[L:] Mask:                          [ Occ:  ] [ Time:  ]"
        for mask in sorted(self.masks.keys(), key=lambda mask: self.masks[mask][sorting_mode], reverse=True):

            if self.showmasks:
                time_human = ">1 year" if self.masks[mask]['time'] > 60 * 60 * 24 * 365 else str(
                    datetime.timedelta(seconds=self.masks[mask]['time']))
                print
                "[{:>2}] {:<30} [{:<7}] [{:>8}]  ".format(self.masks[mask]['length'], mask,
                                                          self.masks[mask]['occurrence'], time_human)

            if self.output_file:
                self.output_file.write("%s\n" % mask)

            sample_occurrence += self.masks[mask]['occurrence']
            sample_time += self.masks[mask]['time']
            sample_count += 1

            if self.target_time and sample_time > self.target_time:
                print
                "[!] Target time exceeded."
                break

        print
        "[*] Finished generating masks:"
        print
        "    Masks generated: %s" % sample_count
        print
        "    Masks coverage:  %d%% (%d/%d)" % (
            sample_occurrence * 100 / self.total_occurrence, sample_occurrence, self.total_occurrence)
        time_human = ">1 year" if sample_time > 60 * 60 * 24 * 365 else str(datetime.timedelta(seconds=sample_time))
        print
        "    Masks runtime:   %s" % time_human

    def getmaskscoverage(self, checkmasks):

        sample_count = 0
        sample_occurrence = 0

        total_complexity = 0

        if self.showmasks: print
        "[L:] Mask:                          [ Occ:  ] [ Time:  ]"
        for mask in checkmasks:
            mask = mask.strip()
            mask_complexity = self.getcomplexity(mask)

            total_complexity += mask_complexity

            if mask in self.masks:

                if self.showmasks:
                    time_human = ">1 year" if self.masks[mask]['time'] > 60 * 60 * 24 * 365 else str(
                        datetime.timedelta(seconds=self.masks[mask]['time']))
                    print
                    "[{:>2}] {:<30} [{:<7}] [{:>8}]  ".format(self.masks[mask]['length'], mask,
                                                              self.masks[mask]['occurrence'], time_human)

                if self.output_file:
                    self.output_file.write("%s\n" % mask)

                sample_occurrence += self.masks[mask]['occurrence']
                sample_count += 1

            if self.target_time and total_complexity / self.pps > self.target_time:
                print
                "[!] Target time exceeded."
                break

        # TODO: Something wrong here, complexity and time doesn't match with estimated from policygen
        total_time = total_complexity / self.pps
        time_human = ">1 year" if total_time > 60 * 60 * 24 * 365 else str(datetime.timedelta(seconds=total_time))
        print
        "[*] Finished matching masks:"
        print
        "    Masks matched: %s" % sample_count
        print
        "    Masks coverage:  %d%% (%d/%d)" % (
            sample_occurrence * 100 / self.total_occurrence, sample_occurrence, self.total_occurrence)
        print
        "    Masks runtime:   %s" % time_human


if __name__ == "__main__":

    header = "                       _ \n"
    header += "     MaskGen %s    | |\n" % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog pass0.masks [pass1.masks ...] [options]", version="%prog " + VERSION)

    parser.add_option("-t", "--targettime", dest="target_time", type="int", metavar="86400",
                      help="Target time of all masks (seconds)")
    parser.add_option("-o", "--outputmasks", dest="output_masks", metavar="masks.hcmask", help="Save masks to a file")

    filters = OptionGroup(parser, "Individual Mask Filter Options")
    filters.add_option("--minlength", dest="minlength", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlength", dest="maxlength", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--mintime", dest="mintime", type="int", metavar="3600", help="Minimum mask runtime (seconds)")
    filters.add_option("--maxtime", dest="maxtime", type="int", metavar="3600", help="Maximum mask runtime (seconds)")
    filters.add_option("--mincomplexity", dest="mincomplexity", type="int", metavar="1", help="Minimum complexity")
    filters.add_option("--maxcomplexity", dest="maxcomplexity", type="int", metavar="100", help="Maximum complexity")
    filters.add_option("--minoccurrence", dest="minoccurrence", type="int", metavar="1", help="Minimum occurrence")
    filters.add_option("--maxoccurrence", dest="maxoccurrence", type="int", metavar="100", help="Maximum occurrence")
    parser.add_option_group(filters)

    sorting = OptionGroup(parser, "Mask Sorting Options")
    sorting.add_option("--optindex", action="store_true", dest="optindex", help="sort by mask optindex (default)",
                       default=False)
    sorting.add_option("--occurrence", action="store_true", dest="occurrence", help="sort by mask occurrence",
                       default=False)
    sorting.add_option("--complexity", action="store_true", dest="complexity", help="sort by mask complexity",
                       default=False)
    parser.add_option_group(sorting)

    coverage = OptionGroup(parser, "Check mask coverage")
    coverage.add_option("--checkmasks", dest="checkmasks", help="check mask coverage",
                        metavar="?u?l?l?l?l?l?d,?l?l?l?l?l?d?d")
    coverage.add_option("--checkmasksfile", dest="checkmasks_file", help="check mask coverage in a file",
                        metavar="masks.hcmask")
    parser.add_option_group(coverage)

    parser.add_option("--showmasks", dest="showmasks", help="Show matching masks", action="store_true", default=False)

    misc = OptionGroup(parser, "Miscellaneous options")
    misc.add_option("--pps", dest="pps", help="Passwords per Second", type="int", metavar="1000000000")
    misc.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    parser.add_option_group(misc)

    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print
        header

    if len(args) < 1:
        parser.error("no masks file specified! Please provide statsgen output.")
        exit(1)

    print
    "[*] Analyzing masks in [%s]" % args[0]

    maskgen = MaskGen()

    # Settings
    if options.target_time: maskgen.target_time = options.target_time
    if options.output_masks:
        print
        "[*] Saving generated masks to [%s]" % options.output_masks
        maskgen.output_file = open(options.output_masks, 'w')

    # Filters
    if options.minlength:     maskgen.minlength = options.minlength
    if options.maxlength:     maskgen.maxlength = options.maxlength
    if options.mintime:       maskgen.mintime = options.mintime
    if options.maxtime:       maskgen.maxtime = options.maxtime
    if options.mincomplexity: maskgen.mincomplexity = options.mincomplexity
    if options.maxcomplexity: maskgen.maxcomplexity = options.maxcomplexity
    if options.minoccurrence: maskgen.minoccurrence = options.minoccurrence
    if options.maxoccurrence: maskgen.maxoccurrence = options.maxoccurrence

    # Misc
    if options.pps: maskgen.pps = options.pps
    if options.showmasks: maskgen.showmasks = options.showmasks

    print
    "[*] Using {:,d} keys/sec for calculations.".format(maskgen.pps)

    # Load masks
    for arg in args:
        maskgen.loadmasks(arg)

    # Matching masks from the command-line
    if options.checkmasks:
        checkmasks = [m.strip() for m in options.checkmasks.split(',')]
        print
        "[*] Checking coverage of the these masks [%s]" % ", ".join(checkmasks)
        maskgen.getmaskscoverage(checkmasks)

    # Matching masks from a file
    elif options.checkmasks_file:
        checkmasks_file = open(options.checkmasks_file, 'r')
        print
        "[*] Checking coverage of masks in [%s]" % options.checkmasks_file
        maskgen.getmaskscoverage(checkmasks_file)

    # Printing masks in a file
    else:
        # Process masks according to specified sorting algorithm
        if options.occurrence:
            sorting_mode = "occurrence"
        elif options.complexity:
            sorting_mode = "complexity"
        else:
            sorting_mode = "optindex"

        print
        "[*] Sorting masks by their [%s]." % sorting_mode
        maskgen.generate_masks(sorting_mode)
