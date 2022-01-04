#!/usr/bin/env python
# StatsGen - Password Statistical Analysis tool
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
import re, operator, string
from optparse import OptionParser, OptionGroup
import time

VERSION = "0.0.3"


class StatsGen:
    def __init__(self):
        self.output_file = None

        # Filters
        self.minlength = None
        self.maxlength = None
        self.simplemasks = None
        self.charsets = None
        self.quiet = False
        self.debug = True

        # Stats dictionaries
        self.stats_length = dict()
        self.stats_simplemasks = dict()
        self.stats_advancedmasks = dict()
        self.stats_charactersets = dict()

        # Ignore stats with less than 1% coverage
        self.hiderare = False

        self.filter_counter = 0
        self.total_counter = 0

        # Minimum password complexity counters
        self.mindigit = None
        self.minupper = None
        self.minlower = None
        self.minspecial = None

        self.maxdigit = None
        self.maxupper = None
        self.maxlower = None
        self.maxspecial = None

    def analyze_password(self, password):

        # Password length
        pass_length = len(password)

        # Character-set and policy counters
        digit = 0
        lower = 0
        upper = 0
        special = 0

        simplemask = list()
        advancedmask_string = ""

        # Detect simple and advanced masks
        for letter in password:

            if letter in string.digits:
                digit += 1
                advancedmask_string += "?d"
                if not simplemask or not simplemask[-1] == 'digit': simplemask.append('digit')

            elif letter in string.ascii_lowercase:
                lower += 1
                advancedmask_string += "?l"
                if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')


            elif letter in string.ascii_uppercase:
                upper += 1
                advancedmask_string += "?u"
                if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')

            else:
                special += 1
                advancedmask_string += "?s"
                if not simplemask or not simplemask[-1] == 'special': simplemask.append('special')

        # String representation of masks
        simplemask_string = ''.join(simplemask) if len(simplemask) <= 3 else 'othermask'

        # Policy
        policy = (digit, lower, upper, special)

        # Determine character-set
        if digit and not lower and not upper and not special:
            charset = 'numeric'
        elif not digit and lower and not upper and not special:
            charset = 'loweralpha'
        elif not digit and not lower and upper and not special:
            charset = 'upperalpha'
        elif not digit and not lower and not upper and special:
            charset = 'special'

        elif not digit and lower and upper and not special:
            charset = 'mixedalpha'
        elif digit and lower and not upper and not special:
            charset = 'loweralphanum'
        elif digit and not lower and upper and not special:
            charset = 'upperalphanum'
        elif not digit and lower and not upper and special:
            charset = 'loweralphaspecial'
        elif not digit and not lower and upper and special:
            charset = 'upperalphaspecial'
        elif digit and not lower and not upper and special:
            charset = 'specialnum'

        elif not digit and lower and upper and special:
            charset = 'mixedalphaspecial'
        elif digit and not lower and upper and special:
            charset = 'upperalphaspecialnum'
        elif digit and lower and not upper and special:
            charset = 'loweralphaspecialnum'
        elif digit and lower and upper and not special:
            charset = 'mixedalphanum'
        else:
            charset = 'all'

        return (pass_length, charset, simplemask_string, advancedmask_string, policy)

    def generate_stats(self, filename):
        """ Generate password statistics. """

        f = open(filename, 'r')

        for password in f:
            password = password.rstrip('\r\n')

            if len(password) == 0: continue

            self.total_counter += 1

            (pass_length, characterset, simplemask, advancedmask, policy) = self.analyze_password(password)
            (digit, lower, upper, special) = policy

            if (self.charsets == None or characterset in self.charsets) and \
                    (self.simplemasks == None or simplemask in self.simplemasks) and \
                    (self.maxlength == None or pass_length <= self.maxlength) and \
                    (self.minlength == None or pass_length >= self.minlength):

                self.filter_counter += 1

                if self.mindigit == None or digit < self.mindigit: self.mindigit = digit
                if self.maxdigit == None or digit > self.maxdigit: self.maxdigit = digit

                if self.minupper == None or upper < self.minupper: self.minupper = upper
                if self.maxupper == None or upper > self.maxupper: self.maxupper = upper

                if self.minlower == None or lower < self.minlower: self.minlower = lower
                if self.maxlower == None or lower > self.maxlower: self.maxlower = lower

                if self.minspecial == None or special < self.minspecial: self.minspecial = special
                if self.maxspecial == None or special > self.maxspecial: self.maxspecial = special

                if pass_length in self.stats_length:
                    self.stats_length[pass_length] += 1
                else:
                    self.stats_length[pass_length] = 1

                if characterset in self.stats_charactersets:
                    self.stats_charactersets[characterset] += 1
                else:
                    self.stats_charactersets[characterset] = 1

                if simplemask in self.stats_simplemasks:
                    self.stats_simplemasks[simplemask] += 1
                else:
                    self.stats_simplemasks[simplemask] = 1

                if advancedmask in self.stats_advancedmasks:
                    self.stats_advancedmasks[advancedmask] += 1
                else:
                    self.stats_advancedmasks[advancedmask] = 1

        f.close()

    def print_stats(self):
        """ Print password statistics. """

        print
        "[+] Analyzing %d%% (%d/%d) of passwords" % (
            self.filter_counter * 100 / self.total_counter, self.filter_counter, self.total_counter)
        print
        "    NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords"
        print
        "\n[*] Length:"
        for (length, count) in sorted(self.stats_length.items(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count * 100 / self.filter_counter > 0: continue
            print
            "[+] %25d: %02d%% (%d)" % (length, count * 100 / self.filter_counter, count)

        print
        "\n[*] Character-set:"
        for (char, count) in sorted(self.stats_charactersets.items(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count * 100 / self.filter_counter > 0: continue
            print
            "[+] %25s: %02d%% (%d)" % (char, count * 100 / self.filter_counter, count)

        print
        "\n[*] Password complexity:"
        print
        "[+]                     digit: min(%s) max(%s)" % (self.mindigit, self.maxdigit)
        print
        "[+]                     lower: min(%s) max(%s)" % (self.minlower, self.maxlower)
        print
        "[+]                     upper: min(%s) max(%s)" % (self.minupper, self.maxupper)
        print
        "[+]                   special: min(%s) max(%s)" % (self.minspecial, self.maxspecial)

        print
        "\n[*] Simple Masks:"
        for (simplemask, count) in sorted(self.stats_simplemasks.items(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count * 100 / self.filter_counter > 0: continue
            print
            "[+] %25s: %02d%% (%d)" % (simplemask, count * 100 / self.filter_counter, count)

        print
        "\n[*] Advanced Masks:"
        for (advancedmask, count) in sorted(self.stats_advancedmasks.items(), key=operator.itemgetter(1),
                                            reverse=True):
            if count * 100 / self.filter_counter > 0:
                print
                "[+] %25s: %02d%% (%d)" % (advancedmask, count * 100 / self.filter_counter, count)

            if self.output_file:
                self.output_file.write("%s,%d\n" % (advancedmask, count))


if __name__ == "__main__":

    header = "                       _ \n"
    header += "     StatsGen %s   | |\n" % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog [options] passwords.txt\n\nType --help for more options", version="%prog " + VERSION)

    filters = OptionGroup(parser, "Password Filters")
    filters.add_option("--minlength", dest="minlength", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlength", dest="maxlength", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--charset", dest="charsets", help="Password charset filter (comma separated)",
                       metavar="loweralpha,numeric")
    filters.add_option("--simplemask", dest="simplemasks", help="Password mask filter (comma separated)",
                       metavar="stringdigit,allspecial")
    parser.add_option_group(filters)

    parser.add_option("-o", "--output", dest="output_file", help="Save masks and stats to a file",
                      metavar="password.masks")
    parser.add_option("--hiderare", action="store_true", dest="hiderare", default=False,
                      help="Hide statistics covering less than 1% of the sample")

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print
        header

    if len(args) != 1:
        parser.error("no passwords file specified")
        exit(1)

    print
    "[*] Analyzing passwords in [%s]" % args[0]

    statsgen = StatsGen()

    if not options.minlength == None: statsgen.minlength = options.minlength
    if not options.maxlength == None: statsgen.maxlength = options.maxlength
    if not options.charsets == None: statsgen.charsets = [x.strip() for x in options.charsets.split(',')]
    if not options.simplemasks == None: statsgen.simplemasks = [x.strip() for x in options.simplemasks.split(',')]

    if options.hiderare: statsgen.hiderare = options.hiderare

    if options.output_file:
        print
        "[*] Saving advanced masks and occurrences to [%s]" % options.output_file
        statsgen.output_file = open(options.output_file, 'w')

    statsgen.generate_stats(args[0])
    statsgen.print_stats()
