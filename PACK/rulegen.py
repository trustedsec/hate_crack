#!/usr/bin/env python
# Rulegen.py - Advanced automated password rule and wordlist generator for the 
#              Hashcat password cracker using the Levenshtein Reverse Path 
#              algorithm and Enchant spell checking library.
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
import re
import time
import operator
import enchant

from optparse import OptionParser, OptionGroup

from collections import Counter

import subprocess

import multiprocessing

VERSION = "0.0.3"

# Testing rules with hashcat --stdout
HASHCAT_PATH = "hashcat/"


# Rule Generator class responsible for the complete cycle of rule generation
class RuleGen:
    # Initialize Rule Generator class
    def __init__(self, language="en", providers="aspell,myspell", basename='analysis', threads=4):

        self.enchant_broker = enchant.Broker()
        self.enchant_broker.set_ordering("*", providers)

        self.enchant = enchant.Dict(language, self.enchant_broker)

        # Output options
        self.basename = basename

        # Finetuning word generation
        self.max_word_dist = 10
        self.max_words = 10
        self.more_words = False
        self.simple_words = False

        # Finetuning rule generation
        self.max_rule_len = 10
        self.max_rules = 10
        self.more_rules = False
        self.simple_rules = False
        self.brute_rules = False

        # Debugging options
        self.verbose = False
        self.debug = False
        self.word = None  # Custom word to use.
        self.quiet = False

        ########################################################################
        # Word and Rule Statistics
        self.numeric_stats_total = 0
        self.special_stats_total = 0
        self.foreign_stats_total = 0

        ########################################################################
        # Preanalysis Password Patterns
        self.password_pattern = dict()
        self.password_pattern["insertion"] = re.compile('^[^a-z]*(?P<password>.+?)[^a-z]*$', re.IGNORECASE)
        self.password_pattern["email"] = re.compile('^(?P<password>.+?)@[A-Z0-9.-]+\.[A-Z]{2,4}', re.IGNORECASE)
        self.password_pattern["alldigits"] = re.compile('^(\d+)$', re.IGNORECASE)
        self.password_pattern["allspecial"] = re.compile('^([^a-z0-9]+)$', re.IGNORECASE)

        ########################################################################
        # Hashcat Rules Engine
        self.hashcat_rule = dict()

        # Dummy rule
        self.hashcat_rule[':'] = lambda x: x  # Do nothing

        # Case rules
        self.hashcat_rule["l"] = lambda x: x.lower()  # Lowercase all letters
        self.hashcat_rule["u"] = lambda x: x.upper()  # Capitalize all letters
        self.hashcat_rule["c"] = lambda x: x.capitalize()  # Capitalize the first letter
        self.hashcat_rule["C"] = lambda x: x[0].lower() + x[
                                                          1:].upper()  # Lowercase the first found character, uppercase the rest
        self.hashcat_rule["t"] = lambda x: x.swapcase()  # Toggle the case of all characters in word
        self.hashcat_rule["T"] = lambda x, y: x[:y] + x[y].swapcase() + x[
                                                                        y + 1:]  # Toggle the case of characters at position N
        self.hashcat_rule["E"] = lambda x: " ".join(
            [i[0].upper() + i[1:] for i in x.split(" ")])  # Upper case the first letter and every letter after a space

        # Rotation rules
        self.hashcat_rule["r"] = lambda x: x[::-1]  # Reverse the entire word
        self.hashcat_rule["{"] = lambda x: x[1:] + x[0]  # Rotate the word left
        self.hashcat_rule["}"] = lambda x: x[-1] + x[:-1]  # Rotate the word right

        # Duplication rules
        self.hashcat_rule["d"] = lambda x: x + x  # Duplicate entire word
        self.hashcat_rule["p"] = lambda x, y: x * y  # Duplicate entire word N times
        self.hashcat_rule["f"] = lambda x: x + x[::-1]  # Duplicate word reversed
        self.hashcat_rule["z"] = lambda x, y: x[0] * y + x  # Duplicate first character N times
        self.hashcat_rule["Z"] = lambda x, y: x + x[-1] * y  # Duplicate last character N times
        self.hashcat_rule["q"] = lambda x: "".join([i + i for i in x])  # Duplicate every character
        self.hashcat_rule["y"] = lambda x, y: x[:y] + x  # Duplicate first N characters
        self.hashcat_rule["Y"] = lambda x, y: x + x[-y:]  # Duplicate last N characters

        # Cutting rules
        self.hashcat_rule["["] = lambda x: x[1:]  # Delete first character
        self.hashcat_rule["]"] = lambda x: x[:-1]  # Delete last character
        self.hashcat_rule["D"] = lambda x, y: x[:y] + x[y + 1:]  # Deletes character at position N
        self.hashcat_rule["'"] = lambda x, y: x[:y]  # Truncate word at position N
        self.hashcat_rule["x"] = lambda x, y, z: x[:y] + x[y + z:]  # Delete M characters, starting at position N
        self.hashcat_rule["@"] = lambda x, y: x.replace(y, '')  # Purge all instances of X

        # Insertion rules
        self.hashcat_rule["$"] = lambda x, y: x + y  # Append character to end
        self.hashcat_rule["^"] = lambda x, y: y + x  # Prepend character to front
        self.hashcat_rule["i"] = lambda x, y, z: x[:y] + z + x[y:]  # Insert character X at position N

        # Replacement rules
        self.hashcat_rule["o"] = lambda x, y, z: x[:y] + z + x[y + 1:]  # Overwrite character at position N with X
        self.hashcat_rule["s"] = lambda x, y, z: x.replace(y, z)  # Replace all instances of X with Y
        self.hashcat_rule["L"] = lambda x, y: x[:y] + chr(ord(x[y]) << 1) + x[
                                                                            y + 1:]  # Bitwise shift left character @ N
        self.hashcat_rule["R"] = lambda x, y: x[:y] + chr(ord(x[y]) >> 1) + x[
                                                                            y + 1:]  # Bitwise shift right character @ N
        self.hashcat_rule["+"] = lambda x, y: x[:y] + chr(ord(x[y]) + 1) + x[
                                                                           y + 1:]  # Increment character @ N by 1 ascii value
        self.hashcat_rule["-"] = lambda x, y: x[:y] + chr(ord(x[y]) - 1) + x[
                                                                           y + 1:]  # Decrement character @ N by 1 ascii value
        self.hashcat_rule["."] = lambda x, y: x[:y] + x[y + 1] + x[
                                                                 y + 1:]  # Replace character @ N with value at @ N plus 1
        self.hashcat_rule[","] = lambda x, y: x[:y] + x[y - 1] + x[
                                                                 y + 1:]  # Replace character @ N with value at @ N minus 1

        # Swappping rules
        self.hashcat_rule["k"] = lambda x: x[1] + x[0] + x[2:]  # Swap first two characters
        self.hashcat_rule["K"] = lambda x: x[:-2] + x[-1] + x[-2]  # Swap last two characters
        self.hashcat_rule["*"] = lambda x, y, z: x[:y] + x[z] + x[y + 1:z] + x[y] + x[z + 1:] if z > y else x[:z] + x[
            y] + x[z + 1:y] + x[z] + x[y + 1:]  # Swap character X with Y

        ########################################################################
        # Common numeric and special character substitutions (1337 5p34k)
        self.leet = dict()
        self.leet["1"] = "i"
        self.leet["2"] = "z"
        self.leet["3"] = "e"
        self.leet["4"] = "a"
        self.leet["5"] = "s"
        self.leet["6"] = "b"
        self.leet["7"] = "t"
        self.leet["8"] = "b"
        self.leet["9"] = "g"
        self.leet["0"] = "o"
        self.leet["!"] = "i"
        self.leet["|"] = "i"
        self.leet["@"] = "a"
        self.leet["$"] = "s"
        self.leet["+"] = "t"

        ########################################################################
        # Preanalysis rules to bruteforce for each word
        self.preanalysis_rules = []
        self.preanalysis_rules.append(([], self.hashcat_rule[':']))  # Blank rule
        self.preanalysis_rules.append((['r'], self.hashcat_rule['r']))  # Reverse rule
        # self.preanalysis_rules.append((['{'],self.hashcat_rule['}'])) # Rotate left
        # self.preanalysis_rules.append((['}'],self.hashcat_rule['{'])) # Rotate right

    ############################################################################
    # Calculate Levenshtein edit path matrix
    def levenshtein(self, word, password):
        matrix = []

        # Generate and populate the initial matrix
        for i in xrange(len(password) + 1):
            matrix.append([])
            for j in xrange(len(word) + 1):
                if i == 0:
                    matrix[i].append(j)
                elif j == 0:
                    matrix[i].append(i)
                else:
                    matrix[i].append(0)

        # Calculate edit distance for each substring
        for i in xrange(1, len(password) + 1):
            for j in xrange(1, len(word) + 1):
                if password[i - 1] == word[j - 1]:
                    matrix[i][j] = matrix[i - 1][j - 1]
                else:
                    insertion = matrix[i - 1][j] + 1
                    deletion = matrix[i][j - 1] + 1
                    substitution = matrix[i - 1][j - 1] + 1
                    matrix[i][j] = min(insertion, deletion, substitution)

        return matrix

    def levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings.

        This is straight from Wikipedia.
        """
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if not s1:
            return len(s2)

        previous_row = xrange(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def levenshtein_print(self, matrix, word, password):
        """ Print word X password matrix """
        print "      %s" % "  ".join(list(word))
        for i, row in enumerate(matrix):
            if i == 0:
                print " ",
            else:
                print password[i - 1],
            print " ".join("%2d" % col for col in row)

    def generate_levenshtein_rules(self, word, password):
        """ Generates levenshtein rules. Returns a list of lists of levenshtein rules. """

        # 1) Generate Levenshtein matrix
        matrix = self.levenshtein(word, password)

        # 2) Trace reverse paths through the matrix.
        paths = self.levenshtein_reverse_recursive(matrix, len(matrix) - 1, len(matrix[0]) - 1, 0)

        # 3) Return a collection of reverse paths.
        return [path for path in paths if len(path) <= matrix[-1][-1]]

    def levenshtein_reverse_recursive(self, matrix, i, j, path_len):
        """ Calculate reverse Levenshtein paths.
        Recursive, Depth First, Short-circuited algorithm by Peter Kacherginsky
        Generates a list of edit operations necessary to transform a source word
        into a password. Edit operations are recorded in the form:
        (operation, password_offset, word_offset)
        Where an operation can be either insertion, deletion or replacement.
        """

        if i == 0 and j == 0 or path_len > matrix[-1][-1]:
            return [[]]
        else:
            paths = list()

            cost = matrix[i][j]

            # Calculate minimum cost of each operation
            cost_delete = cost_insert = cost_equal_or_replace = sys.maxint
            if i > 0: cost_insert = matrix[i - 1][j]
            if j > 0: cost_delete = matrix[i][j - 1]
            if i > 0 and j > 0: cost_equal_or_replace = matrix[i - 1][j - 1]
            cost_min = min(cost_delete, cost_insert, cost_equal_or_replace)

            # Recurse through reverse path for each operation
            if cost_insert == cost_min:
                insert_paths = self.levenshtein_reverse_recursive(matrix, i - 1, j, path_len + 1)
                for insert_path in insert_paths: paths.append(insert_path + [('insert', i - 1, j)])

            if cost_delete == cost_min:
                delete_paths = self.levenshtein_reverse_recursive(matrix, i, j - 1, path_len + 1)
                for delete_path in delete_paths: paths.append(delete_path + [('delete', i, j - 1)])

            if cost_equal_or_replace == cost_min:
                if cost_equal_or_replace == cost:
                    equal_paths = self.levenshtein_reverse_recursive(matrix, i - 1, j - 1, path_len)
                    for equal_path in equal_paths: paths.append(equal_path)
                else:
                    replace_paths = self.levenshtein_reverse_recursive(matrix, i - 1, j - 1, path_len + 1)
                    for replace_path in replace_paths: paths.append(replace_path + [('replace', i - 1, j - 1)])

            return paths

    def load_custom_wordlist(self, wordlist_file):
        self.enchant = enchant.request_pwl_dict(wordlist_file)

    def generate_words(self, password):
        """ Generate source word candidates."""

        if self.debug: print
        "[*] Generating source words for %s" % password

        words = list()
        words_collection = list()

        # Let's collect best edit distance as soon as possible to prevent
        # less efficient pre_rules like reversal and rotation from slowing
        # us down with garbage
        best_found_distance = 9999

        #######################################################################
        # Generate words for each preanalysis rule
        if not self.brute_rules:
            self.preanalysis_rules = self.preanalysis_rules[:1]

        for pre_rule, pre_rule_lambda in self.preanalysis_rules:

            pre_password = pre_rule_lambda(password)

            # Generate word suggestions
            if self.word:
                suggestions = [self.word]
            elif self.simple_words:
                suggestions = self.generate_simple_words(pre_password)
            else:
                suggestions = self.generate_advanced_words(pre_password)

            # HACK: Perform some additional expansion on multi-word suggestions
            # TODO: May be I should split these two and see if I can generate 
            # rules for each of the suggestions
            for suggestion in suggestions[:self.max_words]:
                suggestion = suggestion.replace(' ', '')
                suggestion = suggestion.replace('-', '')
                if not suggestion in suggestions:
                    suggestions.append(suggestion)

            if len(suggestions) != len(set(suggestions)):
                print
                sorted(suggestions)
                print
                sorted(set(suggestions))

            for suggestion in suggestions:
                distance = self.levenshtein_distance(suggestion, pre_password)

                word = dict()
                word["suggestion"] = suggestion
                word["distance"] = distance
                word["password"] = pre_password
                word["pre_rule"] = pre_rule
                word["best_rule_length"] = 9999

                words.append(word)

        #######################################################################
        # Perform Optimization
        for word in sorted(words, key=lambda word: word["distance"], reverse=False):

            # Optimize for best distance
            if not self.more_words:
                if word["distance"] < best_found_distance:
                    best_found_distance = word["distance"]

                elif word["distance"] > best_found_distance:
                    if self.verbose:
                        print
                        "[-] %s => {edit distance suboptimal: %d (%d)} => %s" % \
                        (word["suggestion"], word["distance"], best_found_distance, word["password"])
                    break

                    # Filter words with too big edit distance
            if word["distance"] <= self.max_word_dist:
                if self.debug:
                    print
                    "[+] %s => {edit distance: %d (%d)} = > %s" % \
                    (word["suggestion"], word["distance"], best_found_distance, word["password"])

                words_collection.append(word)

            else:
                if self.verbose:
                    print
                    "[-] %s => {max distance exceeded: %d (%d)} => %s" % \
                    (word["suggestion"], word["distance"], self.max_word_dist, word["password"])

        if self.max_words:
            words_collection = words_collection[:self.max_words]

        return words_collection

    def generate_simple_words(self, password):
        """ Generate simple words. A simple spellcheck."""

        return self.enchant.suggest(password)

    def generate_advanced_words(self, password):
        """ Generate advanced words.
        Perform some additional non-destructive cleaning to help spell-checkers:
        1) Remove non-alpha prefixes and appendixes.
        2) Perform common pattern matches (e.g. email).
        3) Replace non-alpha character substitutions (1337 5p34k)
        """

        # Remove non-alpha prefix and/or appendix
        insertion_matches = self.password_pattern["insertion"].match(password)
        if insertion_matches:
            password = insertion_matches.group('password')

        # Pattern matches
        email_matches = self.password_pattern["email"].match(password)
        if email_matches:
            password = email_matches.group('password')

        # Replace common special character replacements (1337 5p34k)
        preanalysis_password = ''
        for c in password:
            if c in self.leet:
                preanalysis_password += self.leet[c]
            else:
                preanalysis_password += c
        password = preanalysis_password

        if self.debug: "[*] Preanalysis Password: %s" % password

        return self.enchant.suggest(password)

    ############################################################################
    # Hashcat specific offset definition 0-9,A-Z
    def int_to_hashcat(self, N):
        if N < 10:
            return N
        else:
            return chr(65 + N - 10)

    def hashcat_to_int(self, N):
        if N.isdigit():
            return int(N)
        else:
            return ord(N) - 65 + 10

    def generate_hashcat_rules(self, suggestion, password):
        """ Generate hashcat rules. Returns a length sorted list of lists of hashcat rules."""

        # 2) Generate Levenshtein Rules
        lev_rules = self.generate_levenshtein_rules(suggestion, password)

        # 3) Generate Hashcat Rules
        hashcat_rules = []
        hashcat_rules_collection = []

        #######################################################################
        # Generate hashcat rule for each levenshtein rule
        for lev_rule in lev_rules:

            if self.simple_rules:
                hashcat_rule = self.generate_simple_hashcat_rules(suggestion, lev_rule, password)
            else:
                hashcat_rule = self.generate_advanced_hashcat_rules(suggestion, lev_rule, password)

            if hashcat_rule == None:
                print
                "[!] Processing FAILED: %s => ;( => %s" % (suggestion, password)
                print
                "    Sorry about that, please report this failure to"
                print
                "    the developer: iphelix [at] thesprawl.org"

            else:
                hashcat_rules.append(hashcat_rule)

        best_found_rule_length = 9999

        #######################################################################
        # Perform Optimization
        for hashcat_rule in sorted(hashcat_rules, key=lambda hashcat_rule: len(hashcat_rule)):

            rule_length = len(hashcat_rule)

            if not self.more_rules:
                if rule_length < best_found_rule_length:
                    best_found_rule_length = rule_length

                elif rule_length > best_found_rule_length:
                    if self.verbose:
                        print
                        "[-] %s => {best rule length exceeded: %d (%d)} => %s" % \
                        (suggestion, rule_length, best_found_rule_length, password)
                    break

            if rule_length <= self.max_rule_len:
                hashcat_rules_collection.append(hashcat_rule)

        return hashcat_rules_collection

    def generate_simple_hashcat_rules(self, word, rules, password):
        """ Generate basic hashcat rules using only basic insert,delete,replace rules. """
        hashcat_rules = []

        if self.debug: print
        "[*] Simple Processing %s => %s" % (word, password)

        # Dynamically apply rules to the source word
        # NOTE: Special case were word == password this would work as well.
        word_rules = word

        for (op, p, w) in rules:

            if self.debug: print
            "\t[*] Simple Processing Started: %s - %s" % (word_rules, " ".join(hashcat_rules))

            if op == 'insert':
                hashcat_rules.append("i%s%s" % (self.int_to_hashcat(p), password[p]))
                word_rules = self.hashcat_rule['i'](word_rules, p, password[p])

            elif op == 'delete':
                hashcat_rules.append("D%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['D'](word_rules, p)

            elif op == 'replace':
                hashcat_rules.append("o%s%s" % (self.int_to_hashcat(p), password[p]))
                word_rules = self.hashcat_rule['o'](word_rules, p, password[p])

        if self.debug: print
        "\t[*] Simple Processing Ended: %s => %s => %s" % (word_rules, " ".join(hashcat_rules), password)

        # Check if rules result in the correct password
        if word_rules == password:
            return hashcat_rules
        else:
            if self.debug: print
            "[!] Simple Processing FAILED: %s => %s => %s (%s)" % (word, " ".join(hashcat_rules), password, word_rules)
            return None

    def generate_advanced_hashcat_rules(self, word, rules, password):
        """ Generate advanced hashcat rules using full range of available rules. """
        hashcat_rules = []

        if self.debug: print
        "[*] Advanced Processing %s => %s" % (word, password)

        # Dynamically apply and store rules in word_rules variable.
        # NOTE: Special case where word == password this would work as well.
        word_rules = word

        # Generate case statistics
        password_lower = len([c for c in password if c.islower()])
        password_upper = len([c for c in password if c.isupper()])

        for i, (op, p, w) in enumerate(rules):

            if self.debug: print
            "\t[*] Advanced Processing Started: %s - %s" % (word_rules, " ".join(hashcat_rules))

            if op == 'insert':
                hashcat_rules.append("i%s%s" % (self.int_to_hashcat(p), password[p]))
                word_rules = self.hashcat_rule['i'](word_rules, p, password[p])

            elif op == 'delete':
                hashcat_rules.append("D%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['D'](word_rules, p)

            elif op == 'replace':

                # Detecting global replacement such as sXY, l, u, C, c is a non
                # trivial problem because different characters may be added or
                # removed from the word by other rules. A reliable way to solve
                # this problem is to apply all of the rules the source word
                # and keep track of its state at any given time. At the same
                # time, global replacement rules can be tested by completing
                # the rest of the rules using a simplified engine.

                # The sequence of if statements determines the priority of rules

                # This rule was made obsolete by a prior global replacement
                if word_rules[p] == password[p]:
                    if self.debug: print
                    "\t[*] Advanced Processing Obsolete Rule: %s - %s" % (word_rules, " ".join(hashcat_rules))

                # Swapping rules
                elif p < len(password) - 1 and p < len(word_rules) - 1 and word_rules[p] == password[p + 1] and
                    word_rules[p + 1] == password[p]:
                    # Swap first two characters
                if p == 0 and self.generate_simple_hashcat_rules(self.hashcat_rule['k'](word_rules), rules[i + 1:],
                                                                 password):
                    hashcat_rules.append("k")
                    word_rules = self.hashcat_rule['k'](word_rules)
                    # Swap last two characters
                elif p == len(word_rules) - 2 and self.generate_simple_hashcat_rules(
                        self.hashcat_rule['K'](word_rules), rules[i + 1:], password):
                    hashcat_rules.append("K")
                    word_rules = self.hashcat_rule['K'](word_rules)
                    # Swap any two characters (only adjacent swapping is supported)
                elif self.generate_simple_hashcat_rules(self.hashcat_rule['*'](word_rules, p, p + 1), rules[i + 1:],
                                                        password):
                    hashcat_rules.append("*%s%s" % (self.int_to_hashcat(p), self.int_to_hashcat(p + 1)))
                    word_rules = self.hashcat_rule['*'](word_rules, p, p + 1)
                else:
                    hashcat_rules.append("o%s%s" % (self.int_to_hashcat(p), password[p]))
                    word_rules = self.hashcat_rule['o'](word_rules, p, password[p])

                # Case Toggle: Uppercased a letter
                elif word_rules[p].islower() and word_rules[p].upper() == password[
                    p]:  # Toggle the case of all characters in word (mixed cases)
                if password_upper and password_lower and self.generate_simple_hashcat_rules(
                        self.hashcat_rule['t'](word_rules), rules[i + 1:], password):
                    hashcat_rules.append("t")
                    word_rules = self.hashcat_rule['t'](word_rules)

                # Capitalize all letters
                elif self.generate_simple_hashcat_rules(self.hashcat_rule['u'](word_rules), rules[i + 1:],
                                                        password):
                    hashcat_rules.append("u")
                    word_rules = self.hashcat_rule['u'](word_rules)

                # Capitalize the first letter
                elif p == 0 and self.generate_simple_hashcat_rules(self.hashcat_rule['c'](word_rules),
                                                                   rules[i + 1:], password):
                    hashcat_rules.append("c")
                    word_rules = self.hashcat_rule['c'](word_rules)

                # Toggle the case of characters at position N
                else:
                    hashcat_rules.append("T%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['T'](word_rules, p)

            # Case Toggle: Lowercased a letter
            elif word_rules[p].isupper() and word_rules[p].lower() == password[p]:

                # Toggle the case of all characters in word (mixed cases)
                if password_upper and password_lower and self.generate_simple_hashcat_rules(
                        self.hashcat_rule['t'](word_rules), rules[i + 1:], password):
                    hashcat_rules.append("t")
                    word_rules = self.hashcat_rule['t'](word_rules)

                # Lowercase all letters
                elif self.generate_simple_hashcat_rules(self.hashcat_rule['l'](word_rules), rules[i + 1:],
                                                        password):
                    hashcat_rules.append("l")
                    word_rules = self.hashcat_rule['l'](word_rules)

                # Lowercase the first found character, uppercase the rest
                elif p == 0 and self.generate_simple_hashcat_rules(self.hashcat_rule['C'](word_rules),
                                                                   rules[i + 1:], password):
                    hashcat_rules.append("C")
                    word_rules = self.hashcat_rule['C'](word_rules)

                # Toggle the case of characters at position N
                else:
                    hashcat_rules.append("T%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['T'](word_rules, p)

            # Special case substitution of 'all' instances (1337 $p34k)
            elif word_rules[p].isalpha() and not password[p].isalpha() and self.generate_simple_hashcat_rules(
                    self.hashcat_rule['s'](word_rules, word_rules[p], password[p]), rules[i + 1:], password):

                # If we have already detected this rule, then skip it thus
                # reducing total rule count.
                # BUG: Elisabeth => sE3 sl1 u o3Z sE3 => 31IZAB3TH
                # if not "s%s%s" % (word_rules[p],password[p]) in hashcat_rules:
                hashcat_rules.append("s%s%s" % (word_rules[p], password[p]))
                word_rules = self.hashcat_rule['s'](word_rules, word_rules[p], password[p])

            # Replace next character with current
            elif p < len(password) - 1 and p < len(word_rules) - 1 and password[p] == password[p + 1] and password[
                p] == word_rules[p + 1]:
                hashcat_rules.append(".%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['.'](word_rules, p)

            # Replace previous character with current
            elif p > 0 and w > 0 and password[p] == password[p - 1] and password[p] == word_rules[p - 1]:
                hashcat_rules.append(",%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule[','](word_rules, p)

            # ASCII increment
            elif ord(word_rules[p]) + 1 == ord(password[p]):
                hashcat_rules.append("+%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['+'](word_rules, p)

            # ASCII decrement
            elif ord(word_rules[p]) - 1 == ord(password[p]):
                hashcat_rules.append("-%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['-'](word_rules, p)

            # SHIFT left
            elif ord(word_rules[p]) << 1 == ord(password[p]):
                hashcat_rules.append("L%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['L'](word_rules, p)

            # SHIFT right
            elif ord(word_rules[p]) >> 1 == ord(password[p]):
                hashcat_rules.append("R%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['R'](word_rules, p)

                # Position based replacements.
            else:
                hashcat_rules.append("o%s%s" % (self.int_to_hashcat(p), password[p]))
                word_rules = self.hashcat_rule['o'](word_rules, p, password[p])

    if self.debug: print
    "\t[*] Advanced Processing Ended: %s %s" % (word_rules, " ".join(hashcat_rules))

    ########################################################################
    # Prefix rules
    last_prefix = 0
    prefix_rules = list()
    for hashcat_rule in hashcat_rules:
        if hashcat_rule[0] == "i" and self.hashcat_to_int(hashcat_rule[1]) == last_prefix:
            prefix_rules.append("^%s" % hashcat_rule[2])
            last_prefix += 1
        elif len(prefix_rules):
            hashcat_rules = prefix_rules[::-1] + hashcat_rules[len(prefix_rules):]
            break
        else:
            break
    else:
        hashcat_rules = prefix_rules[::-1] + hashcat_rules[len(prefix_rules):]

    ####################################################################
    # Appendix rules
    last_appendix = len(password) - 1
    appendix_rules = list()
    for hashcat_rule in hashcat_rules[::-1]:
        if hashcat_rule[0] == "i" and self.hashcat_to_int(hashcat_rule[1]) == last_appendix:
            appendix_rules.append("$%s" % hashcat_rule[2])
            last_appendix -= 1
        elif len(appendix_rules):
            hashcat_rules = hashcat_rules[:-len(appendix_rules)] + appendix_rules[::-1]
            break
        else:
            break
    else:
        hashcat_rules = hashcat_rules[:-len(appendix_rules)] + appendix_rules[::-1]

    ####################################################################
    # Truncate left rules
    last_precut = 0
    precut_rules = list()
    for hashcat_rule in hashcat_rules:
        if hashcat_rule[0] == "D" and self.hashcat_to_int(hashcat_rule[1]) == last_precut:
            precut_rules.append("[")
        elif len(precut_rules):
            hashcat_rules = precut_rules[::-1] + hashcat_rules[len(precut_rules):]
            break
        else:
            break
    else:
        hashcat_rules = precut_rules[::-1] + hashcat_rules[len(precut_rules):]

    ####################################################################
    # Truncate right rules
    last_postcut = len(password)
    postcut_rules = list()
    for hashcat_rule in hashcat_rules[::-1]:

        if hashcat_rule[0] == "D" and self.hashcat_to_int(hashcat_rule[1]) >= last_postcut:
            postcut_rules.append("]")
        elif len(postcut_rules):
            hashcat_rules = hashcat_rules[:-len(postcut_rules)] + postcut_rules[::-1]
            break
        else:
            break
    else:
        hashcat_rules = hashcat_rules[:-len(postcut_rules)] + postcut_rules[::-1]

    # Check if rules result in the correct password
    if word_rules == password:
        return hashcat_rules
    else:
        if self.debug: print
        "[!] Advanced Processing FAILED: %s => %s => %s (%s)" % (
            word, " ".join(hashcat_rules), password, word_rules)
        return None


def check_reversible_password(self, password):
    """ Check whether the password is likely to be reversed successfuly. """

    # Skip all numeric passwords
    if password.isdigit():
        if self.verbose and not self.quiet: print
        "[!] %s => {skipping numeric} => %s" % (password, password)
        self.numeric_stats_total += 1
        return False

    # Skip passwords with less than 25% of alpha character
    # TODO: Make random word detection more reliable based on word entropy.
    elif len([c for c in password if c.isalpha()]) < len(password) / 4:
        if self.verbose and not self.quiet: print
        "[!] %s => {skipping alpha less than 25%%} => %s" % (password, password)
        self.special_stats_total += 1
        return False

    # Only check english ascii passwords for now
    # TODO: Add support for more languages.
    elif [c for c in password if ord(c) < 32 or ord(c) > 126]:
        if self.verbose and not self.quiet: print
        "[!] %s => {skipping non ascii english} => %s" % (password, password)
        self.foreign_stats_total += 1
        return False

    else:
        return True


def analyze_password(self, password, rules_queue=multiprocessing.Queue(), words_queue=multiprocessing.Queue()):
    """ Analyze a single password. """

    if self.verbose: print
    "[*] Analyzing password: %s" % password

    words = []

    # Short-cut words in the dictionary
    if self.enchant.check(password) and not self.word:

        word = dict()
        word["password"] = password
        word["suggestion"] = password
        word["hashcat_rules"] = [[], ]
        word["pre_rule"] = []
        word["best_rule_length"] = 9999

        words.append(word)

    # Generate rules for words not in the dictionary
    else:

        # Generate source words list
        words = self.generate_words(password)

        # Generate levenshtein reverse paths for each suggestion
        for word in words:
            # Generate a collection of hashcat_rules lists
            word["hashcat_rules"] = self.generate_hashcat_rules(word["suggestion"], word["password"])

    self.print_hashcat_rules(words, password, rules_queue, words_queue)


def print_hashcat_rules(self, words, password, rules_queue, words_queue):
    best_found_rule_length = 9999

    # Sorted list based on rule length
    for word in sorted(words, key=lambda word: len(word["hashcat_rules"][0])):

        words_queue.put(word["suggestion"])

        for hashcat_rule in word["hashcat_rules"]:

            rule_length = len(hashcat_rule)

            if not self.more_rules:
                if rule_length < best_found_rule_length:
                    best_found_rule_length = rule_length

                elif rule_length > best_found_rule_length:
                    if self.verbose:
                        print
                        "[-] %s => {best rule length exceeded: %d (%d)} => %s" % \
                        (word["suggestion"], rule_length, best_found_rule_length, password)
                    break

            if rule_length <= self.max_rule_len:

                hashcat_rule_str = " ".join(hashcat_rule + word["pre_rule"] or [':'])
                if self.verbose: print
                "[+] %s => %s => %s" % (word["suggestion"], hashcat_rule_str, password)

                rules_queue.put(hashcat_rule_str)


def password_worker(self, i, passwords_queue, rules_queue, words_queue):
    if self.debug: print
    "[*] Password analysis worker [%d] started." % i
    try:
        while True:
            password = passwords_queue.get()

            # Interrupted by a Death Pill
            if password == None: break

            self.analyze_password(password, rules_queue, words_queue)
    except (KeyboardInterrupt, SystemExit):
        if self.debug: print
        "[*] Password analysis worker [%d] terminated." % i

    if self.debug: print
    "[*] Password analysis worker [%d] stopped." % i


def rule_worker(self, rules_queue, output_rules_filename):
    """ Worker to store generated rules. """
    print
    "[*] Saving rules to %s" % output_rules_filename

    f = open(output_rules_filename, 'w')
    if self.debug: print
    "[*] Rule worker started."
    try:
        while True:
            rule = rules_queue.get()

            # Interrupted by a Death Pill
            if rule == None: break

            f.write("%s\n" % rule)
            f.flush()

    except (KeyboardInterrupt, SystemExit):
        if self.debug: print
        "[*] Rule worker terminated."

    f.close()
    if self.debug: print
    "[*] Rule worker stopped."


def word_worker(self, words_queue, output_words_filename):
    """ Worker to store generated rules. """
    print
    "[*] Saving words to %s" % output_words_filename

    f = open(output_words_filename, 'w')
    if self.debug: print
    "[*] Word worker started."
    try:
        while True:
            word = words_queue.get()

            # Interrupted by a Death Pill
            if word == None: break

            f.write("%s\n" % word)
            f.flush()

    except (KeyboardInterrupt, SystemExit):
        if self.debug: print
        "[*] Word worker terminated."

    f.close()
    if self.debug: print
    "[*] Word worker stopped."


# Analyze passwords file
def analyze_passwords_file(self, passwords_file):
    """ Analyze provided passwords file. """

    print
    "[*] Analyzing passwords file: %s:" % passwords_file
    print
    "[*] Press Ctrl-C to end execution and generate statistical analysis."

    # Setup queues
    passwords_queue = multiprocessing.Queue(multiprocessing.cpu_count() * 100)
    rules_queue = multiprocessing.Queue()
    words_queue = multiprocessing.Queue()

    # Start workers
    for i in range(multiprocessing.cpu_count()):
        multiprocessing.Process(target=self.password_worker,
                                args=(i, passwords_queue, rules_queue, words_queue)).start()
    multiprocessing.Process(target=self.rule_worker, args=(rules_queue, "%s.rule" % self.basename)).start()
    multiprocessing.Process(target=self.word_worker, args=(words_queue, "%s.word" % self.basename)).start()

    # Continue with the main thread

    f = open(passwords_file, 'r')

    password_count = 0
    analysis_start = time.time()
    segment_start = analysis_start
    try:
        for password in f:
            password = password.rstrip('\r\n')
            if len(password) > 0:

                # Provide analysis time feedback to the user
                if not self.quiet and password_count != 0 and password_count % 5000 == 0:
                    segment_time = time.time() - segment_start
                    print
                    "[*] Processed %d passwords in %.2f seconds at the rate of %.2f p/sec" % \
                    (password_count, segment_start - analysis_start, 5000 / segment_time)
                    segment_start = time.time()

                password_count += 1

                # Perform preliminary checks and add password to the queue
                if self.check_reversible_password(password):
                    passwords_queue.put(password)

    except (KeyboardInterrupt, SystemExit):
        print
        "\n[!] Rulegen was interrupted."

    else:
        # Signal workers to stop.
        for i in range(multiprocessing.cpu_count()):
            passwords_queue.put(None)

            # Wait for all of the queued passwords to finish.
        while not passwords_queue.empty():
            time.sleep(1)

        # Signal writers to stop.
        rules_queue.put(None)
        words_queue.put(None)

    f.close()

    analysis_time = time.time() - analysis_start
    print
    "[*] Finished processing %d passwords in %.2f seconds at the rate of %.2f p/sec" % (
        password_count, analysis_time, float(password_count) / analysis_time)

    print
    "[*] Generating statistics for [%s] rules and words." % self.basename
    print
    "[-] Skipped %d all numeric passwords (%0.2f%%)" % \
    (self.numeric_stats_total, float(self.numeric_stats_total) * 100.0 / float(password_count))
    print
    "[-] Skipped %d passwords with less than 25%% alpha characters (%0.2f%%)" % \
    (self.special_stats_total, float(self.special_stats_total) * 100.0 / float(password_count))
    print
    "[-] Skipped %d passwords with non ascii characters (%0.2f%%)" % \
    (self.foreign_stats_total, float(self.foreign_stats_total) * 100.0 / float(password_count))

    # TODO: Counter breaks on large files. uniq -c | sort -rn is still the most
    #       optimal way.
    rules_file = open("%s.rule" % self.basename, 'r')
    rules_sorted_file = open("%s-sorted.rule" % self.basename, 'w')
    rules_counter = Counter(rules_file)
    rule_counter_total = sum(rules_counter.values())

    print
    "\n[*] Top 10 rules"
    rules_i = 0
    for (rule, count) in rules_counter.most_common():
        rules_sorted_file.write(rule)
        if rules_i < 10: print
        "[+] %s - %d (%0.2f%%)" % (rule.rstrip('\r\n'), count, count * 100 / rule_counter_total)
        rules_i += 1

    rules_file.close()
    rules_sorted_file.close()

    words_file = open("%s.word" % self.basename, 'r')
    words_sorted_file = open("%s-sorted.word" % self.basename, 'w')
    words_counter = Counter(words_file)
    word_counter_total = sum(rules_counter.values())

    print
    "\n[*] Top 10 words"
    words_i = 0
    for (word, count) in words_counter.most_common():
        words_sorted_file.write(word)
        if words_i < 10: print
        "[+] %s - %d (%0.2f%%)" % (word.rstrip('\r\n'), count, count * 100 / word_counter_total)
        words_i += 1

    words_file.close()
    words_sorted_file.close()


############################################################################
def verify_hashcat_rules(self, word, rules, password):
    f = open("%s/test.rule" % HASHCAT_PATH, 'w')
    f.write(" ".join(rules))
    f.close()

    f = open("%s/test.word" % HASHCAT_PATH, 'w')
    f.write(word)
    f.close()

    p = subprocess.Popen(["%s/hashcat-cli64.bin" % HASHCAT_PATH, "-r", "%s/test.rule" % HASHCAT_PATH, "--stdout",
                          "%s/test.word" % HASHCAT_PATH], stdout=subprocess.PIPE)
    out, err = p.communicate()
    out = out.strip()

    if out == password:
        hashcat_rules_str = " ".join(rules or [':'])
        if self.verbose: print
        "[+] %s => %s => %s" % (word, hashcat_rules_str, password)

    else:
        print
        "[!] Hashcat Verification FAILED: %s => %s => %s (%s)" % (word, " ".join(rules or [':']), password, out)


if __name__ == "__main__":

    header = "                       _ \n"
    header += "     RuleGen %s    | |\n" % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog [options] passwords.txt", version="%prog " + VERSION)

    parser.add_option("-b", "--basename",
                      help="Output base name. The following files will be generated: basename.words, basename.rules and basename.stats",
                      default="analysis", metavar="rockyou")
    parser.add_option("-w", "--wordlist", help="Use a custom wordlist for rule analysis.", metavar="wiki.dict")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    parser.add_option("--threads", type="int", default=10, help="Parallel threads to use for processing.")

    wordtune = OptionGroup(parser, "Fine tune source word generation:")
    wordtune.add_option("--maxworddist", help="Maximum word edit distance (Levenshtein)", type="int", default=10,
                        metavar="10")
    wordtune.add_option("--maxwords", help="Maximum number of source word candidates to consider", type="int",
                        default=5, metavar="5")
    wordtune.add_option("--morewords", help="Consider suboptimal source word candidates", action="store_true",
                        default=False)
    wordtune.add_option("--simplewords", help="Generate simple source words for given passwords", action="store_true",
                        default=False)
    parser.add_option_group(wordtune)

    ruletune = OptionGroup(parser, "Fine tune rule generation:")
    ruletune.add_option("--maxrulelen", help="Maximum number of operations in a single rule", type="int", default=10,
                        metavar="10")
    ruletune.add_option("--maxrules", help="Maximum number of rules to consider", type="int", default=5, metavar="5")
    ruletune.add_option("--morerules", help="Generate suboptimal rules", action="store_true", default=False)
    ruletune.add_option("--simplerules", help="Generate simple rules insert,delete,replace", action="store_true",
                        default=False)
    ruletune.add_option("--bruterules", help="Bruteforce reversal and rotation rules (slow)", action="store_true",
                        default=False)
    parser.add_option_group(ruletune)

    spelltune = OptionGroup(parser, "Fine tune spell checker engine:")
    spelltune.add_option("--providers", help="Comma-separated list of provider engines", default="aspell,myspell",
                         metavar="aspell,myspell")
    parser.add_option_group(spelltune)

    debug = OptionGroup(parser, "Debuggin options:")
    debug.add_option("-v", "--verbose", help="Show verbose information.", action="store_true", default=False)
    debug.add_option("-d", "--debug", help="Debug rules.", action="store_true", default=False)
    debug.add_option("--password", help="Process the last argument as a password not a file.", action="store_true",
                     default=False)
    debug.add_option("--word", help="Use a custom word for rule analysis", metavar="Password")
    debug.add_option("--hashcat", help="Test generated rules with hashcat-cli", action="store_true", default=False)
    parser.add_option_group(debug)

    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print
        header

    if len(args) < 1:
        parser.error("no passwords file specified")
        exit(1)

    rulegen = RuleGen(language="en", providers=options.providers, basename=options.basename, threads=options.threads)

    # Finetuning word generation
    rulegen.max_word_dist = options.maxworddist
    rulegen.max_words = options.maxwords
    rulegen.more_words = options.morewords
    rulegen.simple_words = options.simplewords

    # Finetuning rule generation
    rulegen.max_rule_len = options.maxrulelen
    rulegen.max_rules = options.maxrules
    rulegen.more_rules = options.morerules
    rulegen.simple_rules = options.simplerules
    rulegen.brute_rules = options.bruterules
    if rulegen.brute_rules: print
    "[!] Bruteforcing reversal and rotation rules. (slower)"

    # Debugging options
    rulegen.word = options.word
    rulegen.verbose = options.verbose
    rulegen.debug = options.debug
    rulegen.hashcat = options.hashcat
    rulegen.quiet = options.quiet

    # Custom wordlist
    if not options.word:
        if options.wordlist: rulegen.load_custom_wordlist(options.wordlist)
        print
        "[*] Using Enchant '%s' module. For best results please install" % rulegen.enchant.provider.name
        print
        "    '%s' module language dictionaries." % rulegen.enchant.provider.name

    # Analyze a single password or several passwords in a file
    if options.password:
        rulegen.analyze_password(args[0])
    else:
        rulegen.analyze_passwords_file(args[0])
