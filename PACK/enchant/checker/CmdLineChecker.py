# pyenchant
#
# Copyright (C) 2004-2008, Ryan Kelly
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#
# In addition, as a special exception, you are
# given permission to link the code of this program with
# non-LGPL Spelling Provider libraries (eg: a MSFT Office
# spell checker backend) and distribute linked combinations including
# the two.  You must obey the GNU Lesser General Public License in all
# respects for all of the code used other than said providers.  If you modify
# this file, you may extend this exception to your version of the
# file, but you are not obligated to do so.  If you do not wish to
# do so, delete this exception statement from your version.
#
"""

    enchant.checker.CmdLineChecker:  Command-Line spell checker
    
    This module provides the class CmdLineChecker, which interactively
    spellchecks a piece of text by interacting with the user on the
    command line.  It can also be run as a script to spellcheck a file.

"""

import sys

from enchant.checker import SpellChecker
from enchant.utils import printf


class CmdLineChecker:
    """A simple command-line spell checker.
    
    This class implements a simple command-line spell checker.  It must
    be given a SpellChecker instance to operate on, and interacts with
    the user by printing instructions on stdout and reading commands from
    stdin.
    """
    _DOC_ERRORS = ["stdout", "stdin"]

    def __init__(self):
        self._stop = False
        self._checker = None

    def set_checker(self, chkr):
        self._checker = chkr

    def get_checker(self, chkr):
        return self._checker

    def run(self):
        """Run the spellchecking loop."""
        self._stop = False
        for err in self._checker:
            self.error = err
            printf(["ERROR:", err.word])
            printf(["HOW ABOUT:", err.suggest()])
            status = self.read_command()
            while not status and not self._stop:
                status = self.read_command()
            if self._stop:
                break
        printf(["DONE"])

    def print_help(self):
        printf(["0..N:    replace with the numbered suggestion"])
        printf(["R0..rN:  always replace with the numbered suggestion"])
        printf(["i:       ignore this word"])
        printf(["I:       always ignore this word"])
        printf(["a:       add word to personal dictionary"])
        printf(["e:       edit the word"])
        printf(["q:       quit checking"])
        printf(["h:       print this help message"])
        printf(["----------------------------------------------------"])
        printf(["HOW ABOUT:", self.error.suggest()])

    def read_command(self):
        cmd = raw_input(">> ")
        cmd = cmd.strip()

        if cmd.isdigit():
            repl = int(cmd)
            suggs = self.error.suggest()
            if repl >= len(suggs):
                printf(["No suggestion number", repl])
                return False
            printf(["Replacing '%s' with '%s'" % (self.error.word, suggs[repl])])
            self.error.replace(suggs[repl])
            return True

        if cmd[0] == "R":
            if not cmd[1:].isdigit():
                printf(["Badly formatted command (try 'help')"])
                return False
            repl = int(cmd[1:])
            suggs = self.error.suggest()
            if repl >= len(suggs):
                printf(["No suggestion number", repl])
                return False
            self.error.replace_always(suggs[repl])
            return True

        if cmd == "i":
            return True

        if cmd == "I":
            self.error.ignore_always()
            return True

        if cmd == "a":
            self.error.add()
            return True

        if cmd == "e":
            repl = raw_input("New Word: ")
            self.error.replace(repl.strip())
            return True

        if cmd == "q":
            self._stop = True
            return True

        if "help".startswith(cmd.lower()):
            self.print_help()
            return False

        printf(["Badly formatted command (try 'help')"])
        return False

    def run_on_file(self, infile, outfile=None, enc=None):
        """Run spellchecking on the named file.
        This method can be used to run the spellchecker over the named file.
        If <outfile> is not given, the corrected contents replace the contents
        of <infile>.  If <outfile> is given, the corrected contents will be
        written to that file.  Use "-" to have the contents written to stdout.
        If <enc> is given, it specifies the encoding used to read the
        file's contents into a unicode string.  The output will be written
        in the same encoding.
        """
        inStr = "".join(file(infile, "r").readlines())
        if enc is not None:
            inStr = inStr.decode(enc)
        self._checker.set_text(inStr)
        self.run()
        outStr = self._checker.get_text()
        if enc is not None:
            outStr = outStr.encode(enc)
        if outfile is None:
            outF = file(infile, "w")
        elif outfile == "-":
            outF = sys.stdout
        else:
            outF = file(outfile, "w")
        outF.write(outStr)
        outF.close()

    run_on_file._DOC_ERRORS = ["outfile", "infile", "outfile", "stdout"]


def _run_as_script():
    """Run the command-line spellchecker as a script.
    This function allows the spellchecker to be invoked from the command-line
    to check spelling in a file.
    """
    # Check necessary command-line options
    from optparse import OptionParser
    op = OptionParser()
    op.add_option("-o", "--output", dest="outfile", metavar="FILE",
                  help="write changes into FILE")
    op.add_option("-l", "--lang", dest="lang", metavar="TAG", default="en_US",
                  help="use language idenfified by TAG")
    op.add_option("-e", "--encoding", dest="enc", metavar="ENC",
                  help="file is unicode with encoding ENC")
    (opts, args) = op.parse_args()
    # Sanity check
    if len(args) < 1:
        raise ValueError("Must name a file to check")
    if len(args) > 1:
        raise ValueError("Can only check a single file")
    # Create and run the checker
    chkr = SpellChecker(opts.lang)
    cmdln = CmdLineChecker()
    cmdln.set_checker(chkr)
    cmdln.run_on_file(args[0], opts.outfile, opts.enc)


if __name__ == "__main__":
    _run_as_script()
