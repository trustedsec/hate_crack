# pyenchant
#
# Copyright (C) 2004-2008 Ryan Kelly
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

enchant.utils:    Misc utilities for the enchant package
========================================================
    
This module provides miscellaneous utilities for use with the
enchant spellchecking package.  Currently available functionality
includes:
        
    * string/unicode compatibility wrappers
    * functions for dealing with locale/language settings
    * ability to list supporting data files (win32 only)
    * functions for bundling supporting data files from a build
      
"""

import os
import sys
import codecs

from enchant.errors import *

# Attempt to access local language information
try:
    import locale
except ImportError:
    locale = None

#
#  Unicode/Bytes compatabilty wrappers.
#
#  These allow us to support both Python 2.x and Python 3.x from
#  the same codebase.
#
#  We provide explicit type objects "bytes" and "unicode" that can be
#  used to construct instances of the appropriate type.  The class
#  "EnchantStr" derives from the default "str" type and implements the
#  necessary logic for encoding/decoding as strings are passed into
#  the underlying C library (where they must always be utf-8 encoded
#  byte strings).
#

try:
    unicode = unicode
except NameError:
    str = str
    unicode = str
    bytes = bytes
    basestring = (str, bytes)
else:
    str = str
    unicode = unicode
    bytes = str
    basestring = basestring


def raw_unicode(raw):
    """Make a unicode string from a raw string.

    This function takes a string containing unicode escape characters,
    and returns the corresponding unicode string.  Useful for writing
    unicode string literals in your python source while being upwards-
    compatible with Python 3.  For example, instead of doing this:

      s = u"hello\u2149"  # syntax error in Python 3

    Or this:

      s = "hello\u2149"   # not what you want in Python 2.x

    You can do this:

      s = raw_unicode(r"hello\u2149")  # works everywhere!

    """
    return raw.encode("utf8").decode("unicode-escape")


def raw_bytes(raw):
    """Make a bytes object out of a raw string.

    This is analogous to raw_unicode, but processes byte escape characters
    to produce a bytes object.
    """
    return codecs.escape_decode(raw)[0]


class EnchantStr(str):
    """String subclass for interfacing with enchant C library.

    This class encapsulates the logic for interfacing between python native
    string/unicode objects and the underlying enchant library, which expects
    all strings to be UTF-8 character arrays.  It is a subclass of the
    default string class 'str' - on Python 2.x that makes it an ascii string,
    on Python 3.x it is a unicode object.

    Initialise it with a string or unicode object, and use the encode() method
    to obtain an object suitable for passing to the underlying C library.
    When strings are read back into python, use decode(s) to translate them
    back into the appropriate python-level string type.

    This allows us to following the common Python 2.x idiom of returning
    unicode when unicode is passed in, and byte strings otherwise.  It also
    lets the interface be upwards-compatible with Python 3, in which string
    objects are unicode by default.
    """

    def __new__(cls, value):
        """EnchantStr data constructor.

        This method records whether the initial string was unicode, then
        simply passes it along to the default string constructor.
        """
        if type(value) is unicode:
            was_unicode = True
            if str is not unicode:
                value = value.encode("utf-8")
        else:
            was_unicode = False
            if str is not bytes:
                raise Error("Don't pass bytestrings to pyenchant")
        self = str.__new__(cls, value)
        self._was_unicode = was_unicode
        return self

    def encode(self):
        """Encode this string into a form usable by the enchant C library."""
        if str is unicode:
            return str.encode(self, "utf-8")
        else:
            return self

    def decode(self, value):
        """Decode a string returned by the enchant C library."""
        if self._was_unicode:
            if str is unicode:
                # On some python3 versions, ctypes converts c_char_p
                # to str() rather than bytes()
                if isinstance(value, str):
                    value = value.encode()
                return value.decode("utf-8")
            else:
                return value.decode("utf-8")
        else:
            return value


def printf(values, sep=" ", end="\n", file=None):
    """Compatability wrapper from print statement/function.

    This function is a simple Python2/Python3 compatability wrapper
    for printing to stdout.
    """
    if file is None:
        file = sys.stdout
    file.write(sep.join(map(str, values)))
    file.write(end)


try:
    next = next
except NameError:
    def next(iter):
        """Compatability wrapper for advancing an iterator."""
        return iter.next()

try:
    xrange = xrange
except NameError:
    xrange = range


#
#  Other useful functions.
#


def levenshtein(s1, s2):
    """Calculate the Levenshtein distance between two strings.

    This is straight from Wikipedia.
    """
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
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


def trim_suggestions(word, suggs, maxlen, calcdist=None):
    """Trim a list of suggestions to a maximum length.

    If the list of suggested words is too long, you can use this function
    to trim it down to a maximum length.  It tries to keep the "best"
    suggestions based on similarity to the original word.

    If the optional "calcdist" argument is provided, it must be a callable
    taking two words and returning the distance between them.  It will be
    used to determine which words to retain in the list.  The default is
    a simple Levenshtein distance.
    """
    if calcdist is None:
        calcdist = levenshtein
    decorated = [(calcdist(word, s), s) for s in suggs]
    decorated.sort()
    return [s for (l, s) in decorated[:maxlen]]


def get_default_language(default=None):
    """Determine the user's default language, if possible.
    
    This function uses the 'locale' module to try to determine
    the user's preferred language.  The return value is as
    follows:
        
        * if a locale is available for the LC_MESSAGES category,
          that language is used
        * if a default locale is available, that language is used
        * if the keyword argument <default> is given, it is used
        * if nothing else works, None is returned
        
    Note that determining the user's language is in general only
    possible if they have set the necessary environment variables
    on their system.
    """
    try:
        import locale
        tag = locale.getlocale()[0]
        if tag is None:
            tag = locale.getdefaultlocale()[0]
            if tag is None:
                raise Error("No default language available")
        return tag
    except Exception:
        pass
    return default


get_default_language._DOC_ERRORS = ["LC"]


def get_resource_filename(resname):
    """Get the absolute path to the named resource file.

    This serves widely the same purpose as pkg_resources.resource_filename(),
    but tries to avoid loading pkg_resources unless we're actually in
    an egg.
    """
    path = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(path, resname)
    if os.path.exists(path):
        return path
    if hasattr(sys, "frozen"):
        exe_path = unicode(sys.executable, sys.getfilesystemencoding())
        exe_dir = os.path.dirname(exe_path)
        path = os.path.join(exe_dir, resname)
        if os.path.exists(path):
            return path
    else:
        import pkg_resources
        try:
            path = pkg_resources.resource_filename("enchant", resname)
        except KeyError:
            pass
        else:
            path = os.path.abspath(path)
            if os.path.exists(path):
                return path
    raise Error("Could not locate resource '%s'" % (resname,))


def win32_data_files():
    """Get list of supporting data files, for use with setup.py
    
    This function returns a list of the supporting data files available
    to the running version of PyEnchant.  This is in the format expected
    by the data_files argument of the distutils setup function.  It's
    very useful, for example, for including the data files in an executable
    produced by py2exe.
    
    Only really tested on the win32 platform (it's the only platform for
    which we ship our own supporting data files)
    """
    #  Include the main enchant DLL
    try:
        libEnchant = get_resource_filename("libenchant.dll")
    except Error:
        libEnchant = get_resource_filename("libenchant-1.dll")
    mainDir = os.path.dirname(libEnchant)
    dataFiles = [('', [libEnchant])]
    #  And some specific supporting DLLs
    for dll in os.listdir(mainDir):
        if not dll.endswith(".dll"):
            continue
        for prefix in ("iconv", "intl", "libglib", "libgmodule"):
            if dll.startswith(prefix):
                break
        else:
            continue
        dataFiles[0][1].append(os.path.join(mainDir, dll))
    # And anything found in the supporting data directories
    dataDirs = ("share/enchant/myspell", "share/enchant/ispell", "lib/enchant")
    for dataDir in dataDirs:
        files = []
        fullDir = os.path.join(mainDir, os.path.normpath(dataDir))
        for fn in os.listdir(fullDir):
            fullFn = os.path.join(fullDir, fn)
            if os.path.isfile(fullFn):
                files.append(fullFn)
        dataFiles.append((dataDir, files))
    return dataFiles


win32_data_files._DOC_ERRORS = ["py", "py", "exe"]
