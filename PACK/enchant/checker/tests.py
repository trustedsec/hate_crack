# pyenchant
#
# Copyright (C) 2004-2009, Ryan Kelly
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

    enchant.checker.tests:  Unittests for enchant SpellChecker class
    
"""

import unittest

import enchant
import enchant.tokenize
from enchant.utils import *
from enchant.errors import *
from enchant.checker import *


class TestChecker(unittest.TestCase):
    """TestCases for checking behaviour of SpellChecker class."""

    def test_basic(self):
        """Test a basic run of the SpellChecker class."""
        text = """This is sme text with a few speling erors in it. Its gret
        for checking wheather things are working proprly with the SpellChecker
        class. Not gret for much elss though."""
        chkr = SpellChecker("en_US", text=text)
        for n, err in enumerate(chkr):
            if n == 0:
                # Fix up "sme" -> "some" properly
                self.assertEqual(err.word, "sme")
                self.assertEqual(err.wordpos, 8)
                self.assertTrue("some" in err.suggest())
                err.replace("some")
            if n == 1:
                # Ignore "speling"
                self.assertEqual(err.word, "speling")
            if n == 2:
                # Check context around "erors", and replace
                self.assertEqual(err.word, "erors")
                self.assertEqual(err.leading_context(5), "ling ")
                self.assertEqual(err.trailing_context(5), " in i")
                err.replace(raw_unicode("errors"))
            if n == 3:
                # Replace-all on gret as it appears twice
                self.assertEqual(err.word, "gret")
                err.replace_always("great")
            if n == 4:
                # First encounter with "wheather", move offset back
                self.assertEqual(err.word, "wheather")
                err.set_offset(-1 * len(err.word))
            if n == 5:
                # Second encounter, fix up "wheather'
                self.assertEqual(err.word, "wheather")
                err.replace("whether")
            if n == 6:
                # Just replace "proprly", but also add an ignore
                # for "SpellChecker"
                self.assertEqual(err.word, "proprly")
                err.replace("properly")
                err.ignore_always("SpellChecker")
            if n == 7:
                # The second "gret" should have been replaced
                # So it's now on "elss"
                self.assertEqual(err.word, "elss")
                err.replace("else")
            if n > 7:
                self.fail("Extraneous spelling errors were found")
        text2 = """This is some text with a few speling errors in it. Its great
        for checking whether things are working properly with the SpellChecker
        class. Not great for much else though."""
        self.assertEqual(chkr.get_text(), text2)

    def test_filters(self):
        """Test SpellChecker with the 'filters' argument."""
        text = """I contain WikiWords that ShouldBe skipped by the filters"""
        chkr = SpellChecker("en_US", text=text,
                            filters=[enchant.tokenize.WikiWordFilter])
        for err in chkr:
            # There are no errors once the WikiWords are skipped
            self.fail("Extraneous spelling errors were found")
        self.assertEqual(chkr.get_text(), text)

    def test_chunkers(self):
        """Test SpellChecker with the 'chunkers' argument."""
        text = """I contain <html a=xjvf>tags</html> that should be skipped"""
        chkr = SpellChecker("en_US", text=text,
                            chunkers=[enchant.tokenize.HTMLChunker])
        for err in chkr:
            # There are no errors when the <html> tag is skipped
            self.fail("Extraneous spelling errors were found")
        self.assertEqual(chkr.get_text(), text)

    def test_chunkers_and_filters(self):
        """Test SpellChecker with the 'chunkers' and 'filters' arguments."""
        text = """I contain <html a=xjvf>tags</html> that should be skipped
                  along with a <a href='http://example.com/">link to
                  http://example.com/</a> that should also be skipped"""
        # There are no errors when things are correctly skipped
        chkr = SpellChecker("en_US", text=text,
                            filters=[enchant.tokenize.URLFilter],
                            chunkers=[enchant.tokenize.HTMLChunker])
        for err in chkr:
            self.fail("Extraneous spelling errors were found")
        self.assertEqual(chkr.get_text(), text)
        # The "html" is an error when not using HTMLChunker
        chkr = SpellChecker("en_US", text=text,
                            filters=[enchant.tokenize.URLFilter])
        for err in chkr:
            self.assertEqual(err.word, "html")
            break
        self.assertEqual(chkr.get_text(), text)
        # The "http" from the URL is an error when not using URLFilter
        chkr = SpellChecker("en_US", text=text,
                            chunkers=[enchant.tokenize.HTMLChunker])
        for err in chkr:
            self.assertEqual(err.word, "http")
            break
        self.assertEqual(chkr.get_text(), text)

    def test_unicode(self):
        """Test SpellChecker with a unicode string."""
        text = raw_unicode("""I am a unicode strng with unicode erors.""")
        chkr = SpellChecker("en_US", text)
        for n, err in enumerate(chkr):
            if n == 0:
                self.assertEqual(err.word, raw_unicode("unicode"))
                self.assertEqual(err.wordpos, 7)
                chkr.ignore_always()
            if n == 1:
                self.assertEqual(err.word, raw_unicode("strng"))
                chkr.replace_always("string")
                self.assertEqual(chkr._replace_words[raw_unicode("strng")], raw_unicode("string"))
            if n == 2:
                self.assertEqual(err.word, raw_unicode("erors"))
                chkr.replace("erros")
                chkr.set_offset(-6)
            if n == 3:
                self.assertEqual(err.word, raw_unicode("erros"))
                chkr.replace("errors")
        self.assertEqual(n, 3)
        self.assertEqual(chkr.get_text(), raw_unicode("I am a unicode string with unicode errors."))

    def test_chararray(self):
        """Test SpellChecker with a character array as input."""
        # Python 3 does not provide 'c' array type
        if str is unicode:
            atype = 'u'
        else:
            atype = 'c'
        text = "I wll be stord in an aray"
        txtarr = array.array(atype, text)
        chkr = SpellChecker("en_US", txtarr)
        for (n, err) in enumerate(chkr):
            if n == 0:
                self.assertEqual(err.word, "wll")
                self.assertEqual(err.word.__class__, str)
            if n == 1:
                self.assertEqual(err.word, "stord")
                txtarr[err.wordpos:err.wordpos + len(err.word)] = array.array(atype, "stored")
                chkr.set_offset(-1 * len(err.word))
            if n == 2:
                self.assertEqual(err.word, "aray")
                chkr.replace("array")
        self.assertEqual(n, 2)
        if str is unicode:
            self.assertEqual(txtarr.tounicode(), "I wll be stored in an array")
        else:
            self.assertEqual(txtarr.tostring(), "I wll be stored in an array")

    def test_pwl(self):
        """Test checker loop with PWL."""
        from enchant import DictWithPWL
        d = DictWithPWL("en_US", None, None)
        txt = "I am sme text to be cheked with personal list of cheked words"
        chkr = SpellChecker(d, txt)
        for n, err in enumerate(chkr):
            if n == 0:
                self.assertEqual(err.word, "sme")
            if n == 1:
                self.assertEqual(err.word, "cheked")
                chkr.add()
        self.assertEqual(n, 1)

    def test_bug2785373(self):
        """Testcases for bug #2785373."""
        c = SpellChecker(enchant.Dict("en"), "")
        c.set_text("So, one dey when I wes 17, I left.")
        for err in c:
            pass
        c = SpellChecker(enchant.Dict("en"), "")
        c.set_text(raw_unicode("So, one dey when I wes 17, I left."))
        for err in c:
            pass

    def test_default_language(self):
        lang = get_default_language()
        if lang is None:
            self.assertRaises(DefaultLanguageNotFoundError, SpellChecker)
        else:
            checker = SpellChecker()
            self.assertEqual(checker.lang, lang)

    def test_replace_with_shorter_string(self):
        """Testcase for replacing with a shorter string (bug #10)"""
        text = ". I Bezwaar tegen verguning."
        chkr = SpellChecker("en_US", text)
        for i, err in enumerate(chkr):
            err.replace("SPAM")
            assert i < 3
        self.assertEquals(chkr.get_text(), ". I SPAM SPAM SPAM.")

    def test_replace_with_empty_string(self):
        """Testcase for replacing with an empty string (bug #10)"""
        text = ". I Bezwaar tegen verguning."
        chkr = SpellChecker("en_US", text)
        for i, err in enumerate(chkr):
            err.replace("")
            assert i < 3
        self.assertEquals(chkr.get_text(), ". I   .")
