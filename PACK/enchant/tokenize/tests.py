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

    enchant.tokenize.tests:  unittests for enchant tokenization functions.

"""

import unittest
import array

from enchant.tokenize import *
from enchant.tokenize.en import tokenize as tokenize_en
from enchant.utils import raw_unicode, unicode, bytes


class TestTokenization(unittest.TestCase):
    """TestCases for testing the basic tokenization functionality."""

    def test_basic_tokenize(self):
        """Simple regression test for basic white-space tokenization."""
        input = """This is a paragraph.  It's not very special, but it's designed
2 show how the splitter works with many-different combos
of words. Also need to "test" the (handling) of 'quoted' words."""
        output = [
            ("This", 0), ("is", 5), ("a", 8), ("paragraph", 10), ("It's", 22),
            ("not", 27), ("very", 31), ("special", 36), ("but", 45), ("it's", 49),
            ("designed", 54), ("2", 63), ("show", 65), ("how", 70), ("the", 74),
            ("splitter", 78), ("works", 87), ("with", 93), ("many-different", 98),
            ("combos", 113), ("of", 120), ("words", 123),
            ("Also", 130), ("need", 135),
            ("to", 140), ("test", 144), ("the", 150), ("handling", 155),
            ("of", 165), ("quoted", 169), ("words", 177)
        ]
        self.assertEqual(output, [i for i in basic_tokenize(input)])
        for (itmO, itmV) in zip(output, basic_tokenize(input)):
            self.assertEqual(itmO, itmV)

    def test_tokenize_strip(self):
        """Test special-char-stripping edge-cases in basic_tokenize."""
        input = "((' <this> \"\" 'text' has (lots) of (special chars} >>]"
        output = [("<this>", 4), ("text", 15), ("has", 21), ("lots", 26), ("of", 32),
                  ("special", 36), ("chars}", 44), (">>", 51)]
        self.assertEqual(output, [i for i in basic_tokenize(input)])
        for (itmO, itmV) in zip(output, basic_tokenize(input)):
            self.assertEqual(itmO, itmV)

    def test_wrap_tokenizer(self):
        """Test wrapping of one tokenizer with another."""
        input = "this-string will be split@according to diff'rnt rules"
        from enchant.tokenize import en
        tknzr = wrap_tokenizer(basic_tokenize, en.tokenize)
        tknzr = tknzr(input)
        self.assertEqual(tknzr._tokenizer.__class__, basic_tokenize)
        self.assertEqual(tknzr._tokenizer.offset, 0)
        for (n, (word, pos)) in enumerate(tknzr):
            if n == 0:
                self.assertEqual(pos, 0)
                self.assertEqual(word, "this")
            if n == 1:
                self.assertEqual(pos, 5)
                self.assertEqual(word, "string")
            if n == 2:
                self.assertEqual(pos, 12)
                self.assertEqual(word, "will")
                # Test setting offset to a previous token
                tknzr.set_offset(5)
                self.assertEqual(tknzr.offset, 5)
                self.assertEqual(tknzr._tokenizer.offset, 5)
                self.assertEqual(tknzr._curtok.__class__, empty_tokenize)
            if n == 3:
                self.assertEqual(word, "string")
                self.assertEqual(pos, 5)
            if n == 4:
                self.assertEqual(pos, 12)
                self.assertEqual(word, "will")
            if n == 5:
                self.assertEqual(pos, 17)
                self.assertEqual(word, "be")
                # Test setting offset past the current token
                tknzr.set_offset(20)
                self.assertEqual(tknzr.offset, 20)
                self.assertEqual(tknzr._tokenizer.offset, 20)
                self.assertEqual(tknzr._curtok.__class__, empty_tokenize)
            if n == 6:
                self.assertEqual(pos, 20)
                self.assertEqual(word, "split")
            if n == 7:
                self.assertEqual(pos, 26)
                self.assertEqual(word, "according")
                # Test setting offset to middle of current token
                tknzr.set_offset(23)
                self.assertEqual(tknzr.offset, 23)
                self.assertEqual(tknzr._tokenizer.offset, 23)
                self.assertEqual(tknzr._curtok.offset, 3)
            if n == 8:
                self.assertEqual(pos, 23)
                self.assertEqual(word, "it")
                # OK, I'm pretty happy with the behaviour, no need to
                # continue testing the rest of the string


class TestFilters(unittest.TestCase):
    """TestCases for the various Filter subclasses."""

    text = """this text with http://url.com and SomeLinksLike
              ftp://my.site.com.au/some/file AndOthers not:/quite.a.url
              with-an@aemail.address as well"""

    def setUp(self):
        pass

    def test_URLFilter(self):
        """Test filtering of URLs"""
        tkns = get_tokenizer("en_US", filters=(URLFilter,))(self.text)
        out = [t for t in tkns]
        exp = [("this", 0), ("text", 5), ("with", 10), ("and", 30),
               ("SomeLinksLike", 34), ("AndOthers", 93), ("not", 103), ("quite", 108),
               ("a", 114), ("url", 116), ("with", 134), ("an", 139), ("aemail", 142),
               ("address", 149), ("as", 157), ("well", 160)]
        self.assertEqual(out, exp)

    def test_WikiWordFilter(self):
        """Test filtering of WikiWords"""
        tkns = get_tokenizer("en_US", filters=(WikiWordFilter,))(self.text)
        out = [t for t in tkns]
        exp = [("this", 0), ("text", 5), ("with", 10), ("http", 15), ("url", 22), ("com", 26),
               ("and", 30), ("ftp", 62), ("my", 68), ("site", 71), ("com", 76), ("au", 80),
               ("some", 83), ("file", 88), ("not", 103), ("quite", 108),
               ("a", 114), ("url", 116), ("with", 134), ("an", 139), ("aemail", 142),
               ("address", 149), ("as", 157), ("well", 160)]
        self.assertEqual(out, exp)

    def test_EmailFilter(self):
        """Test filtering of email addresses"""
        tkns = get_tokenizer("en_US", filters=(EmailFilter,))(self.text)
        out = [t for t in tkns]
        exp = [("this", 0), ("text", 5), ("with", 10), ("http", 15), ("url", 22), ("com", 26),
               ("and", 30), ("SomeLinksLike", 34),
               ("ftp", 62), ("my", 68), ("site", 71), ("com", 76), ("au", 80),
               ("some", 83), ("file", 88), ("AndOthers", 93), ("not", 103), ("quite", 108),
               ("a", 114), ("url", 116),
               ("as", 157), ("well", 160)]
        self.assertEqual(out, exp)

    def test_CombinedFilter(self):
        """Test several filters combined"""
        tkns = get_tokenizer("en_US", filters=(URLFilter, WikiWordFilter, EmailFilter))(self.text)
        out = [t for t in tkns]
        exp = [("this", 0), ("text", 5), ("with", 10),
               ("and", 30), ("not", 103), ("quite", 108),
               ("a", 114), ("url", 116),
               ("as", 157), ("well", 160)]
        self.assertEqual(out, exp)


class TestChunkers(unittest.TestCase):
    """TestCases for the various Chunker subclasses."""

    def test_HTMLChunker(self):
        """Test filtering of URLs"""
        text = """hello<html><head><title>my title</title></head><body>this is a
                <b>simple</b> HTML document for <p> test<i>ing</i> purposes</p>.
                It < contains > various <-- special characters.
                """
        tkns = get_tokenizer("en_US", chunkers=(HTMLChunker,))(text)
        out = [t for t in tkns]
        exp = [("hello", 0), ("my", 24), ("title", 27), ("this", 53), ("is", 58),
               ("a", 61), ("simple", 82), ("HTML", 93), ("document", 98), ("for", 107),
               ("test", 115), ("ing", 122), ("purposes", 130), ("It", 160),
               ("contains", 165), ("various", 176), ("special", 188),
               ("characters", 196)]
        self.assertEqual(out, exp)
        for (word, pos) in out:
            self.assertEqual(text[pos:pos + len(word)], word)


class TestTokenizeEN(unittest.TestCase):
    """TestCases for checking behaviour of English tokenization."""

    def test_tokenize_en(self):
        """Simple regression test for English tokenization."""
        input = """This is a paragraph.  It's not very special, but it's designed
2 show how the splitter works with many-different combos
of words. Also need to "test" the handling of 'quoted' words."""
        output = [
            ("This", 0), ("is", 5), ("a", 8), ("paragraph", 10), ("It's", 22),
            ("not", 27), ("very", 31), ("special", 36), ("but", 45), ("it's", 49),
            ("designed", 54), ("show", 65), ("how", 70), ("the", 74),
            ("splitter", 78), ("works", 87), ("with", 93), ("many", 98),
            ("different", 103), ("combos", 113), ("of", 120), ("words", 123),
            ("Also", 130), ("need", 135),
            ("to", 140), ("test", 144), ("the", 150), ("handling", 154),
            ("of", 163), ("quoted", 167), ("words", 175)
        ]
        for (itmO, itmV) in zip(output, tokenize_en(input)):
            self.assertEqual(itmO, itmV)

    def test_unicodeBasic(self):
        """Test tokenization of a basic unicode string."""
        input = raw_unicode(
            r"Ik ben ge\u00EFnteresseerd in de co\u00F6rdinatie van mijn knie\u00EBn, maar kan niet \u00E9\u00E9n \u00E0 twee enqu\u00EAtes vinden die recht doet aan mijn carri\u00E8re op Cura\u00E7ao")
        output = input.split(" ")
        output[8] = output[8][0:-1]
        for (itmO, itmV) in zip(output, tokenize_en(input)):
            self.assertEqual(itmO, itmV[0])
            self.assertTrue(input[itmV[1]:].startswith(itmO))

    def test_unicodeCombining(self):
        """Test tokenization with unicode combining symbols."""
        input = raw_unicode(
            r"Ik ben gei\u0308nteresseerd in de co\u00F6rdinatie van mijn knie\u00EBn, maar kan niet e\u0301e\u0301n \u00E0 twee enqu\u00EAtes vinden die recht doet aan mijn carri\u00E8re op Cura\u00E7ao")
        output = input.split(" ")
        output[8] = output[8][0:-1]
        for (itmO, itmV) in zip(output, tokenize_en(input)):
            self.assertEqual(itmO, itmV[0])
            self.assertTrue(input[itmV[1]:].startswith(itmO))

    def test_utf8_bytes(self):
        """Test tokenization of UTF8-encoded bytes (bug #2500184)."""
        # Python3 doesn't support bytestrings, don't run this test
        if str is unicode:
            return
        input = "A r\xc3\xa9sum\xc3\xa9, also spelled resum\xc3\xa9 or resume"
        output = input.split(" ")
        output[1] = output[1][0:-1]
        for (itmO, itmV) in zip(output, tokenize_en(input)):
            self.assertEqual(itmO, itmV[0])
            self.assertTrue(input[itmV[1]:].startswith(itmO))

    def test_utf8_bytes_at_end(self):
        """Test tokenization of UTF8-encoded bytes at end of word."""
        # Python3 doesn't support bytestrings, don't run this test
        if str is unicode:
            return
        input = "A r\xc3\xa9sum\xc3\xa9, also spelled resum\xc3\xa9 or resume"
        output = input.split(" ")
        output[1] = output[1][0:-1]
        for (itmO, itmV) in zip(output, tokenize_en(input)):
            self.assertEqual(itmO, itmV[0])

    def test_utf8_bytes_in_an_array(self):
        """Test tokenization of UTF8-encoded bytes stored in an array."""
        # Python3 doesn't support bytestrings, don't run this test
        if str is unicode:
            return
        input = "A r\xc3\xa9sum\xc3\xa9, also spelled resum\xc3\xa9 or resume"
        output = input.split(" ")
        output[1] = output[1][0:-1]
        input = array.array('c', input)
        output = [array.array('c', w) for w in output]
        for (itmO, itmV) in zip(output, tokenize_en(array.array('c', input))):
            self.assertEqual(itmO, itmV[0])
            self.assertEqual(input[itmV[1]:itmV[1] + len(itmV[0])], itmO)

    def test_bug1591450(self):
        """Check for tokenization regressions identified in bug #1591450."""
        input = """Testing <i>markup</i> and {y:i}so-forth...leading dots and trail--- well, you get-the-point. Also check numbers: 999 1,000 12:00 .45. Done?"""
        output = [
            ("Testing", 0), ("i", 9), ("markup", 11), ("i", 19), ("and", 22),
            ("y", 27), ("i", 29), ("so", 31), ("forth", 34), ("leading", 42),
            ("dots", 50), ("and", 55), ("trail", 59), ("well", 68),
            ("you", 74), ("get", 78), ("the", 82), ("point", 86),
            ("Also", 93), ("check", 98), ("numbers", 104), ("Done", 134),
        ]
        for (itmO, itmV) in zip(output, tokenize_en(input)):
            self.assertEqual(itmO, itmV)

    def test_bug2785373(self):
        """Testcases for bug #2785373"""
        input = "So, one dey when I wes 17, I left."
        for _ in tokenize_en(input):
            pass
        input = raw_unicode("So, one dey when I wes 17, I left.")
        for _ in tokenize_en(input):
            pass

    def test_finnish_text(self):
        """Test tokenizing some Finnish text.

        This really should work since there are no special rules to apply,
        just lots of non-ascii characters.
        """
        inputT = raw_unicode(
            'T\\xe4m\\xe4 on kappale. Eip\\xe4 ole kovin 2 nen, mutta tarkoitus on n\\xe4ytt\\xe4\\xe4 miten sanastaja \\ntoimii useiden-erilaisten sanarypp\\xe4iden kimpussa.\\nPit\\xe4\\xe4p\\xe4 viel\\xe4 \'tarkistaa\' sanat jotka "lainausmerkeiss\\xe4". Heittomerkki ja vaa\'an.\\nUlkomaisia sanoja s\\xfcss, spa\\xdf.')
        outputT = [
            (raw_unicode('T\\xe4m\\xe4'), 0), (raw_unicode('on'), 5), (raw_unicode('kappale'), 8),
            (raw_unicode('Eip\\xe4'), 17), (raw_unicode('ole'), 22), (raw_unicode('kovin'), 26),
            (raw_unicode('nen'), 34), (raw_unicode('mutta'), 39), (raw_unicode('tarkoitus'), 45),
            (raw_unicode('on'), 55), (raw_unicode('n\\xe4ytt\\xe4\\xe4'), 58), (raw_unicode('miten'), 66),
            (raw_unicode('sanastaja'), 72), (raw_unicode('toimii'), 83), (raw_unicode('useiden'), 90),
            (raw_unicode('erilaisten'), 98), (raw_unicode('sanarypp\\xe4iden'), 109), (raw_unicode('kimpussa'), 123),
            (raw_unicode('Pit\\xe4\\xe4p\\xe4'), 133), (raw_unicode('viel\\xe4'), 141), (raw_unicode('tarkistaa'), 148),
            (raw_unicode('sanat'), 159), (raw_unicode('jotka'), 165), (raw_unicode('lainausmerkeiss\\xe4'), 172),
            (raw_unicode('Heittomerkki'), 191), (raw_unicode('ja'), 204), (raw_unicode("vaa'an"), 207),
            (raw_unicode('Ulkomaisia'), 215), (raw_unicode('sanoja'), 226), (raw_unicode('s\\xfcss'), 233),
            (raw_unicode('spa\\xdf'), 239), ]
        for (itmO, itmV) in zip(outputT, tokenize_en(inputT)):
            self.assertEqual(itmO, itmV)
