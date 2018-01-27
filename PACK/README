Password Analysis and Cracking Kit by Peter Kacherginsky (iphelix)
==================================================================

PACK (Password Analysis and Cracking Toolkit) is a collection of utilities developed to aid in analysis of password lists in order to enhance password cracking through pattern detection of masks, rules, character-sets and other password characteristics. The toolkit generates valid input files for Hashcat family of password crackers.

NOTE: The toolkit itself is not able to crack passwords, but instead designed to make operation of password crackers more efficient.

Selecting passwords lists for analysis
======================================

Before we can begin using the toolkit we must establish a selection criteria of password lists. Since we are looking to analyze the way people create their passwords, we must obtain as large of a sample of leaked passwords as possible. One such excellent list is based on RockYou.com compromise. This list both provides large and diverse enough collection that provides a good results for common passwords used by similar sites (e.g. social networking). The analysis obtained from this list may not work for organizations with specific password policies. As such, selecting sample input should be as close to your target as possible. In addition, try to avoid obtaining lists based on already cracked passwords as it will generate statistics bias of rules and masks used by individual(s) cracking the list and not actual users.

StatsGen
=======================================

The most basic analysis that you can perform is simply obtaining most common length, character-set and other characteristics of passwords in the provided list. In the example below, we will use 'rockyou.txt' containing approximately 14 million passwords. Launch `statsgen.py` with the following command line:

    $ python statsgen.py rockyou.txt

Below is the output from the above command:

                           _
         StatsGen #.#.#   | |
          _ __   __ _  ___| | _
         | '_ \ / _` |/ __| |/ /
         | |_) | (_| | (__|   < 
         | .__/ \__,_|\___|_|\_\
         | |                    
         |_| iphelix@thesprawl.org


    [*] Analyzing passwords in [rockyou.txt]
    [+] Analyzing 100% (14344390/14344390) of passwords
        NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords

    [*] Length:
    [+]                         8: 20% (2966037)
    [+]                         7: 17% (2506271)
    [+]                         9: 15% (2191039)
    [+]                        10: 14% (2013695)
    [+]                         6: 13% (1947798)
    ...

    [*] Character-set:
    [+]             loweralphanum: 42% (6074867)
    [+]                loweralpha: 25% (3726129)
    [+]                   numeric: 16% (2346744)
    [+]      loweralphaspecialnum: 02% (426353)
    [+]             upperalphanum: 02% (407431)
    ...

    [*] Password complexity:
    [+]                     digit: min(0) max(255)
    [+]                     lower: min(0) max(255)
    [+]                     upper: min(0) max(187)
    [+]                   special: min(0) max(255)

    [*] Simple Masks:
    [+]               stringdigit: 37% (5339556)
    [+]                    string: 28% (4115314)
    [+]                     digit: 16% (2346744)
    [+]               digitstring: 04% (663951)
    [+]                 othermask: 04% (576324)
    ...

    [*] Advanced Masks:
    [+]          ?l?l?l?l?l?l?l?l: 04% (687991)
    [+]              ?l?l?l?l?l?l: 04% (601152)
    [+]            ?l?l?l?l?l?l?l: 04% (585013)
    [+]        ?l?l?l?l?l?l?l?l?l: 03% (516830)
    [+]            ?d?d?d?d?d?d?d: 03% (487429)
    ...


NOTE: You can reduce the number of outliers displayed by including the --hiderare flag which will not show any items with occurrence of less than 1%.

Here is what we can immediately learn from the above list:

 * Most of the passwords have length 6 to 10 characters.
 * The majority of passwords have loweralphanumeric character-set.
 * There is no obvious minimum or maximum password complexity.
 * Analyzed passwords tend to follow a simple masks "string followed by digits".

The last section, "Advanced Masks", contains most frequently occurring masks using the Hashcat format. Individual symbols can be interpreted as follows:

    ?l - a single lowercase character
    ?u - a single uppercase character
    ?d - a single digit
    ?s - a single special character

For example, the very first mask, "?l?l?l?l?l?l?l?l", will match all of the lowercase alpha passwords. Given the sample size you will be able to crack approximately 4% of passwords. However, after generating the initial output, you may be interested in using filters to narrow down on password data.

Using filters
-------------

Let's see how RockYou users tend to select their passwords using the "stringdigit" simple mask (a string followed by numbers):

    $ python statsgen.py ../PACK-0.0.3/archive/rockyou.txt --simplemask stringdigit -q --hiderare

    [*] Analyzing passwords in [rockyou.txt]
    [+] Analyzing 37% (5339556/14344390) of passwords
        NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords

    [*] Length:
    [+]                         8: 23% (1267260)
    [+]                         7: 18% (981432)
    [+]                         9: 17% (939971)
    [+]                        10: 14% (750938)
    [+]                         6: 11% (618983)
    [+]                        11: 05% (294869)
    [+]                        12: 03% (175875)
    [+]                        13: 01% (103047)
    [+]                        14: 01% (65958)

    [*] Character-set:
    [+]             loweralphanum: 88% (4720184)
    [+]             upperalphanum: 06% (325941)
    [+]             mixedalphanum: 05% (293431)

    [*] Password complexity:
    [+]                     digit: min(1) max(252)
    [+]                     lower: min(0) max(46)
    [+]                     upper: min(0) max(31)
    [+]                   special: min(0) max(0)

    [*] Simple Masks:
    [+]               stringdigit: 100% (5339556)

    [*] Advanced Masks:
    [+]          ?l?l?l?l?l?l?d?d: 07% (420318)
    [+]            ?l?l?l?l?l?d?d: 05% (292306)
    [+]        ?l?l?l?l?l?l?l?d?d: 05% (273624)
    [+]          ?l?l?l?l?d?d?d?d: 04% (235360)
    [+]              ?l?l?l?l?d?d: 04% (215074)
    ...

The very top of the output specifies what percentage of total passwords was analyzed. In this case, by cracking only passwords matching the "stringdigit" mask it is only possible to recover about 37% of the total set just as was displayed in the original output. Next, it appears that only 11% of this password type use anything other than lowercase. So it would be smart to concentrate on only lowercase strings matching this mask. At last, in the "Advanced Mask" section we can see that the majority of "stringdigit" passwords consist of a string with two or four digits following it. With the information gained from the above output, we can begin creating a mental image of target users' password generation patterns.

There are a few other filters available for password length, mask, and character sets:

**Length:** --minlength and/or --maxlength

**Simple Mask:** --simplemask [numeric, loweralpha, upperalpha, mixedalpha, loweralphanum, etc.]

**Character sets:** --charset [digit, string, stringdigit, digitstring, digitstringdigit, etc.]

NOTE: More than one filter of the same class can be specified as a comma-separated list:

    --simplemask="stringdigit,digitstring"

Saving advanced masks
---------------------

While the "Advanced Mask" section only displays patterns matching greater than 1% of all passwords, you can obtain and save a full list of password masks matching a given dictionary by using the following command:

    $ python statsgen.py rockyou.txt -o rockyou.masks

All of the password masks and their frequencies will be saved into the specified file in the CSV format. Naturally, you can provide filters to only generate masks file matching specified parameters. The output file can be used as an input to MaskGen tool covered in the next section.

MaskGen
==================

MaskGen allows you to craft pattern-based mask attacks for input into Hashcat family of password crackers. The tool uses output produced by statsgen above with the '-o' flag in order to produce the most optimal mask attack sorted by mask complexity, mask occurrence or ratio of the two (optimal index).

Let's run MaskGen with only StatGen's output as an argument:

    $ python maskgen.py rockyou.masks

                           _ 
         MaskGen #.#.#    | |
          _ __   __ _  ___| | _
         | '_ \ / _` |/ __| |/ /
         | |_) | (_| | (__|   < 
         | .__/ \__,_|\___|_|\_\
         | |                    
         |_| iphelix@thesprawl.org


    [*] Analyzing masks in [rockyou.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [optindex].
    [*] Finished generating masks:
        Masks generated: 146578
        Masks coverage:  100% (14344390/14344390)
        Masks runtime:   >1 year

There are several pieces of information that you should observe:

 * Default cracking speed used for calculations is 1,000,000,000 keys/sec
 * Default sorting mode is [optindex] equivalent to --optindex flag.
 * 146,578 unique masks were generated which have 100% coverage
 * Total runtime of all generated masks is more than 1 year.

Specifying target time
----------------------

Since you are usually limited in time to perform and craft attacks, maskgen allows you to specify how much time you have to perform mask attacks and will generate the most optimal collection of masks based on the sorting mode. Let's play a bit with different sorting modes and target times:

    $ python maskgen.py rockyou.masks --targettime 600 --optindex -q
    [*] Analyzing masks in [rockyou.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [optindex].
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 779
        Masks coverage:  56% (8116195/14344390)
        Masks runtime:   0:11:36


    $ python maskgen.py rockyou.masks --targettime 600 --complexity -q
    [*] Analyzing masks in [rockyou.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [complexity].
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 5163
        Masks coverage:  31% (4572346/14344390)
        Masks runtime:   0:10:01


    $ python maskgen.py rockyou.masks --targettime 600 --occurrence -q
    [*] Analyzing masks in [rockyou.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [occurrence].
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 4
        Masks coverage:  16% (2390986/14344390)
        Masks runtime:   1:34:05

All of the above runs have target time of 600 seconds (or 10 minutes) with different sorting modes. Based on our experiments, masks generated using OptIndex sorting mode can crack 56% of RockYou passwords in about 10 minutes. At the same time masks generated using Occurrence sorting mode not only have pretty weak coverage of only 16%, but also exceeded specified target time by more than an hour.

NOTE: Masks sorted by complexity can be very effective when attacking policy based lists.

Let's see some of the masks generated by maskgen in optindex mode using the --showmasks flag:

    $ python maskgen.py rockyou.masks --targettime 43200 --optindex -q --showmasks
    [*] Analyzing masks in [rockyou.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [optindex].
    [L:] Mask:                          [ Occ:  ] [ Time:  ]
    ...
    [ 7] ?l?d?s?l?l?d?d                 [6      ] [ 0:00:00]  
    [ 8] ?s?l?l?l?l?l?l?s               [3480   ] [ 0:05:36]  
    [ 9] ?l?l?l?l?d?d?d?d?s             [1553   ] [ 0:02:30]  
    [ 8] ?d?l?d?d?d?l?l?l               [47     ] [ 0:00:04]  
    [ 8] ?d?l?l?d?l?d?d?l               [47     ] [ 0:00:04]  
    [ 8] ?d?l?l?d?d?l?d?l               [47     ] [ 0:00:04]  
    [ 8] ?d?l?d?l?d?d?l?l               [47     ] [ 0:00:04]  
    [ 8] ?d?d?l?l?d?l?d?l               [47     ] [ 0:00:04]  
    [ 8] ?d?l?d?d?l?l?l?l               [122    ] [ 0:00:11]  
    [ 8] ?u?u?d?u?d?d?d?d               [18     ] [ 0:00:01]  
    [ 6] ?d?s?s?s?s?s                   [4      ] [ 0:00:00]  
    [10] ?l?l?l?l?l?l?l?l?d?d           [213109 ] [ 5:48:02]  
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 3970
        Masks coverage:  74% (10620959/14344390)
        Masks runtime:   16:10:38
 
Displayed masks follow a pretty intuitive format:


  [ 9] ?l?l?l?l?d?d?d?d?s             [1553   ] [ 0:02:30]
    \   \                              \          \
     \   \_ generated mask              \          \_ mask runtime
      \                                  \
       \_ mask length                     \_ mask occurrence


In the above sample you can see some of the logic that goes into mask generation. For example, while '?s?l?l?l?l?l?l?s' mask has one of the longest runtimes in the sample (5 minutes), it still has higher priority because of its relatively higher occurrence to '?l?l?l?l?d?d?d?d?s'. At the same time, while '?l?d?s?l?l?d?d' has pretty low coverage it still gets a higher priority than other masks because as only a six character mask it executes very quickly.

Specifying mask filters
-----------------------

You can further optimize your generated mask attacks by using filters. For example, you may have sufficiently powerful hardware where you can simple bruteforce all of the passwords up to 8 characters. In this case, you can generate masks only greater than 8 characters using the --minlength flag as follows:

    $ python maskgen.py rockyou.masks --targettime 43200 --optindex -q --minlength 8
    [*] Analyzing masks in [rockyou.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [optindex].
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 585
        Masks coverage:  41% (5905182/14344390)
        Masks runtime:   15:50:36

Naturally the generated mask coverage was reduced, but these filters become useful when preparing a collection of masks when attacking password lists other than the one used to generate them.

The list below shows additional filters you can use:

      Individual Mask Filter Options:
        --minlength=8       Minimum password length
        --maxlength=8       Maximum password length
        --mintime=3600      Minimum mask runtime (seconds)
        --maxtime=3600      Maximum mask runtime (seconds)
        --mincomplexity=1   Minimum complexity
        --maxcomplexity=100
                            Maximum complexity
        --minoccurrence=1   Minimum occurrence
        --maxoccurrence=100
                            Maximum occurrence

Occurrrence and complexity flags can be particularly powerful to fine-tune generated masks using different sorting modes.

Saving generated masks
----------------------

Once you are satisfied with the above generated masks, you can save them using the -o flag:

    $ python maskgen.py rockyou.masks --targettime 43200 --optindex -q -o rockyou.hcmask
    [*] Analyzing masks in [rockyou.masks]
    [*] Saving generated masks to [rockyou.hcmask]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Sorting masks by their [optindex].
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 3970
        Masks coverage:  74% (10620959/14344390)
        Masks runtime:   16:10:38

This will produce 'rockyou.hcmask' file which can be directly used by Hashcat suite of tools or as part of a custom script that loops through them.

Checking mask coverage
----------------------

It is often useful to see how well generated masks perform against already cracked lists. Maskgen can compare a collection of masks against others to see how well they would perform if masks from one password list would be attempted against another. Let's compare how well masks generated from RockYou list will perform against another compromised list such as Gawker:

    $ python statsgen.py ../PACK-0.0.3/archive/gawker.dic -o gawker.masks

    $ python maskgen.py gawker.masks --checkmasksfile rockyou.hcmask -q
    [*] Analyzing masks in [gawker.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Checking coverage of masks in [rockyou.hcmask]
    [*] Finished matching masks:
        Masks matched: 1775
        Masks coverage:  96% (1048889/1084394)
        Masks runtime:   16:25:44

Using the '--checkmasksfile' parameter we attempted to run masks inside 'rockyou.hcmask' file generated earlier against masks from a sample leaked list 'gawker.masks'. This results in a good 96% coverage where 1775 of the 3970 total generated RockYou-based masks matched masks in Gawker list.

It is also possible to see the coverage of one or more masks by specifying them directly on the command-line as follows:

    $ python maskgen.py gawker.masks --checkmasks="?u?l?l?l?l?l?d,?l?l?l?l?l?d?d" -q
    [*] Analyzing masks in [gawker.masks]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Checking coverage of the these masks [?u?l?l?l?l?l?d, ?l?l?l?l?l?d?d]
    [*] Finished matching masks:
        Masks matched: 2
        Masks coverage:  1% (18144/1084394)
        Masks runtime:   0:00:04

Both of the specified masks matched with only 1% coverage.

Specifying speed
----------------

Depending on your exact hardware specs and target hash you may want to increase or decrease keys/sec speed used during calculations using the '--pps' parameter:

    $ python maskgen.py rockyou.masks --targettime 43200 --pps 50000000 -q
    [*] Analyzing masks in [rockyou.masks]
    [*] Using 50,000,000 keys/sec for calculations.
    [*] Sorting masks by their [optindex].
    [!] Target time exceeded.
    [*] Finished generating masks:
        Masks generated: 1192
        Masks coverage:  61% (8754548/14344390)
        Masks runtime:   12:17:31

Using the '--pps' parameter to match you actual performance makes target time more meaningful.

PolicyGen
=========

A lot of the mask and dictionary attacks will fail in the corporate environment with minimum password complexity requirements. Instead of resorting to a pure bruteforcing attack, we can leverage known or guessed password complexity rules to avoid trying password candidates that are not compliant with the policy or inversely only audit for noncompliant passwords. Using PolicyGen, you will be able to generate a collection of masks following the password complexity in order to significantly reduce the cracking time. 

Below is a sample session where we generate all valid password masks for an environment requiring at least one digit, one upper, and one special characters.

    $ python policygen.py --minlength 8 --maxlength 8 --minlower 1 --minupper 1 --mindigit 1 --minspecial 1 -o complexity.hcmask
                           _ 
         PolicyGen #.#.#  | |
          _ __   __ _  ___| | _
         | '_ \ / _` |/ __| |/ /
         | |_) | (_| | (__|   < 
         | .__/ \__,_|\___|_|\_\
         | |                    
         |_| iphelix@thesprawl.org


    [*] Saving generated masks to [complexity.hcmask]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Password policy:
        Pass Lengths: min:8 max:8
        Min strength: l:1 u:1 d:1 s:1
        Max strength: l:None u:None d:None s:None
    [*] Generating [compliant] masks.
    [*] Generating 8 character password masks.
    [*] Total Masks:  65536 Time: 76 days, 18:50:04
    [*] Policy Masks: 40824 Time: 35 days, 0:33:09

From the above output you can see that we have generated 40824 masks matching the specified complexity that will take about 35 days to run at the speed of 1,000,000,000 keys/sec.

In case you are simply performing a password audit and tasked to discover only non-compliant passwords you can specify '--noncompliant' flag to invert generated masks:

    $ python policygen.py --minlength 8 --maxlength 8 --minlower 1 --minupper 1 --mindigit 1 --minspecial 1 -o noncompliant.hcmask -q --noncompliant
    [*] Saving generated masks to [noncompliant.hcmask]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Password policy:
        Pass Lengths: min:8 max:8
        Min strength: l:1 u:1 d:1 s:1
        Max strength: l:None u:None d:None s:None
    [*] Generating [non-compliant] masks.
    [*] Generating 8 character password masks.
    [*] Total Masks:  65536 Time: 76 days, 18:50:04
    [*] Policy Masks: 24712 Time: 41 days, 18:16:55

Let's see some of the non-compliant masks generated above using the '--showmasks' flag:

    $ python policygen.py --minlength 8 --maxlength 8 --minlower 1 --minupper 1 --mindigit 1 --minspecial 1 -o noncompliant.hcmask -q --noncompliant --showmasks
    [*] Saving generated masks to [noncompliant.hcmask]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Password policy:
        Pass Lengths: min:8 max:8
        Min strength: l:1 u:1 d:1 s:1
        Max strength: l:None u:None d:None s:None
    [*] Generating [non-compliant] masks.
    [*] Generating 8 character password masks.
    [ 8] ?d?d?d?d?d?d?d?d               [l: 0 u: 0 d: 8 s: 0] [ 0:00:00]  
    [ 8] ?d?d?d?d?d?d?d?l               [l: 1 u: 0 d: 7 s: 0] [ 0:00:00]  
    [ 8] ?d?d?d?d?d?d?d?u               [l: 0 u: 1 d: 7 s: 0] [ 0:00:00]  
    [ 8] ?d?d?d?d?d?d?d?s               [l: 0 u: 0 d: 7 s: 1] [ 0:00:00]  
    ... 
    [ 8] ?s?s?s?s?s?s?s?d               [l: 0 u: 0 d: 1 s: 7] [ 0:07:06]  
    [ 8] ?s?s?s?s?s?s?s?l               [l: 1 u: 0 d: 0 s: 7] [ 0:18:28]  
    [ 8] ?s?s?s?s?s?s?s?u               [l: 0 u: 1 d: 0 s: 7] [ 0:18:28]  
    [ 8] ?s?s?s?s?s?s?s?s               [l: 0 u: 0 d: 0 s: 8] [ 0:23:26]  
    [*] Total Masks:  65536 Time: 76 days, 18:50:04
    [*] Policy Masks: 24712 Time: 41 days, 18:16:55

As you can see all of the masks have at least one missing password complexity requirement. Interestingly with fewer generated masks it takes longer to attack because of long running masks like '?s?s?s?s?s?s?s?s'.

Specifying maximum complexity
-----------------------------

It is also possible to specify maximum password complexity using --maxlower, --maxupper, --maxdigit and --maxspecial flags in order to fine-tune you attack. For example, below is a sample site which enforces password policy but does not allow any special characters:

    $ python policygen.py --minlength 8 --maxlength 8 --minlower 1 --minupper 1 --mindigit 1 --maxspecial 0 -o maxcomplexity.hcmask -q
    [*] Saving generated masks to [maxcomplexity.hcmask]
    [*] Using 1,000,000,000 keys/sec for calculations.
    [*] Password policy:
        Pass Lengths: min:8 max:8
        Min strength: l:1 u:1 d:1 s:None
        Max strength: l:None u:None d:None s:0
    [*] Generating [compliant] masks.
    [*] Generating 8 character password masks.
    [*] Total Masks:  65536 Time: 76 days, 18:50:04
    [*] Policy Masks: 5796 Time: 1 day, 20:20:55

Rules Analysis
==================

`rulegen.py` implements password analysis and rule generation for the Hashcat password cracker as described in the [Automatic Password Rule Analysis and Generation](http://thesprawl.org/research/automatic-password-rule-analysis-generation/) paper. Please review this document for detailed discussion on the theory of rule analysis and generation.

Reversing source words and word mangling rules from already cracked passwords can be very effective in performing attacks against still encrypted hashes. By continuously recycling/expanding generated rules and words you may be able to crack a greater number of passwords.

Prerequisites
-----------------
There are several prerequisites for the effective use of `rulegen.py`. The tool utilizes Enchant spell-checking library to interface with a number of spell-checking engines such as Aspell, MySpell, etc. You must install these tools prior to use. It is also critical to install dictionaries for whatever spell-checking engine you end up using (alternatively it is possible to use a custom wordlist). At last, I have bundled PyEnchant for convenience which should interface directly with Enchant's shared libraries; however, should there be any issues, simply remove the bundled 'enchant' directory and install PyEnchant for your distribution.

For additional details on specific Hashcat rule syntax see [Hashcat Rule Based Attack](http://hashcat.net/wiki/doku.php?id=rule_based_attack).

Analyzing a Single Password
-------------------------------

The most basic use of `rulegen.py` involves analysis of a single password to automatically detect rules. Let's detect rules and potential source word used to generate a sample password `P@55w0rd123`:

    $ python rulegen.py --verbose --password P@55w0rd123
                           _ 
         RuleGen #.#.#    | |
          _ __   __ _  ___| | _
         | '_ \ / _` |/ __| |/ /
         | |_) | (_| | (__|   < 
         | .__/ \__,_|\___|_|\_\
         | |                    
         |_| iphelix@thesprawl.org


    [*] Using Enchant 'aspell' module. For best results please install
        'aspell' module language dictionaries.
    [*] Analyzing password: P@55w0rd123
    [-] Pas sword => {edit distance suboptimal: 8 (7)} => P@55w0rd123
    [+] Password => sa@ ss5 so0 $1 $2 $3 => P@55w0rd123
    [+] Passwords => sa@ ss5 so0 o81 $2 $3 => P@55w0rd123
    [+] Passwords => sa@ ss5 so0 i81 o92 $3 => P@55w0rd123
    [+] Passwords => sa@ ss5 so0 i81 i92 oA3 => P@55w0rd123
    [+] Password's => sa@ ss5 so0 o81 o92 $3 => P@55w0rd123
    [+] Password's => sa@ ss5 so0 o81 i92 oA3 => P@55w0rd123
    [+] Password's => sa@ ss5 so0 i81 o92 oA3 => P@55w0rd123

There are several flags that we have used for this example:

  * --password - specifies a single password to analyze.
  * --verbose - prints out verbose information such as generated rules and performance statistics.

Processing password files is covered in a section below; however, let's first discuss some of the available fine tuning options using a single password as an example.

Spell-checking provider
---------------------------

Notice that we are using the `aspell` Enchant module for source word detection. The exact spell-checking engine can be changed using the `--provider` flag as follows:

    $ python rulegen.py --verbose --provider myspell --password P@55w0rd123 -q
    [*] Using Enchant 'myspell' module. For best results please install
        'myspell' module language dictionaries.
    ...


NOTE: Provider engine priority can be specified using a comma-separated list (e.g. --provider aspell,myspell).

Forcing source word
-----------------------

The use of the source word detection engine can be completely disabled by specifying a source word with the `--word` flag:

    $ python rulegen.py -q --verbose --word word --password P@55w0rd123
    [*] Analyzing password: P@55w0rd123
    [+] word => ^5 ^5 ^@ ^P so0 $1 $2 $3 => P@55w0rd123

By specifying different source words you can have a lot of fun experimenting with the rule generation engine.

Defining Custom Dictionary
------------------------------

Inevitably you will come across a point where generating rules using the standard spelling-engine wordlist is no longer sufficient. You can specify a custom wordlist using the `--wordlist` flag. This is particularly useful when reusing source words from a previous analysis session:

    $ python rulegen.py -q --verbose --wordlist rockyou.txt --password 1pa55w0rd1
    [*] Using Enchant 'Personal Wordlist' module. For best results please install
        'Personal Wordlist' module language dictionaries.
    [*] Analyzing password: 1pa55w0rd1
    [+] password => ^1 ss5 so0 $1 => 1pa55w0rd1

Custom wordlist can be particularly useful when using not normally found words such as slang as well as using already cracked passwords.

Generating Suboptimal Rules and Words
-----------------------------------------

While `rulegen.py` attempts to generate and record only the best source words and passwords, there may be cases when you are interested in more results. Use `--morewords` and `--morerules` flags to generate words and rules which may exceed optimal edit distance:

    $ python rulegen.py -q --verbose --password '$m0n3y$' --morerules --morewords
    [*] Using Enchant 'aspell' module. For best results please install
        'aspell' module language dictionaries.
    [*] Analyzing password: $m0n3y$
    [+] money => ^$ so0 se3 $$ => $m0n3y$
    [+] moneys => ^$ so0 se3 o6$ => $m0n3y$
    [+] mingy => ^$ si0 sg3 $$ => $m0n3y$
    [+] many => ^$ sa0 i43 $$ => $m0n3y$
    [+] Mooney => sM$ o1m so0 se3 $$ => $m0n3y$

It is possible to further expand generated words using `--maxworddist` and `--maxwords` flags. Similarly, you can produce more rules using `--maxrulelen` and `--maxrules` flags.

Disabling Advanced Engines
------------------------------

`rulegen.py` includes a number of advanced engines to generate better quality words and rules. It is possible to disable them to observe the difference (or if they are causing issues) using `--simplewords` and `--simplerules` flags. Let's observe how both source words and rules change with these flags on:

    $ python rulegen.py -q --verbose --password '$m0n3y$' --simplewords --simplerules
    [*] Using Enchant 'aspell' module. For best results please install
        'aspell' module language dictionaries.
    [*] Analyzing password: $m0n3y$
    [-] Meany => {edit distance suboptimal: 5 (4)} => $m0n3y$
    [+] many => i0$ o20 i43 i6$ => $m0n3y$
    [+] mingy => i0$ o20 o43 i6$ => $m0n3y$
    [+] money => i0$ o20 o43 i6$ => $m0n3y$
    [+] mangy => i0$ o20 o43 i6$ => $m0n3y$
    [+] manky => i0$ o20 o43 i6$ => $m0n3y$

Notice the quality of generated words and rules was reduced significantly with words like 'manky' having less relationship to the actual source word 'money'. At the same time, generated rules were reduced to simple insertions, deletions and replacements.

Processing password lists
-----------------------------

Now that you have mastered all of the different flags and switches, we can attempt to generate words and rules for a collection of passwords. Let's generate a text file `korelogic.txt` containing the following fairly complex test passwords:

    &~defcon
    '#(4)\
    August19681
    '&a123456
    10-D'Ann
    ~|Bailey
    Krist0f3r
    f@cebOOK
    Nuclear$(
    zxcvbn2010!
    13Hark's
    NjB3qqm
    Sydney93?
    antalya%]
    Annl05de
    ;-Fluffy

Now let's observe `rulegen.py` analysis by simply specifying the password file as the first argument:

    $ python rulegen.py korelogic.txt -q
    [*] Using Enchant 'aspell' module. For best results please install
        'aspell' module language dictionaries.
    [*] Analyzing passwords file: korelogic.txt:
    [*] Press Ctrl-C to end execution and generate statistical analysis.
    [*] Saving rules to analysis.rule
    [*] Saving words to analysis.word
    [*] Finished processing 16 passwords in 1.00 seconds at the rate of 15.94 p/sec
    [*] Generating statistics for [analysis] rules and words.
    [-] Skipped 0 all numeric passwords (0.00%)
    [-] Skipped 2 passwords with less than 25% alpha characters (12.50%)
    [-] Skipped 0 passwords with non ascii characters (0.00%)

    [*] Top 10 rules
    [+] ^3 ^1 o4r - 3 (2.00%)
    [+] i61 i79 i86 i98 oA1 - 2 (1.00%)
    [+] ^- ^0 ^1 i4' o5A - 2 (1.00%)
    [+] sS1 i13 T2 - 1 (0.00%)
    [+] i61 se9 i86 i98 oA1 - 1 (0.00%)
    [+] o61 i79 i86 i98 oA1 - 1 (0.00%)
    [+] ^- ^0 ^1 so' i5A - 1 (0.00%)
    [+] D3 si0 i55 $e - 1 (0.00%)
    [+] i61 i79 se6 i98 oA1 - 1 (0.00%)
    [+] i3a o5y o6a i7% o8] - 1 (0.00%)

    [*] Top 10 words
    [+] Analyze - 1 (0.00%)
    [+] defcon - 1 (0.00%)
    [+] Kristen - 1 (0.00%)
    [+] Bailey - 1 (0.00%)
    [+] Augusts - 1 (0.00%)
    [+] Annelid - 1 (0.00%)
    [+] Hack's - 1 (0.00%)
    [+] antlers - 1 (0.00%)
    [+] antelope - 1 (0.00%)
    [+] xxxv - 1 (0.00%)

Using all default settings we were able to produce several high quality rules. The application displays some basic Top 10 rules and words statistics. All of the generated rules and words are saved using basename 'analysis' by default:

* analysis.word - unsorted and ununiqued source words
* analysis-sorted.word - occurrence sorted and unique source words
* analysis.rule - unsorted and ununiqued rules
* analysis-sorted.rule - occurrence sorted and unique rules

Notice that several passwords such as '#(4)\ and '&a123456 were skipped because they do not have sufficient characteristics to be processed. Other than alpha character count, the program will skip all numeric passwords and passwords containing non-ASCII characters. The latter is due to a bug in the Enchant engine which I hope to fix in the future thus allowing word processing of many languages.

Specifying output basename
------------------------------

As previously mentioned `rulegen.py` saves output files using the 'analysis' basename by default. You can change file basename with the `--basename` or `-b` flag as follows:

    $ python rulegen.py korelogic.txt -q -b korelogic
    [*] Using Enchant 'aspell' module. For best results please install
        'aspell' module language dictionaries.
    [*] Analyzing passwords file: korelogic.txt:
    [*] Press Ctrl-C to end execution and generate statistical analysis.
    [*] Saving rules to korelogic.rule
    [*] Saving words to korelogic.word


Debugging rules
--------------------

There may be situations where you run into issues generating rules for the Hashcat password cracker. `rulegen.py` includes the `--hashcat` flag to validate generated words and rules using hashcat itself running in --stdout mode. In order for this mode to work correctly, you must download the latest version of hashcat-cli and edit the `HASHCAT_PATH` variable in the source. For example, at the time of this writing I have placed the hashcat-0.## folder in the PACK directory and defined `HASHCAT_PATH` as 'hashcat-0.##/'.

You can also observe the inner workings of the rule generation engine with the `--debug` flag. Don't worry about messages of certain rule failings, this is the result of the halting problem solver trying to find an optimal and valid solution.

Conclusion
==============

While this guide introduces a number of methods to analyze passwords, reverse rules and generate masks, there are a number of other tricks that are waiting for you to discover. I would be excited if you told me about some unusual use or suggestions for any of the covered tools.

Happy Cracking!

   -Peter