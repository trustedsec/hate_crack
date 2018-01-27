```
  ___ ___         __             _________                       __    
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    < 
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
```

## Installation
Get the latest hashcat binaries (https://hashcat.net/hashcat/)

OSX Install (https://www.phillips321.co.uk/2016/07/09/hashcat-on-os-x-getting-it-going/)
```git clone https://github.com/hashcat/hashcat.git
mkdir -p hashcat/deps
git clone https://github.com/KhronosGroup/OpenCL-Headers.git hashcat/deps/OpenCL
cd hashcat/
make
make install
```
### Download hate_crack
```git clone https://github.com/trustedsec/hate_crack.git```
* Customize binary and wordlist paths in "config.json"
* Make sure that at least "rockyou.txt" is within your "wordlists" path
### Create Optimized Wordlists
wordlist_optimizer.py - parses all wordlists from `<input file list>`, sorts them by length and de-duplicates into `<output directory>`

```$ python wordlist_optimizer.py
usage: python wordlist_optimizer.py <input file list> <output directory>

$ python wordlist_optimizer.py wordlists.txt ../optimized_wordlists
```
-------------------------------------------------------------------
## Usage
`$ ./hate_crack.py 
usage: python hate_crack.py <hash_file> <hash_type>`

The <hash_type> is attained by running `hashcat --help`

Example Hashes: http://hashcat.net/wiki/doku.php?id=example_hashes


```
$ hashcat --help |grep -i ntlm
   5500 | NetNTLMv1                                        | Network protocols
   5500 | NetNTLMv1 + ESS                                  | Network protocols
   5600 | NetNTLMv2                                        | Network protocols
   1000 | NTLM                                             | Operating-Systems
```

```
$ ./hate_crack.py <hash file> 1000

  ___ ___         __             _________                       __    
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    < 
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
                         Public Release
                          Version 1.00
  

	(1) Quick Crack
	(2) Extensive Pure_Hate Methodology Crack
	(3) Brute Force Attack
	(4) Top Mask Attack
	(5) Fingerprint Attack
	(6) Combinator Attack
	(7) Hybrid Attack
	(8) Pathwell Top 100 Mask Brute Force Crack
	(9) PRINCE Attack
	(10) YOLO Combinator Attack

	(97) Display Cracked Hashes
	(98) Display README
	(99) Quit

Select a task:
```
-------------------------------------------------------------------
#### Quick Crack
* Runs a dictionary attack using all wordlists configured in your "hcatOptimizedWordlists" path
and applies the "best64.rule", with the option of chaining the "best64.rule".

#### Extensive Pure_Hate Methodology Crack
Runs several attack methods provided by Martin Bos (formerly known as pure_hate)
  * Brute Force Attack (7 characters)
  * Dictionary Attack
    * All wordlists in "hcatOptimizedWordlists" with "best64.rule"
    * wordlists/rockyou.txt with "d3ad0ne.rule"
    * wordlists/rockyou.txt with "T0XlC.rule"
  * Top Mask Attack (Target Time = 4 Hours)
  * Fingerprint Attack
  * Combinator Attack
  * Hybrid Attack
  * Extra - Just For Good Measure
    - Runs a dictionary attack using wordlists/rockyou.txt with chained "combinator.rule" and "InsidePro-PasswordsPro.rule" rules
    
#### Brute Force Attack
Brute forces all characters with the choice of a minimum and maximum password length.

#### Top Mask Attack
Uses StatsGen and MaskGen from PACK (https://thesprawl.org/projects/pack/) to perform a top mask attack using passwords already cracked for the current session.
Presents the user a choice of target cracking time to spend (default 4 hours).

#### Fingerprint Attack
https://hashcat.net/wiki/doku.php?id=fingerprint_attack

Runs a fingerprint attack using passwords already cracked for the current session.

#### Combinator Attack
https://hashcat.net/wiki/doku.php?id=combinator_attack

Runs a combinator attack using the "rockyou.txt" wordlist.

#### Hybrid Attack
https://hashcat.net/wiki/doku.php?id=hybrid_attack

* Runs several hybrid attacks using the "rockyou.txt" wordlists.
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1?1
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1?1?1
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1?1?1?1
  - Hybrid Mask + Wordlist - ?s?d ?1?1 wordlists/rockyou.txt
  - Hybrid Mask + Wordlist - ?s?d ?1?1?1 wordlists/rockyou.txt
  - Hybrid Mask + Wordlist - ?s?d ?1?1?1?1 wordlists/rockyou.txt

#### Pathwell Top 100 Mask Brute Force Crack
Runs a brute force attack using the top 100 masks from KoreLogic:
https://blog.korelogic.com/blog/2014/04/04/pathwell_topologies

#### PRINCE Attack
https://hashcat.net/events/p14-trondheim/prince-attack.pdf

Runs a PRINCE attack using wordlists/rockyou.txt

#### YOLO Combinator Attack
Runs a continuous combinator attack using random wordlists from the 
optimized wordlists for the left and right sides.

-------------------------------------------------------------------
### Version History
Version 1.00
  Initial public release
