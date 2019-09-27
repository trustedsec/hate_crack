#!/usr/bin/env perl

## Name........: tmesis
## Autor.......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT

use strict;
use warnings;

#tmesis will take a wordlist and produce insertion rules that would insert each word of the wordlist to preset positions.
#For example:
#Word ‘password’ will create insertion rules that would insert ‘password’ from position 0 to position F (15)  and It will mutate the string ‘123456’ as follows.
#password123456
#1password23456
#12password3456
#123password456
#1234password56
#12345password6
#123456password
#
#Hints:
#*Use tmesis to create rules to attack hashlists the came from the source. Run initial analysis on the cracked passwords , collect the top 10 – 20 words appear on the passwords and use tmesis to generate rules.
#*use tmesis generated rules in combination with best64.rules
#
# inspired by T0XlC

my $min_rule_pos = 0;
my $max_rule_pos = 15;

my $db;

my @intpos_to_rulepos = ('0'..'9', 'A'..'Z');

my $function = "i";
#my $function = "o";

while (my $word = <>)
{
  chomp $word;

  my $word_len = length $word;

  my @word_buf = split "", $word;

  for (my $rule_pos = $min_rule_pos; $rule_pos < $max_rule_pos - $word_len; $rule_pos++)
  {
    my @rule;

    for (my $word_pos = 0; $word_pos < $word_len; $word_pos++)
    {
      my $function_full = $function . $intpos_to_rulepos[$rule_pos + $word_pos] . $word_buf[$word_pos];

      push @rule, $function_full;
    }

    print join (" ", @rule), "\n";
  }
}

