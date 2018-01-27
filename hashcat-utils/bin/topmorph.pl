#!/usr/bin/env perl

## Name........: topmorph
## Autor.......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT

use strict;
use warnings;

my @intpos_to_rulepos = ('0'..'9', 'A'..'Z');

my $function = "i";
#my $function = "o";

if (scalar @ARGV != 5)
{
  print "usage: $0 dictionary depth width pos_min pos_max\n";

  exit -1;
}

my ($dictionary, $depth, $width, $pos_min, $pos_max) = @ARGV;

if ($width > 20)
{
  print "width > 20\n";

  exit -1;
}

for (my $pos = $pos_min; $pos <= $pos_max; $pos++)
{
  my $db;

  open (IN, $dictionary) or die "$dictionary: $!\n";

  while (my $line = <IN>)
  {
    chomp $line;

    my $len = length $line;

    next if (($len - $pos) < $width);

    my $word = substr ($line, $pos, $width);

    next unless defined $word;

    $db->{$word}++;
  }

  close (IN);

  my @keys = sort { $db->{$b} <=> $db->{$a} } keys %{$db};

  for (my $i = 0; $i < $depth; $i++)
  {
    my @chars = split "", $keys[$i];

    my @rule;

    for (my $j = 0; $j < $width; $j++)
    {
      my $function_full = join "", $function, $intpos_to_rulepos[$pos + $j], $chars[$j];

      push @rule, $function_full;
    }

    print join (" ", @rule), "\n";
  }
}
