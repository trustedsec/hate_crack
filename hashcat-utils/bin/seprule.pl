#!/usr/bin/env perl

## Name........: seprule
## Autor.......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT

use strict;
use warnings;

##
## configuration
##

my @rp = ('0'..'9', 'A'..'Z');

my $width = 3;
my $rule  = "i";
my $sep   = " ";

##
## code
##

my $rp_size = scalar @rp;

my $total = $rp_size ** $width;

my $db;

for (my $i = 0; $i < $total; $i++)
{
  my $left = $i;

  my @out;

  for (my $c = 0; $c < $width; $c++)
  {
    my $m = $left % $rp_size;
    my $d = $left / $rp_size;

    push (@out, $m);

    $left = $d;
  }

  @out = sort { $a <=> $b } @out;

  my $val = join ("", @out);

  next if (exists $db->{$val});

  $db->{$val} = undef;

  my @final;

  for (my $c = 0; $c < $width; $c++)
  {
    my $s = sprintf ("T%s", $rp[$out[$c]]);

    push (@final, $s);
  }

  for (my $c = 0; $c < $width; $c++)
  {
    my $s = sprintf ("%s%s%s", $rule, $rp[$out[$c]], $sep);

    push (@final, $s);
  }

  print join (" ", "l", @final), "\n";
}
