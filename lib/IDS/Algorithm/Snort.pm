# for checking a web request against the rules.

package IDS::Algorithm::Snort;
use base qw(IDS::Algorithm);
$IDS::Algorithm::Snort::VERSION = "1.0";

=head1 NAME

IDS::Algorithm::Snort - and IDS::Algorithm for using Snort rules
as a signature-based IDS.

=head1 SYNOPSIS

A usage synopsis would go here.  Since it is not here, read on.

=head1 DESCRIPTION

See IDS::Algorithm.pm docs for any functions not described here.

Note that this is an incomplete implementation of Snort rule processing.
I implemeted what I needed to for the HTTP testing, and have not yet 
spent the time needed to implement everything.

=cut

use strict;
use warnings;
use Carp qw(cluck carp confess);

use IDS::Algorithm::Snort::Rule;

sub param_options {
    my $self = shift;

    return (
	    "snort_verbose=i" => \${$self->{"params"}}{"verbose"},
	    "rules_file=s"    => \${$self->{"params"}}{"rules_file"},
	   );
}

sub default_parameters {
    my $self = shift;

    %{$self->{"params"}} = (
        "verbose" => 0,
        "rules_file" => 0,
    );
}

sub initialize {
    my $self = shift;

    # nothing to do
}

# the file name is a dir, and we will open all the files in the
# specified directory; this behavior is a better match for how 
# snort rules tend to be set up.

sub load {
    my $self = shift;
    my $dir = $self->find_fname(shift);
    $dir or
	confess *load{PACKAGE} . "::load missing dirname";
    my $rules = [];

    opendir RULEDIR, $dir or confess "Unable to opendir $dir: $!\n";
    foreach my $file (readdir(RULEDIR)) {
	next if /^\..*$/; # skip all dotfiles

	$self->msg(1, "Opening '$dir/$file'");
	open(RULES, "$dir/$file") or confess "Cannot open $dir/$file: $!\n";
	while(<RULES>) {
	    chomp;
	    next if(/^\s*$/);
	    next if(/^\#/);

	    while (/\\\s*$/) { # handle continuations
		s/\\\s*$//;
		my $line = <RULES>; chomp($line);
	        $_ .= " " . $line;
	    }

	    if (/\(.*\)/) {
		$self->msg(2, "rule is '$_'");
		push @{$rules}, new IDS::Algorithm::Snort::Rule($_, $file);
	    }
	}
	close(RULES);
    }
    $self->{"rules"} = $rules;
}

sub verbose {
    my $self = shift;
    my $new = shift;
    my $old = $self->{"verbose"};

    $self->{"verbose"} = $new if $new;

    return $old;
}

sub msg {
    my $self = shift;
    my $level = shift;
    print STDERR (@_, "\n") if $self->{"verbose"} >= $level;
}

sub add {
    my $self = shift;

    # no learning with snort

    return;
}

#
# This test func is HTTP-specific
#
sub test {
    my $self = shift;
    my $tokensref = shift; # ignored
    my $data = shift or
        confess "bug: missing string to ", *test{PACKAGE} . "::test";
    my $instance = shift; # ignored

    my ($result, $path);

    $path = $self->path($data);

    foreach my $rule (@{$self->{"rules"}}) {
        $result = $rule->test($path, $data);
	if ($result) {
	    if (wantarray) {
		$self->{"signature"} = $result;
	        return (0, $result);
	    } else {
	        return 0;
	    }
	}
    }
    return 1; # unless we have a match, it is good.
}

sub path {
    my $self = shift;
    my $string = shift or
        confess "bug: missing string to ", *method{PACKAGE} . "::method";
    
    # The path is the second "word" in the string.  Assume greedy
    # pattern matching
    $string =~ /[^\s]+\s+([^\s]+)/;
    return $1;
}

=head1 AUTHOR INFORMATION

Copyright 2005-2007, Kenneth Ingham.  All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

Address bug reports and comments to: ids_test at i-pi.com.  When sending
bug reports, please provide the versions of IDS::Test.pm, IDS::Algorithm.pm,
IDS::DataSource.pm, the version of Perl, and the name and version of the
operating system you are using.  Since Kenneth is a PhD student, the
speed of the reponse depends on how the research is proceeding.

=head1 BUGS

Please report them.

=head1 SEE ALSO

L<IDS::Algorithm>, L<IDS::DataSource>

=cut


1;
