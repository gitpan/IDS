use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'IDS',
    AUTHOR              => 'Kenneth Ingham <cpan@i-pi.com>',
    VERSION_FROM        => 'lib/IDS/Test.pm',
    ABSTRACT_FROM       => 'lib/IDS/Test.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'IDS-*' },
);
