use ExtUtils::MakeMaker;

WriteMakefile(
    dist	=> {
	            PREOP	=> 'pod2text Rijndael.pm | tee README >$(DISTVNAME)/README; chmod -R u=rwX,go=rX . ;',
	            COMPRESS	=> 'gzip -9v',
	            SUFFIX	=> '.gz',
	           },
    NAME => "Crypt::Rijndael",
    VERSION_FROM => "Rijndael.pm",
);

