#!/usr/bin/perl
# Check padding bytes in common binaries (for House of Pain) - by isra

use strict;


# ELF header keys
my @e_keys = (
    'ei_mag0', 'ei_mag1', 'ei_mag2', 'ei_mag3', 'ei_class', 'ei_data', 
    'ei_version', 'ei_osabi', 'ei_abiversion', 'ei_pad1', 'ei_pad2',
    'ei_pad3', 'ei_pad4', 'ei_pad5', 'ei_pad6', 'ei_pad7',
    'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff', 'e_shoff',
    'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum', 'e_shentsize', 'e_shnum',
    'e_shstrndx'
);

# section header keys
my @sh_keys = (
    'sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 'sh_size',
    'sh_link', 'sh_info', 'sh_addralign', 'sh_entsize'
);

# string table
my %strtab;

my ($init_index, $plt_got_index, $fini_index);
my @DIRS            = ( '/usr/bin', '/usr/sbin' );
my @EXEC_SECTIONS   = ( '.init', '.plt', '.plt.got', '.text', '.fini');
my %INDEX;

#
# parsing subroutines
#

# see https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
sub parse_ehdr {
    my $fh = shift;

    read $fh, my $buff, 64;
    my @e = unpack("C a a a C12 S2 I q3 I S6", $buff);

    # create hash based on ELF header fields and unpacked values
    my %ehdr;
    for(my $i = 0; $i < @e_keys; $i++) {
        $ehdr{$e_keys[$i]} = $e[$i];
    }

    $ehdr{'is_elf'} = 1;
    # check magic number
    if($e[0] != 0x7F && $e[1] !~ 'E' && $e[2] !~ 'L' && $e[3] !~ 'F') {
        # die "Not an ELF file\n";
        $ehdr{'is_elf'} = 0;
    }

    # check ei_class
    $ehdr{'is_64'} = 1;
    if($e[4] != 2) {
        # die "Only ELF64 is supported\n";
        $ehdr{'is_64'} = 0;
    }

    return %ehdr;
}

# see https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
sub parse_shtab {
    my $fh      = shift;
    my %ehdr    = @_;

    # section header table
    my @shtab;

    seek $fh, $ehdr{'e_shoff'}, 0; 
    for (my $i = 0; $i < $ehdr{'e_shnum'}; $i++) {
        
        read $fh, my $buff, $ehdr{'e_shentsize'};
        my @s = unpack("I2 q4 I2 q2", $buff);

        # create entry based on section header fields and unpacked values
        my %shdr;
        for(my $i = 0; $i < @sh_keys; $i++) {
            $shdr{$sh_keys[$i]} = $s[$i];
        }
        push @shtab, \%shdr;

        # read content (strings) when entry of type 'STRTAB' = 3 is found
        if($shdr{'sh_type'} == 3) {
            my $tmpstr;
            my $curr_offset = tell $fh;
            seek $fh, $shdr{'sh_offset'}, 0;
            read $fh, $tmpstr, $shdr{'sh_size'};
            seek $fh, $curr_offset, 0;
            $strtab{$shdr{'sh_offset'}} = $tmpstr;
        }
    }

    return @shtab;
}

# get section name
sub secname {
    my $ndx = shift;
    my $str = shift;

    my $s = substr($str, $ndx);
    my $r = substr($s, 0, index($s, "\0"));
}

# get section names from string table
# must be performed after parsing the section header table
sub parse_secnames {
    my $ehdr    = shift;
    my $shtab   = shift;

    my $shstrtab = $shtab->[$ehdr->{'e_shstrndx'}];
    my $first_exe = 0;
    for(my $i = 0; $i < $ehdr->{'e_shnum'}; $i++) {
        my $name = secname(
            $shtab->[$i]{'sh_name'}, 
            $strtab{$shstrtab->{'sh_offset'}}
        );
        # add 'name' to each section header entry
        $shtab->[$i]{'name'} = $name;

        foreach my $exec_section(@EXEC_SECTIONS) {
            $INDEX{$exec_section} = $i if ($name eq $exec_section);
        }
    }
}


#
# main code
#

# for checking how many binaries have enough padding bytes for House of Pain
# last checked size: march 31st, 2024
my $hop_size = 1855; 

my ($total, $total_hop, $total_hop_100) = (0, 0, 0);
my (%TOTAL, %AVG, %PADDING);
foreach my $exec_section(@EXEC_SECTIONS) {
    $TOTAL{$exec_section}   = 0;
    $AVG{$exec_section}     = 0;
    $PADDING{$exec_section} = {};
}

print "\n [+] Padding bytes analyzer\n";
print " [*]\n";

foreach my $dir(@DIRS) {
    print " [+] Analyzing $dir\n";
    foreach my $file(glob qq{"$dir/*"}) {
        next if(!-f $file);

        open my $fh, '<:raw', $file or die "Couldn't open $file\n";

        my %ehdr = parse_ehdr($fh);
        next if(!$ehdr{'is_elf'} or !$ehdr{'is_64'});

        undef %INDEX;
        my @shtab = parse_shtab($fh, %ehdr);
        parse_secnames(\%ehdr, \@shtab);

        foreach my $exec_section(@EXEC_SECTIONS) {
            if(exists($INDEX{$exec_section})) {
                $TOTAL{$exec_section}++;

                my $section        = @shtab[$INDEX{$exec_section}];
                my $section_next   = @shtab[$INDEX{$exec_section} + 1];

                my $padding_bytes   = $section_next->{'sh_offset'};
                $padding_bytes      -= $section->{'sh_offset'};
                $padding_bytes      -= $section->{'sh_size'};

                if(exists($PADDING{$exec_section}{$padding_bytes})) {
                    $PADDING{$exec_section}{$padding_bytes}++;
                } else {
                    $PADDING{$exec_section}{$padding_bytes} = 1;
                }

                if($exec_section eq '.fini' && $padding_bytes >= $hop_size) {
                    $total_hop++;
                }

                if($exec_section eq '.fini' && $padding_bytes >= $hop_size+80) {
                    $total_hop_100++;
                }

                $AVG{$exec_section} += $padding_bytes;
            }
        }

        $total++;
    }
}


foreach my $exec_section(@EXEC_SECTIONS) {
    $AVG{$exec_section} = $AVG{$exec_section}/$TOTAL{$exec_section};
}

print " [*]\n";
print " [+] Total files analyzed: $total\n";
print " [+] Total files with enough padding bytes for House of Pain: $total_hop\n";
print " [+] Total files with enough padding bytes for 100 bytes payload: $total_hop_100\n";
foreach my $exec_section(@EXEC_SECTIONS) {
    print " [+] Total files with $exec_section section: $TOTAL{$exec_section}\n";   
}

print " [*]\n";
foreach my $exec_section(@EXEC_SECTIONS) {
    print " [+] Average padding size for $exec_section: $AVG{$exec_section}\n";  
}

print " [*]\n";
print " [+] Padding bytes sizes per section\n";
foreach my $exec_section(@EXEC_SECTIONS) {
    print " [+] Section $exec_section:\n";
    foreach my $k(keys %{$PADDING{$exec_section}}) {
        print "     Padding size $k: $PADDING{$exec_section}{$k} file(s)\n";
    }
}

print "\n";
