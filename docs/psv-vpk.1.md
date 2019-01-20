# NAME
  psv-sfo - Generate a System File Object

# SYNOPSIS
  Usage: %s [HOSTPATH[:VPKPATH]]... <in.self >out.vpk
    Generate a VPK with the given HOSTPATH files

  psv-sfo < in.sfo
    Dump given in.sfo

  psv-sfo
    Show the help screen

# EXAMPLES
  psv-sfo TITLE=MyGame ATTRIBUTE=+0xFF > param.sfo

# SEE ALSO
  - sfo(5)




FILES
	Can ba a regular file or a folder
	in wish case will be recursivelly archived

EXAMPLES
	outname.txt:inname.txt
	contrib/vita:contrib
	param.sfo:/sce_sys/param.sfo

NOTES
	A basic /sce_sys/param.sfo will be injected if none given

dd if=/dev/random of=big.img bs=4k iflag=fullblock,count_bytes count=1G

time psv-vpk _param.sfo:sce_sys/param.sfo big.img <main.self >out2.vpk
real	0m5.979s
user	0m0.009s
sys	0m1.824s

time vita-pack-vpk -s _param.sfo -b main.self -a big.img=big.img out2.vpk
real	0m51.453s
user	0m50.016s
sys	0m1.392s
