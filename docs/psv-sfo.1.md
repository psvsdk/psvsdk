# NAME
  psv-sfo - Generate a System File Object

# SYNOPSIS
  psv-sfo [KEY=STR | KEY=+INT]... > out.sfo
    Generate a SFO with the given KEY=VAL tuples

  psv-sfo < in.sfo
    Dump given in.sfo

  psv-sfo
    Show the help screen

# EXAMPLES
  Generate a default SFO
    psv-sfo > param.sfo

  Dump a SFO file
    psv-sfo < param.sfo

  Dump the default generated SFO on the fly
    psv-sfo < param.sfo

  Generate a SFO some string anf integer values (notice the +)
    psv-sfo STITLE=MyGame ATTRIBUTE=+0xFF > param.sfo

  psv-sfo | psv-sfo # generate a default sfo then dump it
# SEE ALSO
  - sfo(5)
