# NAME

psv-db - Vita NID database line-based utility

# SYNOPSIS

    psv-db < db.yml

# OUTPUT

The output use the followin columns :

    fw  ModNID ModName  LibNID LibName LibPrivilege  FuncNID FuncName

These columns can easily be post-processed using awk, grep, sed ...

# EXAMPLES

output the lib + name of a specific NID (4B171BEA)

    psv-db < db.yml | awk '$7~/4B171BEA/{print "lib"$3"_"$1".a:"$8}'

check that *ForKernel/*ForDriver library don't export for users

    psv-db < db.yml | grep -P 'For(Kernel|Driver) +u'

check that no kernel exports are outside a ForDriver/Kernel lib

    psv-db < db.yml | grep -P ' k ' | grep -Pv 'For(Driver|Kernel)'


# SEE ALSO
  - yml(5)
  - psv-lib(1)

