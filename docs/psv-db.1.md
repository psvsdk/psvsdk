# NAME
  psv-db - Vita NID database line-based utility

# SYNOPSIS
	psv-db < db.yml

# OUTPUT
  The output is column based for easy post-processing (awk, grep, sed ...) :

	fw  ModNID ModName  LibNID LibName LibPrivilege  FuncNID FuncName

# EXAMPLES

	psv-db < db.yml | grep -P 'For(Kernel|Driver) +u' # check that *ForKernel/*ForDriver library don't export for users
	psv-db < db.yml | grep -P ' k ' | grep -Pv 'For(Driver|Kernel)' # check that no kernel exports are outside a ForDriver/Kernel lib
	psv-db < db.yml | awk '$7~/4B171BEA/{print "lib"$3"_"$1".a:"$8}' # find a NID (4B171BEA) and print it lib + name

# SEE ALSO
  - yml(5)
  - psv-lib(1)

