#!/bin/sh

# command line shell to run seuser delete/suseradd
#

    SEUSER="/usr/local/selinux/bin/seuser "
    USERDEL="/usr/local/selinux/bin/suserdel "
    seuseropts=""
    suserdelopts=""

usage() {
    echo >&2 "$@"
    echo >&2 "
usage: 
	$0  -X
	$0  -A
	$0  -h
	$0  [-N] [-r] username
"    
}

# -h show this
long_usage() {
    usage ""
    echo >&2 "
    -X             start seuser gui (seuser -X)
    -A             Activate policy (seuser load)
    -r             remove user's home directory
    -h             print out this usage message
"
#    -N             do not load policy (only build and install)
}


# if no arguments are given print usage statement
if [ $# -eq 0 ]; then
    usage ""
    exit 0
fi

while getopts hrANX optvar
do
    case "$optvar"
    in 
	r) # delete user's files as well
	    suserdelopts="${suserdelopts} -r"
	    ;;
	A) # load policy
	    if [ $# -eq 1]; then # we're just loading the policy
		${SEUSER} load
		exit $?
	    fi
	    echo >&2 "Warning: -A ignored (must be used alone)"
	    ;;
#	N) # do not reload policy after deleting user
#	    seuserdelopts="${seuseropts} -N"
#	    ;;
	h) # print usage
	    long_usage
	    exit 0
	    ;;
	X) # start sueser gui
	    if [ ${OPTIND} -ne 2 ]; then
		usage "-X is for running seuser in gui mode"
		exit 1
	    fi
	    ${SEUSER} -g
	    exit $?
	    ;;
    esac
done

# toss out the arguments we've already processed
shift  `expr $OPTIND - 1`

# Here we expect the username
if [ $# -eq 0 ]; then
    usage "Need user name"
    exit 1
fi

USERNAME=$1

if [ "${USERNAME}" = "system_u" ]; then
    usage "You may not delete system_u with $0"
    exit 1
fi


shift

# there should be nothing after the username
if [ $# -ne 0 ]; then
    usage "You're giving me some extra stuff: $@"
    exit 1
fi

# call seuser delete, supress error if its a generic user (ie, not in policy)
${SEUSER} delete -N ${seuseropts} ${USERNAME} 2> /dev/null

# issue warning if user_u is being deleted
if [ "${USERNAME}" = "user_u" ]; then
    echo >&2 "WARNING: You have deleted 'user_u', the generic user definition, from"
    echo >&2 "         the policy.  Any system users not explicitly defined in the"
    echo >&2 "         policy will no longer be able to login."
fi

# delete user from system.
if [ "${USERNAME}" != "user_u" ]; then
    ${USERDEL} ${suserdelopts} ${USERNAME} 2> /dev/null
    exit $?
fi
