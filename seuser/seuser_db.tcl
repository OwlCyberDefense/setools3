##############################################################
#  seuser_db.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#

##############################################################
# ::SEUser_db namespace
#
# This namespace defines the virtual database used by the GUI   
# to manage system and SE Linux policy users. The database is 
# basically a public interface to add, remove, and change a
# user on an selinux system. This database also maintains a 
# list of all roles, groups, sytem users, as well as selinux
# users. Additionally, it defines any special selinux users  
# and tracks any changes made to the selinux policy.
##############################################################
namespace eval SEUser_db {
	# Private list variables
	variable roles_list
	variable sysUsers_list
	variable groups_list
	variable selinuxUsers_list
	# Defined special users
	variable generic_user 		"user_u"
	variable system_user		"system_u"
	# Defined user types
	variable special_usr_type	"Special"
	variable generic_usr_type	"Generic"
	variable def_user_type		"Defined"
	variable undef_user_type	"Undefined"
	# Mod counter used to indicate changes to policy. 
	variable mod_cntr		0
	variable passwd_file		"/etc/passwd"
	# List to hold all users that have been added. We
	# use this list to label home directories after 
	# the policy loaded successfully.
	variable added_users ""
}

########################################################################
# ::reset_mod_cntr
#  	- Resets the current mod counter.
#
proc SEUser_db::reset_mod_cntr { } {
	variable mod_cntr
	set mod_cntr 0
	return 0
}   

########################################################################
# ::update_mod_cntr
#  	- increments the mod counter after a change in the policy.
#
proc SEUser_db::update_mod_cntr { } {
	variable mod_cntr
	set mod_cntr [expr $mod_cntr + 1]
	return 0
}         

###################################################################
# ::get_mod_cntr
#	- Returns the current mod counter in the database.  
#
proc SEUser_db::get_mod_cntr { } {
	variable mod_cntr
	return $mod_cntr	
}            

###################################################################
# ::is_system_user
#	- Determines if user is in the private system users list. 
#	- Returns 1 or 0  
#
proc SEUser_db::is_system_user { user } {
	set idx [lsearch -exact $SEUser_db::sysUsers_list $user]
	if { $idx == -1 } {
		return 0	
	}
	return 1	
}    

###################################################################
# ::is_selinux_user
#	- Determines if user is in the selinux users list. 
#	- Returns 1 or 0 
#
proc SEUser_db::is_selinux_user { user } {
	set idx [lsearch -exact $SEUser_db::selinuxUsers_list $user]
	if { $idx == -1 } {
		return 0	
	}
	return 1
} 

###################################################################
# ::is_generic_user_defined
#	- Determines if special generic user is defined in the selinux policy. 
#	- Returns 1 or 0
#
proc SEUser_db::is_generic_user_defined { } {
	set idx [lsearch -exact $SEUser_db::selinuxUsers_list $SEUser_db::generic_user]
	if { $idx == -1 } {
		return 0	
	}
	return 1
} 

# -----------------------------------------------------------------------------------
#  ::set_sysUser_passwd
#
#  Description: Creates the encrypted password for user. 
#
proc SEUser_db::set_sysUser_passwd { user passwd } {
	set exec_files [auto_execok sadminpasswd]
	# Here we use what should be a TCL principle that commands should always be constructed with "list" and "concat".
	if {$exec_files != ""} {
		set rt [catch {exec echo "$passwd" | sadminpasswd --stdin $user} err]
	} else {
		set rt [catch {exec echo "$passwd" | passwd --stdin $user} err]
	}
	if {$rt != 0} {
		return -code error $err
	}
	return 0
}

# ------------------------------------------------------------------------------
#  ::add_selinuxUser
#
#  Description: Adds a user to the selinux policy
# ------------------------------------------------------------------------------
proc SEUser_db::add_selinuxUser {user roles dflt_login_cxt role_login type_login dflt_cron_cxt role_cron type_cron} {	
	# check for commit access
	set rt [catch {seuser_CheckCommitAccess} err]
	if {$rt != 0 } {
		return -code error $err 
	}  
	set rt [catch {seuser_EditUser add $user $roles $dflt_login_cxt $role_login $type_login $dflt_cron_cxt $role_cron $type_cron} err]
	if {$rt != 0} {	
		return -code error $err
	}  
	# then write the db out to disk
	set rt [catch {seuser_Commit} err]
	if {$rt != 0} {	
		return -code error $err
	} 
	# Update the private list variable
	set SEUser_db::selinuxUsers_list [lappend $SEUser_db::selinuxUsers_list $user]
	set SEUser_db::selinuxUsers_list [lsort $SEUser_db::selinuxUsers_list]
	SEUser_db::update_mod_cntr
	return 0
}

# -----------------------------------------------------------------------------------
#  ::add_sysUser
#
#  Description: This is the interface for adding a user to an selinux system. 
#
proc SEUser_db::add_sysUser { user useradd_args passwd } {
	set exec_files [auto_execok suseradd]
	# Here we use what should be a TCL principle that commands should always be constructed with "list" and "concat".
	if {$exec_files != ""} {
		set cmd [list exec suseradd]
	} else {
		set cmd [list exec useradd]
	}
	foreach arg $useradd_args {
		lappend cmd $arg
	} 
	set rt [catch {eval [concat $cmd $user]} err]
	if {$rt != 0} {
		return -code error $err
	}
	# If the password is null, then the account will be disabled by default and so do nothing.
	# If not, then update the user's authentication token(s).
	if { $passwd != "" } {
		set rt [catch {SEUser_db::set_sysUser_passwd $user $passwd} err]
		if { $rt != 0 } {
			return -code error $err
		} 
	}
	# Update the private system users list variable
	set SEUser_db::sysUsers_list [lappend SEUser_db::sysUsers_list $user]
	return 0
}
	
# -----------------------------------------------------------------------------------
#  ::add_user
#
#  Description: This is the main interface for adding a user to an selinux system. 
#	Its' arguments are:
#		user - the given username to add to the selinux system
#		generic_flag - indicates if this is the selinux generic user.
#		roles - given roles (if generic_flag is ON then will be set to empty.
#		useradd_args - any given options for adding the user to the system (TCL list)
#		passwd - the confirmed password for the user
#		overwrite_policy - option for overwriting an existing policy user with new role information
# 	Make sure all data is validated before making the call to this procedure. 
#
proc SEUser_db::add_user { user generic_flag roles useradd_args passwd overwrite_policy } {
	# Add user to the system. Only add a system user if not in the system users list.
	if { ![SEUser_db::is_system_user $user] } {
		set rt [catch {SEUser_db::add_sysUser $user $useradd_args $passwd} err]
		if {$rt != 0} {
			return -code error $err
		} 	
	}
	# Add user to the policy.
	if { $generic_flag == 0 } {
		# At this point, either the user wishes to overwrite an existing policy user or add a new user to the policy. 
		if { $overwrite_policy && [SEUser_db::is_selinux_user $user] } {
			set rt [catch {SEUser_db::change_selinuxUser $user $roles 0 "" "" 0 "" ""} err]
			if { $rt != 0 } {
				return -code error $err 
			} 
		} elseif { ![SEUser_db::is_selinux_user $user] } {
			set rt [catch {SEUser_db::add_selinuxUser $user $roles 0 "" "" 0 "" ""} err]
			if { $rt != 0 } {
				return -code error $err 
			} 
		}	
		set SEUser_db::added_users [lappend SEUser_db::added_users $user]
		# else, this is an existing policy user and do not wish to overwrite, so do nothing.
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  ::change_sysUser
#
#  Description: This is the interface for changing a user on an selinux system. 
#
proc SEUser_db::change_sysUser { user useradd_args } {
	set exec_files [auto_execok susermod]
	# Here we use what should be a TCL principle that commands should always be constructed with "list" and "concat".
	if {$exec_files != ""} {
		set cmd [list exec susermod]
	} else {
		set cmd [list exec usermod]
	}
	foreach arg $useradd_args {
		lappend cmd $arg
	} 
	set rt [catch {eval [concat $cmd $user]} err]
	if {$rt != 0} {
		return -code error $err
	} 
	return 0
}

# ------------------------------------------------------------------------------
#  ::change_selinuxUser
#
#  Description: Changes a user in the selinux policy
# ------------------------------------------------------------------------------
proc SEUser_db::change_selinuxUser { user roles dflt_login_cxt role_login type_login dflt_cron_cxt role_cron type_cron } {	
	# check for commit access
	set rt [ catch {seuser_CheckCommitAccess } err]
	if {$rt != 0 } {
		return -code error $err
	}  
	set rt [catch {seuser_EditUser change $user $roles  \
		       $dflt_login_cxt $role_login $type_login $dflt_cron_cxt \
		       $role_cron $type_cron} err]
	if {$rt != 0} {	
		return -code error $err
	}  
	# then write the db out to disk
	set rt [catch {seuser_Commit} err]
	if {$rt != 0} {	
		return -code error $err
	} 
	SEUser_db::update_mod_cntr
	return 0
}

# -----------------------------------------------------------------------------------
#  ::change_user
#
#  Description: This is the main interface for changing a user on an selinux system. 
#	Its' arguments are:
#		user - the given username to change on the selinux system
#		generic_flag - indicates if this is the selinux generic user.
#		roles - given roles (if generic_flag is ON then will be set to empty).
#		useradd_args - any given options for adding the user to the system (TCL list)
# 	Make sure all data is validated before making the call to this procedure. 
#
proc SEUser_db::change_user { user generic_flag roles useradd_args } {
	if { [SEUser_db::is_system_user $user] } {
		set rt [catch {SEUser_db::change_sysUser $user $useradd_args} err]
		if {$rt != 0} {
			return -code error $err
		}
	}
	if { $generic_flag == 0 } {
		if {[SEUser_db::is_selinux_user $user]} {
			set rt [catch {SEUser_db::change_selinuxUser $user $roles 0 "" "" 0 "" ""} err]
			if { $rt != 0 } {
				return -code error $err 
			} 	
		} else {
			set rt [catch {SEUser_db::add_selinuxUser $user $roles 0 "" "" 0 "" ""} err]
			if { $rt != 0 } {
				return -code error $err 
			} 
		}
	} else {
		if {[SEUser_db::is_selinux_user $user]} {
			set rt [catch {SEUser_db::remove_selinuxUser $user} err]
			if { $rt != 0 } {
				return -code error $err 
			} 	
		} 
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  ::remove_sysUser
#
#  Description: Removes a user from the system
# ------------------------------------------------------------------------------
proc SEUser_db::remove_sysUser { user remove_home_dir } {
	set idx [lsearch -exact $SEUser_db::sysUsers_list $user]
	if { $idx != -1 } {
		set exec_files [auto_execok suserdel]
		# Here we use what should be a TCL principle that commands should always be constructed with "list" and "concat".
		if {$exec_files != ""} {
			if { $remove_home_dir } {
				set rt [catch {exec suserdel -r $user} err]
			} else {
				set rt [catch {exec suserdel $user} err] 
			}
		} else {
			if { $remove_home_dir } {
				set rt [catch {exec userdel -r $user} err]
			} else {
				set rt [catch {exec userdel $user} err] 
			}
		}

		if {$rt != 0} {
			return -code error $err
		} 
		# Update the private system users list variable
		set SEUser_db::sysUsers_list [lreplace $SEUser_db::sysUsers_list $idx $idx]
	}
	return 0	
}

# ------------------------------------------------------------------------------
#  ::remove_selinuxUser
#
#  Description: Removes a user from the selinux policy
# ------------------------------------------------------------------------------
proc SEUser_db::remove_selinuxUser { user } {
	set idx [lsearch -exact $SEUser_db::selinuxUsers_list $user]
	if { $idx != -1 } {
		# check for commit access
		set rt [ catch {seuser_CheckCommitAccess} err]
		if {$rt != 0 } {
			return -code error $err 
		}   
		set rt [catch {seuser_RemoveUser $user} err]
		if {$rt != 0} {	
			return -code error $err
		}	
		# then write the db out to disk
		set rt [catch {seuser_Commit} err]
		if {$rt != 0} {	
			return -code error $err 
		} 	    
		# Update the private list variable
		set SEUser_db::selinuxUsers_list [lreplace $SEUser_db::selinuxUsers_list $idx $idx]
		SEUser_db::update_mod_cntr
	}
	return 0
} 

# -----------------------------------------------------------------------------------
#  ::remove_user
#
#  Description: This is the interface for removing a user from an selinux system. 
#	Its' arguments are:
#		user - the given username to remove to the selinux system
#		remove_home_dir - indicates whether the users' home dir should be removed.
# 
proc SEUser_db::remove_user {user remove_home_dir} {
	set rt [catch {SEUser_db::remove_sysUser $user $remove_home_dir} err]
	if { $rt != 0 } {
		return -code error $err
	}
	set rt [catch {SEUser_db::remove_selinuxUser $user} err]
	if { $rt != 0 } {
		return -code error $err
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_db::get_sysUser_data_field
# -----------------------------------------------------------------------------------
proc SEUser_db::get_sysUser_data_field {user field_descriptor} {
	variable passwd_file
	
	if { [SEUser_db::is_system_user $user] } {
		set rt [catch {set data [exec grep "^$user:" $passwd_file]} err]
		if { $rt != 0 } {
			return -code error $err
		}
		set data [split $data ":"]
		if { [llength $data] != 7 } {
			return -code error "Cannot split field descriptors from the users' entry in $passwd_file"
		}
		switch $field_descriptor {
			account {
				return [lindex $data 0]
			}
			passwd {
				return [lindex $data 1]
			}
			uid {
				return [lindex $data 2]
			}
			gid {
				return [lindex $data 3]
			}
			comment {
				return [lindex $data 4]
			} 
			directory {
				return [lindex $data 5]
			} 
			shell {
				return [lindex $data 6]
			}
			default {
				return -code err "Could not determine the field descriptor needed from the users' entry in $passwd_file"
			}
		}
	}
	return ""
}

# ------------------------------------------------------------------------------
#  ::get_user_type
#
#  Description: Used to retrieve the user type. Type could be:
#			- Defined - user is defined in the policy
#			- Undefined - user is not defined in the policy and generic users are disabled
#			- Generic - user is generic and is not defined in the policy
# 			- Special - user is special (i.e. system_u, user_u, ...)
# ------------------------------------------------------------------------------
proc SEUser_db::get_user_type { user } {
	variable sysUsers_list
	variable selinuxUsers_list
	variable generic_user 
	variable system_user
	
	if { [lsearch -exact $selinuxUsers_list $user] != -1 } {
		if { $user == $generic_user || $user == $system_user } {
			return $SEUser_db::special_usr_type
		} else {
			return $SEUser_db::def_user_type
		}
	} else {
		# Check if user_u is defined in the policy and if so return the generic user type.
		if { [lsearch -exact $selinuxUsers_list $generic_user] != -1 } {
			return $SEUser_db::generic_usr_type
		} else { 
			return $SEUser_db::undef_user_type
		}
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  ::get_user_roles
#
#  Description: Retrieve roles for a given user.
# ------------------------------------------------------------------------------
proc SEUser_db::get_user_roles { username } {
	variable selinuxUsers_list
	variable generic_user
	
	# If the user is defined in the policy, then return roles for the user. If not, then determine
	# if the generic user is defined and if so, return roles for the generic user. 
	if { [lsearch -exact $selinuxUsers_list $username] != -1 } {
		set rt [catch {set currentRoles [seuser_UserRoles $username]} err]
		if {$rt != 0} {	
			return -code error $err
		}
		return [lsort $currentRoles]
	} elseif { [SEUser_db::is_generic_user_defined] } {
		set rt [catch {set currentRoles [seuser_UserRoles $generic_user]} err]
		if {$rt != 0} {	
			return -code error $err
		}
		return [lsort $currentRoles] 
	}
	return ""
}

# ------------------------------------------------------------------------------
#  ::get_user_groups
#
#  Description: Retrieve groups, of which the given user is a member
# ------------------------------------------------------------------------------
proc SEUser_db::get_user_groups { user } {
	variable sysUsers_list
	
	if { [SEUser_db::is_system_user $user] } {
		set rt [catch {set groups [exec groups $user]} err]
		if {$rt != 0} {
			return -code error $err
		}
		# Strip out username and the proceeding colon from the list
		set groups [lreplace $groups 0 1]
		return $groups
	} elseif { [SEUser_db::is_selinux_user $user] } {
		return ""
	} else {
		return -code error "User: $user is neither a system user nor defined in the selinux policy."
	}	
}

# ------------------------------------------------------------------------------
#  ::get_list
#
#  Description: Retrieve a particular list from the virtual database.
# ------------------------------------------------------------------------------
proc SEUser_db::get_list { which } {
	variable roles_list
	variable sysUsers_list
	variable groups_list
	variable all_users_list
	variable selinuxUsers_list
	
	switch $which {
		roles {
			return $roles_list
		}
		sysUsers {
			return $sysUsers_list
		}
		groups {
			return $groups_list
		}
		seUsers {
			return $selinuxUsers_list
		}
		default {
			return -code error "Cannot find the specified list: $which"
		}
	}
}

# ------------------------------------------------------------------------------
#  ::free_db
#
#  Description: Free virtual database
# ------------------------------------------------------------------------------
proc SEUser_db::free_db {} {	
	set SEUser_db::roles_list 		""
	set SEUser_db::sysUsers_list 		""
	set SEUser_db::groups_list 		""
	set SEUser_db::selinuxUsers_list 	""
	set SEUser_db::added_users 		""
	SEUser_db::reset_mod_cntr
	return 0	
}
# ------------------------------------------------------------------------------
#  ::load_policy
#
#  Description: Load the selinux policy
# ------------------------------------------------------------------------------
proc SEUser_db::load_policy { } {
	set rt [catch {seuser_ReinstallPolicy} err]
	if { $rt != 0 } {
		return -code error $err
	}
	foreach user $SEUser_db::added_users {
		set rt [catch {seuser_LabelHomeDirectory $user} err]
		if {$rt != 0 } {
			return -code error $err 
		}  
	}
	set SEUser_db::added_users ""
	return 0
}

# ------------------------------------------------------------------------------
#  ::init_db
#
#  Description: Performs initialization for the virtual database.
# ------------------------------------------------------------------------------
proc SEUser_db::init_db { } {
	variable roles_list
	variable sysUsers_list
	variable groups_list
	variable selinuxUsers_list
			
	# All System Users (include types information)
	set rt [catch {set sysUsers_list_with_types [seuser_GetSysUsers 1]} err]
	if {$rt != 0} {
		return -code error $err
	}
	# All System Users (not including type information)
	set rt [catch {set sysUsers_list [seuser_GetSysUsers]} err]
	if {$rt != 0} {
		return -code error $err
	}
	set sysUsers_list [lsort $sysUsers_list]
	# All SE Linux Users
	set rt [catch {set selinuxUsers_list [seuser_GetSeUserNames]} err]
	if {$rt != 0} {	
		return -code error $err
	}
	set selinuxUsers_list [lsort $selinuxUsers_list]
	# All Roles
	set rt [catch {set roles_list [apol_GetNames roles]} err]
	if {$rt != 0} {	
		return -code error $err
	}    
	set roles_list [lsort $roles_list] 
	# All Groups
	set rt [catch {set groups_list [seuser_GetSysGroups]} err]
	if {$rt != 0} {	
		return -code error $err
	}    
	set groups_list [lsort $groups_list]	
	return 0
} 
                                                                                                                                                                                                                          