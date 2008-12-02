##############################################################
#  seuser_selinux_users.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#

##############################################################
# ::SEUser_SELinux_Users namespace
#
# This namespace creates the selinux users tab, which 
# allows the user to directly add/remove users from the policy
# without adding/removing users from the system  
##############################################################
namespace eval SEUser_SELinux_Users {	
	####################
	# Global Widget(s) 
	variable main_frame
	# Listboxes
	variable listbox_sysUsers
	variable listbox_SEUsers
	variable listbox_availRoles
	variable listbox_currentRoles
	# Buttons
	variable u_add
	variable u_remove
	variable r_add
	variable r_remove			
	
	####################################
	# User Policy Management Variables 
	variable opts
	
	# Global list variables 
	# - NOTE: When changing these variable names, do not forget to change argument
	#	  names accordingly for calls to SEUser_Top::check_list_for_redundancy.
	#	  This is because calls to SEUser_Top::check_list_for_redundancy use 
	#	  these names explicitly as arguments to simulate call-by-reference.
	# 
	variable sysUsers_list 			""
	variable selinuxUsers_list 		""      
	variable currentRoles_list 		""
	variable type_list
	# this is the var attached to the listbox
	variable availRoles_list 		""
	# this is the var holding the original copy
	variable allRoles_list 			""
	variable all_sysUsers_list 		""
	# Variables for adding/deleting a user
	variable user_to_add			""
	variable user_to_del			""
	# Micellaneous variables
	variable modified_user 			"none"
	variable empty_string 			"<none>"
	
	# state variables
	variable state
	# edit indicates that we are in edit mode
	set state(edit) 0
	# users_changed indicates that these changes includes a change
	# to the list of users or user roles (i.e., changes that impact
	# the users_file).  Such changes would require the policy to be
	# rebuilt to be effective (unlike default context changes)
	set state(users_changed) 0
	# edit_type indicates which type of pending edit: delete, add, change, none
	set state(edit_type) "none"
	# roles_changed indicates whether roles were changed in a "change" edit
	# if roles were changed (rather than just default contexts) then we need to increment 
	# users_changed on commit
	set state(roles_changed) 0  
	variable mcntr 		0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::SetEditMode 
#
#  Description: Sets important state variables based on the mode argument. 
#		Also, makes the proc calls to update the status bar and then perform   
#		disabling/enabling of widgets.
# -----------------------------------------------------------------------------------
proc SEUser_SELinux_Users::SetEditMode { mode } {
	variable state
	variable modified_user
	
	switch -- $mode {
		delete {
		    set state(edit) 1
		    set state(edit_type) "delete"
		    set state(users_changed) [expr $state(users_changed) + 1]
		}
		undelete {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(users_changed) [expr $state(users_changed) - 1]
		}
		add {
		    set state(edit) 1
		    set state(edit_type) "add"
		    set state(users_changed) [expr $state(users_changed) + 1]
		}
		unadd {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(users_changed) [expr $state(users_changed) - 1]
		}
		change {
		    # we might be making changes for a new user, in which case we don't want 
		    # to change edit type or any other state
		    if { $state(edit) == 1 && $state(edit_type) == "add" } {
		    	return
		    }
		    # Grab the modified user from the list box.
		    # This will only invoked if this is the first time we do a change.
		    if { $state(edit) == 0 } {
		    	set idx [$SEUser_SELinux_Users::listbox_SeLinuxUsers curselection]
			set modified_user [$SEUser_SELinux_Users::listbox_SeLinuxUsers get $idx]
		    }
		    set state(edit) 1
		    set state(edit_type) "change"
		}
		unchange {
		    set state(edit) 0
		    set state(edit_type) "none"
		}
		commit {
		    set state(edit) 0
		    set state(edit_type) "none"
		}
		init {
		    set state(edit) 0
		    set state(users_changed) 0
		    set state(edit_type) "none"
		    set state(roles_changed) 0
		}
		default {
		    tk_messageBox -icon error -type ok -title "Error" -message "Invalid Edit Mode!" \
		    	-parent $SEUser_SELinux_Users::main_frame
		    return
		}
	}
	
	SEUser_SELinux_Users::edit_type_disable_enable
	# Updates the highlights for the seusers.
	SEUser_SELinux_Users::CheckSeUserHighlights
	
	return 0		
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::initialize
#
#  Description: Performs dialog initialization 
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::initialize { } {
	variable all_sysUsers_list
	variable sysUsers_list
	variable selinuxUsers_list
	variable availRoles_list
	variable allRoles_list
	
	SEUser_SELinux_Users::reset_variables
	# Set system users list
	set all_sysUsers_list [SEUser_db::get_list sysUsers]
	set sysUsers_list $all_sysUsers_list
	
	# SE Linux users
	set selinuxUsers_list [SEUser_db::get_list seUsers]
	set selinuxUsers_list [lsort $selinuxUsers_list]

	# Available Roles
	set allRoles_list [SEUser_db::get_list roles]
	set allRoles_list [lsort $allRoles_list]
	set availRoles_list $allRoles_list  
	
	# The following function checks for redundancy in lists
	SEUser_Top::check_list_for_redundancy "sysUsers_list" "selinuxUsers_list"
	SEUser_SELinux_Users::SetEditMode init
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::addUser
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::addUser { idx } {
	variable modified_user	
	variable listbox_sysUsers
	variable listbox_SeLinuxUsers
	variable selinuxUsers_list
	
	if { $idx == "" } {
		return
	}
	
	set modified_user [$listbox_sysUsers get $idx]
	if { $modified_user == "user_u" } {
		set answer [tk_messageBox -icon warning -type yesno \
			-title "Adding Special user_u user" -parent $SEUser_SELinux_Users::main_frame \
		 	-message \
		    "Warning: Adding the special user user_u will \n\
		    mean that any user not explicity defined to the \n\
		    policy can login with the roles and default \n\
		    contexts defined for user_u, and need not be \n\
		    explictly defined to the policy.\n\n\
		    Do you wish to continue?"]
		 switch -- $answer {
		 	yes {
		 		#continue on
		 	}
		 	no {
		 		return
		 	}
		}   	
	}
	
	# remove from system users
	$listbox_sysUsers delete $idx
	# and put in selinux users
	set selinuxUsers_list [lappend selinuxUsers_list $modified_user]
	set selinuxUsers_list [lsort $selinuxUsers_list]
	set newidx [lsearch -exact $selinuxUsers_list $modified_user]
	$listbox_SeLinuxUsers selection set $newidx
	$listbox_SeLinuxUsers see $newidx	
	SEUser_SELinux_Users::ClearCurrUserInfo 
	SEUser_SELinux_Users::SetEditMode add		
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::addRole
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::addRole { idx } {
	variable listbox_availRoles
	variable listbox_currentRoles	
	variable currentRoles_list 
	variable state
	
	if { $idx == "" } {
		return
	}
	
	# remove from avail roles
	set role [$listbox_availRoles get $idx]
	$listbox_availRoles delete $idx
	# and put in current roles
	set currentRoles_list [lappend currentRoles_list $role]
	set currentRoles_list [lsort $currentRoles_list]
	set newidx [lsearch -exact $currentRoles_list $role]
	$listbox_currentRoles selection set $newidx
	$listbox_currentRoles see $newidx
	set state(roles_changed) 1
	
	SEUser_SELinux_Users::SetEditMode change
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::removeRole
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::removeRole { idx } {
	variable listbox_availRoles
	variable listbox_currentRoles
	variable availRoles_list
	variable state
	
	if { $idx == "" } {
		return
	}
	
	# remove from cur roles
	set role [$listbox_currentRoles get $idx]
	$listbox_currentRoles delete $idx
	# and put in current roles
	set availRoles_list [lappend availRoles_list $role]
	set availRoles_list [lsort $availRoles_list]
	set newidx [lsearch -exact $availRoles_list $role]
	$listbox_availRoles selection set $newidx	
	$listbox_availRoles see $newidx
	set state(roles_changed) 1
	
	SEUser_SELinux_Users::SetEditMode change
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::ShowUserInfo
#
#  Description: Displays info for the selected SE Linux user.
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::ShowUserInfo  { username } {
	variable availRoles_list
	variable currentRoles_list
	variable allRoles_list	
	
	set no_login_context 0	

	set rt [catch { set currentRoles_list [seuser_UserRoles $username] } err]
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err" \
			-parent $SEUser_SELinux_Users::main_frame
		return 
	}
	set currentRoles_list [lsort $currentRoles_list]	
	
	set rt [catch {seuser_IsUserValid $username} err]
	if {$rt != 0} {	
		tk_messageBox -icon warning -type ok -title "Warning: Problem with user record" -message "$err" \
			-parent $SEUser_SELinux_Users::main_frame
	}
	
	# The following functions reset the available roles list and then checks for redundancy
	set allRoles_list [lsort $allRoles_list]
	set availRoles_list $allRoles_list    
	SEUser_Top::check_list_for_redundancy "availRoles_list" "currentRoles_list"
	
	return 0
}

# ----------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::commit
#
#  Description: Commits any changes to the db by first, committing the change to the 
#		im-memory database then, writes the db out to disk. Then sets the 
#		application to view mode. 
# ----------------------------------------------------------------------------------
proc SEUser_SELinux_Users::commit { } {
	variable modified_user
	variable state
	
	# first commit the change to the im-memory database
	if { $state(edit) != 1 } {
		tk_messageBox -icon warning -type ok -title "Warning" \
		    -message "There are no changes to commit!"	\
		    -parent $SEUser_SELinux_Users::main_frame
		return 
	}	
	
	# check for committ access
	set rt [ catch {seuser_CheckCommitAccess } err ]
	if {$rt != 0 } {
		tk_messageBox -icon error -type ok -title "Access Error" -message "$err" \
			-parent $SEUser_SELinux_Users::main_frame
		return 
	}   
	
	switch -- $state(edit_type) {
		delete {
		    set rt [catch {SEUser_db::remove_selinuxUser $modified_user} err]
		    if {$rt != 0} {	
			tk_messageBox -icon error -type ok -title "Error" -message "$err" \
				-parent $SEUser_SELinux_Users::main_frame
			return 
		    }			
		}
		add {
		    set rt [catch {SEUser_db::add_selinuxUser $modified_user $SEUser_SELinux_Users::currentRoles_list 0 \
		    			"" "" 0 "" ""} err]
		    if {$rt != 0} {	
		     	tk_messageBox -icon error -type ok -title "Error" -message "$err" \
		     		-parent $SEUser_SELinux_Users::main_frame
		    	return 
		    } 
		}
		change {
		    set rt [catch {SEUser_db::change_selinuxUser $modified_user $SEUser_SELinux_Users::currentRoles_list 0 \
		    			"" "" 0 "" ""} err]
		    if {$rt != 0} {	
		     	tk_messageBox -icon error -type ok -title "Error" -message "$err" \
		     		-parent $SEUser_SELinux_Users::main_frame
		    	return 
		    } 
		 
		    # Here is where we check to see if a changed user effects the user file 
		    # by changing the roles (rather than just the default contexts)
		    if {$state(roles_changed) != 0 } {
			set state(users_changed) [expr $state(users_changed) + 1]
			set state(roles_changed) 0
		    }
		}
		default {
		    tk_messageBox -icon warning -type ok -title "Warning" \
			-message "There are no changes to commit!" \
			-parent $SEUser_SELinux_Users::main_frame
		    return
		}
	}
	
	# then write the db out to disk
	set rt [catch {seuser_Commit} err]
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err" \
			-parent $SEUser_SELinux_Users::main_frame
		return 
	} 
	# reset state
	SEUser_SELinux_Users::SetEditMode commit
	SEUser_Top::initialize
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::cancel
#
#  Description: This procedure is associated with the "Cancel" button.
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::cancel { } {
	variable state
	
	if { $state(edit) != 1 } {
		return
	}	
	switch -- $state(edit_type) {
		delete {
		    SEUser_SELinux_Users::unremoveUser
		}
		add {
		    SEUser_SELinux_Users::unaddUser
		}
		change {
		    SEUser_SELinux_Users::unchangeUser
		}
		default {
		    return
		}
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::remove_SELinux_User
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::remove_SELinux_User { idx } {
	variable modified_user
	variable listbox_SeLinuxUsers
	variable listbox_sysUsers
	variable sysUsers_list
	variable all_sysUsers_list
	variable state
	
	# If nothing is selected, return
	if { $idx == "" } {
		return
	}
	# Get the selected user to be deleted. If is special system user, popup error message.
	set modified_user [$listbox_SeLinuxUsers get $idx]
	if { $modified_user == "system_u" } {	
		tk_messageBox -icon error -type ok -title "Remove User Error" -message \
		    "The special user: system_u cannot be removed." \
		    -parent $SEUser_SELinux_Users::main_frame
		return
	} elseif { $modified_user == "user_u" } {
		set answer [tk_messageBox -icon warning -type yesno -title "Removing Special user_u user" -message \
		    "Warning: Removing the special user user_u will \n\
		    mean that any user not explicity defined to the \n\
		    policy will not be able to login to the system.\n\n\
		    Do you wish to continue?" \
		    	-parent $SEUser_SELinux_Users::main_frame]
		switch -- $answer {
		 	yes {
		 		$listbox_SeLinuxUsers delete $idx
		 	}
		 	no {
		 		return
		 	}
		}
	} else {
		$listbox_SeLinuxUsers delete $idx
	}
	
	SEUser_SELinux_Users::ClearCurrUserInfo 
	# Insert name back into sysuser list (if it is indeed a sys user)
	if { [lsearch -exact $all_sysUsers_list "$modified_user"] != -1 } {
		set sysUsers_list [lappend sysUsers_list $modified_user]
		set sysUsers_list [lsort $sysUsers_list]
		set newidx [lsearch -exact $sysUsers_list $modified_user]
		$listbox_sysUsers selection set $newidx	
		$listbox_sysUsers see $newidx
	}
	
	set state(roles_changed) 1
	SEUser_SELinux_Users::SetEditMode delete
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::unaddUser
#
#  Description: This procedure is called by SEUser_SELinux_Users::cancel
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::unaddUser { } {
	variable modified_user	
	variable sysUsers_list
	variable selinuxUsers_list
	variable all_sysUsers_list
	variable state
	
	if { $state(edit_type) != "add" } {
		puts stderr "Cannot unadd a user because edit_type is $state(edit_type)"
		return
	}
	# NOTE: Since we're "unadding" we have to verify if the modified_user is a 
	#	valid system user, because this could be a cancel to adding a system
	#	user. 
	#
	# put back into system users
	if { [lsearch -exact $all_sysUsers_list $modified_user] != -1 } {
	    set sysUsers_list [lappend sysUsers_list $modified_user]
	    set sysUsers_list [lsort $sysUsers_list]
	    set newidx [lsearch -exact $sysUsers_list $modified_user]
	    $SEUser_SELinux_Users::listbox_sysUsers selection set $newidx	
	}
	
	# and remove from selinux users
	set idx [lsearch -exact $selinuxUsers_list $modified_user]
	$SEUser_SELinux_Users::listbox_SeLinuxUsers delete $idx	
	SEUser_SELinux_Users::ClearCurrUserInfo 
	SEUser_SELinux_Users::SetEditMode unadd
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::unchangeUser
#
#  Description: This procedure is called by SEUser_SELinux_Users::cancel
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::unchangeUser { } {	
	variable state
	
	if { $state(edit_type) != "change" } {
		puts stderr "Cannot unchange a user because edit_type is $state(edit_type)"
		return
	}
	SEUser_SELinux_Users::ClearCurrUserInfo 
	SEUser_SELinux_Users::SetEditMode unchange
	return 0
}

# -------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::edit_type_disable_enable 
#
#  Description: Makes procedure calls for the disabling/enabling of widgets based 
#		on the edit type.
# -------------------------------------------------------------------------------
proc SEUser_SELinux_Users::edit_type_disable_enable { } { 
    	variable state
    	
	switch $state(edit_type) {
		delete {
		    SEUser_SELinux_Users::delete_disable_enable
		}
		add {
		    SEUser_SELinux_Users::add_change_disable_enable
		}
		change {
		    SEUser_SELinux_Users::add_change_disable_enable
		}
		none {
		    SEUser_SELinux_Users::view_mode_enable_disable
		}
	} 
	
	return 0	
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::add_change_disable_enable
#
#  Description: Performs disabling/enabling of widgets during an edit of 
#		type "add" or "change"
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::add_change_disable_enable { } {
	variable state
	variable listbox_SeLinuxUsers
	variable listbox_sysUsers
	
	if { $state(edit) == 1 } {
		SEUser_Advanced::change_tab_state disabled
		$SEUser_SELinux_Users::u_add configure -state disabled 
		$SEUser_SELinux_Users::u_remove configure -state disabled 
		$SEUser_SELinux_Users::r_add configure -state normal
		$SEUser_SELinux_Users::r_remove configure -state normal
		SEUser_Advanced::change_buttons_state 1
		SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_availRoles
		SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_currentRoles		
		bind sysUsers_Tag <<ListboxSelect>> " "
		bind SeLinuxUsers_Tag <<ListboxSelect>> " "
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_SeLinuxUsers
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_sysUsers	
		$SEUser_SELinux_Users::listbox_availRoles configure -bg white
		$SEUser_SELinux_Users::listbox_currentRoles configure -bg white
	}  
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::delete_disable_enable
#
#  Description: Performs disabling/enabling of widgets during an edit of 
#		type "delete"
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::delete_disable_enable { } {
	variable state
	variable listbox_SeLinuxUsers
	variable listbox_sysUsers
	
	if { $state(edit) == 1 } {
		SEUser_Advanced::change_tab_state disabled
		$SEUser_SELinux_Users::u_add configure -state disabled 
		$SEUser_SELinux_Users::u_remove configure -state disabled 
		$SEUser_SELinux_Users::r_add configure -state disabled 
		$SEUser_SELinux_Users::r_remove configure -state disabled 
		SEUser_Advanced::change_buttons_state 1
		$SEUser_SELinux_Users::listbox_availRoles configure -bg $SEUser_Top::default_bg_color
		$SEUser_SELinux_Users::listbox_currentRoles configure -bg $SEUser_Top::default_bg_color
		bind sysUsers_Tag <<ListboxSelect>> " " 	
		bind SeLinuxUsers_Tag <<ListboxSelect>> " "
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_SeLinuxUsers
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_sysUsers		
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_availRoles
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_currentRoles
	} 
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::view_mode_enable_disable
#
#  Description: Performs disabling/enabling of widgets during view mode
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::view_mode_enable_disable { } {
	variable state
	
	if { $state(edit) == 0 } {		
		$SEUser_SELinux_Users::u_add configure -state normal
		$SEUser_SELinux_Users::u_remove configure -state normal
		$SEUser_SELinux_Users::r_add configure -state disabled 
		$SEUser_SELinux_Users::r_remove configure -state disabled 		
		SEUser_Advanced::change_buttons_state 0
		$SEUser_SELinux_Users::listbox_SeLinuxUsers selection clear 0 end
		$SEUser_SELinux_Users::listbox_sysUsers selection clear 0 end
		$SEUser_SELinux_Users::listbox_availRoles selection clear 0 end
		$SEUser_SELinux_Users::listbox_currentRoles selection clear 0 end
		
		bind SeLinuxUsers_Tag <<ListboxSelect>> { SEUser_SELinux_Users::SeLinuxUsers_Selection %W %x %y } 
		bind sysUsers_Tag <<ListboxSelect>> { SEUser_SELinux_Users::sysUsers_Selection %W %x %y }
		SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_SeLinuxUsers
		SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_sysUsers
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_availRoles
		SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_currentRoles
		$SEUser_SELinux_Users::listbox_availRoles configure -bg $SEUser_Top::default_bg_color
		$SEUser_SELinux_Users::listbox_currentRoles configure -bg $SEUser_Top::default_bg_color
		SEUser_Advanced::change_tab_state normal
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::SeLinuxUsers_Selection
#
#  Description: This procedure is binded to SEUser_SELinux_Users::listbox_SeLinuxUsers and is 
#		typically invoked on button-1 presses. It begins the process of 
#		making a selection in the listbox and performs "enabling" of
#		Roles and Default Contexts widgets and their bindings.
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::SeLinuxUsers_Selection { path x y } {
	SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_SeLinuxUsers
	$SEUser_SELinux_Users::listbox_sysUsers selection clear 0 end
	$SEUser_SELinux_Users::listbox_availRoles selection clear 0 end
	$SEUser_SELinux_Users::listbox_currentRoles selection clear 0 end
	set user [$path get [$path curselection ]]
	SEUser_SELinux_Users::ShowUserInfo $user 
	set SEUser_SELinux_Users::user_to_del $user
	
	$SEUser_SELinux_Users::r_add configure -state normal
	$SEUser_SELinux_Users::r_remove configure -state normal
	SEUser_Advanced::change_buttons_state 0
	SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_availRoles
	SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_currentRoles  
	$SEUser_SELinux_Users::listbox_availRoles configure -bg white
	$SEUser_SELinux_Users::listbox_currentRoles configure -bg white	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::sysUsers_Selection
#
#  Description: This procedure is binded to SEUser_SELinux_Users::listbox_sysUsers and is 
#		typically invoked on button-1 presses. It begins the process of 
#		making a selection in the listbox and performs "disabling" of
#		Roles and Default Contexts widgets and their bindings.
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::sysUsers_Selection { path x y } {	
	# This procedure is typically invoked on button-1 presses.  It begins
	# the process of making a selection in the listbox. 
	SEUser_Top::enable_tkListbox $SEUser_SELinux_Users::listbox_sysUsers
	$SEUser_SELinux_Users::listbox_SeLinuxUsers selection clear 0 end
	SEUser_SELinux_Users::ClearCurrUserInfo
	set user [$path get [$path curselection ]]
	set SEUser_SELinux_Users::user_to_del $user
		
	$SEUser_SELinux_Users::r_add configure -state disabled
	$SEUser_SELinux_Users::r_remove configure -state disabled
	SEUser_Advanced::change_buttons_state 0
	
	SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_availRoles
	SEUser_Top::disable_tkListbox $SEUser_SELinux_Users::listbox_currentRoles
	$SEUser_SELinux_Users::listbox_availRoles configure -bg $SEUser_Top::default_bg_color
	$SEUser_SELinux_Users::listbox_currentRoles configure -bg $SEUser_Top::default_bg_color
	
    	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::ClearCurrUserInfo
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::ClearCurrUserInfo { } {
	set SEUser_SELinux_Users::currentRoles_list ""
	set SEUser_SELinux_Users::user_to_add	""
	set SEUser_SELinux_Users::user_to_del 	""
	# reset the avail role list to the whole list   
	set SEUser_SELinux_Users::allRoles_list [lsort $SEUser_SELinux_Users::allRoles_list]
	set SEUser_SELinux_Users::availRoles_list $SEUser_SELinux_Users::allRoles_list  
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::ClearView
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::ClearView { } {	
	SEUser_SELinux_Users::ClearCurrUserInfo
	set SEUser_SELinux_Users::sysUsers_list ""
	set SEUser_SELinux_Users::selinuxUsers_list ""
	set SEUser_SELinux_Users::availRoles_list ""
	return 0
}

# ----------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::CheckSeUserHighlights
#
#  Description: Performs highlighting in the selinuxUsers_list. If the selinux_User 
#		is not a valid SE Linux User .. highlight red. If selinux_User is 
#		not a valid system user ... highlight yellow. Ignore the special
#		special user "system_u" and "user_u"
# ----------------------------------------------------------------------------------
proc SEUser_SELinux_Users::CheckSeUserHighlights { } {
	variable all_sysUsers_list
	variable listbox_SeLinuxUsers
	variable selinuxUsers_list
	
	# First, clear all highlights
	foreach user $selinuxUsers_list {		
	    set index [lsearch -exact $selinuxUsers_list "$user"]
	    $listbox_SeLinuxUsers itemconfigure $index -background ""
	}
	# Then perform highlighting
	foreach user $selinuxUsers_list {
		set rt [catch {seuser_IsUserValid $user} err]
		# If is not a valid SE Linux User .. highlight red
		if {$rt != 0 } {
		    set index [lsearch -exact $selinuxUsers_list "$user"]
		    $listbox_SeLinuxUsers itemconfigure $index -background red
		    continue
		} elseif {$user == "system_u"} {
		    continue
		} elseif {$user == "user_u" } {
		    continue
		} else {		
		    set index [lsearch -exact $selinuxUsers_list "$user"]
		    $listbox_SeLinuxUsers itemconfigure $index -background ""
		}
		# If selinux_User is not a valid system user ... highlight yellow 
		if { [lsearch -exact $all_sysUsers_list "$user"] == -1 } {
		    # Find the index of the selinux_User and change the background color
		    set index [lsearch -exact $selinuxUsers_list "$user"]
		    $listbox_SeLinuxUsers itemconfigure $index -background yellow
		} 
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::PopulateTypeContextList
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::PopulateTypeContextList { role combo } {
	variable empty_string
	variable type_list
	
	set type_list ""
	if {$role != $empty_string } {
	set rt [catch { set type_list [apol_RoleTypes $role] } err]
		if {$rt != 0} {	
		    # We don't want to pop an error, just provide no types in the lsit
		    # tk_messageBox -icon error -type ok -title "Error" -message "$err"
		    set type_list ""
		} else {
		    set type_list [lsort $type_list]
		}
	}
	$combo configure -values $type_list	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::PopulateRoleContextList
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::PopulateRoleContextList { combo } {
	variable currentRoles_list
	$combo configure -values $currentRoles_list
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::unremoveUser
#
#  Description: This procedure is called by SEUser_SELinux_Users::cancel
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::unremoveUser { } {
	variable modified_user
	variable selinuxUsers_list
	variable sysUsers_list
	variable all_sysUsers_list
	variable listbox_SeLinuxUsers
	variable listbox_sysUsers
	variable state
	
	if { $state(edit_type) != "delete" } {
		puts stderr "Cannot unremove a user because edit_type is $state(edit_type)"
		return
	}
	# Find the index of the selinux_User in the sysUsers listbox and delete it. 
	set index [lsearch -exact $sysUsers_list "$modified_user"]
	$listbox_sysUsers delete $index  
	# Re-append the deleted selinux user to the selinuxUsers list.
	set selinuxUsers_list [lappend selinuxUsers_list $modified_user]
	set selinuxUsers_list [lsort $selinuxUsers_list]
	# The following function checks for redundancy in lists
	SEUser_Top::check_list_for_redundancy "sysUsers_list" "selinuxUsers_list"
	$listbox_sysUsers selection clear 0 end
	SEUser_SELinux_Users::SetEditMode undelete
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::reset_variables
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::reset_variables { } {
	# List variables
	set SEUser_SELinux_Users::sysUsers_list 	""
	set SEUser_SELinux_Users::selinuxUsers_list 	""      
	set SEUser_SELinux_Users::currentRoles_list 	""
	set SEUser_SELinux_Users::type_list		""
	set SEUser_SELinux_Users::availRoles_list 	""
	set SEUser_SELinux_Users::allRoles_list 	""
	set SEUser_SELinux_Users::all_sysUsers_list 	""
	# Other vars
	set SEUser_SELinux_Users::user_to_add		""
	set SEUser_SELinux_Users::user_to_del		""
	set SEUser_SELinux_Users::modified_user 	"none"
	set SEUser_SELinux_Users::empty_string 		"<none>"
	set SEUser_SELinux_Users::state(edit) 		0
	set SEUser_SELinux_Users::state(users_changed) 	0
	set SEUser_SELinux_Users::state(edit_type) 	"none"
	set SEUser_SELinux_Users::state(roles_changed) 	0
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::close
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::close { } {
	# List variables
	set SEUser_SELinux_Users::sysUsers_list 	""
	set SEUser_SELinux_Users::selinuxUsers_list 	""      
	set SEUser_SELinux_Users::currentRoles_list 	""
	set SEUser_SELinux_Users::type_list		""
	set SEUser_SELinux_Users::availRoles_list 	""
	set SEUser_SELinux_Users::allRoles_list 	""
	set SEUser_SELinux_Users::all_sysUsers_list 	""
	# Other vars
	set SEUser_SELinux_Users::user_to_add	""
	set SEUser_SELinux_Users::user_to_del	""
	set SEUser_SELinux_Users::modified_user ""
	set SEUser_SELinux_Users::empty_string 	""
	# array variables
	array unset SEUser_SELinux_Users::state
	array unset SEUser_SELinux_Users::opts
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::update_changes
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::enter_tab { } {
	variable mcntr
	
	if { [SEUser_db::get_mod_cntr] != $mcntr } {
		SEUser_SELinux_Users::initialize 
	}
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::leave_tab
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::leave_tab { } {
	variable mcntr
	set mcntr [SEUser_db::get_mod_cntr]
	return 0
}  

# -------------------------------------------------------------
#  Command SEUser_SELinux_Users::create_UserPolicyMgnt_Tab
# -------------------------------------------------------------
proc SEUser_SELinux_Users::create_UserPolicyMgnt_Tab { notebook } {
	variable main_frame
	
	# Layout frames
	set main_frame [$notebook insert end $SEUser_Advanced::usr_polMgnt_tabID -text "SE Linux Users"]
	set topf  [frame $main_frame.topf -width 100 -height 200]
	set lb_desc [label $topf.lb_desc -text "This tab allows you to directly add/remove \
		users from the policy\nwithout adding/removing users from the system." \
		-justify left]
	pack $topf -side top -fill both  
	pack $lb_desc -side top -fill x -expand yes -anchor nw -pady 4
	
	SEUser_SELinux_Users::createUsersFrame $topf
	SEUser_SELinux_Users::createRolesFrame $topf
	return 0
}    

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::createUsersFrame
#
#  Description: This procedure is called by SEUser_SELinux_Users::createMainFrame
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::createUsersFrame { mainframe } {
	variable listbox_SeLinuxUsers
	variable listbox_sysUsers
	variable u_add
	variable u_remove
	
	# Frames
	set user_f [TitleFrame $mainframe.user_f -text "Users"]
	set lf [LabelFrame [$user_f getframe].lf -relief flat -borderwidth 0]
	set cf [frame [$user_f getframe].cf -relief flat -borderwidth 0]
	set rf [LabelFrame [$user_f getframe].rf -relief flat -borderwidth 0]
	set lf_inner_top [frame [$lf getframe].in_top]
	set lf_inner_bot [ScrolledWindow [$lf getframe].in_bot]
	set rf_inner_top [frame [$rf getframe].in_top]
	set rf_inner_bot [ScrolledWindow [$rf getframe].in_bot]
		
	# Labels
	set lb_sysUsers   [Label $lf_inner_top.lb_sysUsers -text "System Users"]
	set lb_linuxUsers [Label $rf_inner_top.lb_linuxUsers -text "SE Linux Users"]
	
	# List Boxes
	set listbox_sysUsers   [listbox [$lf_inner_bot getframe].listbox_sysUsers -height 6 -width 20 \
				-highlightthickness 0 \
				-listvar SEUser_SELinux_Users::sysUsers_list -bg white \
				-selectmode single] 
	set listbox_SeLinuxUsers [listbox [$rf_inner_bot getframe].listbox_SeLinuxUsers -height 6 \
				  -width 20 -highlightthickness 0 \
				  -listvar SEUser_SELinux_Users::selinuxUsers_list \
				  -exportselection no -bg white -selectmode single]  
	$lf_inner_bot setwidget $listbox_sysUsers				  
	$rf_inner_bot setwidget $listbox_SeLinuxUsers
	
	# Action Buttons
	set u_add [Button $cf.add -text "-->" -width 6 \
		   -command { SEUser_SELinux_Users::addUser  [$SEUser_SELinux_Users::listbox_sysUsers curselection]} \
		   -helptext "Add the selected system user to SE Linunx policy"]
	set u_remove [Button $cf.remove -text "<--" -width 6 -command \
		      { SEUser_SELinux_Users::remove_SELinux_User [$SEUser_SELinux_Users::listbox_SeLinuxUsers curselection]} \
		      -helptext "Remove the selected user from the SE Linux policy"]
	
	# Bindings 
	bindtags $listbox_SeLinuxUsers [linsert [bindtags $listbox_SeLinuxUsers] 3 SeLinuxUsers_Tag]
	bindtags $listbox_sysUsers [linsert [bindtags $listbox_sysUsers] 3 sysUsers_Tag]
		
	# Placing widgets
	pack $user_f -side top -fill both -anchor n -expand yes -padx 5 -pady 2
	pack $lf -side left -anchor w -expand yes
	pack $lf_inner_top -side top -anchor n -fill x
	pack $lf_inner_bot -side bottom -anchor s -fill x -expand yes
	pack $cf -side left -anchor center -expand yes
	pack $rf -side right -anchor e -expand yes
	pack $rf_inner_top -side top -anchor n -fill x
	pack $rf_inner_bot -side bottom -anchor s -fill x -expand yes
	pack $lb_sysUsers -side top 
	pack $u_add $u_remove -side top -anchor center -pady 5 -padx 5
	pack $lb_linuxUsers -side top -fill y -expand yes
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_SELinux_Users::createRolesFrame
#
#  Description: This procedure is called by SEUser_SELinux_Users::createMainFrame
# ------------------------------------------------------------------------------
proc SEUser_SELinux_Users::createRolesFrame { mainframe } {
	variable listbox_availRoles
	variable listbox_currentRoles
	variable r_add
	variable r_remove
	
	# Frames 
	set roles_f [TitleFrame $mainframe.roles_f -text "Roles"]
	set lf [LabelFrame [$roles_f getframe].lf -relief flat -borderwidth 0]
	set cf [frame [$roles_f getframe].cf -relief flat -borderwidth 0]
	set rf [LabelFrame [$roles_f getframe].rf -relief flat -borderwidth 0]
	set lf_inner_top [frame [$lf getframe].in_top]
	set lf_inner_bot [ScrolledWindow [$lf getframe].in_bot]
	set rf_inner_top [frame [$rf getframe].in_top]
	set rf_inner_bot [ScrolledWindow [$rf getframe].in_bot]  
	
	# Labels
	set lb_availRoles   [Label $lf_inner_top.lb_availRoles -text "Available Roles"]
	set lb_currentRoles [Label $rf_inner_top.lb_currentRoles -text "Assigned Roles"]
	
	# Listboxes
	set listbox_availRoles   [listbox [$lf_inner_bot getframe].listbox_availRoles -height 6 -width 20 -highlightthickness 0 \
				  -listvar SEUser_SELinux_Users::availRoles_list -bg white] 	
	set listbox_currentRoles [listbox [$rf_inner_bot getframe].listbox_SeLinuxUsers -height 6 -width 20 -highlightthickness 0 \
				  -listvar SEUser_SELinux_Users::currentRoles_list -bg white]  		  
	$lf_inner_bot setwidget $listbox_availRoles				        
	$rf_inner_bot setwidget $listbox_currentRoles
	
	# Buttons					       
	set r_add    [Button $cf.add -text "-->" -width 6 \
		      -command { SEUser_SELinux_Users::addRole [$SEUser_SELinux_Users::listbox_availRoles curselection]} \
		      -helptext "Add a new role to the user account"]
	set r_remove [Button $cf.remove -text "<--" -width 6 \
		      -command { SEUser_SELinux_Users::removeRole [$SEUser_SELinux_Users::listbox_currentRoles curselection]} \
		      -helptext "Remove a role from the user account"]
	
	# Bindings
	bindtags $listbox_currentRoles [linsert [bindtags $listbox_currentRoles] 3 currentRoles_Tag]
	bindtags $listbox_availRoles [linsert [bindtags $listbox_availRoles] 3 availRoles_Tag]
	
	pack $roles_f -side top -fill both -expand yes -padx 5 -pady 2
	pack $lf -side left -anchor w -expand yes 
	pack $lf_inner_top -side top -anchor n -fill x
	pack $lf_inner_bot -side bottom -anchor s -fill x -expand yes
	pack $cf -side left -anchor center -expand yes
	pack $rf -side right -anchor e -expand yes
	pack $rf_inner_top -side top -anchor n -fill x
	pack $rf_inner_bot -side bottom -anchor s -fill x -expand yes 				       
	pack $lb_availRoles -side top 
	pack $r_add $r_remove -side top -anchor center -pady 5 -padx 5
	pack $lb_currentRoles -side top -fill y -expand yes
	
	return 0
}

