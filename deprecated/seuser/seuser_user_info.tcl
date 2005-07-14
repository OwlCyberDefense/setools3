#############################################################
#  seuser_userInfo.tcl

# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#

##############################################################
# ::SEUser_UserInfo
#  
# This namespace creates and configures the dialog to add/change 
# a user on the selinux system.
##############################################################
namespace eval SEUser_UserInfo {
	#################
	# Global Widgets
	variable notebook
	# Top-level dialogs
	variable userInfoDlg
	set userInfoDlg .userInfoDlg
	# Listboxes
	variable listbox_availRoles
	variable listbox_assignedRoles
	variable listbox_availableGroups
	variable listbox_assignedGroups
	# Buttons
	variable g_add
	variable g_remove
	variable r_add
	variable r_remove
	variable b_add_change
	variable b_cancel
	variable b_exit
	# Radiobuttons
	variable r_defined
	variable r_generic
	# Checkbuttons
	variable cb_newGroup
	# Entry/Combo Boxes
	variable entry_userName
	variable entry_comment
	variable combo_initGroup
	# Labels
	variable usr_type_lbl
	variable lb_assignGroups
	
	###########################
	# Miscellaneous 
	variable user_info_tabID	"UserInfoTab"
	variable adv_opts_tabID		"AdvancedOptsTab"
	# User types 
	variable special_usr_type	"Special"
	variable generic_usr_type	"Generic"
	variable def_user_type		"Defined"
	variable undef_user_type	"Undefined"
	
	###########################
	# Add/Change user variables
	# NOTE: Somehow need to get any default options from the system.
	variable useradd_args 
	set useradd_args(create_new_userGroup)		1
	set useradd_args(create_systemAcct)		0
	set useradd_args(do_not_create_home_dir)	0
	set useradd_args(initGroup)		""
	set useradd_args(comment)		""
	set useradd_args(uid)			""
	set useradd_args(passwd)		""
	set useradd_args(passwd_expDays)	""
	set useradd_args(account_expDate)	""
	set useradd_args(login_shell)		""
	set useradd_args(home_dir)		""
	variable passwd_confirm			""
	variable usr_type		""
	variable usr_type_sel		Defined
	variable curr_policy_type	""
	variable usr_name		""
	variable current_user		""
	variable mode 			""
	variable generic_user		"user_u"
	
	# Global list variables 
	# - NOTE: When changing these variable names, do not forget to change argument
	#	  names accordingly for calls to SEUser_Top::check_list_for_redundancy.
	#	  This is because calls to SEUser_Top::check_list_for_redundancy use 
	#	  these names explicitly as arguments to simulate call-by-reference.
	# 
	variable availGroups_list	""
	variable assignedGroups_list	""
	variable availRoles_list	""
	variable assignedRoles_list	""
	variable allGroups_list		""
	variable allRoles_list		""
	
	# state variables
	variable state
	set state(edit) 		0
	set state(edit_type) 		"none"
	set state(users_changed) 	0
	
	variable policy_changes_flag	0
	# Set up a trace on the policy_changes_flag variable in order to monitor 
	# changes to this variable, which would indicate changes to the policy.
	SEUser_Top::set_trace_on_var "SEUser_UserInfo" "policy_changes_flag"
}

############################
# Event Handling functions #
############################

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo:change_user
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::change_user { } {	
	variable assignedGroups_list		
	variable assignedRoles_list	
	variable usr_name		
	variable useradd_args	
	variable state
	
	if { $state(edit_type) != "change" } {
		return
	}
		
	set command_args ""
	set generic_flag 0
	
	# Comment data
	lappend command_args "-c"
	lappend command_args "$useradd_args(comment)"
	# Want to set comment argument as a string, so enclose with quotes
	set command_args [lreplace $command_args 1 1 "[lindex $command_args 1]"]
	
	# Groups data
	lappend command_args "-g"
	lappend command_args "$useradd_args(initGroup)"
	lappend command_args "-G"
	set groups_str ""
	foreach group $assignedGroups_list {
		append groups_str "$group,"
	}
	if { $groups_str != "" } {
		set groups_str [string trimright $groups_str ","]
	}
	lappend command_args "$groups_str"
	
	if { $SEUser_UserInfo::usr_type == "Generic" } {
		set generic_flag 1
	} elseif { $SEUser_UserInfo::usr_type == "Defined" || $SEUser_UserInfo::usr_type == "Special"} {
		if { $assignedRoles_list == "" } {
			tk_messageBox -icon error -type ok -parent $SEUser_UserInfo::userInfoDlg \
			    	-title "Error" -message "Users must have at least one role defined for them."
			return -1
		}
		set generic_flag 0
	} else {
		# This is an undefined user.
		set generic_flag 1
	}
			
	set rt [catch {SEUser_db::change_user $usr_name $generic_flag $assignedRoles_list $command_args } err] 
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $SEUser_UserInfo::userInfoDlg
		return -1
	} 
	SEUser_Top::initialize
	SEUser_UserInfo::set_UserInfo $usr_name
		
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo:add_user
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::add_user { } {		
	variable assignedGroups_list		
	variable assignedRoles_list			
	variable usr_type_sel		
	variable usr_name		
	variable useradd_args	
		
	if { $usr_name == "" } {
		tk_messageBox -icon error -type ok -parent $SEUser_UserInfo::userInfoDlg \
		    	-title "Error" -message "Must provide a user name."
		return -1
	}
	if { [SEUser_db::is_system_user $usr_name] } {
		tk_messageBox -icon error -type ok -parent $SEUser_UserInfo::userInfoDlg \
			-title "Error" -message "User: $usr_name already exists on the system\
			and will not be added. Select the user from\
			the system users list to make changes."
		return -1
	} 
	if { ![SEUser_UserInfo::confirm_password] } {
		tk_messageBox -icon error -type ok -parent $SEUser_UserInfo::userInfoDlg \
		    	-title "Error" -message "Passwords do not match."
		return -1
	}
			
	set command_args ""
	if { $useradd_args(comment) != "" } {
		lappend command_args "-c"
		lappend command_args "$useradd_args(comment)"
		# Want to set comment argument as a string, so enclose with quotes
		set command_args [lreplace $command_args end end "[lindex $command_args end]"]
	}
	if { $useradd_args(home_dir) != "" } {
		lappend command_args "-d"
		lappend command_args "$useradd_args(home_dir)"
	} 
	if { $useradd_args(account_expDate) != "" } {
		lappend command_args "-e"
		lappend command_args "$useradd_args(account_expDate)"
	}
	if { $useradd_args(passwd_expDays) != "" } {
		lappend command_args "-f"
		lappend command_args "$useradd_args(passwd_expDays)"
	}
	# If the initial group exists and the user has "Create new group" selected 
	# then we don't need to create new group
	set init_group_idx [lsearch -exact $SEUser_UserInfo::allGroups_list $useradd_args(initGroup)]
	if { $useradd_args(initGroup) != "" && $useradd_args(create_new_userGroup) == 0 } {
		lappend command_args "-g"
		lappend command_args "$useradd_args(initGroup)"
	} elseif { $useradd_args(initGroup) != "" && $useradd_args(create_new_userGroup) == 1 && \
		$init_group_idx != -1 } {
		lappend command_args "-g"
		lappend command_args "$useradd_args(initGroup)"
	}
	if { $assignedGroups_list != "" } {
		lappend command_args "-G"
		foreach group $assignedGroups_list {
			append groups_str "$group,"
		}
		set groups_str [string trimright $groups_str ","]
		lappend command_args "$groups_str"
	}
	if { $useradd_args(do_not_create_home_dir) } {
		lappend command_args "-M"
	} else {
		lappend command_args "-m"
	}
	if { $useradd_args(login_shell) != "" } {
		lappend command_args "-s"
		lappend command_args "$useradd_args(login_shell)"
	}
	if { $useradd_args(uid) != "" } {
		lappend command_args "-u"
		lappend command_args "$useradd_args(uid)"
	}
	if { $useradd_args(create_new_userGroup) == 1 && $init_group_idx != -1 } {
		lappend command_args "-n"
	} elseif { $useradd_args(create_new_userGroup) == 0 } {
		lappend command_args "-n"
	}
	if { $useradd_args(create_systemAcct) } {
		lappend command_args "-r"
	}
	
	if { $usr_type_sel == "Generic" } {
		set generic_flag 1
	} elseif { $usr_type_sel == "Defined" } {
		if { $assignedRoles_list == "" } {
			tk_messageBox -icon error -type ok -parent $SEUser_UserInfo::userInfoDlg \
			    	-title "Error" -message "Users must have at least one role defined for them."
			return -1
		}
		set generic_flag 0
	} else { 
		# This is an undefined user.
		set generic_flag 1
	}
	
	set overwrite_policy 0
	# The user existing in the policy at this point means that the policy file is out of sync
	# with the system. Give the user the option to overwrite the existing policy user with new
	# role information or leave it alone.
	if { [SEUser_db::is_selinux_user $usr_name] } {
		set ans [tk_messageBox -icon warning -type yesnocancel -parent $SEUser_UserInfo::userInfoDlg \
				-title "Existing user" -message "User: $usr_name already exists in the policy. Do you wish to overwrite\
				the current roles for $usr_name."]
		switch -- $ans {
			yes {
				set overwrite_policy 1
			}
			cancel {
				return 
			}
			no { }
			default { return -code error }
		}
	}
	
	set rt [catch {SEUser_db::add_user $usr_name $generic_flag $assignedRoles_list $command_args $useradd_args(passwd) $overwrite_policy} err] 
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $SEUser_UserInfo::userInfoDlg
		return -1
	} 
	# Re-initialize the application and its state.
	SEUser_Top::initialize
	# Now select the newly added user in the listbox. 
	SEUser_Top::select_added_user $usr_name
	# Reset the the initial state for the add dialog.
	SEUser_UserInfo::set_to_initial_add_state
	raise $SEUser_UserInfo::userInfoDlg
	focus -force $SEUser_UserInfo::entry_userName
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::add_Role
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::add_Role { idx } {
	variable listbox_availRoles
	variable listbox_assignedRoles
	variable availRoles_list	
	variable assignedRoles_list	
	
	if { $idx == "" } {
		return
	}
	
	# remove from avail roles list
	set role [$listbox_availRoles get $idx]
	set idx  [lsearch -exact $availRoles_list $role]
	set availRoles_list [lreplace $availRoles_list $idx $idx]
	# put in current roles
	set assignedRoles_list [lappend assignedRoles_list $role]
	set assignedRoles_list [lsort $assignedRoles_list]
	set new_idx [lsearch -exact $assignedRoles_list $role]
	# Clear the selection in the listbox and then set the new selection.
	$listbox_availRoles selection clear 0 end
	$listbox_assignedRoles selection set $new_idx
	# Force the selected item to be shown in the listbox. 
	$listbox_assignedRoles see $new_idx
	SEUser_UserInfo::SetEditMode change	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::remove_Role
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::remove_Role { idx } {
	variable listbox_availRoles
	variable listbox_assignedRoles
	variable availRoles_list	
	variable assignedRoles_list
	
	if { $idx == "" } {
		return
	}
	
	# remove from user_u's current roles
	set role [$listbox_assignedRoles get $idx]
	set idx  [lsearch -exact $assignedRoles_list $role]
	set assignedRoles_list [lreplace $assignedRoles_list $idx $idx]
	# and put in available roles list
	set availRoles_list [lappend availRoles_list $role]
	set availRoles_list [lsort $availRoles_list]  
	set assignedRoles_list [lsort $assignedRoles_list]  
	set new_idx [lsearch -exact $availRoles_list $role]
	# Clear the selection and then set the new selection. 
	$listbox_assignedRoles selection clear 0 end 
	$listbox_availRoles selection set $new_idx
	# Forece the selected item to be shown in the listbox.
	$listbox_availRoles see $new_idx
	SEUser_UserInfo::SetEditMode change
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::add_Group
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::add_Group { idx } {
	variable listbox_assignedGroups
	variable listbox_availableGroups
	variable availGroups_list	
	variable assignedGroups_list	
	
	if { $idx == "" } {
		return
	}
	
	# remove from avail groups list
	set group [$listbox_availableGroups get $idx]
	set idx  [lsearch -exact $availGroups_list $group]
	set availGroups_list [lreplace $availGroups_list $idx $idx]
	# put in assigned groups list
	set assignedGroups_list [lappend assignedGroups_list $group]
	set assignedGroups_list [lsort $assignedGroups_list]
	set new_idx [lsearch -exact $assignedGroups_list $group]
	# Clear the selection and then set the new selection.
	$listbox_availableGroups selection clear 0 end
	$listbox_assignedGroups selection set $new_idx
	# Force the selected item to be shown in the listbox. 
	$listbox_assignedGroups see $new_idx
	SEUser_UserInfo::SetEditMode change
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::remove_Group
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::remove_Group { idx } {
	variable listbox_assignedGroups
	variable listbox_availableGroups
	variable availGroups_list	
	variable assignedGroups_list	
	
	if { $idx == "" } {
		return
	}
	
	# remove from user_u's current roles
	set group [$listbox_assignedGroups get $idx]
	set idx  [lsearch -exact $assignedGroups_list $group]
	set assignedGroups_list [lreplace $assignedGroups_list $idx $idx]
	# and put in available roles list
	set availGroups_list [lappend availGroups_list $group]
	set availGroups_list [lsort $availGroups_list]	
	set assignedGroups_list [lsort $assignedGroups_list]	
	set new_idx [lsearch -exact $availGroups_list $group]
	# Clear the selection and then set the new selection 
	$listbox_assignedGroups selection clear 0 end
	$listbox_availableGroups selection set $new_idx
	# Force the selected item to be shown in the listbox.
	$listbox_availableGroups see $new_idx
	SEUser_UserInfo::SetEditMode change
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo:exit_userInfoDlg
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::exit_userInfoDlg { } {	
	variable policy_changes_flag
	if { $SEUser_UserInfo::state(users_changed) > 0 }  {
		set policy_changes_flag 1
	}
	destroy $SEUser_UserInfo::userInfoDlg
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::change_init_group
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::change_init_group { } {	
	variable combo_initGroup
	
	# clear the selection and set the edit mode 
	selection clear -displayof $combo_initGroup
	SEUser_UserInfo::SetEditMode change
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::cancel
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::cancel { } {
	variable state
	variable userInfoDlg
	
	if { $state(edit) != 1 } {
		return
	}	
	switch -- $state(edit_type) {
		add {
		    SEUser_UserInfo::unadd
		}
		change {
		    SEUser_UserInfo::unchange
		}
		default {
		    return -code error
		}
	}	
	raise $userInfoDlg
	focus -force $SEUser_UserInfo::entry_userName
	return 0
}

# ----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::commit
#
#  Description:
# ----------------------------------------------------------------------------------
proc SEUser_UserInfo::commit { } {
	variable state
	variable userInfoDlg
	
	if { $state(edit) != 1 } {
		tk_messageBox -icon info -type ok -title "Commit Info" \
		    -message "There are no changes to commit!"	\
		    -parent $SEUser_UserInfo::userInfoDlg
		return 
	}
	
	switch -- $state(edit_type) {
		add {
			set rt [SEUser_UserInfo::add_user]
		}
		change {
			set rt [SEUser_UserInfo::change_user]
		}
		default {
			return -code error
		}
	}	
	if { $rt != 0 } {
		return -1
	}
	# reset state
	SEUser_UserInfo::SetEditMode commit
	raise $userInfoDlg
	focus -force $SEUser_UserInfo::entry_userName
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::change_homeDir_state
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::change_homeDir_state { entry_box } {
	if { $SEUser_UserInfo::useradd_args(do_not_create_home_dir) } {
		$entry_box configure -state disabled -bg $SEUser_Top::default_bg_color
	} else {
		$entry_box configure -state normal -bg white
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::create_new_user_group
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::create_new_user_group { } {
	variable combo_initGroup
	
	selection clear -displayof $combo_initGroup
	set user [$SEUser_UserInfo::entry_userName cget -text]
	$SEUser_UserInfo::combo_initGroup configure -state disabled
	set SEUser_UserInfo::useradd_args(initGroup) $user
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::change_init_group_state
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::change_init_group_state { } {
	if { $SEUser_UserInfo::useradd_args(create_new_userGroup) } {
		$SEUser_UserInfo::combo_initGroup configure -state disabled -entrybg $SEUser_Top::default_bg_color
		bind UserName_Entry_Tag <KeyPress> { SEUser_UserInfo::create_new_user_group }
		SEUser_UserInfo::create_new_user_group
	} else {
		$SEUser_UserInfo::combo_initGroup configure -state normal -entrybg white 
		set SEUser_UserInfo::useradd_args(initGroup) ""
		bind UserName_Entry_Tag <KeyPress> " "
	}
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::configure_on_type_sel
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::configure_on_type_sel { } {
	variable userInfoDlg
	variable curr_policy_type
	variable mode
	
	# Return if this is the same radiobutton already selected. 
	if { $curr_policy_type == $SEUser_UserInfo::usr_type_sel } {
		return 
	}	
	# Re-enable all widgets and then disable accordingly
	SEUser_UserInfo::enable_default_tab_widgets
	selection clear -displayof $userInfoDlg
	# Reset role information to initial state.
	set SEUser_UserInfo::availRoles_list $SEUser_UserInfo::allRoles_list
	set SEUser_UserInfo::assignedRoles_list ""
	switch $SEUser_UserInfo::usr_type_sel {
		Defined {
			set SEUser_UserInfo::usr_type $SEUser_UserInfo::def_user_type
		} 
		Generic {
			set SEUser_UserInfo::usr_type $SEUser_UserInfo::generic_usr_type
			SEUser_UserInfo::disable_role_widgets
			SEUser_UserInfo::set_role_info $SEUser_UserInfo::generic_user
		} 
		Undefined {
			set SEUser_UserInfo::usr_type $SEUser_db::undef_user_type
			SEUser_UserInfo::disable_role_widgets
		} 
		default {
			return -code error
		} 
	}
	
	if { $mode == "add" } {
		SEUser_UserInfo::change_init_group_state
	} 
	
	# Set the currently selected type to be the previous type
	set curr_policy_type $SEUser_UserInfo::usr_type_sel
	SEUser_UserInfo::SetEditMode change
	return 0
}

############################
# Worker functions 	   #
############################

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::populate_initGroups_list
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::populate_initGroups_list { combo group_list } {
	update idletasks
	$combo configure -values $group_list
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::reset_option_variables
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::reset_option_variables { } {
	set SEUser_UserInfo::useradd_args(create_new_userGroup)		1
	set SEUser_UserInfo::useradd_args(create_systemAcct)		0
	set SEUser_UserInfo::useradd_args(do_not_create_home_dir)	0
	set SEUser_UserInfo::usr_type				$SEUser_UserInfo::def_user_type
	set SEUser_UserInfo::usr_type_sel			Defined
	set SEUser_UserInfo::curr_policy_type			""
	set SEUser_UserInfo::usr_name				""
	set SEUser_UserInfo::useradd_args(initGroup)		""
	set SEUser_UserInfo::useradd_args(comment)		""
	set SEUser_UserInfo::useradd_args(uid)			""
	set SEUser_UserInfo::useradd_args(passwd)		""
	set SEUser_UserInfo::passwd_confirm			""
	set SEUser_UserInfo::useradd_args(passwd_expDays)	""
	set SEUser_UserInfo::useradd_args(account_expDate)	""
	set SEUser_UserInfo::useradd_args(login_shell)		""
	set SEUser_UserInfo::useradd_args(home_dir)		""
	set SEUser_UserInfo::availGroups_list 			$SEUser_UserInfo::allGroups_list
	set SEUser_UserInfo::availRoles_list 			$SEUser_UserInfo::allRoles_list
	set SEUser_UserInfo::assignedGroups_list		""
	set SEUser_UserInfo::assignedRoles_list			""
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::unchange
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::unchange { } {	
	variable state
	variable current_user
	
	if { $state(edit_type) != "change" } {
		puts stderr "Cannot unchange a user because edit_type is $state(edit_type)"
		return
	}	
	# Set to default initialized state
	SEUser_UserInfo::set_to_initial_change_state
	# Reset user information
	SEUser_UserInfo::set_UserInfo $current_user	
	# Reset bindings
	bind UserName_Entry_Tag <KeyPress> {SEUser_UserInfo::change_to_edit_mode %A %K} 
	bind Comment_Entry_Tag <KeyPress> {SEUser_UserInfo::change_to_edit_mode %A %K}
	# Set edit mode
	SEUser_UserInfo::SetEditMode unchange
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::unadd
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::unadd { } {	
	variable state	
	
	if { $state(edit_type) != "add" } {
		puts stderr "Cannot unadd a user because edit_type is $state(edit_type)"
		return
	}	
	# Set to default initialized state
	SEUser_UserInfo::set_to_initial_add_state
	# Set edit mode
	SEUser_UserInfo::SetEditMode unadd 		
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::close
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::close { } {
	variable state
	variable useradd_args
	
	set SEUser_UserInfo::usr_type			""
	set SEUser_UserInfo::usr_type_sel		Defined
	set SEUser_UserInfo::usr_name			""
	set SEUser_UserInfo::passwd_confirm		""
	set SEUser_UserInfo::availGroups_list		""
	set SEUser_UserInfo::assignedGroups_list	""
	set SEUser_UserInfo::availRoles_list		""
	set SEUser_UserInfo::assignedRoles_list		""
	set SEUser_UserInfo::allGroups_list		""
	set SEUser_UserInfo::allRoles_list		""
	set SEUser_UserInfo::current_user		""
	set SEUser_UserInfo::mode 			""
	array unset state
	array unset useradd_args
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::disable_group_widgets
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::disable_group_widgets { } {
	# Disable group buttons and listboxes
	$SEUser_UserInfo::combo_initGroup configure -state disabled -entrybg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::g_add configure -state disabled 
	$SEUser_UserInfo::g_remove configure -state disabled
	$SEUser_UserInfo::listbox_availableGroups configure -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::listbox_assignedGroups configure -bg $SEUser_Top::default_bg_color
	SEUser_Top::disable_tkListbox $SEUser_UserInfo::listbox_availableGroups
	SEUser_Top::disable_tkListbox $SEUser_UserInfo::listbox_assignedGroups
	
	# Reset role information to initial state.
	set SEUser_UserInfo::availGroups_list $SEUser_UserInfo::allGroups_list
	set SEUser_UserInfo::assignedGroups_list ""
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::disable_role_widgets
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::disable_role_widgets { } {
	$SEUser_UserInfo::r_add configure -state disabled 
	$SEUser_UserInfo::r_remove configure -state disabled
	$SEUser_UserInfo::listbox_availRoles configure -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::listbox_assignedRoles configure -bg $SEUser_Top::default_bg_color
	SEUser_Top::disable_tkListbox $SEUser_UserInfo::listbox_availRoles
	SEUser_Top::disable_tkListbox $SEUser_UserInfo::listbox_assignedRoles	
	# Reset role information to initial state.
	set SEUser_UserInfo::availRoles_list $SEUser_UserInfo::allRoles_list
	set SEUser_UserInfo::assignedRoles_list ""

	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::set_to_default_state
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::set_to_default_state { event_type {user_selected ""} } {
	switch $event_type {
		add {
			SEUser_UserInfo::set_to_initial_add_state
		}
		change {
			SEUser_UserInfo::set_to_initial_change_state
			SEUser_UserInfo::set_UserInfo $user_selected
		}
		default {
			return -code error
		}
	}	
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::initialize
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::initialize { event_type user_selected } {			
	# Set the mode to either add or change
	set SEUser_UserInfo::mode $event_type
	# Initialize roles and groups list variables 
	set SEUser_UserInfo::availGroups_list		""
	set SEUser_UserInfo::assignedGroups_list	""
	set SEUser_UserInfo::availRoles_list		""
	set SEUser_UserInfo::assignedRoles_list		""
	# Set all groups and roles list variables
	set SEUser_UserInfo::allGroups_list [SEUser_db::get_list groups]
	set SEUser_UserInfo::allRoles_list  [SEUser_db::get_list roles]
	# Set to default initialized state based upon the event type
	SEUser_UserInfo::set_to_default_state $event_type $user_selected
	SEUser_UserInfo::SetEditMode init
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::set_to_initial_add_state
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::set_to_initial_add_state { } {
	SEUser_UserInfo::reset_option_variables	
	SEUser_UserInfo::disable_default_option_widgets
	SEUser_UserInfo::disable_advanced_tab_widgets
	# Configure widgets to reflect adding a user.
	$SEUser_UserInfo::lb_assignGroups configure -text "Additional Groups"
	$SEUser_UserInfo::b_add_change configure -text "Add"
	# First check to see if the generic user is defined and if not then change the
	# configuration options for the generic radiobutton to handle the "Undefined" user.
	if {![SEUser_db::is_generic_user_defined]} {
		$SEUser_UserInfo::r_generic configure -text "$SEUser_UserInfo::undef_user_type" -value Undefined
	}
	# Set binding on the user name entry box
	bind UserName_Entry_Tag <KeyPress> { SEUser_UserInfo::change_to_edit_mode %A %K}
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::set_to_initial_change_state
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::set_to_initial_change_state { } {
	# Reset default tab to initial state.
	SEUser_UserInfo::reset_option_variables
	SEUser_UserInfo::enable_default_tab_widgets
	
	# Configure widgets to reflect changing a user.
	destroy $SEUser_UserInfo::cb_newGroup
	$SEUser_UserInfo::entry_userName configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::lb_assignGroups configure -text "Additional Groups"
	
	# Set binding on the user name and comment entry boxes
	bind UserName_Entry_Tag <KeyPress> { SEUser_UserInfo::change_to_edit_mode %A %K} 
	bind Comment_Entry_Tag <KeyPress> { SEUser_UserInfo::change_to_edit_mode %A %K}
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::disable_default_tab_widgets
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::disable_default_option_widgets { } {	
	# Disable all widgets except the entry box widget.  
	$SEUser_UserInfo::r_defined configure -state disabled
	$SEUser_UserInfo::r_generic configure -state disabled
	$SEUser_UserInfo::g_add configure -state disabled
	$SEUser_UserInfo::g_remove configure -state disabled
	$SEUser_UserInfo::entry_comment configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::lbl_type configure -state disabled
	$SEUser_UserInfo::usr_type_lbl configure -state disabled
	$SEUser_UserInfo::lbl_initGroup configure -state disabled
	$SEUser_UserInfo::lbl_comment configure -state disabled
	$SEUser_UserInfo::combo_initGroup configure -state disabled -entrybg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_userName configure -state normal -bg white 
	
	# Set the focus to the user name entry box
	focus -force $SEUser_UserInfo::entry_userName
	
	# Disable listbox selections
	SEUser_UserInfo::disable_group_widgets
	SEUser_UserInfo::disable_role_widgets
	
	# Set default user type selected to "Defined"
	set SEUser_UserInfo::usr_type_sel Defined 
	set SEUser_UserInfo::curr_policy_type $SEUser_UserInfo::usr_type_sel
	
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::disable_advanced_tab_widgets
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::disable_advanced_tab_widgets { } {		
	# Disable all widgets   
	$SEUser_UserInfo::cb_newGroup configure -state disabled 
	$SEUser_UserInfo::cb_home_dir configure -state disabled
	$SEUser_UserInfo::cb_systemAcct configure -state disabled
	$SEUser_UserInfo::entry_uid configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_passwd configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_passwd_confirm configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_passwd_expDays configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_account_expDate configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_login_shell configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::entry_home_dir configure -state disabled -bg $SEUser_Top::default_bg_color
	$SEUser_UserInfo::lbl_uid configure -state disabled
	$SEUser_UserInfo::lbl_passwd configure -state disabled
	$SEUser_UserInfo::lbl_passwd_confirm configure -state disabled
	$SEUser_UserInfo::lbl_passwd_expDays configure -state disabled
	$SEUser_UserInfo::lbl_account_expDate configure -state disabled
	$SEUser_UserInfo::lbl_login_shell configure -state disabled
	$SEUser_UserInfo::lbl_home_dir configure -state disabled
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::enable_advanced_tab_widgets
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::enable_advanced_tab_widgets { } {		
	# Enable all widgets   
	$SEUser_UserInfo::cb_newGroup configure -state normal
	$SEUser_UserInfo::cb_home_dir configure -state normal
	$SEUser_UserInfo::cb_systemAcct configure -state normal
	$SEUser_UserInfo::entry_uid configure -state normal -bg white
	$SEUser_UserInfo::entry_passwd configure -state normal -bg white
	$SEUser_UserInfo::entry_passwd_confirm configure -state normal -bg white
	$SEUser_UserInfo::entry_passwd_expDays configure -state normal -bg white
	$SEUser_UserInfo::entry_account_expDate configure -state normal -bg white
	$SEUser_UserInfo::entry_login_shell configure -state normal -bg white
	$SEUser_UserInfo::entry_home_dir configure -state normal -bg white
	$SEUser_UserInfo::lbl_uid configure -state normal
	$SEUser_UserInfo::lbl_passwd configure -state normal
	$SEUser_UserInfo::lbl_passwd_confirm configure -state normal
	$SEUser_UserInfo::lbl_passwd_expDays configure -state normal
	$SEUser_UserInfo::lbl_account_expDate configure -state normal
	$SEUser_UserInfo::lbl_login_shell configure -state normal
	$SEUser_UserInfo::lbl_home_dir configure -state normal
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::change_buttons_state
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::change_buttons_state { changes } {
	if { $changes == 1 } {
		$SEUser_UserInfo::b_add_change configure -state normal
		$SEUser_UserInfo::b_cancel configure -state normal
		$SEUser_UserInfo::b_exit configure -state disabled
	} else {
		$SEUser_UserInfo::b_add_change configure -state disabled
		$SEUser_UserInfo::b_cancel configure -state disabled
		$SEUser_UserInfo::b_exit configure -state normal
	}	
	return 0
}
		
# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::change_to_edit_mode
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::change_to_edit_mode { key_pressed keySym } {
	set len [string length $key_pressed]
	set bool1 [expr {[string is alnum $key_pressed] && $len == 1}]
	set bool2 [expr {[string is punct $key_pressed] && $len == 1}]
	set bool3 [expr {[string is space $key_pressed] && $keySym == "space"}]
	set bool [expr {$bool1 || $bool2 || $bool3 || $keySym == "BackSpace"}]
	if { $bool } {
		# Remove binding on entry boxes	
		bind UserName_Entry_Tag <KeyPress> " " 
		bind Comment_Entry_Tag <KeyPress> " "
		if { $SEUser_UserInfo::mode == "add" } {
			SEUser_UserInfo::enable_default_tab_widgets
			SEUser_UserInfo::change_init_group_state
			SEUser_UserInfo::create_new_user_group
			SEUser_UserInfo::enable_advanced_tab_widgets 
			SEUser_UserInfo::SetEditMode add 
		} else {
			SEUser_UserInfo::SetEditMode change
		}
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::enable_default_tab_widgets
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::enable_default_tab_widgets { } {
	# Enable all widgets
	$SEUser_UserInfo::r_defined configure -state normal
	$SEUser_UserInfo::r_generic configure -state normal
	$SEUser_UserInfo::g_add configure -state normal
	$SEUser_UserInfo::g_remove configure -state normal
	$SEUser_UserInfo::r_add configure -state normal
	$SEUser_UserInfo::r_remove configure -state normal
	$SEUser_UserInfo::entry_comment configure -state normal -bg white
	$SEUser_UserInfo::combo_initGroup configure -state normal -entrybg white	
	$SEUser_UserInfo::lbl_type configure -state normal
	$SEUser_UserInfo::usr_type_lbl configure -state normal
	$SEUser_UserInfo::lbl_comment configure -state normal
	$SEUser_UserInfo::lbl_initGroup configure -state normal
	
	SEUser_Top::enable_tkListbox $SEUser_UserInfo::listbox_availRoles
	SEUser_Top::enable_tkListbox $SEUser_UserInfo::listbox_assignedRoles
	SEUser_Top::enable_tkListbox $SEUser_UserInfo::listbox_availableGroups
	SEUser_Top::enable_tkListbox $SEUser_UserInfo::listbox_assignedGroups

	# Configure listboxes to enabled state
	$SEUser_UserInfo::listbox_availRoles configure -bg white
	$SEUser_UserInfo::listbox_assignedRoles configure -bg white
	$SEUser_UserInfo::listbox_availableGroups configure -bg white
	$SEUser_UserInfo::listbox_assignedGroups configure -bg white
	
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::confirm_password
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::confirm_password { } {
	if { $SEUser_UserInfo::useradd_args(passwd) == $SEUser_UserInfo::passwd_confirm	} {
		return 1
	} 
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::set_role_info
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::set_role_info { user } {
	# Set role information
	set rt [catch {set SEUser_UserInfo::assignedRoles_list [SEUser_db::get_user_roles $user]} err]
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $SEUser_UserInfo::userInfoDlg
		return -1
	} 
	SEUser_Top::check_list_for_redundancy "SEUser_UserInfo::availRoles_list" "SEUser_UserInfo::assignedRoles_list"
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::set_group_info
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::set_group_info { user } {
	variable assignedGroups_list
	
	# Set group information
	set SEUser_UserInfo::availGroups_list $SEUser_UserInfo::allGroups_list
	# SEUser_db::get_user_groups returns group info in the form PRIMARY_GROUP, GROUP2, ..
	set rt [catch {set SEUser_UserInfo::assignedGroups_list [SEUser_db::get_user_groups $user]} err]
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Groups Error" \
			-parent $SEUser_UserInfo::userInfoDlg \
			-message "$err"
		return
	} 
	# Set initial group and available groups information. 
	if {$assignedGroups_list != ""} {
		set SEUser_UserInfo::useradd_args(initGroup) [lindex $assignedGroups_list 0]
		# Remove the initial group from the assigned groups listbox
		set idx [lsearch -exact $SEUser_UserInfo::assignedGroups_list $SEUser_UserInfo::useradd_args(initGroup)]
		if { $idx != -1 } {
			set SEUser_UserInfo::assignedGroups_list [lreplace $SEUser_UserInfo::assignedGroups_list $idx $idx]
		}
		SEUser_Top::check_list_for_redundancy "SEUser_UserInfo::availGroups_list" "SEUser_UserInfo::assignedGroups_list"
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::set_UserInfo
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::set_UserInfo { user } {
	variable usr_type_sel 
	variable r_defined
	variable r_generic
	variable current_user
	variable entry_comment
	variable useradd_args
	
	# First check to see if the generic user is defined and if not then change the
	# configuration options for the generic radiobutton to handle the "Undefined" user.
	if {![SEUser_db::is_generic_user_defined]} {
		$r_generic configure -text "$SEUser_UserInfo::undef_user_type" -value Undefined
	}
	
	# Set user type information.	
	set SEUser_UserInfo::usr_name $user	
	set SEUser_UserInfo::current_user $user		
	set SEUser_UserInfo::usr_type [SEUser_db::get_user_type $user]
	
	# Based upon the user type, configure widgets
	switch $SEUser_UserInfo::usr_type \
		$SEUser_UserInfo::def_user_type {
			set usr_type_sel Defined
			if { ![SEUser_db::is_system_user $user] } {
				$entry_comment configure -state disabled -state disabled -bg $SEUser_Top::default_bg_color
				SEUser_UserInfo::disable_group_widgets 
			}
		} \
		$SEUser_UserInfo::generic_usr_type {
			set usr_type_sel Generic
			SEUser_UserInfo::disable_role_widgets
		} \
		$SEUser_UserInfo::special_usr_type {
			set usr_type_sel Defined
			$r_defined configure -state disabled
			$r_generic configure -state disabled
			if { ![SEUser_db::is_system_user $user] } {
				$entry_comment configure -state disabled -state disabled -bg $SEUser_Top::default_bg_color
				SEUser_UserInfo::disable_group_widgets 
			}
		} \
		$SEUser_UserInfo::undef_user_type {
			set usr_type_sel Undefined
			SEUser_UserInfo::disable_role_widgets
		} \
		default {
			return -code error
		} 
		
	# Set role information
	SEUser_UserInfo::set_role_info $user
	# Update the previous type selected variable
	set SEUser_UserInfo::curr_policy_type $usr_type_sel
	# Set the comment field in the dialog. 	
	set rt [catch {set SEUser_UserInfo::useradd_args(comment) [SEUser_db::get_sysUser_data_field $user comment]} err]
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $SEUser_UserInfo::userInfoDlg
		set useradd_args(comment) ""
		$entry_comment configure -state disabled -bg $SEUser_Top::default_bg_color
	}
	SEUser_UserInfo::set_group_info $user
	
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::SetEditMode 
#
#  Description: 
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::SetEditMode { mode } {
	variable state
		
	switch -- $mode {
		add {
		    set state(edit) 1
		    set state(edit_type) "add"
		    set state(users_changed) [expr $state(users_changed) + 1]
		}
		commit {
		    set state(edit) 0
		    set state(edit_type) "none"
		}
		init {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(users_changed) 0
		}
		change {
		    # we might be making changes for a new user, in which case we don't want 
		    # to change edit type or any other state
		    if { $state(edit) == 1 && $state(edit_type) == "add" } {
		    	return
		    }
		    # If we are already in change mode then just return.
		    if { $state(edit) == 1 && $state(edit_type) == "change"  } {
		    	return
		    }
		    set state(edit) 1
		    set state(edit_type) "change"
		    set state(users_changed) 1
		}
		unchange {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(users_changed) [expr $state(users_changed) - 1]
		}
		unadd {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(users_changed) [expr $state(users_changed) - 1]
		}
		default {
		    return -code error
		}
	}
	# Configure button states
	SEUser_UserInfo::change_buttons_state $state(edit)
	return 0		
}

############################
# GUI Building functions   #
############################

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::create_AdvancedOpts_Frame
#
#  Description:
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::create_AdvancedOpts_Frame { mainframe } {	
	variable cb_home_dir
	variable cb_systemAcct
	variable entry_uid 
	variable entry_passwd 
	variable entry_passwd_confirm
	variable entry_passwd_expDays
	variable entry_account_expDate
	variable entry_login_shell
	variable entry_home_dir 
	variable lbl_uid
	variable lbl_passwd
	variable lbl_passwd_confirm
	variable lbl_passwd_expDays
	variable lbl_account_expDate
	variable lbl_login_shell
	variable lbl_home_dir 
	
	# Frames
	set top_f [TitleFrame $mainframe.top_f]
	set mid_f [TitleFrame $mainframe.mid_f]
	set bot_f [TitleFrame $mainframe.bot_f]
	set top_in_t [frame [$top_f getframe].top_in_t -relief flat -borderwidth 0]
	set top_in_b [frame [$top_f getframe].top_in_b -relief flat -borderwidth 0]
	set top_in_bl [frame $top_in_b.top_in_bl -relief flat -borderwidth 0]
	set top_in_br [frame $top_in_b.top_in_br -relief flat -borderwidth 0]
	set mid_in_t [frame [$mid_f getframe].mid_in_t -relief flat -borderwidth 0]
	set mid_in_b [frame [$mid_f getframe].mid_in_b -relief flat -borderwidth 0]
	set mid_in_bl [frame $mid_in_b.mid_in_bl -relief flat -borderwidth 0]
	set mid_in_bc [frame $mid_in_b.mid_in_bc -relief flat -borderwidth 0]
	set mid_in_br [frame $mid_in_b.mid_in_br -relief flat -borderwidth 0]
	set bot_in_f [frame [$bot_f getframe].bot_in_f -relief flat -borderwidth 0]
	set bot_in_l [frame $bot_in_f.bot_in_l -relief flat -borderwidth 0]
	set bot_in_r [frame $bot_in_f.bot_in_r -relief flat -borderwidth 0]
	
	# Top widgets	
	set lbl_uid [Label $top_in_t.lbl_uid -text "UID:"]
	set entry_uid [Entry $top_in_t.entry_uid -textvariable SEUser_UserInfo::useradd_args(uid) -width 15]
	set lbl_passwd_expDays  [Label $top_in_bl.lbl_passwd_expDays -text "Days before account inactive (-1 to disable):"]
	set cb_systemAcct [checkbutton $top_in_t.cb_systemAcct -text "Create System Account" \
			  -variable SEUser_UserInfo::useradd_args(create_systemAcct)]
	set entry_passwd_expDays  [Entry $top_in_br.entry_passwd_expDays -textvariable SEUser_UserInfo::useradd_args(passwd_expDays) -width 15]
	set lbl_account_expDate [Label $top_in_bl.lbl_account_expDate -text "Account Expires on date (YYYY-MM-DD):"]
	set entry_account_expDate [Entry $top_in_br.entry_account_expDate -textvariable SEUser_UserInfo::useradd_args(account_expDate) -width 15]
	
	# Middle widgets
	set lbl_home_dir [Label $mid_in_bl.lbl_home_dir -text "Home Directory:"]
	set entry_home_dir [Entry $mid_in_bc.entry_home_dir -textvariable SEUser_UserInfo::useradd_args(home_dir) -width 15]
	set cb_home_dir [checkbutton $mid_in_br.cb_home_dir -text "Do not create home directory" \
			  -variable SEUser_UserInfo::useradd_args(do_not_create_home_dir) \
			  -command { SEUser_UserInfo::change_homeDir_state $SEUser_UserInfo::entry_home_dir}]
	set lbl_login_shell 	[Label $mid_in_bl.lbl_login_shell -text "Log-in shell:"]
	set entry_login_shell 	  [Entry $mid_in_bc.entry_login_shell -textvariable SEUser_UserInfo::useradd_args(login_shell) -width 15]
	
	# Bottom widgets
	set lbl_passwd 	[Label $bot_in_l.lbl_passwd -text "Password:"]
	set lbl_passwd_confirm  [Label $bot_in_l.lbl_passwd_confirm -text "Confirm Password:"]
	set entry_passwd   [Entry $bot_in_r.entry_passwd -textvariable SEUser_UserInfo::useradd_args(passwd) -width 15 -show "*"]
	set entry_passwd_confirm  [Entry $bot_in_r.entry_passwd_confirm -textvariable SEUser_UserInfo::passwd_confirm -width 15 -show "*"]
	
	# Placing frames
	pack $top_f $mid_f -side top -anchor nw -fill x 
	pack $bot_f -side top -anchor nw -fill both -expand yes
	pack $top_in_t $top_in_b -side top -anchor nw -fill x -padx 2 -pady 2
	pack $top_in_bl $top_in_br -side left -anchor nw -fill x -expand yes
	pack $mid_in_t $mid_in_b -side top -anchor nw -fill x -padx 2 -pady 2
	pack $mid_in_bl $mid_in_bc $mid_in_br -side left -anchor nw -fill x 
	pack $bot_in_f -side top -anchor nw -fill x -padx 2 -pady 2
	pack $bot_in_l $bot_in_r -side left -anchor nw -fill x 
	
	# Placing top widgets			  
	pack $lbl_uid -side left -anchor nw -fill x
	pack $entry_uid -side left -anchor nw -fill x -expand yes -padx 2
	pack $cb_systemAcct -side right -anchor ne 
	pack $lbl_passwd_expDays $lbl_account_expDate -side top -anchor nw -pady 4
	pack $entry_passwd_expDays $entry_account_expDate -side top -fill x -expand yes -anchor nw -pady 4
	
	# Placing middle widgets
	pack $lbl_home_dir $lbl_login_shell -side top -anchor nw -pady 4
	pack $entry_home_dir $entry_login_shell -side top -anchor nw -fill x -expand yes -pady 4
	pack $cb_home_dir -side left -anchor nw -pady 4
	
	# Placing bottom widgets
	pack $lbl_passwd $lbl_passwd_confirm -side top -anchor nw  -pady 4
	pack $entry_passwd $entry_passwd_confirm -side top -anchor nw -fill x -pady 4
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::createUserInfoFrame
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::createUserInfoFrame { mainframe } {
	variable entry_userName
	variable usr_type_lbl
	variable r_defined
	variable r_generic
	variable entry_comment
	variable lbl_type
	variable usr_type_lbl
	variable lbl_comment
	
	set userInfo_f [TitleFrame $mainframe.userInfo_f]
	set t_frame  [frame [$userInfo_f getframe].t_frame -relief flat -borderwidth 0]
	set t_frame_t  [frame $t_frame.t_frame_t -relief flat -borderwidth 0]
	set t_frame_m  [frame $t_frame.t_frame_m -relief flat -borderwidth 0]
	set t_frame_lm  [frame $t_frame_m.t_frame_ml -relief flat -borderwidth 0]
	set t_frame_rm  [frame $t_frame_m.t_frame_mr -relief flat -borderwidth 0]
	set t_frame_b  [frame $t_frame.t_frame_b -relief flat -borderwidth 0]
	set b_frame  [frame [$userInfo_f getframe].b_frame -relief flat -borderwidth 0]
	set b_frame_t [frame $b_frame.b_frame_t -relief flat -borderwidth 0]
	set b_frame_b [frame $b_frame.b_frame_b -relief flat -borderwidth 0]
	pack $t_frame -side top -anchor n -fill x  
	pack $t_frame_t -side top -anchor nw -fill x
	pack $t_frame_m -side top -anchor nw -pady 4 
	pack $t_frame_lm -side left -anchor nw -fill x -expand yes -ipadx 20
	pack $t_frame_rm -side left -anchor nw -padx 30
	pack $t_frame_b -side top -anchor nw -fill x -expand yes -pady 2
	pack $b_frame -side bottom -after $t_frame -anchor s -fill x 
	pack $b_frame_t -side left -anchor sw
	pack $b_frame_b -side left -anchor se -padx 5
	pack $userInfo_f -side top -fill both -expand yes -padx 5 -pady 2
	
	# Labels
	set lbl_usr [Label $t_frame_t.lbl_usr -text "User Name:"]
	set lbl_type [Label $t_frame_t.lbl_type -text "Type:"]
	set usr_type_lbl [Label $t_frame_t.usr_type_lbl -textvariable SEUser_UserInfo::usr_type]
	
	# Entry box
	set entry_userName [Entry $t_frame_t.entry_user_login -textvariable SEUser_UserInfo::usr_name -width 28]
	pack $lbl_usr -side left -anchor nw 
	pack $entry_userName -anchor nw -side left -expand yes 
	pack $lbl_type -side left -anchor ne
	pack $usr_type_lbl -side left -after $lbl_type -anchor ne
	
	set lbl_comment   [Label $t_frame_b.lbl_comment -text "Comment:"]
	set entry_comment [Entry $t_frame_b.entry_comment -textvariable SEUser_UserInfo::useradd_args(comment) -width 15]
	pack $lbl_comment -side left -anchor nw 
	pack $entry_comment -side left -anchor nw -fill x -expand yes -padx 6
	
	# Radiobuttons
	set r_defined [radiobutton  $t_frame_rm.r_defined -text "Defined" \
			  -variable SEUser_UserInfo::usr_type_sel -value Defined \
			  -command { SEUser_UserInfo::configure_on_type_sel }]
	set r_generic [radiobutton  $t_frame_rm.r_generic -text "Generic" \
			  -variable SEUser_UserInfo::usr_type_sel -value Generic \
			  -command { SEUser_UserInfo::configure_on_type_sel }]
	pack $r_defined $r_generic -side left -anchor nw 
	
	# Set binding on entry box widget
	bindtags $entry_userName { $entry_userName Entry UserName_Entry_Tag \
					[winfo toplevel $entry_userName] all }
	# Set binding on entry box widget
	bindtags $entry_comment { $entry_comment Entry Comment_Entry_Tag \
					[winfo toplevel $entry_comment] all }	 			
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::createGroupsFrame
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::createGroupsFrame { mainframe } {
	variable listbox_availableGroups
	variable listbox_assignedGroups
	variable g_add
	variable g_remove
	variable lbl_initGroup
	variable lb_assignGroups
	variable combo_initGroup
	variable cb_newGroup
	
	# Frames
	set groups_f [TitleFrame $mainframe.groups_f -text "Groups"]
	set t_frame  [frame [$groups_f getframe].t_frame -relief flat -borderwidth 0]
	set b_frame  [frame [$groups_f getframe].b_frame -relief flat -borderwidth 0]
	set lf [LabelFrame $b_frame.lf -relief flat -borderwidth 0]
	set cf [frame $b_frame.cf -relief flat -borderwidth 0]
	set rf [LabelFrame $b_frame.rf -relief flat -borderwidth 0]
	set lf_inner_top [frame [$lf getframe].in_top]
	set lf_inner_bot [ScrolledWindow [$lf getframe].in_bot]
	set rf_inner_top [frame [$rf getframe].in_top]
	set rf_inner_bot [ScrolledWindow [$rf getframe].in_bot]
	
	pack $groups_f -side top -fill x -anchor n -expand yes -padx 5 -pady 2
	pack $t_frame -side top -fill x -anchor nw -expand yes -pady 2
	pack $b_frame -side bottom -fill x -anchor nw -expand yes -pady 4
	pack $lf -side left -anchor w -expand yes
	pack $lf_inner_top -side top -anchor n -fill x
	pack $lf_inner_bot -side bottom -anchor s -fill x -expand yes
	pack $cf -side left -anchor center -expand yes
	pack $rf -side right -anchor e -expand yes
	pack $rf_inner_top -side top -anchor n -fill x
	pack $rf_inner_bot -side bottom -anchor s -fill x -expand yes
	
	# Default checkbuttons
	set lbl_initGroup   [Label $t_frame.lbl_initGroup -text "Initial Group:" -justify left]
	set combo_initGroup [ComboBox $t_frame.combo_initGroup -textvariable SEUser_UserInfo::useradd_args(initGroup) -width 15 \
			      -postcommand {SEUser_UserInfo::populate_initGroups_list $SEUser_UserInfo::combo_initGroup $SEUser_UserInfo::allGroups_list} \
			      -modifycmd  {SEUser_UserInfo::change_init_group} -editable 0]
	set cb_newGroup [checkbutton $t_frame.cb_newGroup -text "Create New Group" \
			  -variable SEUser_UserInfo::useradd_args(create_new_userGroup) \
			  -command { SEUser_UserInfo::change_init_group_state }]
	pack $lbl_initGroup -side left -anchor nw 
	pack $combo_initGroup -side left -anchor ne -padx 5
	pack $cb_newGroup -side left -anchor ne -padx 5
	
	# Labels
	set lb_availGroups   [Label $lf_inner_top.lb_availGroups -text "Available Groups"]
	set lb_assignGroups [Label $rf_inner_top.lb_assignGroups -text ""]
	
	# ListBoxes
	set listbox_availableGroups [listbox [$lf_inner_bot getframe].listbox_availableGroups -height 6 \
				  	-width 20 -highlightthickness 0 \
				  	-listvar SEUser_UserInfo::availGroups_list]  
	set listbox_assignedGroups  [listbox [$rf_inner_bot getframe].listbox_assignedGroups -height 6 \
					-width 20 -highlightthickness 0 \
					-listvar SEUser_UserInfo::assignedGroups_list] 
	$lf_inner_bot setwidget $listbox_availableGroups
	$rf_inner_bot setwidget $listbox_assignedGroups
	
	# Bindings 
	bindtags $listbox_availableGroups [linsert [bindtags $listbox_availableGroups] 3 AvailGroups_Tag]
	bindtags $listbox_assignedGroups [linsert [bindtags $listbox_assignedGroups] 3 CurrGroups_Tag]
		     	
	# Action Buttons
	set g_add [Button $cf.add -text "-->" -width 6 \
		   -command { SEUser_UserInfo::add_Group [$SEUser_UserInfo::listbox_availableGroups curselection] } \
		   -helptext "Add group"]
	set g_remove [Button $cf.remove -text "<--" -width 6 -command \
		      { SEUser_UserInfo::remove_Group [$SEUser_UserInfo::listbox_assignedGroups curselection] } \
		      -helptext "Remove group"]
	
	# Placing widgets
	pack $lb_availGroups -side top 
	pack $lb_assignGroups -side top 
	pack $g_add $g_remove -side top -anchor center -pady 5 -padx 5
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_UserInfo::createRolesFrame
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_UserInfo::createRolesFrame { mainframe } {
	variable listbox_availRoles
	variable listbox_assignedRoles
	variable r_add
	variable r_remove
	
	set roles_f [TitleFrame $mainframe.roles_f -text "Roles"]
	set lf [LabelFrame [$roles_f getframe].lf -relief flat -borderwidth 0]
	set cf [frame [$roles_f getframe].cf -relief flat -borderwidth 0]
	set rf [LabelFrame [$roles_f getframe].rf -relief flat -borderwidth 0]
	set lf_inner_top [frame [$lf getframe].in_top]
	set lf_inner_bot [ScrolledWindow [$lf getframe].in_bot]
	set rf_inner_top [frame [$rf getframe].in_top]
	set rf_inner_bot [ScrolledWindow [$rf getframe].in_bot]
	
	pack $roles_f -side top -fill both -expand yes -padx 5 -pady 2
	pack $lf -side left -anchor w -expand yes
	pack $lf_inner_top -side top -anchor n -fill x
	pack $lf_inner_bot -side bottom -anchor s -fill x -expand yes
	pack $cf -side left -anchor center -expand yes
	pack $rf -side right -anchor e -expand yes
	pack $rf_inner_top -side top -anchor n -fill x
	pack $rf_inner_bot -side bottom -anchor s -fill x -expand yes    
	
	set lb_availRoles   [Label $lf_inner_top.lb_availRoles -text "Available Roles"]
	set lb_currentRoles [Label $rf_inner_top.lb_currentRoles -text "Assigned Roles"]
	
	set listbox_availRoles   [listbox [$lf_inner_bot getframe].listbox_availRoles \
				  	-height 6 -width 20 -highlightthickness 0 \
				  	-listvar SEUser_UserInfo::availRoles_list] 	
	set listbox_assignedRoles [listbox [$rf_inner_bot getframe].listbox_availableGroups \
				  	-height 6 -width 20 -highlightthickness 0 \
				  	-listvar SEUser_UserInfo::assignedRoles_list]        
	$lf_inner_bot setwidget $listbox_availRoles
	$rf_inner_bot setwidget $listbox_assignedRoles
	
	# Bindings 
	bindtags $listbox_availRoles [linsert [bindtags $listbox_availRoles] 3 AvailRoles_Tag]
	bindtags $listbox_assignedRoles [linsert [bindtags $listbox_assignedRoles] 3 CurrRoles_Tag]
		     	
	set r_add    [Button $cf.add -text "-->" -width 6 \
		      -command { SEUser_UserInfo::add_Role [$SEUser_UserInfo::listbox_availRoles curselection] } \
		      -helptext "Add a new role to the user account"]
	set r_remove [Button $cf.remove -text "<--" -width 6 \
		      -command { SEUser_UserInfo::remove_Role [$SEUser_UserInfo::listbox_assignedRoles curselection]} \
		      -helptext "Remove a role from the user account"]
	
	pack $lb_availRoles -side top 
	pack $r_add $r_remove -side top -anchor center -pady 5 -padx 5
	pack $lb_currentRoles -side top 
	
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::create_UserInfo_Tab
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::create_UserInfo_Tab { notebook } {	
	# Layout frames
	set frame [$notebook insert end $SEUser_UserInfo::user_info_tabID -text "Properties"]
	set mainframe  [frame $frame.topf -width 100 -height 200]
	pack $mainframe -fill both -expand yes 
	
	SEUser_UserInfo::createUserInfoFrame $mainframe
	SEUser_UserInfo::createGroupsFrame $mainframe
	SEUser_UserInfo::createRolesFrame $mainframe
			
	return 0
}     

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::create_AdvancedOpts_Tab
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::create_AdvancedOpts_Tab { notebook } {
	# Layout frames
	set frame [$notebook insert end $SEUser_UserInfo::adv_opts_tabID -text "Advanced Options"]
	set mainframe  [frame $frame.topf -width 100 -height 200]
	pack $mainframe -fill both -expand yes 
	
	SEUser_UserInfo::create_AdvancedOpts_Frame $mainframe
	
	return 0
}    

# -----------------------------------------------------------------------------------
#  Command SEUser_UserInfo::display
# -----------------------------------------------------------------------------------
proc SEUser_UserInfo::display { event_type { user_selected "" } } {
	variable notebook
	variable userInfoDlg
	variable b_add_change
	variable b_cancel
	variable b_exit
	global tcl_platform
    
	# Checking to see if output window already exists. If so, it is destroyed.
	if { [winfo exists $userInfoDlg] } {
		raise $userInfoDlg
		return 
	}
	toplevel $userInfoDlg
	wm protocol $userInfoDlg WM_DELETE_WINDOW "destroy $userInfoDlg"
	wm withdraw $userInfoDlg
	
	set topf  [frame $userInfoDlg.topf -width 100 -height 200]
	set botf  [frame $userInfoDlg.botf -width 100 -height 200]
	pack $topf -side top -fill both -expand yes 
	pack $botf -side bottom -anchor center -fill x -expand yes -padx 4
	set notebook [NoteBook $topf.notebook]
	
	# Buttons
	set b_add_change [button $botf.b_add_change -text "Commit" -width 6 -command {SEUser_UserInfo::commit}]
	set b_cancel     [button $botf.b_cancel -text "Cancel" -width 6 -command { SEUser_UserInfo::cancel }]
	set b_exit [button $botf.b_exit -text "Exit" -width 6 -command { SEUser_UserInfo::exit_userInfoDlg }]
	pack $b_add_change $b_cancel -side left -anchor nw -padx 2
	pack $b_exit -side right -anchor ne
	
	if { $event_type == "add" } {
		wm title $userInfoDlg "Add new user"
		SEUser_UserInfo::create_UserInfo_Tab $notebook
		SEUser_UserInfo::create_AdvancedOpts_Tab $notebook	
	} elseif { $event_type == "change" } {
		wm title $userInfoDlg "User Information"
		SEUser_UserInfo::create_UserInfo_Tab $notebook
	} else {
		return -code error
	}
	
	$notebook compute_size
	pack $notebook -fill both -expand yes -padx 4 -pady 4
	$notebook raise [$notebook page 0]
	update idletasks
	
	# Make dialog non-resizable
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $SEUser_UserInfo::::userInfoDlg 0 0
	} else {
		bind $SEUser_UserInfo::::userInfoDlg <Configure> { wm geometry $SEUser_UserInfo::::userInfoDlg {} }
	}
			
	# Place a toplevel at center
	#::tk::PlaceWindow $userInfoDlg widget center
	wm deiconify $userInfoDlg
	grab $userInfoDlg
	SEUser_UserInfo::initialize $event_type $user_selected
	
	return 0
}           
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           