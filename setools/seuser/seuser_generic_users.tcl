##############################################################
#  seuser_generic_tab.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#

##############################################################
# ::SEUser_Generic_Users namespace
#
# This namespace creates the generic users tab, which 
# is used to enable/disable generic users on the system.
##############################################################
namespace eval SEUser_Generic_Users {	
	# Global widget variables
	variable listbox_availRoles_generic
	variable listbox_currentRoles_generic
	variable b_generic
	variable r_add_generic
	variable r_remove_generic
	variable tabframe
	
	# Global list variables 
	# - NOTE: When changing these variable names, do not forget to change argument
	#	  names accordingly for calls to SEUser_Top::check_list_for_redundancy.
	#	  This is because calls to SEUser_Top::check_list_for_redundancy use 
	#	  these names explicitly as arguments to simulate call-by-reference.
	# 
	variable current_GenericRoles_list	""
	variable avail_GenericRoles_list	""
	variable roles_to_be_added		""
	variable roles_to_be_removed		""
	
	# state variables
	variable state
	set state(edit) 		0
	set state(edit_type) 		"none"
	set state(roles_changed) 	0
	set state(user_u_changed) 	0
	
	# Miscellaneous variables
	variable generic_user			"user_u"
	variable b_generic_label_text		""
	variable generic_user_defined		0
	variable generic_user_mcntr		0
	variable status_text			""
	variable status				""
}

##############################
#  GUI Construction Methods  #
##############################

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::createGenericUserWidgets
#
#  Description: Creates widgets for the Generic Users tab.
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::createGenericUserWidgets { tabframe } {	
	variable listbox_availRoles_generic
	variable listbox_currentRoles_generic
	variable b_generic
	variable r_add_generic
	variable r_remove_generic
	
	# Frames
	set t_frame   [TitleFrame $tabframe.t_frame -text "Enable/Disable"]
	set t_frame_l [frame [$t_frame getframe].t_frame_l]
	set t_frame_r [frame [$t_frame getframe].t_frame_r]
	set b_frame   [frame $tabframe.b_frame -relief flat -borderwidth 0]
	set roles_f [TitleFrame $b_frame.roles_f -text "Roles"]
	set lf [LabelFrame [$roles_f getframe].lf -relief flat -borderwidth 0]
	set cf [frame [$roles_f getframe].cf -relief flat -borderwidth 0]
	set rf [LabelFrame [$roles_f getframe].rf -relief flat -borderwidth 0]
	set lf_inner_top [frame [$lf getframe].in_top]
	set lf_inner_bot [ScrolledWindow [$lf getframe].in_bot]
	set rf_inner_top [frame [$rf getframe].in_top]
	set rf_inner_bot [ScrolledWindow [$rf getframe].in_bot]  
	
	# Labels
	set lb_status       [Label $t_frame_l.lb_status -textvariable SEUser_Generic_Users::status]
	set lb_status_text  [Label $t_frame_r.lb_textInfo -justify left \
			 	-textvariable SEUser_Generic_Users::status_text]
	set lb_availRoles   [Label $lf_inner_top.lb_availRoles -text "Available Roles"]
	set lb_currentRoles [Label $rf_inner_top.lb_currentRoles -text "Assigned Roles"]
	
	# Listboxes
	set listbox_availRoles_generic   [listbox [$lf_inner_bot getframe].listbox_availRoles_generic \
					  	-height 6 -width 20 -highlightthickness 0 \
					  	-listvar SEUser_Generic_Users::avail_GenericRoles_list \
					  	-bg white] 	
	set listbox_currentRoles_generic [listbox [$rf_inner_bot getframe].listbox_currentRoles_generic \
				  		-height 6 -width 20 -highlightthickness 0 \
				  		-listvar SEUser_Generic_Users::current_GenericRoles_list \
				  		-bg white]        
	$lf_inner_bot setwidget $listbox_availRoles_generic
	$rf_inner_bot setwidget $listbox_currentRoles_generic
	
	# Listbox Bindings 				     	
	bindtags $listbox_availRoles_generic [linsert [bindtags $listbox_availRoles_generic] 3 AvailRoles_Tag]
	bindtags $listbox_currentRoles_generic [linsert [bindtags $listbox_currentRoles_generic] 3 CurrRoles_Tag]    
	
	# Buttons
	set b_generic [Button $t_frame_l.b_generic -textvariable SEUser_Generic_Users::b_generic_label_text \
		-width 6 \
		-command { \
			   if { $SEUser_Generic_Users::generic_user_defined } { 
				SEUser_Generic_Users::disable_generic_users
			   } else {
			   	SEUser_Generic_Users::enable_generic_users
			   }}]
	# Radio buttons
	set r_add_generic    [Button $cf.add -text "-->" -width 6 \
			      -command { SEUser_Generic_Users::add_genericRole [$SEUser_Generic_Users::listbox_availRoles_generic curselection] } \
			      -helptext "Add a new role to the generic user account"]
	set r_remove_generic [Button $cf.remove -text "<--" -width 6 \
			      -command { SEUser_Generic_Users::remove_genericRole [$SEUser_Generic_Users::listbox_currentRoles_generic curselection] } \
			      -helptext "Remove a role from the generic user account"]
	
	pack $t_frame -side top -anchor nw -fill x  
	pack $t_frame_l -side left -anchor nw 
	pack $t_frame_r -side left -anchor nw -fill x -expand yes
	pack $b_frame -side bottom -after $t_frame -anchor n -fill both -pady 5 -expand yes
	pack $roles_f -side top -fill both -expand yes -padx 5 -pady 2
	pack $lf -side left -anchor w -expand yes -fill y
	pack $lf_inner_top -side top -anchor n -fill x
	pack $lf_inner_bot -side bottom -anchor s -fill both -expand yes
	pack $cf -side left -anchor center -expand yes
	pack $rf -side right -anchor e -expand yes -fill y
	pack $rf_inner_top -side top -anchor n -fill x
	pack $rf_inner_bot -side bottom -anchor s -fill both -expand yes 
	pack $lb_status $b_generic -side top -anchor nw -pady 2
	pack $lb_status_text -side left -anchor center -padx 2 -fill x -expand yes
	pack $lb_availRoles -side top 
	pack $r_add_generic $r_remove_generic -side top -anchor center -pady 5 -padx 5
	pack $lb_currentRoles -side top 
				
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::create_GenericUsers_Tab
# -----------------------------------------------------------------------------------
proc SEUser_Generic_Users::create_GenericUsers_Tab { notebook } {	
	variable tabframe
		
	# Layout frames
	set tabframe [$notebook insert end $SEUser_Advanced::generic_users_tabID -text "Generic Users"]
	set topf  [frame $tabframe.topf -width 100 -height 200]
	pack $topf -fill both -expand yes -anchor nw 
	
	SEUser_Generic_Users::createGenericUserWidgets $topf
	return 0
}     

####################
#  Event Methods   #
####################

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::unadd_genericRoles
#
#  Description: This proc is called when user selects the Cancel button
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::unadd_genericRoles { } {	
	variable state 
	variable listbox_currentRoles_generic
	variable current_GenericRoles_list
	variable avail_GenericRoles_list
	variable roles_to_be_added
	
	if { $state(edit_type) != "add" } {
		puts stderr "Cannot unadd a user because edit_type is $state(edit_type)"
		return
	}
	
	if { $roles_to_be_added == "" } {
		puts stderr "There were no roles added."
		return
	}
	
	foreach role $roles_to_be_added {
		# Check if in available generic roles list
		if { [lsearch -exact $avail_GenericRoles_list $role] != -1 } {
		   	puts stderr "Already exists in the available generic roles list."
			continue
		} else {	
			set avail_GenericRoles_list [lappend avail_GenericRoles_list $role]
			set avail_GenericRoles_list [lsort $avail_GenericRoles_list]
		}
		# and remove from current generic roles
		set idx [lsearch -exact $current_GenericRoles_list $role]
		set current_GenericRoles_list [lreplace $current_GenericRoles_list $idx $idx]
	}
	$listbox_currentRoles_generic selection clear 0 end
	SEUser_Generic_Users::SetEditMode unadd	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::add_genericRole
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::add_genericRole { idx } {
	variable listbox_availRoles_generic
	variable listbox_currentRoles_generic
	variable current_GenericRoles_list
	variable avail_GenericRoles_list
	variable roles_to_be_added
	variable roles_to_be_removed
	
	if { $idx == "" } {
		return
	}
	# remove from avail roles list
	set role [$listbox_availRoles_generic get $idx]
	set idx  [lsearch -exact $avail_GenericRoles_list $role]
	set avail_GenericRoles_list [lreplace $avail_GenericRoles_list $idx $idx]
	# put in current roles
	set current_GenericRoles_list [lappend current_GenericRoles_list $role]
	set current_GenericRoles_list [lsort $current_GenericRoles_list]
	set new_idx [lsearch -exact $current_GenericRoles_list $role]
	# If this is a role in the list of roles to be removed then remove it from this list.
	if { [set idx [lsearch -exact $roles_to_be_removed $role]] != -1 } {
		set roles_to_be_removed [lreplace $SEUser_Generic_Users::roles_to_be_removed $idx $idx]
	} else {
		set roles_to_be_added [lappend roles_to_be_added $role]
    	}
    	$listbox_currentRoles_generic selection set $new_idx
    	$listbox_currentRoles_generic see $new_idx
	SEUser_Generic_Users::SetEditMode add
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::unremove_genericRole
#
#  Description: This proc is called when user selects the Cancel button
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::unremove_genericRole { } {
	variable listbox_availRoles_generic
	variable roles_to_be_removed
	variable current_GenericRoles_list
	variable avail_GenericRoles_list
	variable state
	
	if { $state(edit_type) != "delete" } {
		puts stderr "Cannot unremove a user because edit_type is $state(edit_type)"
		return
	}
	
	if { $roles_to_be_removed == "" } {
		puts stderr "There were no roles removed."
		return
	}
	
	foreach role $roles_to_be_removed {
		# Check if in current generic roles list. If not, then re-append.
		if { [lsearch -exact $current_GenericRoles_list $role] != -1 } {
		   	puts stderr "Already exists in the current generic roles list."
			continue
		} else {	
			set current_GenericRoles_list [lappend current_GenericRoles_list $role]
			set current_GenericRoles_list [lsort $current_GenericRoles_list]
		}
		# and remove from available generic roles
		set idx [lsearch -exact $avail_GenericRoles_list $role]
		set avail_GenericRoles_list [lreplace $avail_GenericRoles_list $idx $idx]
	}    	
	$listbox_availRoles_generic selection clear 0 end
    	SEUser_Generic_Users::SetEditMode undelete
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::remove_genericRole
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::remove_genericRole { idx } {
	variable listbox_currentRoles_generic
	variable listbox_availRoles_generic	
	variable current_GenericRoles_list
	variable avail_GenericRoles_list
	variable roles_to_be_added
	variable roles_to_be_removed
	
	if { $idx == "" } {
		return
	}
	
	# remove from user_u's current roles
	set role [$listbox_currentRoles_generic get $idx]
	set idx  [lsearch -exact $current_GenericRoles_list $role]
	set current_GenericRoles_list [lreplace $current_GenericRoles_list $idx $idx]
	# and put in available roles list
	set avail_GenericRoles_list [lappend avail_GenericRoles_list $role]
	set avail_GenericRoles_list [lsort $avail_GenericRoles_list]
	set new_idx [lsearch -exact $avail_GenericRoles_list $role]
	# If this is a role in the list of roles to be added then remove it from this list.
	if { [set idx [lsearch -exact $roles_to_be_added $role]] != -1 } {
		set roles_to_be_added [lreplace $SEUser_Generic_Users::roles_to_be_added $idx $idx]
	} else {
		set roles_to_be_removed [lappend roles_to_be_removed $role]
    	}
    	$listbox_availRoles_generic selection set $new_idx
    	$listbox_availRoles_generic see $new_idx
	SEUser_Generic_Users::SetEditMode delete
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::enable_generic_users
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::enable_generic_users { } {
	variable generic_user
    	
    	set ans [tk_messageBox -icon warning -type yesno -title "Adding Special user: $generic_user" \
    		-message \
		    "Warning: Adding the special user $generic_user will \n\
		    mean that any user not explicitly defined to the \n\
		    policy will be able to login to the system.\n\n\
		    Do you wish to continue?" \
		-parent $SEUser_Generic_Users::tabframe]
    	if { $ans == "yes" } {
		SEUser_Generic_Users::SetEditMode enable_generic
    	}
    	
    	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::disable_generic_users
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::disable_generic_users { } {
	variable generic_user
 	
    	set ans [tk_messageBox -icon warning -type yesno -title "Removing Special user: $generic_user" \
    		-message \
		    "Warning: Removing the special user $generic_user will \n\
		    mean that any user not explicitly defined to the \n\
		    policy will not be able to login to the system.\n\n\
		    Do you wish to continue?" \
		-parent $SEUser_Generic_Users::tabframe]
    	if { $ans == "yes" } {
		SEUser_Generic_Users::SetEditMode disable_generic
	} 
	    		
 	return 0   
}    

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::cancel
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::cancel { } {
	variable state
	
	if { $state(edit) != 1 } {
		return
	}	
	switch -- $state(edit_type) {
		delete {
		    	SEUser_Generic_Users::unremove_genericRole
		}
		add {
		    	SEUser_Generic_Users::unadd_genericRoles
		}
		disable_generic {
		    	SEUser_Generic_Users::undo_disabled_state
		}
		enable_generic {
			SEUser_Generic_Users::undo_enabled_state
		}
		default {
			return -code error
		}
	}
	
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::commit
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::commit { } {
	variable generic_user
	variable current_GenericRoles_list
	variable state
	variable generic_user_defined
	
	if { $state(edit) != 1 } {
		tk_messageBox -icon info -type ok -title "Commit info" \
		    -message "There are no changes to commit!"	\
		    -parent $SEUser_Generic_Users::tabframe
		return 
	}

	switch -- $state(edit_type) {
		delete {
			set rt [catch {SEUser_db::change_selinuxUser $generic_user $current_GenericRoles_list 0 \
					"" "" 0 "" ""} err]
			if {$rt != 0} {	
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err" \
					-parent $SEUser_Generic_Users::tabframe
				return -1
			} 	
		}
		add {
			set rt [catch {SEUser_db::change_selinuxUser $generic_user $current_GenericRoles_list 0 \
					"" "" 0 "" ""} err]
			if {$rt != 0} {	
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err" \
					-parent $SEUser_Generic_Users::tabframe
				return -1
			} 
		}
		disable_generic {
			set rt [catch {SEUser_db::remove_selinuxUser $generic_user} err]
			if { $rt != 0 } {
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err" \
					-parent $SEUser_Generic_Users::tabframe
				return -1
			} 
			set generic_user_defined 0
		}
		enable_generic {
			set rt [catch {SEUser_db::add_selinuxUser $generic_user $current_GenericRoles_list 0 "" "" 0 "" ""} err]
			if { $rt != 0 } {
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err" \
					-parent $SEUser_Generic_Users::tabframe
				return -1
			} 
			set generic_user_defined 1
		}
		default {
			return -code error
		}
	}	
	# reset state
	SEUser_Generic_Users::SetEditMode commit
 	SEUser_Top::initialize
	return 0
}         

####################
#  Worker Methods  #
####################

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::initialize
#
#  Description: Performs dialog initialization 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::initialize { } {
	variable avail_GenericRoles_list
	variable generic_user
	variable current_GenericRoles_list
	variable generic_user_defined
	
	SEUser_Generic_Users::reset_variables
	set selinuxUsers_list [SEUser_db::get_list seUsers]
	set avail_GenericRoles_list [SEUser_db::get_list roles]

	# Check if user_u is defined in the policy
	if { [lsearch -exact $selinuxUsers_list $generic_user] != -1 } {
		set generic_user_defined 1
		# Set the current roles for the generic user 
		set current_GenericRoles_list [SEUser_db::get_user_roles $generic_user]
		
		# Need to figure out how to directly modify the global list variables from within this proc
		SEUser_Top::check_list_for_redundancy "avail_GenericRoles_list" "current_GenericRoles_list"
	} else {
		set generic_user_defined 0
	}
	SEUser_Generic_Users::SetEditMode init
	
	return 0
}  

# -----------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::SetEditMode 
#
#  Description: 
# -----------------------------------------------------------------------------------
proc SEUser_Generic_Users::SetEditMode { mode } {
	variable state
	variable roles_to_be_added
	variable roles_to_be_removed
		
	switch -- $mode {
		delete {
		    set state(edit) 1
		    set state(edit_type) "delete"
		    set state(roles_changed) [expr $state(roles_changed) + 1]
		}
		undelete {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(roles_changed) [expr $state(roles_changed) - 1]
		    set roles_to_be_removed 	""
		}
		add {
		    if { $state(edit_type) == "enable_generic" } {
		    	return 
		    }
		    set state(edit) 1
		    set state(edit_type) "add"
		    set state(roles_changed) [expr $state(roles_changed) + 1]
		}
		unadd {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(roles_changed) [expr $state(roles_changed) - 1]
		    set roles_to_be_added 	""
		}
		commit {
		    set state(edit) 0
		    set state(edit_type) "none"
		    # Reset roles to be added and roles to be removed lists.
		    set roles_to_be_added 	""
		    set roles_to_be_removed 	""
		}
		init {
		    set state(edit) 0
		    set state(edit_type) "none"
		    set state(roles_changed) 0
		}
		disable_generic {
			set state(edit) 1
			set state(edit_type) "disable_generic"
			set state(user_u_changed) 1
		} 
		enable_generic {
			set state(edit) 1
			set state(edit_type) "enable_generic"
			set state(user_u_changed) 1
		}
		default {
		    return -code error
		}
	}
	SEUser_Generic_Users::configure_widget_states
	return 0		
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::disable_genericWidgets
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::disable_genericWidgets { } {
	variable r_add_generic
	variable r_remove_generic
	variable listbox_availRoles_generic
	variable listbox_currentRoles_generic
	
	$listbox_availRoles_generic selection clear 0 end
	$listbox_currentRoles_generic selection clear 0 end
	$r_add_generic configure -state disabled
	$r_remove_generic configure -state disabled
	SEUser_Top::disable_tkListbox $listbox_availRoles_generic
	SEUser_Top::disable_tkListbox $listbox_currentRoles_generic
	$listbox_availRoles_generic configure -bg $SEUser_Top::default_bg_color
	$listbox_currentRoles_generic configure -bg $SEUser_Top::default_bg_color	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::enable_genericWidgets
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::enable_genericWidgets { } {
	variable r_add_generic
	variable r_remove_generic
	variable listbox_availRoles_generic
	variable listbox_currentRoles_generic
	variable current_GenericRoles_list
	variable avail_GenericRoles_list
	
	$r_add_generic configure -state normal
	$r_remove_generic configure -state normal
	SEUser_Top::enable_tkListbox $listbox_availRoles_generic
	SEUser_Top::enable_tkListbox $listbox_currentRoles_generic
	$listbox_availRoles_generic configure -bg white 
	$listbox_currentRoles_generic configure -bg white 
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::undo_disabled_state
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::undo_disabled_state { } {
	variable b_generic
	variable status_text
	variable roles_to_be_removed
	variable current_GenericRoles_list
	variable avail_GenericRoles_list
	
	SEUser_Generic_Users::enable_genericWidgets
	foreach role $roles_to_be_removed {
		set idx  [lsearch -exact $avail_GenericRoles_list $role]
		set avail_GenericRoles_list [lreplace $avail_GenericRoles_list $idx $idx]
		# and put in assigned roles list
		set current_GenericRoles_list [lappend current_GenericRoles_list $role]
		set current_GenericRoles_list [lsort $current_GenericRoles_list]
	}
	set status_text "Press 'Disable' button to disable generic users"
	$b_generic configure -state normal
	SEUser_Advanced::change_tab_state normal
	SEUser_Advanced::change_buttons_state 0
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::undo_enabled_state
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::undo_enabled_state { } {
	variable b_generic
	variable status_text
	
	SEUser_Generic_Users::disable_genericWidgets
	set status_text "Press 'Enable' button to enable generic users"
	$b_generic configure -state normal
	SEUser_Advanced::change_tab_state normal
	SEUser_Advanced::change_buttons_state 0
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::change_to_enabled_state
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::change_to_enabled_state { } {
	variable b_generic
	variable status_text
	
	SEUser_Generic_Users::enable_genericWidgets
	set status_text "Press 'Commit' button to commit changes\nor 'Cancel' to undo changes."
	$b_generic configure -state disabled
	SEUser_Advanced::change_tab_state disabled
	SEUser_Advanced::change_buttons_state 1
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::change_to_disabled_state
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::change_to_disabled_state { } {
	variable b_generic
	variable status_text
	variable roles_to_be_removed
	variable current_GenericRoles_list
	variable avail_GenericRoles_list		
	
	SEUser_Generic_Users::disable_genericWidgets
	foreach role $current_GenericRoles_list {
		set idx  [lsearch -exact $current_GenericRoles_list $role]
		set current_GenericRoles_list [lreplace $current_GenericRoles_list $idx $idx]
		# and put in available roles list
		set avail_GenericRoles_list [lappend avail_GenericRoles_list $role]
		set avail_GenericRoles_list [lsort $avail_GenericRoles_list]
		lappend roles_to_be_removed $role
	}
	
    	set status_text "Press 'Commit' button to commit changes\nor 'Cancel' to undo changes."
    	$b_generic configure -state disabled
    	SEUser_Advanced::change_tab_state disabled
	SEUser_Advanced::change_buttons_state 1
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::configure_widget_states
#
#  Description: 
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::configure_widget_states { } {
	variable state
	variable generic_user_defined
	variable b_generic
	variable status_text
	
	switch $state(edit_type) {
		delete {
			$b_generic configure -state disabled
		    	SEUser_Advanced::change_tab_state disabled
			SEUser_Advanced::change_buttons_state 1
		}
		add {
			$b_generic configure -state disabled
		    	SEUser_Advanced::change_tab_state disabled
			SEUser_Advanced::change_buttons_state 1
		}
		disable_generic {
		    	SEUser_Generic_Users::change_to_disabled_state
		}
		enable_generic {
			SEUser_Generic_Users::change_to_enabled_state
		}
		none {
			if { $generic_user_defined } {
				$b_generic configure -state normal -helptext "Disable generic users"
				set SEUser_Generic_Users::b_generic_label_text "Disable"		
				set SEUser_Generic_Users::status "Status: Enabled"
				set status_text "Press 'Disable' button to disable generic users"
				SEUser_Generic_Users::enable_genericWidgets
			} else {
				$b_generic configure -state normal -helptext "Enable generic users"
				set SEUser_Generic_Users::b_generic_label_text "Enable"
				set SEUser_Generic_Users::status "Status: Disabled"
				set status_text "Press 'Enable' button to enable generic users"
				SEUser_Generic_Users::disable_genericWidgets
			}
			SEUser_Advanced::change_tab_state normal
			SEUser_Advanced::change_buttons_state 0
		}
		default {
		   	return -code error
		}
	} 
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::reset_variables
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::reset_variables { } {
	# List variables
 	set SEUser_Generic_Users::current_GenericRoles_list	""
	set SEUser_Generic_Users::avail_GenericRoles_list	""
	set SEUser_Generic_Users::roles_to_be_added		""
	set SEUser_Generic_Users::roles_to_be_removed		""
	
	# state variables
	set SEUser_Generic_Users::state(edit) 			0
	set SEUser_Generic_Users::state(edit_type) 		"none"
	set SEUser_Generic_Users::state(roles_changed) 		0
	set SEUser_Generic_Users::state(user_u_changed) 	0
	
	# Miscellaneous variables
	set SEUser_Generic_Users::b_generic_label_text		""
	set SEUser_Generic_Users::generic_user_defined		0
	
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::close
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::close { } {
	SEUser_Generic_Users::reset_variables
	# Unset the entire state array
	array unset SEUser_Generic_Users::state	
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::leave_tab
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::leave_tab { } {
	variable generic_user_mcntr
	set generic_user_mcntr [SEUser_db::get_mod_cntr]
	return 0
}  

# ------------------------------------------------------------------------------
#  Command SEUser_Generic_Users::enter_tab
#
#  Description:  
# ------------------------------------------------------------------------------
proc SEUser_Generic_Users::enter_tab { } {
	variable generic_user_mcntr
	if { [SEUser_db::get_mod_cntr] != $generic_user_mcntr } {
		SEUser_Generic_Users::initialize 
	}
	return 0
}  

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             