#!/usr/local/bin/selinux/awish

# Copyright (C) 2002 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
#
# Authors: don.patterson@tresys.com, mayerf@tresys.com


##############################################################
# ::SE_User
#  
# SE Linux User Manager
##############################################################
#  Index of commands:
#     - SE_User::SetEditMode
#     - SE_User::edit_type_disable_enable
#     - SE_User::updateStatusBar
#     - SE_User::add_change_disable_enable
#     - SE_User::delete_disable_enable
#     - SE_User::view_mode_enable_disable
#     - SE_User::SeLinuxUsers_Selection
#     - SE_User::sysUsers_Selection
#     - SE_User::check_list_for_redundancy
#     - SE_User::_getIndexValue
#     - SE_User::_mapliste
#     - SE_User::_create_dropdown_list
#     - SE_User::setSelection
#     - SE_User::ClearCurrUserInfo
#     - SE_User::ClearView
#     - SE_User::CheckSeUserHighlights
#     - SE_User::initialize
#     - SE_User::PopulateTypeContextList
#     - SE_User::PopulateRoleContextList
#     - SE_User::unremoveUser
#     - SE_User::removeUser
#     - SE_User::unaddUser
#     - SE_User::unchangeUser
#     - SE_User::addUser
#     - SE_User::addRole
#     - SE_User::removeRole
#     - SE_User::ShowUserInfo
#     - SE_User::refresh
#     - SE_User::se_exit
#     - SE_User::commit
#     - SE_User::cancel
#     - SE_User::createMainFrame
#     - SE_User::createUsersFrame
#     - SE_User::createRolesFrame
#     - SE_User::createDefaultContextFrame
#     - SE_User::createMainButtons
#     - SE_User::unimplemented
#     - SE_User::aboutBox
#     - SE_User::helpDlg
#     - SE_User::viewMakeResults 
#     - SE_User::readFile
#     - SE_User::display_splashScreen
#     - SE_User::destroy_splashScreen
#     - SE_User::create_splashDialog
#     - SE_User::splashUpdate
#     - SE_User::main
###############################################################

namespace eval SE_User {
    variable opts
    set opts(dflt_login_cxt)             1
    set opts(dflt_cron_cxt)              0
    variable gui_ver		"0.4"
    variable mainframe
    variable status ""
    variable sysUsers_list ""
    variable selinuxUsers_list ""      
    variable currentRoles_list ""
    variable type_list
    # this is the var attached to the listbox
    variable availRoles_list ""
    # this is the var holding the original copy
    variable allRoles_list ""
    variable all_sysUsers_list ""
    variable usr_login ""
    variable role_login ""
    variable type_login ""
    variable usr_cron ""
    variable role_cron ""
    variable type_cron ""
    variable stateText ""
    # Variable used to define the the help file.
    variable helpFilename ""

    ####################
    # Global Widget(s) #
    ####################
    # Listboxes
    variable listbox_SeLinuxUsers
    variable listbox_sysUsers
    variable listbox_availRoles
    variable listbox_currentRoles
    # Combo Boxes
    variable combo_login_role
    variable combo_login_type
    variable combo_cron_role
    variable combo_cron_type
    # Buttons
    variable u_add
    variable u_remove
    variable r_add
    variable r_remove
    variable b_exit
    variable b_refresh
    variable b_cancel
    variable b_commit
    # Checkboxes
    variable cb_login_cxt
    variable cb_cron_cxt
    # Entry widgets
    variable entry_user_login
    variable entry_user_cron
    # Top level dialog windows
    variable make_resultsDlg
    set make_resultsDlg .make_resultsDlg
    variable helpDlg 
    set helpDlg .helpDlg
    variable splashDlg
    set splashDlg .splash
    variable progressMsg ""
    
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
    # TODO: We don't quite have logic for tracking changes to users files.  users_changed will indicate
    #	if any changes occured during the entire edit session.  This allows us to re-install the policy
    #	on exit.  It is also used on REFRESH to determine whether to re-build policy.conf before
    #	refreshing.  This leaves us in the situation of possibly having policy.conf being unecessarily
    #	re-built on REFRESH because users_changed won't get reset until exit, yet changes between
    #	refreshes may not have effect user file (but policy.conf will be rebuilt anyway).  We
    #	probably need to introduce another variable (user_fresh) to track state between refreshes
    
    variable modified_user "none"
    
    # Misc
    variable empty_string "<none>"
    
    variable tmpfile ""
    
    variable use_old_login_context_style 0

}

# -----------------------------------------------------------------------------------
#  Command SE_User::SetEditMode 
#
#  Description: Sets important state variables based on the mode argument. 
#		Also, makes the proc calls to update the status bar and then perform   
#		disabling/enabling of widgets.
# -----------------------------------------------------------------------------------
proc SE_User::SetEditMode { mode } {
    variable state
    variable modified_user
    variable usr_login
    variable listbox_SeLinuxUsers
    
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
	    	# Note: Need to call here because default context checkbuttons will not perform disabling/enabling when in
	    	# "add" mode.
	    	SE_User::add_change_disable_enable
		return
	    }
	    # Grab the modified user from the list box.
	    # This will only invoked if this is the first time we do a change.
	    if { $state(edit) == 0 } {
	    	set idx [$listbox_SeLinuxUsers curselection]
		set modified_user [$listbox_SeLinuxUsers get $idx]
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
	refresh {
	    set state(edit) 0
	    set state(edit_type) "none"
	    set state(roles_changed) 0		}
	init {
	    set state(edit) 0
	    set state(users_changed) 0
	    set state(edit_type) "none"
	    set state(roles_changed) 0
	}
	default {
	    tk_messageBox -icon error -type ok -title "Error" -message "Invalid Edit Mode!"
	    return
	}
    }

    SE_User::updateStatusBar
    SE_User::edit_type_disable_enable
    # Updates the highlights for the seusers.
    SE_User::CheckSeUserHighlights
    return 0		
}

# -------------------------------------------------------------------------------
#  Command SE_User::edit_type_disable_enable 
#
#  Description: Makes procedure calls for the disabling/enabling of widgets based 
#		on the edit type.
# -------------------------------------------------------------------------------
proc SE_User::edit_type_disable_enable { } { 
	variable state
	variable entry_user_login
	variable entry_user_cron  
    
	if { $SE_User::use_old_login_context_style } { 
		if { $state(edit) } {
			$entry_user_login configure -state disabled 
			$entry_user_cron configure -state disabled
		}
	}
	
	switch $state(edit_type) {
		delete {
		    SE_User::delete_disable_enable
		}
		add {
		    SE_User::add_change_disable_enable
		}
		change {
		    SE_User::add_change_disable_enable
		}
		none {
		    SE_User::view_mode_enable_disable
		}
	} 
	
	return 0	
}

# ------------------------------------------------------------------------------
#  Command SE_User::updateStatusBar
#
#  Description: Updates the status bar to the current mode (View or Edit)
# ------------------------------------------------------------------------------
proc SE_User::updateStatusBar { } {
    variable mainframe
    variable stateText

    if { $SE_User::state(edit) } {
	set stateText "Edit Mode"
    } else {
	set stateText "View Mode"
    }        
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::add_change_disable_enable
#
#  Description: Performs disabling/enabling of widgets during an edit of 
#		type "add" or "change"
# ------------------------------------------------------------------------------
proc SE_User::add_change_disable_enable { } {
    variable state
    
    if { $state(edit) == 1 } {
	$SE_User::u_add configure -state disabled 
	$SE_User::u_remove configure -state disabled 
	$SE_User::b_exit configure -state disabled
	$SE_User::b_refresh configure -state disabled
	$SE_User::b_commit configure -state normal
	$SE_User::b_cancel configure -state normal
	$SE_User::r_add configure -state normal
	$SE_User::r_remove configure -state normal
	
	if { $SE_User::use_old_login_context_style } {
		$SE_User::cb_login_cxt configure -state normal
		$SE_User::cb_cron_cxt configure -state normal
		$SE_User::entry_user_login configure -state disabled -disabledforeground black
		$SE_User::entry_user_cron configure -state disabled -disabledforeground black
		
		if { $SE_User::opts(dflt_login_cxt) == 1 } {
	    		$SE_User::combo_login_role configure -state normal
	    		$SE_User::combo_login_type configure -state normal
	    	} else {
	    		$SE_User::combo_login_role configure -state disabled
	    		$SE_User::combo_login_type configure -state disabled
	    	}
	    	if { $SE_User::opts(dflt_cron_cxt) == 1 } {
	   		$SE_User::combo_cron_role configure -state normal
	    		$SE_User::combo_cron_type configure -state normal
	   	} else {
	    		$SE_User::combo_cron_role configure -state disabled
	   	 	$SE_User::combo_cron_type configure -state disabled
	   	}
	}
	
	bind currentRoles_Tag <Button-1> {
	    #Begins the process of making a selection in the listbox.  
	    tkListboxBeginSelect %W [%W index @%x,%y]
	}
	bind availRoles_Tag <Button-1> {
	    #Begins the process of making a selection in the listbox.  
	    tkListboxBeginSelect %W [%W index @%x,%y]
	}
	bind sysUsers_Tag <Button-1> " "
	bind SeLinuxUsers_Tag <Button-1> " "	
    }  
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::delete_disable_enable
#
#  Description: Performs disabling/enabling of widgets during an edit of 
#		type "delete"
# ------------------------------------------------------------------------------
proc SE_User::delete_disable_enable { } {
    variable state  
    if { $state(edit) == 1 } {
    	if { $SE_User::use_old_login_context_style } { 
		$SE_User::cb_login_cxt configure -state disabled
		$SE_User::cb_cron_cxt configure -state disabled
		$SE_User::entry_user_login configure -state disabled -disabledforeground black
		$SE_User::entry_user_cron configure -state disabled  -disabledforeground black
		$SE_User::combo_login_role configure -state disabled
		$SE_User::combo_login_type configure -state disabled
		$SE_User::combo_cron_role configure -state disabled
		$SE_User::combo_cron_type configure -state disabled
		
		bind login_typeTag <KeyPress> " "
		bind login_roleTag <KeyPress> " "
		bind cron_roleTag  <KeyPress> " "
	    	bind cron_typeTag  <KeyPress> " "
	}
	
	$SE_User::u_add configure -state disabled 
	$SE_User::u_remove configure -state disabled 
	$SE_User::r_add configure -state disabled 
	$SE_User::r_remove configure -state disabled 
	$SE_User::b_exit configure -state disabled
	$SE_User::b_refresh configure -state disabled
	$SE_User::b_commit configure -state normal
	$SE_User::b_cancel configure -state normal
	
	bind sysUsers_Tag <Button-1> " " 	
	bind SeLinuxUsers_Tag <Button-1> " "
	bind currentRoles_Tag <Button-1> " " 	
	bind availRoles_Tag <Button-1> " "
    } 
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::view_mode_enable_disable
#
#  Description: Performs disabling/enabling of widgets during view mode
# ------------------------------------------------------------------------------
proc SE_User::view_mode_enable_disable { } {
    variable state
    if { $state(edit) == 0 } {
    	if { $SE_User::use_old_login_context_style } { 
	    	$SE_User::cb_login_cxt configure -state disabled
	    	$SE_User::cb_cron_cxt configure -state disabled
	    	$SE_User::entry_user_login configure -state disabled -disabledforeground black
    		$SE_User::entry_user_cron configure -state disabled -disabledforeground black
    		$SE_User::combo_login_role configure -state disabled
	   	$SE_User::combo_login_type configure -state disabled
	   	$SE_User::combo_cron_role configure -state disabled
	   	$SE_User::combo_cron_type configure -state disabled
   	
	    	if { $SE_User::opts(dflt_login_cxt) == 1 } {
	    		$SE_User::cb_login_cxt deselect
	    	}
	    	if { $SE_User::opts(dflt_cron_cxt) == 1 } {
	    		$SE_User::cb_cron_cxt deselect
	    	}
	    	
	    	bind login_typeTag <KeyPress> " "
	   	bind login_roleTag <KeyPress> " "	
	   	bind cron_roleTag  <KeyPress> " "
	   	bind cron_typeTag  <KeyPress> " "
    	}
    	
   	$SE_User::u_add configure -state normal
   	$SE_User::u_remove configure -state normal
   	$SE_User::r_add configure -state disabled 
  	$SE_User::r_remove configure -state disabled 
  	$SE_User::b_exit configure -state normal
  	$SE_User::b_refresh configure -state normal
  	$SE_User::b_commit configure -state disabled
  	$SE_User::b_cancel configure -state disabled
   	$SE_User::listbox_SeLinuxUsers selection clear 0 end
   	$SE_User::listbox_sysUsers selection clear 0 end
   	$SE_User::listbox_availRoles selection clear 0 end
   	$SE_User::listbox_currentRoles selection clear 0 end
   	
   	bind SeLinuxUsers_Tag <Button-1> { SE_User::SeLinuxUsers_Selection %W %x %y } 
   	bind sysUsers_Tag <Button-1> { SE_User::sysUsers_Selection %W %x %y }
   	bind currentRoles_Tag <Button-1> " " 	
   	bind availRoles_Tag <Button-1> " "
   	
    }
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::SeLinuxUsers_Selection
#
#  Description: This procedure is binded to SE_User::listbox_SeLinuxUsers and is 
#		typically invoked on button-1 presses. It begins the process of 
#		making a selection in the listbox and performs "enabling" of
#		Roles and Default Contexts widgets and their bindings.
# ------------------------------------------------------------------------------
proc SE_User::SeLinuxUsers_Selection { path x y } {
	tkListboxBeginSelect $path [$path index @$x,$y]
	$SE_User::listbox_sysUsers selection clear 0 end
	$SE_User::listbox_availRoles selection clear 0 end
	$SE_User::listbox_currentRoles selection clear 0 end
	set item [$path get [$path nearest $y]]
	SE_User::ShowUserInfo $item 
	
	$SE_User::r_add configure -state normal
	$SE_User::r_remove configure -state normal
	$SE_User::b_exit configure -state normal
	$SE_User::b_refresh configure -state normal
	$SE_User::b_commit configure -state disabled
	$SE_User::b_cancel configure -state disabled
	  
	bind currentRoles_Tag <Button-1> {
		tkListboxBeginSelect %W [%W index @%x,%y]
	}
	bind availRoles_Tag <Button-1> {
		tkListboxBeginSelect %W [%W index @%x,%y]
	}
	
	if { $SE_User::use_old_login_context_style } { 
		$SE_User::cb_login_cxt configure -state normal
		$SE_User::cb_cron_cxt configure -state normal
		$SE_User::entry_user_login configure -state disabled -disabledforeground black
		$SE_User::entry_user_cron configure -state disabled -disabledforeground black
		
		if { $SE_User::opts(dflt_login_cxt) == 1 } {
			$SE_User::combo_login_role configure -state normal
			$SE_User::combo_login_type configure -state normal
		} else {
			$SE_User::combo_login_role configure -state disabled
			$SE_User::combo_login_type configure -state disabled
		}
		if { $SE_User::opts(dflt_cron_cxt) == 1 } {
			$SE_User::combo_cron_role configure -state normal
			$SE_User::combo_cron_type configure -state normal
		} else {
			$SE_User::combo_cron_role configure -state disabled
			$SE_User::combo_cron_type configure -state disabled
		}
		
		SE_User::PopulateRoleContextList $SE_User::combo_login_role
		SE_User::PopulateRoleContextList $SE_User::combo_cron_role
		SE_User::PopulateTypeContextList $SE_User::role_login $SE_User::combo_login_type
		SE_User::PopulateTypeContextList $SE_User::role_cron $SE_User::combo_cron_type  
	
		bind login_roleTag <KeyPress> { SE_User::_create_dropdown_list $SE_User::combo_login_role %W %K roles}
		bind login_typeTag <KeyPress> { SE_User::_create_dropdown_list $SE_User::combo_login_type %W %K types}
		bind cron_roleTag  <KeyPress> { SE_User::_create_dropdown_list $SE_User::combo_cron_role %W %K roles}
		bind cron_typeTag  <KeyPress> { SE_User::_create_dropdown_list $SE_User::combo_cron_type %W %K types}
	}	
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::sysUsers_Selection
#
#  Description: This procedure is binded to SE_User::listbox_sysUsers and is 
#		typically invoked on button-1 presses. It begins the process of 
#		making a selection in the listbox and performs "disabling" of
#		Roles and Default Contexts widgets and their bindings.
# ------------------------------------------------------------------------------
proc SE_User::sysUsers_Selection { path x y } {
	# This procedure is typically invoked on button-1 presses.  It begins
	# the process of making a selection in the listbox. 
	tkListboxBeginSelect $path [$path index @$x,$y]
	$SE_User::listbox_SeLinuxUsers selection clear 0 end
	SE_User::ClearCurrUserInfo
	
	if { $SE_User::use_old_login_context_style } {
		$SE_User::cb_login_cxt configure -state disabled
		$SE_User::cb_cron_cxt configure -state disabled
		$SE_User::entry_user_login configure -state disabled -disabledforeground black
		$SE_User::entry_user_cron configure -state disabled -disabledforeground black
		$SE_User::combo_login_role configure -state disabled
		$SE_User::combo_login_type configure -state disabled
		$SE_User::combo_cron_role configure -state disabled
		$SE_User::combo_cron_type configure -state disabled
	
		if { $SE_User::opts(dflt_login_cxt) == 1 } {
			$SE_User::cb_login_cxt deselect
		}
		if { $SE_User::opts(dflt_cron_cxt) == 1 } {
			$SE_User::cb_cron_cxt deselect
		}
		
		bind login_typeTag <KeyPress> " "
		bind login_roleTag <KeyPress> " "
		bind cron_roleTag  <KeyPress> " "
		bind cron_typeTag  <KeyPress> " "
	}		
	
	$SE_User::r_add configure -state disabled
	$SE_User::r_remove configure -state disabled
	$SE_User::b_exit configure -state normal
	$SE_User::b_refresh configure -state normal
	$SE_User::b_commit configure -state disabled
	$SE_User::b_cancel configure -state disabled
	
	bind currentRoles_Tag <Button-1> " "
	bind availRoles_Tag <Button-1> " "
	
    	return 0
}

# ----------------------------------------------------------------------------------------
#  Command SE_User::check_list_for_redundancy
#
#  Description: "Checks" System Users list for elements in SE Linux Users list.
#		Also, "checks" Available Roles list for elements in Current Roles list.
#		If a matching element is found in the list being "checked", it is deleted.
# ----------------------------------------------------------------------------------------
proc SE_User::check_list_for_redundancy { target_listbox compare_listbox compare_list} {    
    # Returns a count of the number of elements in the listbox (not the index of the last element). 
    set lastElement [$target_listbox index end]

    # Gets each element in compare_list and then loops through target_list looking for any matches. If 
    # an element in the target_list matches the current value of the compare_list, it is deleted.
    foreach compare_listValue $compare_list {	
	for { set idx 0 } { $idx != $lastElement } { incr idx } {
	    set target_listValue [$target_listbox get $idx]
	    if { [string match $target_listValue "$compare_listValue"] } {
		$target_listbox delete $idx
	    }
	}	
    }
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::_getIndexValue
#
#  Description: Searches through values in the combobox and returns the index 
# 		of the first matching value. If no matches are found, returns -1
# ------------------------------------------------------------------------------
proc SE_User::getIndexValue { path value contextType } { 
    variable currentRoles_list
    variable type_list
    if { $contextType == "roles" } {
    	return [lsearch -glob $currentRoles_list "$value*"]
    } elseif { $contextType == "types" } {
    	return [lsearch -glob $type_list "$value*"]
    }
}

# -------------------------------------------------------------------------------------
#  Command SE_User::_mapliste
#
#  Description: Performs the actual creation of the dropdown list for the combobox. 
#		Note!!: The input focus will follow the mouse and any any key press 
#		or key release events for the display are sent to the window in focus.
# -------------------------------------------------------------------------------------
proc SE_User::_mapliste { path } {
    set listb $path.shell.listb
    if {[winfo exists $path.shell] &&
        ![string compare [wm state $path.shell] "normal"]} {
    	ComboBox::_unmapliste $path
        return
    }

    if { [Widget::cget $path -state] == "disabled" } {
        return
    }
    if { [set cmd [Widget::getMegawidgetOption $path -postcommand]] != "" } {
        uplevel \#0 $cmd
    }
    if { ![llength [Widget::getMegawidgetOption $path -values]] } {
        return
    }

    ComboBox::_create_popup $path
    ArrowButton::configure $path.a -relief sunken
    update

    $listb selection clear 0 end
    BWidget::place $path.shell [winfo width $path] 0 below $path
    wm deiconify $path.shell
    raise $path.shell
    BWidget::grab global $path
    #Note: at present there is no built-in support for returning the application to an explicit 
    #focus model; to do this you'll have to write a script that deletes the bindings created 
    #by tk_focusFollowsMouse.
    #tk_focusFollowsMouse
    return $listb
}

# ---------------------------------------------------------------------------------
#  Command SE_User::_create_dropdown_list
#
#  Description: This procedure is binded to comboboxes and is typically invoked
#		when a key is pressed. Makes the procedure calls for AUTO SEARCHING
#		and creating the dropdown_list of values for the combobox.
# ----------------------------------------------------------------------------------
proc SE_User::_create_dropdown_list { path entryBox key contextType } { 
    SE_User::SetEditMode change
    # Getting value from the entry subwidget of the combobox and then checking its' length
    set value  [Entry::cget $path.e -text]
    set len [string length $value]
 
    # If the length is zero, remove drop-down list window
    if {$len == 0} {
	ComboBox::_unmapliste $path
	return
    } 
    # Switch statement which handles the key pressed and performs the auto searching
    switch $key {
	Shift_L {
	    return
	}
	Shift_R {
	    return
	}
	Tab {
	    return
	}
	Ctrl {
	    return
	}
	BackSpace {
	    ComboBox::_unmapliste $path
	    set last [$entryBox index $len]
	    $entryBox delete $last end
	    $entryBox icursor $last
	    set idx [ SE_User::getIndexValue $path $value $contextType ]  
	}
	default {
	    ComboBox::_unmapliste $path
	    set idx [ SE_User::getIndexValue $path $value $contextType ]  
	}
    }
    # Calling setSelection function
    SE_User::setSelection $idx $path $entryBox $key

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::setSelection
#
#  Description: If the index value returned by SE_User::getIndexValue is not -1,
#		this procedure sets the selection in the dropdown list for the
#		combobox to that index value.
# ------------------------------------------------------------------------------
proc SE_User::setSelection { idx path entryBox key } {
    if {$idx != -1} {
	set listb [SE_User::_mapliste $path]
	$listb selection set $idx
	$listb activate $idx
	$listb see $idx
    } 
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::ClearCurrUserInfo
# ------------------------------------------------------------------------------
proc SE_User::ClearCurrUserInfo { } {
    variable usr_login 
    variable role_login
    variable type_login 
    variable usr_cron 
    variable role_cron 
    variable type_cron 	
    variable currentRoles_list
    variable availRoles_list
    variable allRoles_list
    
    set usr_login ""
    set role_login ""
    set type_login ""
    set usr_cron ""
    set role_cron ""
    set type_cron ""
    set currentRoles_list ""
    
    # reset the avail role list to the whole list   
    set allRoles_list [lsort $allRoles_list]
    set availRoles_list $allRoles_list     	

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::ClearView
#
#  Description: Called by SE_User::refresh procedure
# ------------------------------------------------------------------------------
proc SE_User::ClearView { } {
    variable sysUsers_list
    variable selinuxUsers_list
    variable availRoles_list
    
    SE_User::ClearCurrUserInfo
    set sysUsers_list ""
    set selinuxUsers_list ""
    set availRoles_list ""
    
    return 0
}

# ----------------------------------------------------------------------------------
#  Command SE_User::CheckSeUserHighlights
#
#  Description: Performs highlighting in the selinuxUsers_list. If the selinux_User 
#		is not a valid SE Linux User .. highlight red. If selinux_User is 
#		not a valid system user ... highlight yellow. Ignore the special
#		special user "system_u" and "user_u"
# ----------------------------------------------------------------------------------
proc SE_User::CheckSeUserHighlights { } {
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
#  Command SE_User::initialize
#
#  Description: Performs application initialization 
# ------------------------------------------------------------------------------
proc SE_User::initialize { mode } {
    variable sysUsers_list
    variable selinuxUsers_list
    variable availRoles_list
    variable currentRoles_list
    variable allRoles_list
    variable all_sysUsers_list
    variable listbox_SeLinuxUsers
    variable listbox_sysUsers
    variable state
    variable tmpfile
    variable progressMsg
    variable use_old_login_context_style
	
    # Get temporary makefile name
    set rt [catch {set tmpfile [seuser_GetTmpMakeFileName]} err]
    if {$rt != 0} {
      	tk_messageBox -icon error -type ok -title "Error" -message "$err"
      	return
    }
	
    # Set system users list
    set rt [catch {set all_sysUsers_list [seuser_GetSysUsers]} err]
    if {$rt != 0} {
      	tk_messageBox -icon error -type ok -title "Error" -message "$err"
      	return
    }
	
    # add the special user "user_u" to the list
    lappend all_sysUsers_list "user_u"
    set all_sysUsers_list [lsort $all_sysUsers_list]
    set sysUsers_list $all_sysUsers_list
    
    # SE Linux users
    set rt [catch {set selinuxUsers_list [seuser_GetSeUserNames]} err]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" -message "$err"
	return 
    }
    set selinuxUsers_list [lsort $selinuxUsers_list]
	
    # Available Roles
    set rt [catch {set allRoles_list [apol_GetNames roles]} err]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" -message "$err"
	return 
    }    
    set allRoles_list [lsort $allRoles_list]
    set availRoles_list $allRoles_list    
      
    # The following function checks for redundancy in lists
    SE_User::check_list_for_redundancy $listbox_sysUsers $listbox_SeLinuxUsers $selinuxUsers_list
    SE_User::SetEditMode $mode
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::PopulateTypeContextList
# ------------------------------------------------------------------------------
proc SE_User::PopulateTypeContextList { role combo } {
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
#  Command SE_User::PopulateRoleContextList
# ------------------------------------------------------------------------------
proc SE_User::PopulateRoleContextList { combo } {
    variable currentRoles_list
    $combo configure -values $currentRoles_list
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::unremoveUser
#
#  Description: This procedure is called by SE_User::cancel
# ------------------------------------------------------------------------------
proc SE_User::unremoveUser { } {
    variable state
    variable modified_user
    variable selinuxUsers_list
    variable sysUsers_list
    variable all_sysUsers_list
    variable listbox_SeLinuxUsers
    variable listbox_sysUsers
    
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
    SE_User::check_list_for_redundancy $listbox_sysUsers $listbox_SeLinuxUsers $selinuxUsers_list
    $listbox_sysUsers selection clear 0 end
    SE_User::SetEditMode undelete
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::removeUser
# ------------------------------------------------------------------------------
proc SE_User::removeUser { idx } {
    variable modified_user
    variable listbox_SeLinuxUsers
    variable listbox_sysUsers
    variable sysUsers_list
    variable all_sysUsers_list
    # If nothing is selected, return
    if { $idx == "" } {
	return
    }
    # Get the selected user to be deleted. If is special system user, popup error message.
    set modified_user [$listbox_SeLinuxUsers get $idx]
    if { $modified_user == "system_u" } {	
	tk_messageBox -icon error -type ok -title "Remove User Error" -message \
	    "The special user: system_u cannot be removed."	
	return
    } elseif { $modified_user == "user_u" } {
    	set answer [tk_messageBox -icon warning -type yesno -title "Removing Special user_u user" -message \
    	    "Warning: Removing the special user user_u will \n\
    	    mean that any user not explicity defined to the \n\
    	    policy will not be able to login to the system.\n\n\
    	    Do you wish to continue?" ]
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
    
    SE_User::ClearCurrUserInfo 
    # Insert name back into sysuser list (if it is indeed a sys user)
    if { [lsearch -exact $all_sysUsers_list "$modified_user"] != -1 } {
	set sysUsers_list [lappend sysUsers_list $modified_user]
	set sysUsers_list [lsort $sysUsers_list]
	set newidx [lsearch -exact $sysUsers_list $modified_user]
	$listbox_sysUsers selection set $newidx	
	$listbox_sysUsers see $newidx
    }
 	
    set state(roles_changed) 1
    SE_User::SetEditMode delete
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::unaddUser
#
#  Description: This procedure is called by SE_User::cancel
# ------------------------------------------------------------------------------
proc SE_User::unaddUser { } {
    variable modified_user	
    variable listbox_sysUsers
    variable listbox_SeLinuxUsers
    variable sysUsers_list
    variable selinuxUsers_list
    variable state
    
    if { $state(edit_type) != "add" } {
	puts stderr "Cannot unadd a user because edit_type is $state(edit_type)"
	return
    }
    # NOTE: Since we're "unadding" we know the modified_user was from the sys_user list,
    #	and therefore we can just reinsert it rather than check to see if it is a
    #	valid system user as is needed in the case of unremove
    #
    # put back into system users
    set sysUsers_list [lappend sysUsers_list $modified_user]
    set sysUsers_list [lsort $sysUsers_list]
    set newidx [lsearch -exact $sysUsers_list $modified_user]
    $listbox_sysUsers selection set $newidx	
    
    # and remove from selinux users
    set idx [lsearch -exact $selinuxUsers_list $modified_user]
    $listbox_SeLinuxUsers delete $idx	
    SE_User::ClearCurrUserInfo 
    SE_User::SetEditMode unadd
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::unchangeUser
#
#  Description: This procedure is called by SE_User::cancel
# ------------------------------------------------------------------------------
proc SE_User::unchangeUser { } {	
    variable state
    
    if { $state(edit_type) != "change" } {
	puts stderr "Cannot unchange a user because edit_type is $state(edit_type)"
	return
    }
    SE_User::ClearCurrUserInfo 
    SE_User::SetEditMode unchange
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::addUser
# ------------------------------------------------------------------------------
proc SE_User::addUser { idx } {
    variable modified_user	
    variable listbox_sysUsers
    variable listbox_SeLinuxUsers
    variable selinuxUsers_list
    variable entry_user_login
    variable entry_user_cron
    variable usr_login 
    variable usr_cron

    if { $idx == "" } {
	return
    }
    
    set modified_user [$listbox_sysUsers get $idx]
    if { $modified_user == "user_u" } {
 	set answer [tk_messageBox -icon warning -type yesno -title "Adding Special user_u user" -message \
    	    "Warning: Adding the special user user_u will \n\
    	    mean that any user not explicity defined to the \n\
    	    policy can login with the roles and default \n\
    	    contexts defined for user_u, and need not be \n\
    	    explictly defined to the policy.\n\n\
    	    Do you wish to continue?" ]
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
    SE_User::ClearCurrUserInfo 
    set usr_login $modified_user
    set usr_cron $modified_user
    SE_User::SetEditMode add		
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::addRole
# ------------------------------------------------------------------------------
proc SE_User::addRole { idx } {
    variable listbox_availRoles
    variable listbox_currentRoles	
    variable currentRoles_list 
    variable availRoles_list
    variable listbox_SeLinuxUsers
    variable modified_user
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
    
    set state(roles_changed) 1

    SE_User::SetEditMode change
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::removeRole
# ------------------------------------------------------------------------------
proc SE_User::removeRole { idx } {
    variable listbox_availRoles
    variable listbox_currentRoles	
    variable currentRoles_list 
    variable availRoles_list
    variable listbox_SeLinuxUsers
    variable modified_user
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
    
    SE_User::SetEditMode change
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::ShowUserInfo
#
#  Description: Displays info for the selected SE Linux user.
# ------------------------------------------------------------------------------
proc SE_User::ShowUserInfo  { username } {
    variable availRoles_list
    variable currentRoles_list
    variable listbox_availRoles
    variable listbox_currentRoles
    variable allRoles_list	
    variable usr_login 
    variable role_login 
    variable type_login 
    variable usr_cron 
    variable role_cron 
    variable type_cron 
    variable opts
    
    variable combo_login_role
    variable combo_login_type
    variable combo_cron_role
    variable combo_cron_type
    variable empty_string
       
    set no_login_context 0	
    
    set rt [catch { set currentRoles_list [seuser_UserRoles $username] } err]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" -message "$err"
	return 
    }
    set currentRoles_list [lsort $currentRoles_list]	
    
    if { $SE_User::use_old_login_context_style } {
	    set usr_login $username
	    set usr_cron $username
  
	    set rt [catch {set context [seuser_UserContext $username 0] } err]
	    if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "Problem with login context\n\n$err"
		return 
	    }
	    scan $context "%s %s" role_login type_login
	    if {$role_login == $empty_string} {
		set no_login_context 1
		set opts(dflt_login_cxt) 0
	    } else {
		set opts(dflt_login_cxt) 1
	    }
	    
	    # cron context
	    set rt [catch {set context [seuser_UserContext $username 1] } err]
	    if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "Problem with cron contet\n\n$err"
		return 
	    }
	    scan $context "%s %s" role_cron type_cron    	
	
	    if {$role_cron == $empty_string } {
		set opts(dflt_cron_cxt)  0		
		#		if {$no_login_context == 1} {
		#			tk_messageBox -icon warning -type ok -title "Warning: Invalid default context" \
		#				-message "User ($username) does not have either a login or cron\n\
		#					default context; all users must have one or both."
		#		}
		
	    } else {
		set opts(dflt_cron_cxt)  1
	    }
    }
    
    set rt [catch {seuser_IsUserValid $username} err]
    if {$rt != 0} {	
	tk_messageBox -icon warning -type ok -title "Warning: Problem with user record" -message "$err"
    }
    
    # The following functions reset the available roles list and then checks for redundancy
    set allRoles_list [lsort $allRoles_list]
    set availRoles_list $allRoles_list    
    SE_User::check_list_for_redundancy $listbox_availRoles $listbox_currentRoles $currentRoles_list

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::refresh
#
#  Description: Clears the view and re-initializes the application.	
# ------------------------------------------------------------------------------
proc SE_User::refresh { } {
    variable state
    global tcl_platform
   
    # Display progress dialog
    set progressval 0
    set progressmsg ""
    set progressBar [ ProgressDlg .progress -parent . -title "Re-making policy..." \
	    -textvariable progressmsg -variable progressval ]
    update  

    # Need to address changes to user_file (i.e., by re-making
    # the policy.conf file if user_file has changed
    if {$state(users_changed) > 0} {	
	set rt [ catch {seuser_RemakePolicyConf } err ]
	if {$rt != 0} {
	    destroy $progressBar
	    set answer [tk_messageBox -icon error -type yesno -title "Error re-making policy.conf with new users" \
	    	-message "$err\n\nPress YES to view make results."]
	    switch -- $answer {
	    	yes {
	    		SE_User::viewMakeResults make
	    		return
	    	}
	    	no 	{return}
	    }	   
	    return 
	}
    }
    
    set rt [ catch { seuser_CloseDatabase } err ]
    if {$rt != 0} {
	destroy $progressBar
	tk_messageBox -icon error -type ok -title "Error" -message "$err"
	return 
    } 
    
    SE_User::ClearView    
    
    # Configure tool and read user database
    set rt [catch [seuser_InitUserdb] err]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" \
		-message "$err\n\nCheck seuser.conf file for correct configuration"
	exit 
    }
    	
    SE_User::initialize refresh  
    # Destroy the progress dialog
    destroy $progressBar

    return 0
}

# -------------------------------------------------------------------------------------------
#  Command SE_User::se_exit
#
#  Description: Checks for changes to the users file. If there no changes, exits gracefully.
#`		If there are changes, ask the user if the policy should be re-made and 
#		installed.
# -------------------------------------------------------------------------------------------
proc SE_User::se_exit { } {
    variable state
    global tcl_platform
    
    # we don't change for uncommitted changes (i.e., state(edit) == 1) since
    # the GUI should not allow the exit button to be available while in 
    # edit mode.
    #
    # users_changed means that committed changes to the users_file has occured,
    # which won't take effect unless the policy is re-made and installed
    if {$state(users_changed) > 0 }  {
	set answer [tk_messageBox -icon question  -type yesnocancel \
		    	-title "Users file changed" -message \
			"There are changes to the users file.  To be effective the policy must be re-made and installed.\n\nDo you want to re-make and install the new policy now?\n\nNO will exit without installing the policy but the policy source files are ready to be built." \
		       ]
	switch -- $answer {
	    no	{ }
	    yes {
		set progressmsg ""
		set progressBar [ ProgressDlg .progress -parent . -title "Re-installing policy..." \
                -textvariable progressmsg -variable progressval ]
		update 
		set rt [catch {seuser_ReinstallPolicy} err]
		if { $rt != 0 } {
		    destroy $progressBar
		    set answer [tk_messageBox -icon error -type yesno -title "Error: Policy not installed" \
		    	-message "$err\n\nPress YES to view make results, NO to exit."]
		    switch -- $answer {
		    	yes {
		    		set rt [SE_User::viewMakeResults install]
		    	}
		    	no 	{ }
		    }
		} else {
		    destroy $progressBar
		    set answer [tk_messageBox -icon info -type yesno -title "Policy was installed" \
		    	-message "Press YES to view make results, NO to exit."]
		    switch -- $answer {
		    	yes {
		    		SE_User::viewMakeResults install
		    	}
		    	no 	{ }
		    }		
		}
	    }
	    cancel	return
	}
    }
    seuser_Exit
    exit
}

proc SE_User::create_MakeDialog { operation } {
    global tcl_platform
    # Building custom dialog window
 	catch {destroy .customDlg}
  	    set w .customDlg
  	    toplevel $w -class Dialog 
  	    wm withdraw $w
  	    wm title $w "Success!"
  	    wm iconname $w Dialog
    	    wm protocol $w WM_DELETE_WINDOW "destroy $w"
    	    if {$tcl_platform(platform) == "windows"} {
        	wm resizable $w 0 0
   	    } else {
		bind $w <Configure> { wm geometry .customDlg {} }
   	    }
    	         	
   	    # Dialog widgets
   	    set main_frame [ frame $w.main_frame ]
   	    set b_frame [ frame $main_frame.b_frame ]
   	    set label [label $main_frame.label -text "Make was successful.\nPlease select VIEW to view make results."]
    	    set okButton [Button $b_frame.okButton -text "OK" -width 6 \
			-command { if { $operation == "refresh" } {destroy $w} else {exit} }]
	    set viewButton [Button $b_frame.viewButton -text "View" -width 6 \
			-command { 
				if { $operation == "refresh" } {
					SE_User::viewMakeResults refresh $w
				} else {
					SE_User::viewMakeResults exitApp $w
				} }]
	
    	    # Placing display widgets
    	    pack $main_frame -fill both -padx 5 -pady 5 -anchor center
    	    pack $b_frame -fill x -pady 5 -side bottom -anchor center
    	    pack $label -side top -fill x
    	    pack $okButton $viewButton -side left -padx 5 -pady 5 -anchor center -expand yes
    	    # Place a toplevel at a particular position
   	    ::tk::PlaceWindow $w widget center
   	    wm deiconify $w
    	    # Set a grab and claim the focus too.
    	    ::tk::SetFocusGrab $w $main_frame
    	    
    	    return 0
}

# ----------------------------------------------------------------------------------
#  Command SE_User::commit
#
#  Description: Commits any changes to the db by first, committing the change to the 
#		im-memory database then, writes the db out to disk. Then sets the 
#		application to view mode. 
# ----------------------------------------------------------------------------------
proc SE_User::commit { } {
    variable state
    variable modified_user
    variable currentRoles_list
    variable opts
    variable role_login 
    variable type_login 
    variable role_cron 
    variable type_cron 
    global tcl_platform
    
    # first commit the change to the im-memory database
    if { $state(edit) != 1 } {
	tk_messageBox -icon warning -type ok -title "Warning" \
	    -message "There are no changes to commit!"		
	return 
    }	
    
    # check for committ access
    set rt [ catch {seuser_CheckCommitAccess } err ]
    if {$rt != 0 } {
	tk_messageBox -icon error -type ok -title "Access Error" -message "$err"
	return 
    }   
    
    if { $SE_User::use_old_login_context_style == 0 } { 
    	set SE_User::opts(dflt_login_cxt)  0
    	set SE_User::opts(dflt_cron_cxt)   0	
    }
    	
    switch -- $state(edit_type) {
	delete {
	    set rt [catch {seuser_RemoveUser $modified_user} err]
	    if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 
	    }			
	}
	add {
	    set rt [catch {seuser_EditUser add $modified_user $currentRoles_list  \
			       $opts(dflt_login_cxt) $role_login $type_login $opts(dflt_cron_cxt) \
			       $role_cron $type_cron} err]
	    if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 
	    }
	    
	}
	change {
	    set rt [catch {seuser_EditUser change $modified_user $currentRoles_list  \
			       $opts(dflt_login_cxt) $role_login $type_login $opts(dflt_cron_cxt) \
			       $role_cron $type_cron} err ]
	    if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
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
		-message "There are no changes to commit!"
	    return
	}		

    }

    # then write the db out to disk
    set rt [catch [ seuser_Commit ] err ]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" -message "$err"
	return 
    } 
    # reset state
    SE_User::SetEditMode commit
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::cancel
#
#  Description: This procedure is associated with the "Cancel" button.
# ------------------------------------------------------------------------------
proc SE_User::cancel { } {
    variable state
    variable modified_user
    
    if { $state(edit) != 1 } {
	return
    }	
    switch -- $state(edit_type) {
	delete {
	    SE_User::unremoveUser
	}
	add {
	    SE_User::unaddUser
	}
	change {
	    SE_User::unchangeUser
	}
	default {
	    return
	}
    }
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::createMainFrame
#
#  Description: Manage toplevel with menu, toolbar and statusbar and buttons. 	
# 		Also, makes the porcedure calls to create each major subframe 
#		and its' widgets.
# ------------------------------------------------------------------------------
proc SE_User::createMainFrame { } {
    #SelectFont::loadfont

    # Menu description
    set descmenu {
        "&Help" {} help 0 {
	    {command "&Help" {all option} "Display Help" {} -command SE_User::helpDlg}
            {command "&About" {all option} "Display About Box" {} -command SE_User::aboutBox}
        }
    }

    set mainframe [MainFrame .mainframe \
                       -menu         $descmenu \
                       -textvariable SE_User::status]		   
    set edit_typeLabel [$mainframe addindicator -textvariable SE_User::state(edit_type) -width 10]
    set stateLabel     [$mainframe addindicator -textvariable SE_User::stateText -width 15]

    # Main Inner Frame creation
    set frame    [$mainframe getframe]
    set t_frame  [frame $frame.t_frame -relief flat -borderwidth 0]
    set b_frame  [frame $frame.b_frame -relief flat -borderwidth 0]
    pack $b_frame -side bottom -fill x -padx 5
    pack $t_frame -side top -fill both -expand yes 
    
    SE_User::createMainButtons $b_frame
    SE_User::createUsersFrame $t_frame
    SE_User::createRolesFrame $t_frame
    
    if { $SE_User::use_old_login_context_style } { 
	    	SE_User::createDefaultContextFrame $t_frame
    }
            
    pack $mainframe -fill both -expand yes
    update idletasks

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::createUsersFrame
#
#  Description: This procedure is called by SE_User::createMainFrame
# ------------------------------------------------------------------------------
proc SE_User::createUsersFrame { mainframe } {
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
    
    pack $user_f -side top -fill both -anchor n -expand yes -padx 5 -pady 2
    pack $lf -side left -anchor w -expand yes
    pack $lf_inner_top -side top -anchor n -fill x
    pack $lf_inner_bot -side bottom -anchor s -fill x -expand yes
    pack $cf -side left -anchor center -expand yes
    pack $rf -side right -anchor e -expand yes
    pack $rf_inner_top -side top -anchor n -fill x
    pack $rf_inner_bot -side bottom -anchor s -fill x -expand yes
    
    # Labels
    set lb_sysUsers   [Label $lf_inner_top.lb_sysUsers -text "System Users"]
    set lb_linuxUsers [Label $rf_inner_top.lb_linuxUsers -text "SE Linux Users"]
    
    # ListBoxes
    set listbox_sysUsers   [listbox [$lf_inner_bot getframe].listbox_sysUsers -height 6 -width 20 \
				-highlightthickness 0 \
				-listvar SE_User::sysUsers_list ] 
    $lf_inner_bot setwidget $listbox_sysUsers
    
    set listbox_SeLinuxUsers [listbox [$rf_inner_bot getframe].listbox_SeLinuxUsers -height 6 \
				  -width 20 -highlightthickness 0 \
				  -listvar SE_User::selinuxUsers_list \
				  -exportselection no]  
    $rf_inner_bot setwidget $listbox_SeLinuxUsers
    
    bindtags $listbox_SeLinuxUsers { $listbox_SeLinuxUsers ListBox SeLinuxUsers_Tag \
					 [winfo toplevel $listbox_SeLinuxUsers] all }
    bindtags $listbox_sysUsers { $listbox_SeLinuxUsers ListBox sysUsers_Tag \
				     [winfo toplevel $listbox_SeLinuxUsers] all }
    
    # Action Buttons
    set u_add [Button $cf.add -text "-->" -width 6 \
		   -command { SE_User::addUser  [$SE_User::listbox_sysUsers curselection]} \
		   -helptext "Add the selected system user to SE Linunx policy"]
    set u_remove [Button $cf.remove -text "<--" -width 6 -command \
		      { SE_User::removeUser [$SE_User::listbox_SeLinuxUsers curselection]} \
		      -helptext "Remove the selected user from the SE Linux policy"]
    
    # Placing widgets
    pack $lb_sysUsers -side top 
    pack $listbox_sysUsers -side left -anchor w
    pack $u_add $u_remove -side top -anchor center -pady 5 -padx 5
    pack $lb_linuxUsers -side top 
    pack $listbox_SeLinuxUsers -side right -anchor e 
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::createRolesFrame
#
#  Description: This procedure is called by SE_User::createMainFrame
# ------------------------------------------------------------------------------
proc SE_User::createRolesFrame { mainframe } {
    variable listbox_availRoles
    variable listbox_currentRoles
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
    set lb_currentRoles [Label $rf_inner_top.lb_currentRoles -text "Current Roles"]

    set listbox_availRoles   [listbox [$lf_inner_bot getframe].listbox_availRoles -height 6 -width 20 -highlightthickness 0 \
				  -listvar SE_User::availRoles_list] 
    $lf_inner_bot setwidget $listbox_availRoles
    
    set listbox_currentRoles [listbox [$rf_inner_bot getframe].listbox_SeLinuxUsers -height 6 -width 20 -highlightthickness 0 \
				  -listvar SE_User::currentRoles_list]        
    $rf_inner_bot setwidget $listbox_currentRoles
    bindtags $listbox_currentRoles { $list_currentRoles ListBox currentRoles_Tag \
					 [winfo toplevel $list_currentRoles] all }
    bindtags $listbox_availRoles { $list_availRoles ListBox availRoles_Tag \
				       [winfo toplevel $list_availRoles] all }
    set r_add    [Button $cf.add -text "-->" -width 6 \
		      -command { SE_User::addRole [$SE_User::listbox_availRoles curselection]} \
		      -helptext "Add a new role to the user account"]
    set r_remove [Button $cf.remove -text "<--" -width 6 \
		      -command { SE_User::removeRole [$SE_User::listbox_currentRoles curselection]} \
		      -helptext "Remove a role from the user account"]

    pack $lb_availRoles -side top 
    pack $listbox_availRoles -side left -anchor w -expand yes 
    pack $r_add $r_remove -side top -anchor center -pady 5 -padx 5
    pack $lb_currentRoles -side top 
    pack $listbox_currentRoles -side right -anchor e -expand yes

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::createDefaultContextFrame
#
#  Description: This procedure is called by SE_User::createMainFrame
# ------------------------------------------------------------------------------
proc SE_User::createDefaultContextFrame { mainframe } {
    variable combo_login_role
    variable combo_login_type
    variable combo_cron_role
    variable combo_cron_type 
    variable cb_login_cxt
    variable cb_cron_cxt
    variable entry_user_login
    variable entry_user_cron
    
    set default_cxt_f [TitleFrame $mainframe.default_cxt_f -text "Default Contexts"]
    set t_frame  [frame [$default_cxt_f getframe].t_frame -relief flat -borderwidth 0]
    set b_frame  [frame [$default_cxt_f getframe].b_frame -relief flat -borderwidth 0]

    # Default checkbuttons
    set cb_login_cxt [checkbutton $t_frame.dflt_login_cxt -text "Default Login Context" \
			  -variable SE_User::opts(dflt_login_cxt) -padx 10 \
			  -command "SE_User::SetEditMode change"]
    set cb_cron_cxt [checkbutton $b_frame.dflt_cron_cxt -text "Default Cron Context" \
			 -variable SE_User::opts(dflt_cron_cxt) -padx 10 \
			 -command "SE_User::SetEditMode change"] 

    pack $cb_login_cxt -side top -anchor w
    pack $t_frame -side top -anchor n -fill x  
    pack $b_frame -side bottom -after $t_frame -anchor s -fill x -pady 10
    pack $cb_cron_cxt -side top -anchor w

    set lf_top [frame $t_frame.lf_top -relief flat -borderwidth 0]
    set cf_top [frame $t_frame.cf_top -relief flat -borderwidth 0]
    set rf_top [frame $t_frame.rf_top -relief flat -borderwidth 0]
    set lf_bot [frame $b_frame.lf_bot -relief flat -borderwidth 0]
    set cf_bot [frame $b_frame.cf_bot -relief flat -borderwidth 0]
    set rf_bot [frame $b_frame.rf_bot -relief flat -borderwidth 0]

    pack $default_cxt_f -side bottom -fill both -expand yes -padx 5 -pady 2
    pack $lf_top -side left -anchor e -expand yes -padx 15
    pack $cf_top -side left -expand yes -padx 10
    pack $rf_top -side left -anchor w -expand yes -padx 10
    pack $lf_bot -side left -anchor e -expand yes -padx 15 
    pack $cf_bot -side left -expand yes -padx 10
    pack $rf_bot -side left -anchor w -expand yes -padx 10

    # Top default login context labels
    set lbEntry_usr [Label $lf_top.lbEntry_usr -text "User"]
    pack $lbEntry_usr -side top -anchor w
    set lb_role_login [Label $cf_top.lb_role_login -text "Role"]
    pack $lb_role_login -side top -anchor w
    set lb_type_login [Label $rf_top.lb_type_login -text "Type"]
    pack $lb_type_login -side top -anchor w

    # Default Cron Context labels
    set lbEntry_usr2 [Label $lf_bot.lbEntry_usr2 -text "User"]
    pack $lbEntry_usr2 -side top -anchor w 
    set lb_role_cron [Label $cf_bot.lb_role_cron -text "Role"]
    pack $lb_role_cron -side top -anchor w
    set lb_type_cron [Label $rf_bot.lb_type_cron -text "Type"]
    pack $lb_type_cron -side top -anchor w

    # Default login context widgets
    set entry_user_login [Entry $lf_top.entry_user_login -textvariable SE_User::usr_login -width 15]
    pack $entry_user_login -anchor e -side left -ipady 1 -fill x -expand yes -ipadx 5
    set combo_login_role [ComboBox $cf_top.combo_role1 -textvariable SE_User::role_login -width 15 \
			      -postcommand {SE_User::PopulateRoleContextList $SE_User::combo_login_role} \
			      -modifycmd "SE_User::SetEditMode change"]
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $combo_login_role.e [linsert [bindtags $combo_login_role.e] 3 login_roleTag]
    bind $combo_login_role.e <FocusIn> { $SE_User::combo_login_role.e selection clear }
    bind $combo_login_role.e <FocusOut> { $SE_User::combo_login_role.e selection clear }
    pack $combo_login_role -anchor w -side left
    set combo_login_type [ComboBox $rf_top.combo_type1 -textvariable SE_User::type_login -width 15 \
			      -postcommand {SE_User::PopulateTypeContextList $SE_User::role_login $SE_User::combo_login_type} \
			      -modifycmd "SE_User::SetEditMode change"]
    bindtags $combo_login_type.e [linsert [bindtags $combo_login_type.e] 3 login_typeTag]
    bind $combo_login_type.e <FocusIn> { $SE_User::combo_login_type.e selection clear }
    bind $combo_login_type.e <FocusOut> { $SE_User::combo_login_type.e selection clear }
    pack $combo_login_type -anchor w -side right 

    # Default cron context widgets
    set entry_user_cron [Entry $lf_bot.entry_user_cron -textvariable SE_User::usr_cron -width 15]
    pack $entry_user_cron -anchor e -side left -ipady 1 -fill x -expand yes -ipadx 5
    set combo_cron_role [ComboBox $cf_bot.combo_role2 -textvariable SE_User::role_cron -width 15\
			     -postcommand {SE_User::PopulateRoleContextList $SE_User::combo_cron_role } \
			     -modifycmd "SE_User::SetEditMode change"]
    bindtags $combo_cron_role.e [linsert [bindtags $combo_cron_role.e] 3 cron_roleTag]
    bind $combo_cron_role.e <FocusIn> { $SE_User::combo_cron_role.e selection clear }
    bind $combo_cron_role.e <FocusOut> { $SE_User::combo_cron_role.e selection clear }
    pack $combo_cron_role -anchor w -side left
    set combo_cron_type [ComboBox $rf_bot.combo_type2 -textvariable SE_User::type_cron -width 15\
			     -postcommand {SE_User::PopulateTypeContextList $SE_User::role_cron $SE_User::combo_cron_type } \
			     -modifycmd "SE_User::SetEditMode change"]
    bindtags $combo_cron_type.e [linsert [bindtags $combo_cron_type.e] 3 cron_typeTag]
    bind $combo_cron_type.e <FocusIn> { $SE_User::combo_cron_type.e selection clear }
    bind $combo_cron_type.e <FocusOut> { $SE_User::combo_cron_type.e selection clear }
    pack $combo_cron_type -anchor w -side right

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::createMainButtons
#
#  Description: This procedure is called by SE_User::createMainFrame
# ------------------------------------------------------------------------------
proc SE_User::createMainButtons { b_frame } {
    variable b_exit
    variable b_refresh
    variable b_cancel
    variable b_commit

    # Main Action buttons
    set b_commit [Button $b_frame.commit -text "Commit" -width 6 -command { SE_User::commit } \
		      -helptext "Permanently record changes to current user record."]
    set b_cancel [Button $b_frame.cancel -text "Cancel" -width 6 -command { SE_User::cancel } \
		      -helptext "Discard changes made to current user record."]
    set b_refresh [Button $b_frame.refresh -text "Refresh" -width 6 -command { SE_User::refresh} \
		       -helptext "Reload the policy database."]
    set b_exit   [Button $b_frame.exit -text "Exit" -width 6 -command { SE_User::se_exit } \
		      -helptext "Exit SE Linux user manager"]

    # Placing buttons
    pack $b_commit $b_cancel -side left -pady 2 -padx 2
    pack $b_exit $b_refresh -side right -pady 2 -padx 2

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::unimplemented
#
#  Description: Used for any unimplemented functionality.
# ------------------------------------------------------------------------------
proc SE_User::unimplemented {} {
    tk_messageBox -icon warning -type ok -title "Warning: Unimplemented Command" -message \
	"This command is not currently implemented."
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::aboutBox
# ------------------------------------------------------------------------------
proc SE_User::aboutBox {} {
     variable gui_ver
     set apol_ver [apol_GetVersion]
     set seuser_ver [seuser_GetVersion]
	
    tk_messageBox -icon info -type ok -title "About SE Linux User Manager" -message \
	"Security Enhanced Linux User Manager\n\n\Copyright (c) 2001-2002 Tresys Technology, LLC \n\www.tresys.com/selinux\n
GUI Version ($gui_ver)\nApol Lib Version ($apol_ver)\nSEUser Lib Version ($seuser_ver)"
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::helpDlg
# ------------------------------------------------------------------------------
proc SE_User::helpDlg {} {
    variable helpFilename
    variable helpDlg
    
    # Checking to see if output window already exists. If so, it is destroyed.
    if { [winfo exists $helpDlg] } {
    	destroy $helpDlg
    }
    toplevel $helpDlg
    wm protocol $helpDlg WM_DELETE_WINDOW "destroy $helpDlg"
    wm withdraw $helpDlg
    wm title $helpDlg "Help"
    
    set hbox [frame $helpDlg.hbox ]
    # Display results window
    set sw [ScrolledWindow $hbox.sw -auto both]
    set resultsbox [text [$sw getframe].text -bg white -wrap none -font fixed]
    $sw setwidget $resultsbox
    set okButton [Button $hbox.okButton -text "OK" \
		      -command "destroy $helpDlg"]

    # go to the script dir to find the help file
    set script_dir  [apol_GetScriptDir "seuser_help.txt"]
    set helpFilename "$script_dir/seuser_help.txt"

    # Placing display widgets
    pack $hbox -expand yes -fill both -padx 5 -pady 5
    pack $okButton -side bottom
    pack $resultsbox -expand yes -fill both
    pack $sw -side left -expand yes -fill both 
    # Place a toplevel at a particular position
    ::tk::PlaceWindow $helpDlg widget center
    wm deiconify $helpDlg
    
    set filename $helpFilename
    set data [SE_User::readFile $filename]
 
    if { $data != "" } {
    	$resultsbox delete 0.0 end
	$resultsbox insert end $data
    } else {
    	tk_messageBox -icon error -type ok -title "Help File Error" -message \
	"Help file is not readable."
    }
    
    return 0
}

# ------------------------------------------------------------------------------------
#  Command SE_User::viewMakeResults
#
#  Description: Displays the output for the make results in a dialog window. Called by 
#		SE_User::commit and SE_User::se_exit procedures.
# ------------------------------------------------------------------------------------
proc SE_User::viewMakeResults { operation } {
    variable tmpfile 
    variable make_resultsDlg
    
    # Checking to see if output window already exists. If so, it is destroyed.
    if { [winfo exists $make_resultsDlg] } {
    	destroy $make_resultsDlg
    }
    # Creating output dialog window
    toplevel $make_resultsDlg
    wm protocol $make_resultsDlg WM_DELETE_WINDOW "destroy $make_resultsDlg"
    wm withdraw $make_resultsDlg
    wm title $make_resultsDlg "Make Results Output"
          
    # Display results window
    set resultsFrame [frame $make_resultsDlg.resultsFrame ]
    set sw [ScrolledWindow $resultsFrame.sw -auto both]
    set resultsbox [text [$sw getframe].text -bg white -wrap none]
    $sw setwidget $resultsbox
    set okButton [Button $resultsFrame.okButton -text "OK" -command "destroy $make_resultsDlg"]

    # Placing display widgets
    pack $resultsFrame -expand yes -fill both -padx 5 -pady 5
    pack $okButton -side bottom
    pack $resultsbox -expand yes -fill both
    pack $sw -side left -expand yes -fill both 
    # Place a toplevel at a particular position
    ::tk::PlaceWindow $make_resultsDlg widget center
    wm deiconify $make_resultsDlg
    
    # Determine the button operation and then read the correct file for the operation
    if { $operation == "make" } {
    	set filename $tmpfile
    	set data [SE_User::readFile $filename]
    } elseif { $operation == "install" } {
    	set filename $tmpfile
    	set data [SE_User::readFile $filename]
    }
    # If data was readble...insert the data into the text widget
    if { $data != "" } {
    	$resultsbox delete 0.0 end
	$resultsbox insert end $data
    } else {
    	tk_messageBox -icon error -type ok -title "Make Results Output Error" -message \
	"Output file: $filename not readable!"
    }
    # Will wait until the window is destroyed.
    tkwait window $make_resultsDlg
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::readFile
#
#  Description: Reads a file. 
# ------------------------------------------------------------------------------
proc SE_User::readFile { filename } {
    set data ""
    if { [file readable $filename] } {
    	set fileid [open $filename "r"]
    	set data [read $fileid]
    	close $fileid
    }
    return $data
}

# ------------------------------------------------------------------------------
#  Command SE_User::display_splashScreen
#
#  Description: Displays the splash screen dialog window.
# ------------------------------------------------------------------------------
proc SE_User::display_splashScreen { } {
    variable splashDlg
	
    if { [winfo exists $splashDlg] } {
	destroy $splashDlg
    }
    toplevel $splashDlg
    wm withdraw $splashDlg
    SE_User::create_splashDialog
    wm title $splashDlg "SE Linux User Manager"
    # Place a toplevel at a particular position
    ::tk::PlaceWindow $splashDlg widget center
    wm deiconify $splashDlg
    update
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::destroy_splashScreen
#
#  Description: Destroys the splash screen dialog.
# ------------------------------------------------------------------------------
proc SE_User::destroy_splashScreen { } {
    variable splashDlg

    destroy $splashDlg
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::create_splashDialog
#
#  Description: Creates a splash screen dialog window.
# ------------------------------------------------------------------------------
proc SE_User::create_splashDialog { } {
    variable gui_ver
    variable splashDlg
    
    set apol_ver [apol_GetVersion]
    set seuser_ver [seuser_GetVersion]

    # Top area
    set frm $splashDlg.top
    frame $frm -bd 2 -relief groove
    label $frm.guiVer -text "SE Linux User Manager $gui_ver" 
    label $frm.apolVer -text "Apol Lib Version: $apol_ver"
    label $frm.seuserVer -text "SEUser Lib Version: $seuser_ver"
    message $frm.copyright -text "Copyright (c) 2001-2002 Tresys Technology, LLC\n" -width 4i
    pack $frm.guiVer $frm.copyright $frm.apolVer $frm.seuserVer -fill x
    pack $frm -side top -fill x -padx 8 -pady 8

    # Bottom area
    set frm $splashDlg.bottom
    frame $frm -bd 2 -relief groove
    label $frm.msg -textvariable SE_User::progressMsg -anchor w -width 40
    pack $frm.msg -side left -ipadx 6 -ipady 4
    pack $frm -side bottom -fill x -padx 8 -pady 8

    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::splashUpdate
#
#  Description: Updates the splash screen dialog message.
# ------------------------------------------------------------------------------
proc SE_User::splashUpdate { msg } {
    variable splashDlg

    set name $splashDlg.bottom.msg
    if { [winfo exists $name] } {
	$name config -text "$msg"
	update
    }
    return 0
}

# ------------------------------------------------------------------------------
#  Command SE_User::main
#
#  Description: Requests and loads other packages. Creates the toplevel with  
#		specified settings and then performs application initialization. 
# ------------------------------------------------------------------------------
proc SE_User::main {} { 
    variable progressMsg
    variable splashDlg	
   
    set rt [catch {package require BWidget} ]
    if {$rt != 0 } {
    	tk_messageBox -icon error -type ok -title "Missing BWidgets" -message \
    		"Missing BWidgets package.  Ensure that you \n\
    		TCL/TK includes BWdigets, which can be found at\n\n\
    		http://sourceforge.net/projects/tcllib"
    	exit
    }
    set rt [catch {package require apol } ]
    if {$rt != 0 } {
    	tk_messageBox -icon error -type ok -title "Missing SE Linux package" -message \
    		"Missing the SE Linux package.  This script will not\n\
    		work correctly using the generic TK wish program.  You\n\
    		must either use the apol executable or the awish\n\
    		interpreter."
    	exit
    }
         
    global tcl_platform

    if {$tcl_platform(platform) == "windows"} {
        wm resizable . 0 0
        # catch {console hide}
    } else {
	bind . <Configure> { wm geometry . {} }
	# The following are other methods to resolve the wm resizing bug found on Redhat Linux 7.0
	#wm overrideredirect . 1
	#wm maxsize . 465 615
	#wm minsize . 465 615
    }

    option add *TitleFrame.l.font {helvetica 11 bold italic}
    option add *Dialog*font {helvetica 11}

    wm withdraw .
    wm title . "SE Linux User Manager"
    wm protocol . WM_DELETE_WINDOW "SE_User::se_exit"
    
    # Creates the splash screen 
    SE_User::display_splashScreen 
    set progressMsg "Loading policy..."   
    update idletasks
    
    # Configure tool and read user database
    set rt [catch [seuser_InitUserdb] err]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" \
		-message "$err\n\nCheck seuser.conf file for correct configuration"
	exit 
    }
    
    if { [seuser_Use_Old_Login_Contexts] == "1" } {
    	set SE_User::use_old_login_context_style 1
    } else {
    	set SE_User::use_old_login_context_style 0
    }
    
    # Create the main application window
    set progressMsg "Initializing interface..." 
    SE_User::createMainFrame
    update idletasks
    SE_User::initialize init  
    SE_User::destroy_splashScreen
    set progressMsg ""
#    BWidget::place . 0 0 center
    wm deiconify .
    raise .
    focus -force .
        
    return 0
}

#######################################################
# Start script here
SE_User::main


