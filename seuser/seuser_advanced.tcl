#############################################################
#  seuser_advanced.tcl
#
# -----------------------------------------------------------
#  Copyright (C) 2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#


##############################################################
# ::SEUser_Advanced
#
# This namespace creates the advanced management dialog which 
# is used to enable/disable generic users on the system, and 
# allows the user to directly add/remove users from the policy
# without adding/removing users from the system
##############################################################

###############################################################

namespace eval SEUser_Advanced {
	# Global Widget(s) 
	variable notebook
	variable b_exit
	variable b_cancel
	variable b_commit
	
	# Top level dialog windows
	variable advanced_Dlg
	set advanced_Dlg .advanced_Dlg
	
	# Notebook tab IDENTIFIERS; NOTE: We name all tabs after their related namespace qualified names.
	# We use the prefix 'SEUser_' for all notebook tabnames. Note that the prefix must end with an 
	# underscore and that that tabnames may NOT have a colon.
	variable generic_users_tabID		"SEUser_Generic_Users"
	variable usr_polMgnt_tabID		"SEUser_SELinux_Users"
	
	# Miscellaneous variables
	variable policy_changes_flag		0
	
	# Set up a trace on the policy_changes_flag variable in order to monitor 
	# changes to this variable, which would indicate changes to the policy.
	SEUser_Top::set_trace_on_var "SEUser_Advanced" "policy_changes_flag" 
}

########################
# GUI Creation Methods #
########################

# -----------------------------------------------------------------------------------
#  Command SEUser_Advanced::change_buttons_state
# -----------------------------------------------------------------------------------
proc SEUser_Advanced::change_buttons_state { changes } {
	if { $changes == 1 } {
		$SEUser_Advanced::b_exit configure -state disabled
		$SEUser_Advanced::b_commit configure -state normal
		$SEUser_Advanced::b_cancel configure -state normal
	} else {
		$SEUser_Advanced::b_exit configure -state normal
		$SEUser_Advanced::b_commit configure -state disabled
		$SEUser_Advanced::b_cancel configure -state disabled
	}
	
	return 0
}
		
# -----------------------------------------------------------------------------------
#  Command SEUser_Advanced::display
# -----------------------------------------------------------------------------------
proc SEUser_Advanced::display {} {
	variable notebook
	variable advanced_Dlg
    	global tcl_platform
    	
	# Checking to see if output window already exists. If so, it is destroyed.
	if { [winfo exists $advanced_Dlg] } {
		raise $advanced_Dlg
		return 
	}
	toplevel $advanced_Dlg
	wm protocol $advanced_Dlg WM_DELETE_WINDOW "destroy $advanced_Dlg"
	wm withdraw $advanced_Dlg
	wm title $advanced_Dlg "Advanced Management"
		
	set topf  [frame $advanced_Dlg.topf -width 100 -height 200]
	set botf  [frame $advanced_Dlg.botf -width 100 -height 200]
	pack $topf -side top -fill both -expand yes 
	pack $botf -side bottom -fill x -padx 5
	set notebook [NoteBook $topf.notebook]
	$notebook bindtabs <Button-1> { SEUser_Advanced::switch_tab }
	
	SEUser_Advanced::createMainButtons $botf	
	SEUser_Generic_Users::create_GenericUsers_Tab $notebook
	SEUser_SELinux_Users::create_UserPolicyMgnt_Tab $notebook
			
	$notebook compute_size
	pack $notebook -fill both -expand yes -padx 4 -pady 4
	$notebook raise [$notebook page 0]
	update idletasks
		
	# Place a toplevel at a particular position. Disabled. Let the window manager handle placing.
	#::tk::PlaceWindow $advanced_Dlg widget center
	wm deiconify $advanced_Dlg
	grab $advanced_Dlg
	
	# Make dialog non-resizable
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $SEUser_Advanced::::advanced_Dlg 0 0
	} else {
		bind $SEUser_Advanced::::advanced_Dlg <Configure> { wm geometry $SEUser_Advanced::::advanced_Dlg {} }
	}
	SEUser_Advanced::initialize  
	return 0
}                     

# ------------------------------------------------------------------------------
#  Command SEUser_Advanced::createMainButtons
#
#  Description: This procedure is called by SEUser_Advanced::createMainFrame
# ------------------------------------------------------------------------------
proc SEUser_Advanced::createMainButtons { b_frame } {
	variable b_exit
	variable b_cancel
	variable b_commit
	
	# Main Action buttons
	set b_commit [Button $b_frame.commit -text "Commit" -width 6 -command { [$SEUser_Advanced::notebook raise]::commit } \
		      -helptext "Permanently record changes to current user record."]
	set b_cancel [Button $b_frame.cancel -text "Cancel" -width 6 -command { [$SEUser_Advanced::notebook raise]::cancel } \
		      -helptext "Discard changes made to current user record."]
	set b_exit   [Button $b_frame.exit -text "Exit" -width 6 -command { SEUser_Advanced::exit_advancedDlg } \
		      -helptext "Exit Advanced Management dialog."]
	
	# Placing buttons
	pack $b_commit $b_cancel -side left -pady 2 -padx 2
	pack $b_exit -side right -pady 2 -padx 2
	
	return 0
}

#################
# Event Methods #
#################

# ------------------------------------------------------------------------------
#  Command SEUser_Advanced::switch_tab
#
#  Description: Checks for and applies any updates 
# ------------------------------------------------------------------------------
proc SEUser_Advanced::switch_tab { tabID } {	
	variable notebook
	
	set tabID [SEUser_Top::get_tabname $tabID]
	set raisedPage [$notebook raise]
	
	# if selecting same tab do nothing
	if { $raisedPage == $tabID } {
    		return 0
    	}
    	
    	# Do processing before leaving a tab. 
	${raisedPage}::leave_tab 
	# Second let the entering tab do its processing
	${tabID}::enter_tab 
	$SEUser_Advanced::notebook raise $tabID
	return 0
}

# -------------------------------------------------------------------------------------------
#  Command SEUser_Advanced::exit_advancedDlg
#
#  Description: Checks for changes to the users file. If there no changes, exits gracefully.	
# -------------------------------------------------------------------------------------------
proc SEUser_Advanced::exit_advancedDlg { } {
	variable policy_changes_flag
	
	if {$SEUser_SELinux_Users::state(users_changed) > 0 || $SEUser_Generic_Users::state(roles_changed) > 0 || $SEUser_Generic_Users::state(user_u_changed) > 0 }  {
		set policy_changes_flag 1
	}
	destroy $SEUser_Advanced::advanced_Dlg
	
	return 0
}

##################
# Worker Methods #
##################

# ------------------------------------------------------------------------------
#  Command SEUser_Advanced::change_tab_state
#
#  Description: Takes either "normal" or "disabled" as argument
# ------------------------------------------------------------------------------
proc SEUser_Advanced::change_tab_state { state } {	
	variable notebook
	variable generic_users_tabID	
	variable usr_polMgnt_tabID	
	
	set raisedPage [$notebook raise]
	if { $raisedPage == $generic_users_tabID } {
    		$notebook itemconfigure $usr_polMgnt_tabID -state $state
    	} elseif { $raisedPage == $usr_polMgnt_tabID } {
    		$notebook itemconfigure $generic_users_tabID -state $state
	} else {
		puts "Cannot determine tab to disable/enable"
		return -1
	}
    			
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Advanced::initialize
#
#  Description: Performs dialog initialization 
# ------------------------------------------------------------------------------
proc SEUser_Advanced::initialize { } {	
	SEUser_Generic_Users::initialize 
	SEUser_SELinux_Users::initialize 
	return 0
}
