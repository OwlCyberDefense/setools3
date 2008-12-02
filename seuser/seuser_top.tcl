##############################################################
#  seuser_top.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#

##############################################################
#
# ::SEUser_Top namespace
#
# This namespace reads the user database and then creates the 
# main toplevel GUI. 
##############################################################
namespace eval SEUser_Top {   	
	# Global widget variables
	variable mainframe
	# Main listbox for system users.
	variable listbox_Users
	# Top-level dialogs
	variable helpDlg 
    	set helpDlg .helpDlg
    	variable splashDlg
	set splashDlg .splashDlg
	variable delete_user_Dlg
	set delete_user_Dlg .delete_user_Dlg
	variable make_resultsDlg
	set make_resultsDlg .make_resultsDlg
	# Main listbox column buttons
	variable b_lbl_user
	variable b_lbl_type
	variable b_lbl_roles
	variable b_lbl_groups
	
	# All capital letters is the convention for variables defined via the Makefile.
	# The version number is defined as a magical string here. This is later configured in the make environment.
	variable gui_ver		SEUSER_GUI_VERSION
	variable copyright_date		"2002-2004"
	variable bwidget_version	""
	variable progressMsg 		""
	variable delete_user_ans 
	variable tmpfile
	variable policy_changes_flag	0
	variable generic_user 		"user_u"
	variable system_user		"system_u"
	variable root_user		"root"
	variable remove_homeDir		0
	variable home_dir		""
	# Variable used to define the the help file.
    	variable helpFilename "" 
    	variable trace_vars   ""
    	variable text_font		"Courier 10"
    	variable curr_sort_type		user_name	
    	variable default_bg_color
    	
    	# Notebook tab IDENTIFIER prefix;  Note that the prefix must end with an underscore.
    	variable tabName_prefix		"SEUser_"
    	
    	# Get default bg color of toplevel window
	set default_bg_color [. cget -background]
}

####################
#  Worker Methods  #
####################

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::set_trace_on_var
#  Description: This function sets a trace on the given namespace variable and will
#		invoke SEUser_Top::denote_policy_changes whenever the variable is written
#		This provides a way to track selinux policy changes. 
# -----------------------------------------------------------------------------------
proc SEUser_Top::set_trace_on_var { namespace trace_var } {
	trace variable "${namespace}::${trace_var}" w SEUser_Top::denote_policy_changes
	lappend SEUser_Top::trace_vars "${namespace}::${trace_var}"
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::remove_trace_on_vars
# -----------------------------------------------------------------------------------
proc SEUser_Top::remove_trace_on_vars { } {
	variable trace_vars
	
	foreach var $trace_vars {
		trace vdelete $var w SEUser_Top::denote_policy_changes
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::denote_policy_changes
# -----------------------------------------------------------------------------------
proc SEUser_Top::denote_policy_changes { name1 name2 op } {	
	set SEUser_Top::policy_changes_flag 1
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command SEUser_Top::check_list_for_redundancy
#
#  Description: "Checks" target list for elements in compare list.
#		If a matching element is found in the list being "checked", it is deleted.
# ----------------------------------------------------------------------------------------
proc SEUser_Top::check_list_for_redundancy { target_list_name compare_list_name } {
	upvar 1 $target_list_name target_list
	upvar 1 $compare_list_name compare_list	
	# Returns a count of the number of elements in the listbox (not the index of the last element). 
	set list_size [llength $target_list]
	
	# Gets each element in compare_list and then loops through target_list looking for any matches. If 
	# an element in the target_list matches the current value of the compare_list, it is deleted.
	foreach compare_listValue $compare_list {	
		for { set idx 0 } { $idx != $list_size } { incr idx } {
		    set target_listValue [lindex $target_list $idx]
		    if { [string match $target_listValue "$compare_listValue"] } {
				set target_list [lreplace $target_list $idx $idx]
		    }
		}	
	}
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::select_added_user
# -----------------------------------------------------------------------------------
proc SEUser_Top::select_added_user { new_user } {
	variable listbox_Users
	if {[$listbox_Users exists $new_user] } {
		$listbox_Users selection set $new_user
	}
	return 0
}

# ------------------------------------------------------------------------------------
#  Command SEUser_Top::viewMakeResults
#
#  Description: Displays the output for the make results in a dialog window. 
# ------------------------------------------------------------------------------------
proc SEUser_Top::viewMakeResults { } {
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
	pack $sw -side left -expand yes -fill both 
	
	# Place a toplevel at a particular position
	#::tk::PlaceWindow $make_resultsDlg widget center
	wm deiconify $make_resultsDlg
	
	# Determine the button operation and then read the correct file for the operation
	set filename $SEUser_Top::tmpfile
	set data [SEUser_Top::readFile $filename]
	
	# If data was readble...insert the data into the text widget
	if { $data != "" } {
		$resultsbox delete 0.0 end
		$resultsbox insert end $data
	} else {
		tk_messageBox -icon error -type ok -title "Make Results Output Error" \
			-parent $SEUser_Top::mainframe \
			-message "Output file: $filename not readable!"
	}
	# Will wait until the window is destroyed.
	tkwait window $make_resultsDlg
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::readFile
#
#  Description: Reads a file. 
# ------------------------------------------------------------------------------
proc SEUser_Top::readFile { filename } {
	set data ""
	if { [file readable $filename] } {
		set fileid [::open $filename "r"]
		set data [::read $fileid]
		::close $fileid
	}
	
	return $data
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::close
#
#  Description: Free all data variables 
# ------------------------------------------------------------------------------
proc SEUser_Top::close {} {
	SEUser_Top::remove_trace_on_vars
	SEUser_Generic_Users::close
	SEUser_SELinux_Users::close
	SEUser_UserInfo::close
	return 0	
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::sort_listbox_items
# -----------------------------------------------------------------------------------
proc SEUser_Top::sort_listbox_items { sort_type } {
	variable listbox_Users
	variable curr_sort_type
	
	switch -- $sort_type {
		user_name {
			set idx 0
		}
		user_type {
			set idx 1
		}
		user_roles {
			return 			
		}
		user_groups {
			return
		}
		default {
			return -code error
		}
	}
	set list_items [$listbox_Users items]
	if { $sort_type == "user_name" } {
		set reordered_list [lsort -dictionary $list_items]
	} else {
		foreach item $list_items {
			set data_list [$listbox_Users itemcget $item -data]
			lappend new_list "{[lindex $data_list $idx]} {$item}"
		}
		set new_list [lsort -dictionary $new_list]
		foreach item $new_list {
			lappend reordered_list [lindex $item 1]
		}
	}
	$listbox_Users reorder $reordered_list
	set curr_sort_type $sort_type
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::disable_tkListbox
#	-
# ------------------------------------------------------------------------------
proc SEUser_Top::disable_tkListbox { my_list_box } {
	global tk_version
	
	if {$tk_version >= "8.4"} {
	    	$my_list_box configure -state disabled
        } else {
		set class_name [winfo class $my_list_box]
		# Insert for the class name in the bindtags list
		if {$class_name != ""} {
			set idx [lsearch -exact [bindtags $my_list_box] $class_name]
			if {$idx != -1} {
				bindtags $my_list_box [lreplace [bindtags $my_list_box] $idx $idx]
			} else {
				# The default class bindtag is already unavailable, so just return.
				return 
			}
		} else {
			tk_messageBox -parent $SEUser_Top::mainframe -icon error -type ok -title "Error" -message \
				"Could not determine the class name of the widget."
			return -1
		}
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::enable_tkListbox
#	-
# ------------------------------------------------------------------------------
proc SEUser_Top::enable_tkListbox { my_list_box } {
	global tk_version
	
	if {$tk_version >= "8.4"} {
	    	$my_list_box configure -state normal
        } else {
		set class_name [winfo class $my_list_box]
		# Insert for the class name in the bindtags list
		if {$class_name != ""} {
			set idx [lsearch -exact [bindtags $my_list_box] $class_name]
			if {$idx != -1} {
				# Default class bindtag already defined, so return
				return 
			}
			bindtags $my_list_box [linsert [bindtags $my_list_box] 1 $class_name]
		} else {
			tk_messageBox -parent $SEUser_Top::mainframe -icon error -type ok -title "Error" -message \
				"Could not determine the class name of the widget."
			return -1
		}
	}
        
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::configure_ListBox
#	-
# ------------------------------------------------------------------------------
proc SEUser_Top::configure_ListBox { listbox_Users } {
	variable generic_user 	
	variable system_user
	
	$listbox_Users delete [$listbox_Users items]	
	
	# Gather only system users and exclude policy users, except the special 
	# users "user_u" and "system_u", if they exist in the policy.
	set all_users_list [SEUser_db::get_list sysUsers]
	set seUsers  [SEUser_db::get_list seUsers]
	if { [lsearch -exact $seUsers $generic_user] != -1 } {
		lappend all_users_list $generic_user
	} 
	if { [lsearch -exact $seUsers $system_user] != -1 } {
		lappend all_users_list $system_user
	}
	
	foreach user $all_users_list {
		# Set group information
		set rt [catch {set groups [SEUser_db::get_user_groups $user]} err]
		if { $rt != 0 } {
			return -code error $err
		} 
		if { $groups == "" } {
			set groups "<none>"
		} 
		# Set role information
		set rt [catch {set roles [SEUser_db::get_user_roles $user]} err]
		if { $rt != 0 } {
			return -code error $err
		} 
		if { $roles == "" } {
			set roles "<none>"
		}
		# Create a list to provide substitute values to the proceeding format command
		set data_list [list "$user" "[SEUser_db::get_user_type $user]" "$roles" "$groups"]
		
		##
		# In the format string "%-num1.num2":
		#	(-) Specifies that the converted argument should be left-justified in its field 
		#	num1 - number giving a minimum field width for this conversion, in order to make 
		#	       columns line up in tabular printouts. Set this to the same width as the 
		#	       related column label button above the main listbox.
		#       .num2 -  For s conversions, specifies the maximum number of characters to be printed;
		#	         if the string is longer than this then the trailing characters will be dropped.
		##
		if { ![$listbox_Users exists $user] } {
			$listbox_Users insert end "$user" \
				-data $data_list \
			  	-text  [eval format {"%-20.20s %-14.14s %-25.25s %-20.20s"} $data_list]
		}
	}    
	# Redraw the tree and listbox
	$listbox_Users configure -redraw 1
	return 0
}

####################
#  Event Methods   #
####################


# -----------------------------------------------------------------------------------
#  Command SEUser_Top::add_user
# -----------------------------------------------------------------------------------
proc SEUser_Top::add_user {} {	
	variable listbox_Users 
	SEUser_UserInfo::display add  
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::change_user
# -----------------------------------------------------------------------------------
proc SEUser_Top::change_user { user } {	
	variable listbox_Users
	
	set user_selected [$listbox_Users selection get] 
	if { $user_selected != "" } {
		SEUser_UserInfo::display change $user_selected
	}
	
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::delete_user
# -----------------------------------------------------------------------------------
proc SEUser_Top::delete_user {} {
	variable delete_user_ans
	variable listbox_Users
	variable generic_user 	
	variable system_user	
	variable root_user
	variable home_dir
	
	set user_selected [$listbox_Users selection get] 	
	if { $user_selected != "" } {
		# Do not allow user to delete the special users or the system user "root"
		if { $user_selected == $generic_user } {
			tk_messageBox -icon error -type ok -title "Error" \
				-parent $SEUser_Top::mainframe \
				-message "Cannot remove special user $generic_user. Please\
				select the Advanced button if you wish to remove $generic_user."
			return -1
		} elseif { $user_selected == $system_user } {
			tk_messageBox -icon error -type ok -title "Error" \
				-parent $SEUser_Top::mainframe \
				-message "Cannot remove special user $system_user"
			return -1
		} elseif { $user_selected == $root_user } {
			tk_messageBox -icon error -type ok -title "Error" \
				-parent $SEUser_Top::mainframe \
				-message "Cannot remove user $root_user with this tool."
			return -1
		}
		# Get the home directory as defined in the /etc/passwd file
		set rt [catch {set home_dir [SEUser_db::get_sysUser_data_field $user_selected directory]} err]
		if { $rt != 0 } {
			tk_messageBox -icon error -type ok -title "Error" \
				-parent $SEUser_Top::mainframe \
				-message "$err"
			return -1
		}
		SEUser_Top::display_delete_user_Dlg $user_selected 
		if { $SEUser_Top::delete_user_ans == "yes" } {
			set curr_mod_ctr [SEUser_db::get_mod_cntr]
			set rt [catch {SEUser_db::remove_user [$listbox_Users selection get] $SEUser_Top::remove_homeDir} err]
			if { $rt != 0 } {
				tk_messageBox -icon error -type ok -title "Error" \
					-parent $SEUser_Top::mainframe \
					-message "$err"
				return -1
			}
			set new_mod_ctr [SEUser_db::get_mod_cntr]
			SEUser_Top::initialize
			if { $new_mod_ctr > $curr_mod_ctr } {
				set SEUser_Top::policy_changes_flag 1
			}
		}
	}
	
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::display_advanced_Dlg
# -----------------------------------------------------------------------------------
proc SEUser_Top::display_advanced_Dlg {} {	
	SEUser_Advanced::display
	return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::load_policy
# -----------------------------------------------------------------------------------
proc SEUser_Top::load_policy {} {
	variable progressmsg
	
	if {$SEUser_Top::policy_changes_flag}  {
		set progressmsg "Loading policy..."
		set progressBar [ ProgressDlg .progress -parent . -title "Load Progress..." \
	        			-textvariable SEUser_Top::progressmsg]
		update 
		set rt [catch {SEUser_db::load_policy} err]
		if { $rt != 0 } {
		    destroy $progressBar
		    set answer [tk_messageBox -icon error -type yesno -title "Error: Policy not installed" \
		    	-parent $SEUser_Top::mainframe \
		    	-message "$err\n\nPress YES to view make results, NO to exit."]
		    switch -- $answer {
		    	yes { SEUser_Top::viewMakeResults }
		    	no 	{ }
		    }
		} else {
			set progressmsg "Policy installed."
		    	destroy $progressBar
		}
		SEUser_Top::initialize
	}	  	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::update_environment_vars
# ------------------------------------------------------------------------------ 
proc SEUser_Top::update_environment_vars { } {
	# Append /sbin and /usr/sbin to path for exec commands
	set new_value [append ::env(PATH) ":/sbin"] 
	set ::env(PATH) $new_value
	set new_value [append ::env(PATH) ":/usr/sbin"]
	set ::env(PATH) $new_value

	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::initialize
#
#  Description: Performs application initialization 
# ------------------------------------------------------------------------------
proc SEUser_Top::initialize { } {
	variable listbox_Users
	
	# Reset flag for indicating policy changes.		
	set SEUser_Top::policy_changes_flag 0
	SEUser_Top::update_environment_vars
	
	set rt [catch {SEUser_db::init_db} err]
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" \
			-parent $SEUser_Top::mainframe \
			-message "The following error occurred when initializing the virtual database: ${err}.\n\nNow exiting application..."
		SEUser_Top::se_exit
	}
	# Get the currently selected user, so we can re-select the user after listbox has been re-configured.
	set sel_user [$listbox_Users selection get]
	set rt [catch {SEUser_Top::configure_ListBox $SEUser_Top::listbox_Users} err]
	if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" \
			-parent $SEUser_Top::mainframe \
			-message "$err"
		return
	}
	# Re-sort listbox items based on the current sort type. 
	SEUser_Top::sort_listbox_items  $SEUser_Top::curr_sort_type
	# Re-select the previosly selected user in the listbox. 
	$listbox_Users selection set $sel_user
	return 0
}

# -------------------------------------------------------------------------------------------
#  Command SEUser_Top::se_exit
#
#  Description: Checks for changes to the users file. If there no changes, exits gracefully.
#`		If there are changes, force the policy to be re-made and installed.
# -------------------------------------------------------------------------------------------
proc SEUser_Top::se_exit { } {
	variable progressmsg
	
	if {$SEUser_Top::policy_changes_flag}  {
		set progressmsg "Loading policy..."
		set progressBar [ ProgressDlg .progress -parent . -title "Load Progress..." \
	        			-textvariable SEUser_Top::progressmsg]
		update 
		set rt [catch {SEUser_db::load_policy} err]
		if { $rt != 0 } {
		    destroy $progressBar
		    set answer [tk_messageBox -icon error -type yesno \
		    	-parent $SEUser_Top::mainframe \
		    	-title "Error: Policy not installed" \
		    	-message "$err\n\nPress YES to view make results, NO to exit."]
		    switch -- $answer {
		    	yes { SEUser_Top::viewMakeResults }
		    	no  { }
		    }
		} else {
			set progressmsg "Policy installed."
		    	destroy $progressBar
		}
	}
	# Free the virtual database.
	SEUser_db::free_db
	SEUser_Top::close
	seuser_Exit
	exit
}

################################################################################
# ::get_tabname -- 
#	args:	
#		- tabID - the tabID provided from the Notebook::bindtabs command
#
# Description: 	There is a bug with the BWidgets 1.7.0 Notebook widget where the 
#	  	tabname is stripped of its' first 2 characters AND an additional 
#		string, consisting of a colon followed by an embedded widget name 
#		from the tab, is appended. For example, the tab name will be 
#		'sults1:text' instead of 'Results1".
#
proc SEUser_Top::get_tabname {tab} {	
	variable tabName_prefix
	
	set idx [string last ":" $tab]
	if {$idx != -1} {
		# Strip off the last ':' and any following characters from the end of the string
		set tab [string range $tab 0 [expr $idx - 1]]
	}
	set prefix_len [string length $tabName_prefix]
	if {[string range $tab 0 $prefix_len] == $tabName_prefix} {
		return $tab
	}
	
	set tmp $tabName_prefix
	set idx [string first "_" $tab]
	if {$idx == -1} {
		return $tab
	}
	set tab_fixed [append tmp [string range $tab [expr $idx + 1] end]]
	return $tab_fixed
}


##############################
#  GUI Construction Methods  #
##############################

##############################################################
# ::display_delete_homeDir_Dlg
#  	- This dialog is displayed when the user selects the 
# 	  "Remove home directory.." checkbutton on the delete_user_Dlg
#
proc SEUser_Top::display_delete_homeDir_Dlg { home_dir } {	
	if { $SEUser_Top::remove_homeDir } {
		set ans [tk_messageBox -icon warning -type yesno -title "Remove home directory?" \
				-parent $SEUser_Top::delete_user_Dlg \
				-message "By turning this checkbutton ON, you will be deleting the directory $home_dir.\
				Are you sure you want to delete this directory?"]
		switch $ans {
			yes { }
			no { 
				set SEUser_Top::remove_homeDir 0
			} 	
		}
	}
	return 0
}

##################################################################
# ::display_delete_user_Dlg
#  	- This dialog is displayed when a user selects the delete
#	  button. 
proc SEUser_Top::display_delete_user_Dlg { user_selected } {	
	variable delete_user_Dlg
	variable remove_homeDir	
	global tcl_platform
	
    	if { [winfo exists $delete_user_Dlg] } {
    		destroy $delete_user_Dlg 
    	}
    	
	# Set remove home dir to be OFF by default.
	set remove_homeDir 0
    	# Create the toplevel dialog window and set its' properties.
	toplevel $delete_user_Dlg
	wm protocol $delete_user_Dlg WM_DELETE_WINDOW "destroy $delete_user_Dlg"
	wm withdraw $delete_user_Dlg
	wm title $delete_user_Dlg "Delete User"
	
	set inner_f [frame $delete_user_Dlg.inner_f]
    	set inner_f1 [frame $delete_user_Dlg.inner_f1]
    	set inner_f2 [frame $delete_user_Dlg.inner_f2]
    	set lbl_save  [label $inner_f1.lbl_save -image [Bitmap::get warning]]
    	set lbl_save2  [label $inner_f2.lbl_save2 -text "User: $user_selected is about to be removed from the system.\n\
    	Are you sure you want to continue?"]
    	set b_yes [button $inner_f.b_yes -text "Yes" -width 6 -command {set SEUser_Top::delete_user_ans yes; destroy $SEUser_Top::delete_user_Dlg} -font {Helvetica 11 bold}]
	set b_cancel [button $inner_f.b_cancel -text "Cancel" -width 6 -command {set SEUser_Top::delete_user_ans cancel; destroy $SEUser_Top::delete_user_Dlg} -font {Helvetica 11 bold}]
	
	pack $inner_f -side bottom -anchor center
	pack $inner_f1 -side left -anchor n  -pady 10
	pack $inner_f2 -side left -anchor n -pady 10
	pack $lbl_save -side left -anchor center -padx 10
	pack $lbl_save2 -side top -anchor center -padx 5
	# Only display the "Remove home directory.." checkbutton if the user has a home directory
	# defined in /etc/passwd and that directory exists.
	if { $SEUser_Top::home_dir != "" && [file exists $SEUser_Top::home_dir] } {
	    	set cb_rm_homeDir [checkbutton $inner_f2.cb_rm_homeDir -text "Remove home directory and contents." \
				  -variable SEUser_Top::remove_homeDir \
				  -command { SEUser_Top::display_delete_homeDir_Dlg $SEUser_Top::home_dir }]
		pack $cb_rm_homeDir -side bottom -anchor nw 
	}
	pack $b_yes $b_cancel -side left -anchor center -padx 2
	
	# Place toplevel at center position. Disabled. Let window manager handle placing. 
	#::tk::PlaceWindow $delete_user_Dlg widget center
	wm deiconify $delete_user_Dlg
	focus -force $b_cancel
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $SEUser_Top::::delete_user_Dlg 0 0
	} else {
		bind $SEUser_Top::::delete_user_Dlg <Configure> { wm geometry $SEUser_Top::::delete_user_Dlg {} }
	}
	::tk::SetFocusGrab $delete_user_Dlg 	
	tkwait variable SEUser_Top::delete_user_ans     		
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::create_splashDialog
#
#  Description: Creates a splash screen dialog window.
# ------------------------------------------------------------------------------
proc SEUser_Top::create_splashDialog { } {
    variable gui_ver
    variable splashDlg
    variable copyright_date
    
    set apol_ver [apol_GetVersion]
    set seuser_ver [seuser_GetVersion]

    # Top area
    set frm $splashDlg.top
    frame $frm -bd 2 -relief groove
    label $frm.guiVer -text "SE Linux User Manager $gui_ver" 
    label $frm.apolVer -text "Apol Lib Version: $apol_ver"
    label $frm.seuserVer -text "SEUser Lib Version: $seuser_ver"
    message $frm.copyright -text "Copyright (c) $copyright_date Tresys Technology, LLC\n" -width 4i
    pack $frm.guiVer $frm.copyright $frm.apolVer $frm.seuserVer -fill x
    pack $frm -side top -fill x -padx 8 -pady 8

    # Bottom area
    set frm $splashDlg.bottom
    frame $frm -bd 2 -relief groove
    label $frm.msg -textvariable SEUser_Top::progressMsg -anchor w -width 40
    pack $frm.msg -side left -ipadx 6 -ipady 4
    pack $frm -side bottom -fill x -padx 8 -pady 8

    return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::destroy_splashScreen
#
#  Description: Destroys the splash screen dialog.
# ------------------------------------------------------------------------------
proc SEUser_Top::destroy_splashScreen { } {
    variable splashDlg
    destroy $splashDlg
    return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::display_splashScreen
#
#  Description: Displays the splash screen dialog window.
# ------------------------------------------------------------------------------
proc SEUser_Top::display_splashScreen { } {
    variable splashDlg
	
    if { [winfo exists $splashDlg] } {
	destroy $splashDlg
    }
    toplevel $splashDlg
    wm overrideredirect $splashDlg 0
    wm withdraw $splashDlg
    SEUser_Top::create_splashDialog
    wm title $splashDlg "SE Linux User Manager"
    # Place a toplevel at a particular position
    ::tk::PlaceWindow $splashDlg widget center
    wm deiconify $splashDlg
    update
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::aboutBox
# ------------------------------------------------------------------------------
proc SEUser_Top::aboutBox {} {
     variable gui_ver
     variable copyright_date
     
     set apol_ver [apol_GetVersion]
     set seuser_ver [seuser_GetVersion]
	
    tk_messageBox -icon info -type ok -title "About SE Linux User Manager" \
    	-parent $SEUser_Top::mainframe \
    	-message \
	"Security Enhanced Linux User Manager\n\n\Copyright (c) $copyright_date Tresys Technology, LLC\n\www.tresys.com/selinux\n\
	GUI Version ($gui_ver)\nApol Lib Version ($apol_ver)\nSEUser Lib Version ($seuser_ver)"
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::helpDlg
# ------------------------------------------------------------------------------
proc SEUser_Top::helpDlg {} {
    variable helpFilename
    variable helpDlg
    

    # Checking to see if output window already exists. If so, it is destroyed.
    if { [winfo exists $helpDlg] } {
    	raise $helpDlg
    	return
    }
    toplevel $helpDlg
    wm protocol $helpDlg WM_DELETE_WINDOW "destroy $helpDlg"
    wm withdraw $helpDlg
    wm title $helpDlg "Help"
    
    set hbox [frame $helpDlg.hbox ]
    # Display results window
    set sw [ScrolledWindow $hbox.sw -auto both]
    set resultsbox [text [$sw getframe].text -bg white -wrap none -font $SEUser_Top::text_font]
    $sw setwidget $resultsbox
    set okButton [Button $hbox.okButton -text "OK" \
		      -command "destroy $helpDlg"]

    # go to the script dir to find the help file
    set script_dir  [apol_GetScriptDir "seuser_help.txt"]
    set helpFilename "$script_dir/seuser_help.txt"

    # Placing display widgets
    pack $hbox -expand yes -fill both -padx 5 -pady 5
    pack $okButton -side bottom
    pack $sw -side left -expand yes -fill both 
    # Place a toplevel at a particular position
    #::tk::PlaceWindow $helpDlg widget center
    wm deiconify $helpDlg
    
    set filename $helpFilename
    set data [SEUser_Top:::readFile $filename]
 
    if { $data != "" } {
    	$resultsbox delete 0.0 end
	$resultsbox insert end $data
    } else {
    	tk_messageBox -icon error -type ok -title "Help File Error" -parent $SEUser_Top::mainframe \
    		-message "Help file is not readable."
    }
    $resultsbox configure -state disabled
    return 0
}

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::create_Main_ListBox
# -----------------------------------------------------------------------------------
proc SEUser_Top::create_Main_ListBox { t_frame } {				
	# ListBoxes
	set listbox_Users [ListBox $t_frame.listbox_Users -height 40 -width 80 \
				-highlightthickness 2 -selectmode single \
				-borderwidth 0 -bg white -redraw 0 -padx 0] 
	# Placing widgets
	pack $listbox_Users -side left -fill both -expand yes -anchor nw
    	$listbox_Users bindText <Double-ButtonPress-1> { SEUser_Top::change_user } 
	return $listbox_Users
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::create_column_header_frame
# ------------------------------------------------------------------------------
proc SEUser_Top::create_column_header_frame { parent } {  	
	set tmp [frame $parent.column_frame]
	pack $tmp -side top -fill x -anchor nw 
     	return $tmp
} 

# ------------------------------------------------------------------------------
#  Command SEUser_Top::create_listbox_frame
# ------------------------------------------------------------------------------
proc SEUser_Top::create_listbox_frame { parent } {  	
	set tmp [frame $parent.listbox_frame]
	pack $tmp -side bottom -fill both -anchor nw -expand yes 
     	return $tmp
} 

# -----------------------------------------------------------------------------------
#  Command SEUser_Top::create_TopLevel
# -----------------------------------------------------------------------------------
proc SEUser_Top::create_TopLevel {} {   
	variable mainframe
	variable b_lbl_user
	variable b_lbl_type
	variable b_lbl_roles
	variable b_lbl_groups	
	variable listbox_Users 	
	
	# Menu description
	set descmenu {
	"&Help" {} help 0 {
	    {command "&Help" {all option} "Display Help" {} -command SEUser_Top::helpDlg}
	    {command "&About" {all option} "Display About Box" {} -command SEUser_Top::aboutBox}
	}
	}
		               		  	
	# Frames creation
	set mainframe [MainFrame .mainframe -menu $descmenu]
	set frame    [$mainframe getframe]
	set t_frame  [frame $frame.t_frame -relief flat -borderwidth 0]
	set b_frame  [frame $frame.b_frame -relief flat -borderwidth 0]
	set users_frame [TitleFrame $t_frame.users_frame -text "System Users"]
	
	# Using the implicit tcl frame (from the above BWidgets TitleFrame) as the parent 
	# create frames for the column headers and the main listbox.
	set columns_f [SEUser_Top::create_column_header_frame [$users_frame getframe]]
	set listbox_f [SEUser_Top::create_listbox_frame [$users_frame getframe]]
	
	# Column labels for listbox items
	set b_lbl_user 	 [Button $columns_f.b_lbl_user -text "User"  \
		-font $SEUser_Top::text_font -width 20  -pady 0 -padx 0 \
		-command { SEUser_Top::sort_listbox_items user_name } -relief groove -bd 1]
	set b_lbl_type 	 [Button $columns_f.b_lbl_type -text "Policy Type" \
		-font $SEUser_Top::text_font -width 14   -pady 0 -padx 0 \
		-command { SEUser_Top::sort_listbox_items user_type } -relief groove -bd 1]
	set b_lbl_roles  [Button $columns_f.b_lbl_roles -text "Roles"  \
		-font $SEUser_Top::text_font -width 25  -pady 0 -padx 0 \
		-command { SEUser_Top::sort_listbox_items user_roles } -relief groove -bd 1]
	set b_lbl_groups [Button $columns_f.b_lbl_groups -text "Groups" \
		-font $SEUser_Top::text_font -width 20  -pady 0 -padx 0 \
		-command { SEUser_Top::sort_listbox_items user_groups } -relief groove -bd 1]
	
	set user_sw  [ScrolledWindow $listbox_f.user_sw -auto none -scrollbar vertical]
	set listbox_Users [SEUser_Top::create_Main_ListBox $listbox_f]
	$user_sw setwidget $listbox_Users
	
	# Main Action buttons
	set b_add_user 	  [Button $b_frame.b_add_user -text "Add" -width 10 -command { SEUser_Top::add_user } \
		      		-helptext "Add user to selinux system."]
	set b_change_user [Button $b_frame.b_change_user -text "View/Change" -width 10 -command { SEUser_Top::change_user [$SEUser_Top::listbox_Users selection get] } \
		      		-helptext "Change user information"]
	set b_del_user [Button $b_frame.b_del_user -text "Delete" -width 10 -command { SEUser_Top::delete_user } \
		      	-helptext "Remove user from selinux system."]
	set b_advanced [Button $b_frame.b_advanced -text "Advanced" -width 10 -command { SEUser_Top::display_advanced_Dlg} \
		       	-helptext "Perform advanced policy user management tasks."]
	set b_load_pol [Button $b_frame.b_load_pol -text "Update Policy" -width 10 -command { SEUser_Top::load_policy } \
		      	-helptext "Load the selinux policy."]
	set b_exit     [Button $b_frame.b_exit -text "Exit" -width 10 -command { SEUser_Top::se_exit } \
		      	-helptext "Exit SE Linux user manager tool."]
	
	pack $user_sw -side left -anchor nw -fill both -expand yes       
	pack $b_frame -side bottom -padx 2 -anchor center 
	pack $t_frame -side top -fill both -expand yes
	pack $users_frame -padx 2 -side bottom -fill both -expand yes
	pack $b_lbl_user $b_lbl_type $b_lbl_roles -side left -anchor nw
	pack $b_lbl_groups -side left -anchor center -fill x -expand yes 
	pack $b_add_user $b_change_user $b_del_user $b_advanced $b_load_pol $b_exit -side left -pady 2 -padx 4 -anchor center
	pack $mainframe -side left -fill both -expand yes
	# Bind the delete button key-press to the delete_user procedure
	bind [winfo parent $mainframe] <KeyPress-Delete> { SEUser_Top::delete_user }
	update idletasks
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command SEUser_Top::main
#
#  Description: Requests and loads other packages. Creates the toplevel with  
#		specified settings and then performs application initialization. 
# ------------------------------------------------------------------------------
proc SEUser_Top::main {} { 
	variable progressMsg
	variable splashDlg
	variable tmpfile
	global tcl_platform
	global tk_version
	global tk_patchLevel
	variable bwidget_version
	
	# Prevent the application from responding to incoming send requests and sending 
	# outgoing requests. This way any other applications that can connect to our X 
	# server cannot send harmful scripts to our application. 
	rename send {}

	set rt [catch {set bwidget_version [package require BWidget]} err]
	if {$rt != 0 } {
		tk_messageBox -icon error -type ok -title "Missing BWidgets package" \
			-parent . \
			-message \
			"Missing BWidgets package.  Ensure that your installed version of \n\
			TCL/TK includes BWidgets, which can be found at\n\n\
			http://sourceforge.net/projects/tcllib"
		exit
	}
	if {[package vcompare $bwidget_version "1.4.1"] == -1} {
		tk_messageBox -icon warning -type ok -title "Package Version" -parent . \
			-message \
			"This tool requires BWidgets 1.4.1 or later. You may experience problems\
			while running the application. It is recommended that you upgrade your BWidgets\
			package to version 1.4.1 or greater. See 'Help' for more information."	
	}
	
	# Provide the user with a warning if incompatible Tk and BWidget libraries are being used.
	if {[package vcompare $bwidget_version "1.4.1"] && $tk_version == "8.3"} {
		tk_messageBox -icon error -type ok -title "Warning" -parent . -message \
			"Your installed Tk version $tk_version includes an incompatible BWidgets $bwidget_version package version. \
			This has been known to cause a tk application to crash.\n\nIt is recommended that you either upgrade your \
			Tk library to version 8.4 or greater or use BWidgets 1.4.1 instead. See the README for more information."	
		exit
	}
	
	set rt [catch {package require apol}]
	if {$rt != 0 } {
		tk_messageBox -icon error -type ok -title "Missing SE Linux package" \
			-parent . \
			-message \
			"Missing the SE Linux package.  This script will not\n\
			work correctly using the generic TK wish program.  You\n\
			must either use the apol executable or the awish\n\
			interpreter."
		exit
	}
	
	# First set all fonts in general; then we can change specific fonts 
	option add *Font "Helvetica 10"
	option add *TitleFrame.l.font "Helvetica 10 bold italic"
	option add *Dialog*font "Helvetica 10"
	option add *ListBox*font $SEUser_Top::text_font
	option add *text*font $SEUser_Top::text_font
	
	wm withdraw .
	wm title . "SE Linux User Manager"
	wm protocol . WM_DELETE_WINDOW "SEUser_Top::se_exit"
	
	# Creates the splash screen 
	SEUser_Top::display_splashScreen 
	set progressMsg "Loading policy..."   
	update idletasks

	# Configure tool and read user database
	set rt [catch {seuser_InitUserdb} err]
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" \
			-parent . \
			-message "$err\n\nCheck seuser.conf file for correct configuration"
		exit 
	}
	
	if { [seuser_Use_Old_Login_Contexts] == "1" } {
		tk_messageBox -icon error -type ok -title "Error" \
			-parent . \
			-message "Cannot find /etc/security/default_contexts file."
		exit 
	}
	 

	# Get temporary makefile name
	set rt [catch {set tmpfile [seuser_GetTmpMakeFileName]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-parent . \
			-message "$err"
		return
	}
	
	# Create the main application window
	set progressMsg "Initializing interface..." 
	SEUser_Top::create_TopLevel
	update idletasks
	SEUser_Top::initialize   
	SEUser_Top::destroy_splashScreen
	set progressMsg ""
	set width 740
	set height 550
	wm geom . ${width}x${height}
	wm resizable . 1 1    
	#BWidget::place . 0 0 center
	wm deiconify .
	raise .
	focus -force .
	
	return 0
}


