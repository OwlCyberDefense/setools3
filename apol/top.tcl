# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget 

##############################################################
# ::ApolTop
#  
# The top level GUI
##############################################################
namespace eval ApolTop {
	# All capital letters is the convention for variables defined via the Makefile.
	variable status 		""
	variable policy_version_string	""
	variable policy_type		""
    variable policy_mls_type	""
	variable filename 		""
	# The following is used with opening a policy for loading all or pieces of a policy. 
	# The option defaults to 0 (or all portions of the policy).
	variable policyConf_lineno	""
	variable polstats
        variable policy_stats_summary   ""
	# The version number is defined as a magical string here. This is later configured in the make environment.
	variable gui_ver 		APOL_GUI_VERSION 
	variable copyright_date		"2001-2006"
	# install_dir is a magical string to be defined via the makefile!
	variable apol_install_dir	APOL_INSTALL_DIR
	variable recent_files
	variable num_recent_files 	0
	variable most_recent_file 	-1
	# The max # can be changed by the .apol file
	variable max_recent_files 	5
	# env array element HOME is an environment variable
	variable dot_apol_file 		"[file join "$::env(HOME)" ".apol"]"
	variable goto_line_num
	# Default GUI settings
	variable prevCursor		arrow
	# store the default background color for use when diabling widgets
	variable default_bg_color
	set default_bg_color 		[. cget -background] 
	variable text_font		""
	variable title_font		""
	variable dialog_font		""
	variable general_font		""
	variable temp_recent_files	""
	variable query_file_ext 	".qf"
	# Main window dimension defaults
        variable top_width             1000
        variable top_height            700
	variable libsefs		0
	
	# Top-level dialog widgets
	variable helpDlg
	set helpDlg .apol_helpDlg
	variable searchDlg
	set searchDlg .searchDlg
	variable goto_Dialog
	set goto_Dialog .goto_Dialog
	variable options_Dialog
	set options_Dialog .options_Dialog
	
	######################
	# Other global widgets
	variable mainframe
	variable textbox_policyConf
	variable searchDlg_entryBox
	variable gotoDlg_entryBox
	# Main top-level notebook widget
	variable notebook
	# Subordinate notebook widgets
	variable components_nb
	variable rules_nb

    variable mls_tabs {}  ;# list of notebook tabs that are only for MLS
	
	# Search-related variables
	variable searchString		""
	variable case_Insensitive	0
	variable regExpr 		0
	variable srch_Direction		"down"
	variable policy_is_open		0
	
	# Notebook tab IDENTIFIERS; NOTE: We name all tabs after their related namespace qualified names.
	# We use the prefix 'Apol_' for all notebook tabnames. Note that the prefix must end with an 
	# underscore and that that tabnames may NOT have a colon.
	variable tabName_prefix		"Apol_"
	variable components_tab 	"Apol_Components"
	variable types_tab		"Apol_Types"
	variable class_perms_tab	"Apol_Class_Perms"
	variable roles_tab		"Apol_Roles"
	variable users_tab		"Apol_Users"
	variable cond_bools_tab		"Apol_Cond_Bools"
        variable mls_tab                "Apol_MLS"
	variable initial_sids_tab	"Apol_Initial_SIDS"
        variable net_contexts_tab	"Apol_NetContexts"
        variable fs_contexts_tab	"Apol_FSContexts"

    	variable rules_tab 		"Apol_Rules"
	variable terules_tab		"Apol_TE"
	variable cond_rules_tab		"Apol_Cond_Rules"
	variable rbac_tab		"Apol_RBAC"
	variable range_tab		"Apol_Range"

	variable file_contexts_tab	"Apol_File_Contexts"

	variable analysis_tab		"Apol_Analysis"

        variable policy_conf_tab	"Apol_PolicyConf"

        variable tab_names {
            Types Class_Perms Roles Users Cond_Bools MLS Initial_SIDS NetContexts FSContexts
            TE Cond_Rules RBAC Range
            File_Contexts
            Analysis
            PolicyConf
        }
	variable tk_msgBox_Wait

	# Initialize the recent files list
	for {set i 0} {$i<$max_recent_files} {incr i} {
		set recent_files($i) ""
	}

	#show warning for loading policy with fake attribute names
	variable show_fake_attrib_warning 1
}

proc ApolTop::is_policy_open {} {
	return $ApolTop::policy_is_open
}

proc ApolTop::get_install_dir {} {
	return $ApolTop::apol_install_dir
}

proc ApolTop::get_toplevel_dialog {} {
	return $ApolTop::mainframe
}

proc ApolTop::is_binary_policy {} {
	if {$ApolTop::policy_type == "binary"} {
		return 1
	}
	return 0
}

proc ApolTop::is_mls_policy {} {
    if {![is_policy_open] || $ApolTop::policy_mls_type == "mls"} {
        return 1
    }
    return 0
}

proc ApolTop::load_fc_index_file {} {
	set rt [Apol_File_Contexts::load_fc_db]
	if {$rt == 1} {
		ApolTop::configure_load_index_menu_item 1
	}
	return 0
}

proc ApolTop::create_fc_index_file {} {
	Apol_File_Contexts::display_create_db_dlg
	return 0
}

########################################################################
# ::load_perm_map_fileDlg -- 
#	- Called from Advanced menu
proc ApolTop::load_perm_map_fileDlg {} {
    if {[Apol_Perms_Map::loadPermMapFromFile]} {
        ApolTop::configure_edit_pmap_menu_item 1
    }
}

########################################################################
# ::load_default_perm_map_Dlg --
#	- Called from Advanced menu
proc ApolTop::load_default_perm_map_Dlg {} {
    if {[Apol_Perms_Map::loadDefaultPermMap]} {
        ApolTop::configure_edit_pmap_menu_item 1
    }
}

########################################################################
# ::configure_edit_pmap_menu_item --
#	-
proc ApolTop::configure_edit_pmap_menu_item {enable} {
	variable mainframe
	
	if {$enable} {
		[$mainframe getmenu pmap_menu] entryconfigure last -state normal -label "Edit Perm Map..."
	} else {
		[$mainframe getmenu pmap_menu] entryconfigure last -state disabled -label "Edit Perm Map... (Not loaded)"	     
	}
	return 0
}

proc ApolTop::configure_load_index_menu_item {enable} {
	variable mainframe
	
	if {$enable} {
		[$mainframe getmenu fc_index_menu] entryconfigure last -label "Load Index..."
	} else {
		[$mainframe getmenu fc_index_menu] entryconfigure last -label "Load Index... (Not loaded)"	     
	}
	return 0
}

########################################################################
# ::strip_list_of_empty_items -- takes a tcl list and checks for empty
#	list items. If empty list items are found, it will be removed
#	from the list and a new formatted list will be returned.
#
proc ApolTop::strip_list_of_empty_items {list_1} {
	global tcl_version
	
	set len [llength $list_1]
	set items ""
	for {set i 0} {$i < $len} {incr i} {
		if {[lindex $list_1 $i] != ""} {
			set items [lappend items [lindex $list_1 $i]]	
		}
	}
	
	return $items
}
	

# ------------------------------------------------------------------------------
#  Command ApolTop::popup_listbox_Menu
# ------------------------------------------------------------------------------
proc ApolTop::popup_listbox_Menu { global x y popup callbacks list_box} {
	focus -force $list_box
	
	set selected_item [$list_box get active]
	if {$selected_item == ""} {
		return
	}
	# Getting global coordinates of the application window (of position 0, 0)
	set gx [winfo rootx $global]	
	set gy [winfo rooty $global]
	
	# Add the global coordinates for the application window to the current mouse coordinates
	# of %x & %y
	set cmx [expr $gx + $x]
	set cmy [expr $gy + $y]
	
	$popup delete 0 end
	foreach callback $callbacks {
		$popup add command -label "[lindex $callback 0]" -command "[lindex $callback 1] $selected_item"
	}
	
	# Posting the popup menu
	tk_popup $popup $cmx $cmy
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTop::popup_Tab_Menu
# ------------------------------------------------------------------------------
proc ApolTop::popup_Tab_Menu { window x y popupMenu callbacks page } {
	if {$page == ""} {
		return
	}
	
	# Getting global coordinates of the application window (of position 0, 0)
	set gx [winfo rootx $window]	
	set gy [winfo rooty $window]
	
	# Add the global coordinates for the application window to the current mouse coordinates
	# of %x & %y
	set cmx [expr $gx + $x]
	set cmy [expr $gy + $y]
	
	$popupMenu delete 0 end
	foreach callback $callbacks {
            $popupMenu add command -label [lindex $callback 0] -command [list [lindex $callback 1] $page]
	}
		
	# Posting the popup menu
   	tk_popup $popupMenu $cmx $cmy
   	
   	return 0
}

proc ApolTop::set_Focus_to_Text { tab } {
	variable components_nb
	variable rules_nb
	variable file_contexts_tab
	
	$ApolTop::mainframe setmenustate Disable_SearchMenu_Tag normal
	# The load query menu option should be enabled across all tabs. 
	# However, we disable the save query menu option if it this is not the Analysis or TE Rules tab.
	# Currently, these are the only tabs providing the ability to save queries. It would be too trivial
	# to allow saving queries for the other tabs.
	$ApolTop::mainframe setmenustate Disable_LoadQuery_Tag normal
	set ApolTop::policyConf_lineno ""
	
	switch -exact -- $tab \
		$ApolTop::components_tab {
			$ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
			ApolTop::set_Focus_to_Text [$components_nb raise]
		} \
		$ApolTop::rules_tab {
			ApolTop::set_Focus_to_Text [$rules_nb raise]
		} \
		$ApolTop::terules_tab {
			$ApolTop::mainframe setmenustate Disable_SaveQuery_Tag normal 
			set raisedPage [Apol_TE::get_results_raised_tab]
			if {$raisedPage != ""} {
				Apol_TE::set_Focus_to_Text $raisedPage
			} else {
				focus [$ApolTop::rules_nb getframe $ApolTop::terules_tab]
			}
		} \
		$ApolTop::analysis_tab {
			$ApolTop::mainframe setmenustate Disable_SaveQuery_Tag normal
		} \
            default {
                $ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
                ${tab}::set_Focus_to_Text
            }
}

########################################################################
# ::textSearch --
# 	- Search for an instances of a given string in a text widget and
# 	- selects matching text..
#
# Arguments:
# w -			The window in which to search.  Must be a text widget.
# str -			The string to search for. BUG NOTE: '-' as first character throws an error.
# case_Insensitive	Whether to ignore case differences or not
# regExpr		Whether to treat $str as a regular expression and match it against the text 
# srch_Direction	What direction to search in the text. (-forward or -backward)
#
proc ApolTop::textSearch { w str case_Insensitive regExpr srch_Direction } {
	if {$str == ""} {
		return 0
	}
			
	# Local variables to hold search options. Initialized to space characters. 
	set case_opt " "
	set regExpr_opt " "
	set direction_opt " "
	
	# Setting search options.
	if { $case_Insensitive } {
		set case_opt "-nocase"
	}
	if { $regExpr } {
		set regExpr_opt "-regexp"
	}
	if { $srch_Direction == "down" } {
		set direction_opt "-forward"
		# Get the current insert position. 
		set cur_srch_pos [$w index insert]
	} else {
		set direction_opt "-backward"
		# Get the first character index of the current selection.
		set cur_srch_pos [lindex [$w tag ranges sel] 0]
	}
	
	if { $cur_srch_pos == "" } {
		set cur_srch_pos "1.0"
	}
	
	# Remove any selection tags.
	$w tag remove sel 0.0 end
		
	# Set the command string and strip out any space characters (meaning that an option was not selected).
	# BUG NOTE: Currently, there is a bug with text widgets' search command. It does not
	# handle a '-' as the first character in the string. 
	set cmd "$w search -count cur_srch_pos_length $case_opt $regExpr_opt $direction_opt"
	set rt [catch {set cur_srch_pos [eval $cmd {"$str"} $cur_srch_pos] } err]
	
	# Catch any error performing the search command and display error message to user.
	if { $rt != 0 } {
		tk_messageBox -parent $ApolTop::searchDlg -icon error -type ok -title "Search Error" -message \
				"$err"
		return -1
	}
	
	# Prompt the user if a match was not found.	
	if { $cur_srch_pos == "" } {
		# NOTE: Use vwait command.to block the application if the event hasn't completed.
		# This is because when Return button is hit multiple times a TCL/TK bug is being
		# thrown:can't read "::tk::FocusGrab(...)
		# The problem is that tkMessageBox summarily destroys the old window -
		# which screws up SetFocusGrab's private variables because SetFocusGrab isn't reentrant.
		set ApolTop::tk_msgBox_Wait  \
			[tk_messageBox -parent $ApolTop::searchDlg -icon warning -type ok -title "Search Failed" -message \
					"Search string not found!"]
		vwait ApolTop::tk_msgBox_Wait
	} else {	
		# Set the insert position in the text widget. 
		# If the direction is down, set the mark to index of the END character in the match.
		# If the direction is up, set the mark to the index of the FIRST character in the match.
		$w mark set insert "$cur_srch_pos + $cur_srch_pos_length char"
		$w tag add sel $cur_srch_pos "$cur_srch_pos + $cur_srch_pos_length char"
		
		# Adjust the view in the window.
		$w see $cur_srch_pos
	}
	
	return 0
}

##############################################################
# ::search
#  	- Search raised text widget for a string
# 
proc ApolTop::search {} {
	variable searchString
	variable case_Insensitive	
	variable regExpr 		
	variable srch_Direction
	variable notebook
	variable components_nb
	variable rules_nb
	variable components_tab 	
    	variable rules_tab 		
	variable policy_conf_tab	
	variable analysis_tab	
	variable file_contexts_tab
	
	set raised_tab [$notebook raise]	
	switch -- $raised_tab \
    		$policy_conf_tab {
    			${policy_conf_tab}::search $searchString $case_Insensitive $regExpr $srch_Direction
    		} \
    		$analysis_tab {
    			${analysis_tab}::search $searchString $case_Insensitive $regExpr $srch_Direction
    		} \
    		$rules_tab {
    			[$rules_nb raise]::search $searchString $case_Insensitive $regExpr $srch_Direction
    		} \
    		$components_tab {
    			[$components_nb raise]::search $searchString $case_Insensitive $regExpr $srch_Direction
    		} \
    		$file_contexts_tab {
    			${file_contexts_tab}::search $searchString $case_Insensitive $regExpr $srch_Direction
    		} \
    		default {
    			puts "Invalid raised tab!"
    		}  
	
	return 0
}

##############################################################
# ::load_query_info
#  	- Call load_query proc for valid tab
# 
proc ApolTop::load_query_info {} {
	variable notebook 
	variable rules_tab
	variable terules_tab
	variable analysis_tab
	variable rules_nb
	variable mainframe
	
	set query_file ""
        set types {
		{"Query files"		{$ApolTop::query_file_ext}}
    	}
	set query_file [tk_getOpenFile -filetypes $types -title "Select Query to Load..." \
		-defaultextension $ApolTop::query_file_ext -parent $mainframe]
	if {$query_file != ""} {
		if {[file exists $query_file] == 0 } {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "File $query_file does not exist." -parent $mainframe
			return -1
		}
		set rt [catch {set f [::open $query_file]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "Cannot open $query_file: $err"
			return -1
		}
		# Search for the analysis type line
		gets $f line
		set query_id [string trim $line]
		while {[eof $f] != 1} {
			# Skip empty lines and comments
			if {$query_id == "" || [string compare -length 1 $query_id "#"] == 0} {
				gets $f line
				set query_id [string trim $line]
				continue
			}
			break
		}

		switch -- $query_id \
	    		$analysis_tab {
	    			set rt [catch {${analysis_tab}::load_query_options $f $mainframe} err]
	    			if {$rt != 0} {
	    				tk_messageBox -icon error -type ok -title "Error" \
						-message "$err"
					return -1
				}
	    			$notebook raise $analysis_tab
	    		} \
	    		$terules_tab {
	    			if {[string equal [$rules_nb raise] $ApolTop::terules_tab]} {
	    				set rt [catch {${ApolTop::terules_tab}::load_query_options $f $mainframe} err]
	    				if {$rt != 0} {
		    				tk_messageBox -icon error -type ok -title "Error" \
							-message "$err"
						return -1
					}
	    				$notebook raise $rules_tab
	    				$rules_nb raise $ApolTop::terules_tab
	    			}
	    		} \
	    		default {
	    			tk_messageBox -icon error -type ok -title "Error" \
					-message "Invalid query ID."
	    		}
	    	ApolTop::set_Focus_to_Text [$notebook raise]
	    	::close $f
	}
    	return 0  
}

##############################################################
# ::save_query_info
#  	- Call save_query proc for valid tab
# 
proc ApolTop::save_query_info {} {
	variable notebook 
	variable rules_tab
	variable terules_tab
	variable analysis_tab
	variable rules_nb
	variable mainframe
	
	# Make sure we only allow saving from the Analysis and TERules tabs
	set raised_tab [$notebook raise]

	if {![string equal $raised_tab $analysis_tab] && ![string equal $raised_tab $rules_tab]} {
		tk_messageBox -icon error -type ok -title "Save Query Error" \
			-message "You cannot save a query from this tab! \
			You can only save from the Policy Rules->TE Rules tab and the Analysis tab."
		return -1
    	} 
    	if {[string equal $raised_tab $rules_tab] && ![string equal [$rules_nb raise] $terules_tab]} {
		tk_messageBox -icon error -type ok -title "Save Query Error" \
			-message "You cannot save a query from this tab! \
			You can only save from the Policy Rules->TE Rules tab and the Analysis tab."
		return -1
	}
			    		
	set query_file ""
        set types {
		{"Query files"		{$ApolTop::query_file_ext}}
    	}
    	set query_file [tk_getSaveFile -title "Save Query As?" \
    		-defaultextension $ApolTop::query_file_ext \
    		-filetypes $types -parent $mainframe]
	if {$query_file != ""} {
		set rt [catch {set f [::open $query_file w+]} err]
		if {$rt != 0} {
			return -code error $err
		}	
		switch -- $raised_tab \
	    		$analysis_tab {
	    			puts $f "$analysis_tab"
	    			set rt [catch {${analysis_tab}::save_query_options $f $query_file} err]
	    			if {$rt != 0} {
	    				::close $f
	    				tk_messageBox -icon error -type ok -title "Save Query Error" \
						-message "$err"
					return -1
				}
	    		} \
	    		$rules_tab {
	    			if {[string equal [$rules_nb raise] $terules_tab]} {
	    				puts $f "$terules_tab"	
	    				set rt [catch {${terules_tab}::save_query_options $f $query_file} err]
	    				if {$rt != 0} {
	    					::close $f
		    				tk_messageBox -icon error -type ok -title "Save Query Error" \
							-message "$err"
						return -1
					}
	    			}
	    		} \
	    		default {
	    			::close $f
	    			tk_messageBox -icon error -type ok -title "Save Query Error" \
					-message "You cannot save a query from this tab!"
				return -1
	    		}  
	    	::close $f
	}	  
	
	
    		
    	return 0
}

##############################################################
# ::display_searchDlg
#  	- Display the search dialog
# 
proc ApolTop::display_searchDlg {} {
	variable searchDlg
	variable searchDlg_entryBox
	global tcl_platform
	
	if { [$ApolTop::notebook raise] == $ApolTop::analysis_tab } {
		return
	}
	# Checking to see if window already exists. If so, it is destroyed.
	if { [winfo exists $searchDlg] } {
		raise $searchDlg
		focus $searchDlg_entryBox
		$searchDlg_entryBox selection range 0 end
		return
	}
	
	# Create the toplevel dialog window and set its' properties.
	toplevel $searchDlg
	wm protocol $searchDlg WM_DELETE_WINDOW " "
	wm withdraw $searchDlg
	wm title $searchDlg "Find"
	
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $ApolTop::searchDlg 0 0
	} else {
		bind $ApolTop::searchDlg <Configure> { wm geometry $ApolTop::searchDlg {} }
	}
    
	# Display results window
	set sbox [frame $searchDlg.sbox]
	set lframe [frame $searchDlg.lframe]
	set rframe [frame $searchDlg.rframe]
	set lframe_top [frame $lframe.lframe_top]
	set lframe_bot [frame $lframe.lframe_bot]
	set lframe_bot_left [frame $lframe_bot.lframe_bot_left]
	set lframe_bot_right [frame $lframe_bot.lframe_bot_right]
	
	set lbl_entry [label $lframe_top.lbl_entry -text "Find What:"]
	set searchDlg_entryBox [entry $lframe_top.searchDlg_entryBox -bg white -textvariable ApolTop::searchString ]
	set b_findNext [button $rframe.b_findNext -text "Find Next" \
		      -command { ApolTop::search }]
	set b_cancel [button $rframe.b_cancel -text "Cancel" \
		      -command "destroy $searchDlg"]
	set cb_case [checkbutton $lframe_bot_left.cb_case -text "Case Insensitive" -variable ApolTop::case_Insensitive]
	set cb_regExpr [checkbutton $lframe_bot_left.cb_regExpr -text "Regular Expressions" -variable ApolTop::regExpr]
	set directionBox [TitleFrame $lframe_bot_right.directionBox -text "Direction" ]
	set dir_up [radiobutton [$directionBox getframe].dir_up -text "Up" -variable ApolTop::srch_Direction \
			 -value up ]
    	set dir_down [radiobutton [$directionBox getframe].dir_down -text "Down" -variable ApolTop::srch_Direction \
			 -value down ]
	
	# Placing display widgets
	pack $sbox -expand yes -fill both -padx 5 -pady 5
	pack $lframe -expand yes -fill both -padx 5 -pady 5 -side left
	pack $rframe -expand yes -fill both -padx 5 -pady 5 -side right
	pack $lframe_top -expand yes -fill both -padx 5 -pady 5 -side top
	pack $lframe_bot -expand yes -fill both -padx 5 -pady 5 -side bottom
	pack $lframe_bot_left -expand yes -fill both -padx 5 -pady 5 -side left 
	pack $lframe_bot_right -expand yes -fill both -padx 5 -pady 5 -side right
	pack $lbl_entry -expand yes -fill both -side left 
	pack $searchDlg_entryBox -expand yes -fill both -side right
	pack $b_findNext $b_cancel -side top -expand yes -fill x
	pack $cb_case $cb_regExpr -expand yes -side top -anchor nw
	pack $directionBox -side left -expand yes -fill both
	pack $dir_up $dir_down -side left -anchor center 
	
	# Place a toplevel at a particular position
	#::tk::PlaceWindow $searchDlg widget center
	wm deiconify $searchDlg
	focus $searchDlg_entryBox 
	$searchDlg_entryBox selection range 0 end
	bind $ApolTop::searchDlg <Return> { ApolTop::search }
	wm protocol $searchDlg WM_DELETE_WINDOW "destroy $searchDlg"
	return 0
}	

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc ApolTop::goto_line { line_num textBox } {
	variable notebook
	
	if {[string is integer -strict $line_num] != 1} {
		tk_messageBox -icon error \
			-type ok  \
			-title "Invalid line number" \
			-message "$line_num is not a valid line number"
		return 0
	}
	# Remove any selection tags.
	$textBox tag remove sel 0.0 end
	$textBox mark set insert ${line_num}.0 
	$textBox see ${line_num}.0 
	$textBox tag add sel $line_num.0 $line_num.end
	focus -force $textBox
	
	return 0
}

##############################################################
# ::call_tabs_goto_line_cmd
#  	-  
proc ApolTop::call_tabs_goto_line_cmd { } {
	variable goto_line_num
	variable notebook
	variable components_nb
	variable rules_nb
	variable components_tab 	
    	variable rules_tab 		
	variable policy_conf_tab	
	variable analysis_tab		
	variable file_contexts_tab
	
	set raised_tab [$notebook raise]	
	switch -- $raised_tab \
    		$policy_conf_tab {
    			${policy_conf_tab}::goto_line $goto_line_num
    		} \
    		$analysis_tab {
    			${analysis_tab}::goto_line $goto_line_num
    		} \
    		$rules_tab {
    			[$rules_nb raise]::goto_line $goto_line_num
    		} \
    		$components_tab {
    			[$components_nb raise]::goto_line $goto_line_num
    		} \
    		$file_contexts_tab {
    			${file_contexts_tab}::goto_line $goto_line_num
    		} \
    		default {
    			return -code error
    		}  
    	
	return 0
}

##############################################################
# ::display_goto_line_Dlg
#  	-  
proc ApolTop::display_goto_line_Dlg { } {
	variable notebook
	variable goto_Dialog
	variable gotoDlg_entryBox
	global tcl_platform
	
	if { [$ApolTop::notebook raise] == $ApolTop::analysis_tab } {
		return
	}
	# create dialog
    	if { [winfo exists $goto_Dialog] } {
    		raise $goto_Dialog
    		focus $gotoDlg_entryBox
    		return 0
    	}
    	toplevel $goto_Dialog
   	wm protocol $goto_Dialog WM_DELETE_WINDOW " "
    	wm withdraw $goto_Dialog
    	wm title $goto_Dialog "Goto"
    	
    	if {$tcl_platform(platform) == "windows"} {
		wm resizable $ApolTop::goto_Dialog 0 0
	} else {
		bind $ApolTop::goto_Dialog <Configure> { wm geometry $ApolTop::goto_Dialog {} }
	}
	# Clear the previous line number
	set ApolTop::goto_line_num ""
	set gotoDlg_entryBox [entry $goto_Dialog.gotoDlg_entryBox -textvariable ApolTop::goto_line_num -width 10 ]
	set lbl_goto  [label $goto_Dialog.lbl_goto -text "Goto:"]
	set b_ok      [button $goto_Dialog.ok -text "OK" -width 6 -command { ApolTop::call_tabs_goto_line_cmd; destroy $ApolTop::goto_Dialog}]
	set b_cancel  [button $goto_Dialog.cancel -text "Cancel" -width 6 -command { destroy $ApolTop::goto_Dialog }]
	
	pack $lbl_goto $gotoDlg_entryBox -side left -padx 5 -pady 5 -anchor nw
	pack $b_ok $b_cancel -side left -padx 5 -pady 5 -anchor ne
	
	# Place a toplevel at a particular position
    	#::tk::PlaceWindow $goto_Dialog widget center
	wm deiconify $goto_Dialog
	focus $gotoDlg_entryBox
	bind $ApolTop::goto_Dialog <Return> { ApolTop::call_tabs_goto_line_cmd; destroy $ApolTop::goto_Dialog }
	wm protocol $goto_Dialog WM_DELETE_WINDOW "destroy $goto_Dialog"
	return 0
}

proc ApolTop::check_libsefs {} {
    set ApolTop::libsefs [apol_IsLibsefs_BuiltIn]
}

proc ApolTop::create { } {
	variable notebook 
	variable mainframe  
	variable components_nb
	variable rules_nb
       
	# Menu description
	set descmenu {
	"&File" {} file 0 {
	    {command "&Open..." {} "Open a new policy"  {}  -command ApolTop::openPolicy}
	    {command "&Close" {} "Close an opened polocy"  {} -command ApolTop::closePolicy}
	    {separator}
	    {command "E&xit" {} "Exit policy analysis tool" {} -command ApolTop::apolExit}
	    {separator}
	    {cascad "&Recent files" {} recent 0 {}}
	
	}
	"&Search" {} search 0 {      
	    {command "&Find...                    (C-s)" {Disable_SearchMenu_Tag} "Find"  \
	    	{} -command ApolTop::display_searchDlg }
	    {command "&Goto Line...           (C-g)" {Disable_SearchMenu_Tag} "Goto Line"  \
	    	{} -command ApolTop::display_goto_line_Dlg }
	}
	"&Query" {} query 0 {
	    {command "&Load query..." {Disable_LoadQuery_Tag} "Load query"  \
	    	{} -command "ApolTop::load_query_info" }
	    {command "&Save query..." {Disable_SaveQuery_Tag} "Save query"  \
	    	{} -command "ApolTop::save_query_info" }
	    {separator}
	    {command "&Policy Summary" {Disable_Summary} "Display summary statics" {} -command ApolTop::popupPolicyStats }
	}
	"&Advanced" all options 0 {
	    {cascad "&Permission Mappings" {Perm_Map_Tag} pmap_menu 0 {}}
	    #{cascad "&File Context Indexing" {FC_Index_Tag} fc_index_menu 0 {}}
        }
	"&Help" {} helpmenu 0 {
	    {command "&General Help" {all option} "Show help" {} -command {ApolTop::helpDlg "Help" "apol_help.txt"}}
	    {command "&Domain Transition Analysis" {all option} "Show help" {} -command {ApolTop::helpDlg "Domain Transition Analysis Help" "domaintrans_help.txt"}}
	    {command "&Information Flow Analysis" {all option} "Show help" {} -command {ApolTop::helpDlg "Information Flow Analysis Help" "infoflow_help.txt"}}
	    #{command "&Information Flow Assertion Analysis" {all option} "Show help" {} -command {ApolTop::helpDlg "Information Flow Assertion Analysis Help" "flow_assertion_help.txt"}}
	    {command "&Direct Relabel Analysis" {all option} "Show help" {} -command {ApolTop::helpDlg "Relabel Analysis Help" "file_relabel_help.txt"}}
	    {command "&Types Relationship Summary Analysis" {all option} "Show help" {} -command {ApolTop::helpDlg "Types Relationship Summary Analysis Help" "types_relation_help.txt"}}
	    {separator}
	    {command "&About" {all option} "Show about box" {} -command ApolTop::aboutBox}
	}
	}
	
	set mainframe [MainFrame .mainframe -menu $descmenu -textvariable ApolTop::status]
	[$mainframe getmenu pmap_menu] insert 0 command -label "Edit Perm Map... (Not loaded)" -command "Apol_Perms_Map::editPermMappings"
	[$mainframe getmenu pmap_menu] insert 0 separator
	[$mainframe getmenu pmap_menu] insert 0 command -label "Load Perm Map from File..." -command "ApolTop::load_perm_map_file"
	[$mainframe getmenu pmap_menu] insert 0 command -label "Load Default Perm Map" -command "ApolTop::load_default_perm_map_Dlg"
	
	#[$mainframe getmenu fc_index_menu] insert 0 command -label "Load Index... (Not loaded)" -command "ApolTop::load_fc_index_file"
	#[$mainframe getmenu fc_index_menu] insert 0 command -label "Create Index" -command "ApolTop::create_fc_index_file"
		
	$mainframe addindicator -textvariable ApolTop::policyConf_lineno -width 14
	$mainframe addindicator -textvariable ApolTop::policy_stats_summary -width 88
	$mainframe addindicator -textvariable ApolTop::policy_version_string -width 28
	
	# Disable menu items since a policy is not yet loaded.
	$ApolTop::mainframe setmenustate Disable_SearchMenu_Tag disabled
	$ApolTop::mainframe setmenustate Perm_Map_Tag disabled
	$ApolTop::mainframe setmenustate FC_Index_Tag normal
	$ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
	$ApolTop::mainframe setmenustate Disable_LoadQuery_Tag disabled
	$ApolTop::mainframe setmenustate Disable_Summary disabled
		
	# NoteBook creation
	set frame    [$mainframe getframe]
	set notebook [NoteBook $frame.nb]
	
	# Create Top-level tab frames	
	set components_frame [$notebook insert end $ApolTop::components_tab -text "Policy Components"]
	set rules_frame [$notebook insert end $ApolTop::rules_tab -text "Policy Rules"]

	if {$ApolTop::libsefs == 1} {
		Apol_File_Contexts::create $notebook
	}
	Apol_Analysis::create $notebook
	Apol_PolicyConf::create $notebook
	
	# Create subordinate tab frames
	set components_nb [NoteBook $components_frame.components_nb]
	set rules_nb [NoteBook $rules_frame.rules_nb]

	variable mls_tabs

	# Subtabs for the main policy components tab.
	Apol_Types::create $components_nb
	Apol_Class_Perms::create $components_nb
	Apol_Roles::create $components_nb
	Apol_Users::create $components_nb
	Apol_Cond_Bools::create $components_nb
	Apol_MLS::create $components_nb
	lappend mls_tabs [list $components_nb [$components_nb pages end]]
	Apol_Initial_SIDS::create $components_nb
	Apol_NetContexts::create $components_nb
	Apol_FSContexts::create $components_nb

	# Subtabs for the main policy rules tab
	Apol_TE::create $rules_nb
	Apol_Cond_Rules::create $rules_nb
	Apol_RBAC::create $rules_nb
	Apol_Range::create $rules_nb
	lappend mls_tabs [list $rules_nb [$rules_nb pages end]]

	$components_nb compute_size
	pack $components_nb -fill both -expand yes -padx 4 -pady 4
	$components_nb raise [$components_nb page 0]
	$components_nb bindtabs <Button-1> { ApolTop::set_Focus_to_Text }
	
	$rules_nb compute_size
	pack $rules_nb -fill both -expand yes -padx 4 -pady 4
	$rules_nb raise [$rules_nb page 0]
	$rules_nb bindtabs <Button-1> { ApolTop::set_Focus_to_Text }
	
	bind . <Control-f> {ApolTop::display_searchDlg}
	bind . <Control-g> {ApolTop::display_goto_line_Dlg}
	
	$notebook compute_size
	pack $notebook -fill both -expand yes -padx 4 -pady 4
	$notebook raise [$notebook page 0]
	$notebook bindtabs <Button-1> { ApolTop::set_Focus_to_Text }	
	pack $mainframe -fill both -expand yes
	
	return 0
}

# Saves user data in their $HOME/.apol file
proc ApolTop::writeInitFile { } {
	variable dot_apol_file 
	variable num_recent_files
	variable recent_files
	variable text_font		
	variable title_font
	variable dialog_font
	variable general_font
	variable policy_open_option
	
	set rt [catch {set f [open $dot_apol_file w+]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return
	}
	puts $f "recent_files"
	puts $f $num_recent_files
	for {set i 0} {$i < $num_recent_files} {incr i} {
 		puts $f $recent_files($i)
 	}
	# free the recent files array
	array unset recent_files

	puts $f "\n"
	puts $f "# Font format: family ?size? ?style? ?style ...?"
	puts $f "# Possible values for the style arguments are as follows:"
	puts $f "# normal bold roman italic underline overstrike\n#\n#"
	puts $f "# NOTE: When configuring fonts, remember to remove the following "
	puts $f "# \[window height\] and \[window width\] entries before starting apol. "
	puts $f "# Not doing this may cause widgets to be obscured when running apol."
	puts $f "\[general_font\]"
	if {$general_font == ""} {
		puts $f "Helvetica 10"
	} else {
		puts $f "$general_font" 
	}
	puts $f "\[title_font\]"
	if {$title_font == ""} {
		puts $f "Helvetica 10 bold italic"
	} else {
		puts $f "$title_font"  
	}
	puts $f "\[dialog_font\]"
	if {$dialog_font == ""} {
		puts $f "Helvetica 10"
	} else {
		puts $f "$dialog_font"
	}
	puts $f "\[text_font\]"
	if {$text_font == ""} {
		puts $f "fixed"
	} else {
		puts $f "$text_font"
	}
        puts $f "\[window_height\]"
        puts $f [winfo height .]
        puts $f "\[window_width\]"
        puts $f [winfo width .]
        puts $f "\[policy_open_option\]"
        puts $f $policy_open_option
	puts $f "\[show_fake_attrib_warning\]"
	puts $f $ApolTop::show_fake_attrib_warning
	close $f
	return 0
}


# Reads in user data from their $HOME/.apol file 
proc ApolTop::readInitFile { } {
	variable dot_apol_file
	variable max_recent_files 
	variable recent_files
	variable text_font		
	variable title_font
	variable dialog_font
	variable general_font
	variable temp_recent_files
	variable top_height
        variable top_width
    variable policy_open_option {}
	
	# if it doesn't exist, we'll create later
	if {[file exists $dot_apol_file] == 0 } {
		return
	}
	set rt [catch {set f [open $dot_apol_file]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Cannot open .apol file ($rt: $err)"
		return
	}
	
	# Flags for key words
	set max_recent_flag 0
	set recent_files_flag 0
	
	gets $f line
	set tline [string trim $line]
	while {1} {
		if {[eof $f] && $tline == ""} {
			break
		}
		if {[string compare -length 1 $tline "#"] == 0 || [string is space $tline]} {
			gets $f line
			set tline [string trim $line]
			continue
		}
		switch $tline {
		        "\[window_height\]" {
			        gets $f line
			        set tline [string trim $line]
			        if {[eof $f] == 1 && $tline == ""} {
				    puts "EOF reached trying to read window_height."
			   	    continue
			        }
			        if {[string is integer $tline] != 1} {
				    puts "window_height was not given as an integer ($line) and is ignored"
				    break
			        }
			        set top_height $tline
			}
		        "\[window_width\]" {
			        gets $f line
			        set tline [string trim $line]
			        if {[eof $f] == 1 && $tline == ""} {
				    puts "EOF reached trying to read window_width."
				    continue
			        }
			        if {[string is integer $tline] != 1} {
				    puts "window_width was not given as an integer ($line) and is ignored"
				    break
			        }
			        set top_width $tline
			}
		        "\[title_font\]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read title font."
					continue
				}
				set title_font $tline
			}
			"\[dialog_font\]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read dialog font."
					continue
				}
				set dialog_font $tline
			}
			"\[text_font\]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read text font."
					continue
				}
				set text_font $tline
			}
			"\[general_font\]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read general font."
					continue
				}
				set general_font $tline
			}
			"\[policy_open_option\]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read open policy option."
					continue
				}
				set policy_open_option $tline
			}
			"\[show_fake_attrib_warning\]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read show_fake_attrib_warning"
					continue
				}
				set ApolTop::show_fake_attrib_warning $tline
			}
		
			# The form of [max_recent_file] is a single line that follows
			# containing an integer with the max number of recent files to 
			# keep.  The default is 5 if this is not specified.  A number larger
			# than 10 will be set to 10.  A number of less than 2 is set to 2.
			"max_recent_files" {
				# we shouldn't be getting the max number after reading in the file names
				if {$recent_files_flag == 1} {
					puts "Key word max_recent_files found after recent file names read; ignored"
					# read next line which should be max num
					gets $ line
					continue
				}
				if {$max_recent_flag == 1} {
					puts "Key word max_recent_flag found twice in file!"
					continue
				}
				set max_recent_flag 1
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read max_recent_file."
					continue
				}
				if {[string is integer $tline] != 1} {
					puts "max_recent_files was not given as an integer ($line) and is ignored"
				} else {
					if {$tline>10} {
						set max_recent_files 10
					} elseif {$tline < 2} {
						set max_recent_files 2
					}
					else {
						set max_recent_files $tline
					}
				}
			}
			# The form of this key in the .apol file is as such
			# 
			# [recent_files]
			# 5			(# indicating how many file names follows)
			# filename1
			# filename2
			# ...			
			"recent_files" {
				if {$recent_files_flag == 1} {
					puts "Key word recent_files found twice in file!"
					continue
				}
				set recent_files_flag 1
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read num of recent files."
					continue
				}
				if {[string is integer $tline] != 1} {
					puts "number of recent files was not given as an integer ($line) and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				} elseif {$tline < 0} {
					puts "number of recent was less than 0 and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				}
				set num $tline
				# read in the lines with the files
				for {set i 0} {$i<$num} {incr i} {
					gets $f line
					set tline [string trim $line]
					if {[eof $f] == 1 && $tline == ""} {
						puts "EOF reached trying to read recent file name $num."
						break
					}
					if {[string is space $tline]} {
						continue
					}
					# check if stored num is greater than max; if so just ignore the rest
					if {$i >= $max_recent_files} {
						continue
					}		
					# Add to recent files list.
					set temp_recent_files [lappend temp_recent_files $tline]
				}
			}
			default {
				puts "Unrecognized line in .apol: $line"
			}
		}
		
		gets $f line
		set tline [string trim $line]
	}
	close $f	
	return 0
}


# Add a policy file to the recently opened
proc ApolTop::addRecent {file} {
	variable mainframe
	variable recent_files
	variable num_recent_files
    	variable max_recent_files
    	variable most_recent_file
    	
    	if {$num_recent_files < $max_recent_files} {
    		set x $num_recent_files
    		set less_than_max 1
    	} else {
    		set x $max_recent_files 
    		set less_than_max 0
    	}
	
	# First check if already in recent file list
	for {set i 0} {$i < $x } {incr i} {
		if {[string equal $file $recent_files($i)]} {
 			return
 		}
	}
	if {![file exists $file]} {
		return
	}
	if {$num_recent_files < $max_recent_files} {
		# list not full, just add to list and insert into menu
		set recent_files($num_recent_files) $file
		[$mainframe getmenu recent] insert $num_recent_files command -label "$recent_files($num_recent_files)" -command "ApolTop::openPolicyFile $recent_files($num_recent_files) 0"
		incr num_recent_files
	} else {
		[$mainframe getmenu recent] delete 0 end
		# list is full, need to replace the last entry, which is the oldest.
		set oldest [expr $max_recent_files - 1]
		# Replace the first elements value with the new file. We have now popped the oldest menu item off the bottom of
		# the list and stacked the new opened file to the top of the list. The most recent file should be the top-most.
		set recent_files_tmp($most_recent_file) $file
		[$mainframe getmenu recent] insert $most_recent_file command -label "$recent_files_tmp($most_recent_file)" -command "ApolTop::openPolicyFile $recent_files_tmp($most_recent_file) 0"
		
		for {set i 0} {$i < [expr $max_recent_files - 1]} {incr i} {
			set next [expr $i + 1]
			# Replace the next elements value to the current index value. 
			set recent_files_tmp($next) $recent_files($i)
			[$mainframe getmenu recent] insert $next command -label "$recent_files_tmp($next)" -command "ApolTop::openPolicyFile $recent_files_tmp($next) 0"
		}
		array set recent_files [array get recent_files_tmp]
		array unset recent_files_tmp
		set most_recent_file 0
	}	
	return 0
}

proc ApolTop::helpDlg {title file_name} {
    set help_dir [apol_GetHelpDir "$file_name"]
    set helpfile "$help_dir/$file_name"
    if {[catch {open $helpfile} f]} {
        set info $f
    } else {
        set info [read $f]
    }
    Apol_Widget::showPopupParagraph $title $info
}

proc ApolTop::setBusyCursor {} {
    variable prevCursor
    set prevCursor [. cget -cursor] 
    . configure -cursor watch
}

proc ApolTop::resetBusyCursor {} {
    variable prevCursor
    . configure -cursor $prevCursor
}

proc ApolTop::popupPolicyStats {} {
    variable polstats

    set classes $polstats(classes)
    set common_perms $polstats(common_perms)
    set perms $polstats(perms)
    if {![regexp -- {^([^\(]+) \(([^,]+), ([^\)]+)} $ApolTop::policy_version_string -> policy_version policy_type policy_mls_type]} {
        set policy_version $ApolTop::policy_version_string
        set policy_type "unknown"
        set policy_mls_type "unknown"
    }
    set policy_version [string trim $policy_version]

    destroy .polstatsbox
    set dialog [Dialog .polstatsbox -separator 1 -title "Policy Summary" \
                    -modal none -parent .]
    $dialog add -text Close -command [list destroy $dialog]
    
    set w [$dialog getframe]
	
    label $w.title -text "Policy Summary Statistics"
    set f [frame $w.summary]
    label $f.l -justify left -text "    Policy Version:\n    Policy Type:\n    MLS Status:"
    label $f.r -justify left -text "$policy_version\n$policy_type\n$policy_mls_type"
    grid $f.l $f.r -sticky w
    grid configure $f.r -padx 30
    grid $w.title - -sticky w -padx 8
    grid $f - -sticky w -padx 8
    grid [Separator $w.sep] - -sticky ew -pady 5
    
    set f [frame $w.left]
    set i 0
    foreach {title block} {
        "Number of Classes and Permissions" {
            "Object Classes" classes
            "Common Perms" common_perms
            "Permissions" perms
        }
        "Number of Types and Attributes" {
            "Types" types
            "Attributes" attribs
        }
        "Number of Type Enforcement Rules" {
            "allow" teallow
            "neverallow" neverallow
            "auditallow" auditallow
            "dontaudit" dontaudit
            "type_transition" tetrans
            "type_member" temember
            "type_change" techange
        }
        "Number of Roles" {
            "Roles" roles
        }
        "Number of RBAC Rules" {
            "allow" roleallow
            "role_transition" roletrans
        }
    } {
        set ltext "$title:"
        set rtext {}
        foreach {l r} $block {
            append ltext "\n    $l:"
            append rtext "\n$polstats($r)"
        }
        label $f.l$i -justify left -text $ltext
        label $f.r$i -justify left -text $rtext
        grid $f.l$i $f.r$i -sticky w -padx 4 -pady 2
        incr i
    }

    set i 0
    set g [frame $w.right]
    foreach {title block} {
        "Number of Users" {
            "Users" users
        }
        "Number of Booleans" {
            "Bools" cond_bools
        }
        "Number of MLS Components" {
            "Sensitivities" sens
            "Categories" cats
        }
        "Number of MLS Rules" {
            "range_transition" rangetrans
        }
        "Number of Initial SIDs" {
            "SIDs" sids
        }
        "Number of OContexts" {
            "PortCons" portcons
            "NetIfCons" netifcons
            "NodeCons" nodecons
            "GenFSCons" genfscons
            "fs_use statements" fs_uses
        }
    } {
        set ltext "$title:"
        set rtext {}
        foreach {l r} $block {
            append ltext "\n    $l:"
            append rtext "\n$polstats($r)"
        }
        label $g.l$i -justify left -text $ltext
        label $g.r$i -justify left -text $rtext
        grid $g.l$i $g.r$i -sticky w -padx 4 -pady 2
        incr i
    }
    grid $f $g -sticky nw -padx 4
    $dialog draw
}

proc ApolTop::showPolicyStats {} {
    variable polstats
    variable policy_stats_summary
    if {[catch {apol_GetStats} pstats]} {
        tk_messageBox -icon error -type ok -title "Error" -message $pstats
        return 
    }
    array unset polstats
    array set polstats $pstats

    set policy_stats_summary ""
    append policy_stats_summary "Classes: $polstats(classes)   "
    append policy_stats_summary "Perms: $polstats(perms)   "
    append policy_stats_summary "Types: $polstats(types)   "
    append policy_stats_summary "Attribs: $polstats(attribs)   "
    set num_te_rules [expr {$polstats(teallow) + $polstats(neverallow) +
                            $polstats(auditallow) + $polstats(dontaudit) +
                            $polstats(tetrans) + $polstats(temember) +
                            $polstats(techange)}]
    append policy_stats_summary "TE rules: $num_te_rules   "
    append policy_stats_summary "Roles: $polstats(roles)   "
    append policy_stats_summary "Users: $polstats(users)"
}

proc ApolTop::aboutBox {} {
     variable gui_ver
     variable copyright_date
     
     set lib_ver [apol_GetVersion]
     tk_messageBox -icon info -type ok -title "About SELinux Policy Analysis Tool" -message \
	"Security Policy Analysis Tool for Security Enhanced Linux \n\nCopyright (c) $copyright_date\nTresys Technology, LLC\nwww.tresys.com/selinux\n\nGUI Version ($gui_ver)\nLib Version ($lib_ver)"
     return
}

proc ApolTop::closePolicy {} {
	variable filename 
	variable policy_version_string {}
	variable policy_is_open
	variable policy_stats_summary {}
	
	set filename ""
	variable policy_mls_type ""
	
	wm title . "SE Linux Policy Analysis"

    variable tab_names
    foreach tab $tab_names {
        Apol_${tab}::close
    }
    Apol_Perms_Map::close

	ApolTop::set_Focus_to_Text [$ApolTop::notebook raise]
	set rt [catch {apol_ClosePolicy} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error closing policy" \
			-message "There was an error closing the policy: $err."
	} 
	set policy_is_open 0
	$ApolTop::mainframe setmenustate Disable_SearchMenu_Tag disabled
	# Disable Edit perm map menu item since a perm map is not yet sloaded.
	$ApolTop::mainframe setmenustate Perm_Map_Tag disabled
	$ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
	$ApolTop::mainframe setmenustate Disable_LoadQuery_Tag disabled
	$ApolTop::mainframe setmenustate Disable_Summary disabled
	ApolTop::enable_non_binary_tabs
	ApolTop::enable_disable_conditional_widgets 1
	set_mls_tabs_state normal
	ApolTop::configure_edit_pmap_menu_item 0
	#ApolTop::configure_load_index_menu_item 0

	return 0
}

proc ApolTop::open_apol_modules {file} {
    variable tab_names
    foreach tab $tab_names {
        if {$tab == "PolicyConf"} {
            Apol_PolicyConf::open $file
        } else {
            Apol_${tab}::open
        }
    }
}
 
proc ApolTop::enable_disable_conditional_widgets {enable} {
	set tab [$ApolTop::notebook raise] 
	switch -exact -- $tab \
		$ApolTop::components_tab {
			if {[$ApolTop::components_nb raise] == $ApolTop::cond_bools_tab} {
				if {$enable} {
					$ApolTop::components_nb raise $ApolTop::cond_bools_tab
				} else {
					set name [$ApolTop::components_nb pages 0]
					$ApolTop::components_nb raise $name
				}
			}				
		} \
		$ApolTop::rules_tab {
			if {[$ApolTop::rules_nb raise] == $ApolTop::cond_rules_tab} {
				if {$enable} {
					$ApolTop::rules_nb raise $ApolTop::cond_rules_tab
				} else {
					set name [$ApolTop::rules_nb pages 0]
					$ApolTop::rules_nb raise $name
				}
			}
		} \
		default { 
		}
		
	if {$enable} {
		$ApolTop::components_nb itemconfigure $ApolTop::cond_bools_tab -state normal
		$ApolTop::rules_nb itemconfigure $ApolTop::cond_rules_tab -state normal
	} else {
		$ApolTop::components_nb itemconfigure $ApolTop::cond_bools_tab -state disabled
		$ApolTop::rules_nb itemconfigure $ApolTop::cond_rules_tab -state disabled
	}
			
	return 0
}

proc ApolTop::enable_non_binary_tabs {} {
	# We make sure tabs that were disabled are re-enabled
	$ApolTop::notebook itemconfigure $ApolTop::policy_conf_tab -state normal
}

proc ApolTop::disable_non_binary_tabs {} {
   	if {[$ApolTop::notebook raise] == $ApolTop::policy_conf_tab} {
		set name [$ApolTop::notebook pages 0]
		$ApolTop::notebook raise $name
	} 
   	$ApolTop::notebook itemconfigure $ApolTop::policy_conf_tab -state disabled
}

# Enable/disable all of apol's tabs that deal exclusively with MLS
# components.  If the currently raised page is one of those tabs then
# raise the first page (which hopefully is not MLS specific).
proc ApolTop::set_mls_tabs_state {new_state} {
    variable mls_tabs

    foreach tab $mls_tabs {
        foreach {notebook page} $tab break
        set current_tab [$notebook raise]
        $notebook itemconfigure $page -state $new_state
        if {$current_tab == $page && $new_state == "disabled"} {
            $notebook raise [$notebook pages 0]
        }
    }
}

proc ApolTop::set_initial_open_policy_state {} {
	set rt [catch {set version_num [apol_GetPolicyVersionNumber]} err]
	if {$rt != 0} {
		return -code error $err
	}

	if {$version_num < 16} {
		ApolTop::enable_disable_conditional_widgets 0
	} 
	
	if {[ApolTop::is_binary_policy]} {
		if {$version_num >= 20 } {
			if {$ApolTop::show_fake_attrib_warning != 0} {
				set fake_attrib_warn .fakeattribDlg
				Dialog $fake_attrib_warn -modal local -parent . \
					-title "Warning - Attribute Names"
				set message_text "Warning: Apol has created fake attribute names because
the names are not preserved in the binary policy format."
				set fake_attrib_label [label $fake_attrib_warn.l -text $message_text]
				set fake_attrib_ok [button $fake_attrib_warn.b_ok -text "OK" \
					-command "destroy $fake_attrib_warn"]
				set fake_attrib_show [checkbutton $fake_attrib_warn.show_cb \
					-text "Show this message again next time." \
					-variable ApolTop::show_fake_attrib_warning]
				$fake_attrib_show select
				pack $fake_attrib_label -side top -padx 10 -pady 10
				pack $fake_attrib_show -side top -pady 10
				pack $fake_attrib_ok -side top -padx 10 -pady 10
				$fake_attrib_warn draw
			}
		}
		ApolTop::disable_non_binary_tabs
   	}
	if {![is_mls_policy]} {
		set_mls_tabs_state disabled
	}

	ApolTop::set_Focus_to_Text [$ApolTop::notebook raise]  
	# Enable perm map menu items since a policy is now open.
	$ApolTop::mainframe setmenustate Perm_Map_Tag normal
	$ApolTop::mainframe setmenustate Disable_Summary normal
	$ApolTop::mainframe setmenustate Disable_SearchMenu_Tag normal	
	
   	return 0
}
 
# Do the work to open a policy file:  file is file name, and
# recent_flag indicates whether to add this file to list of recently
# opened files (set to 1 if you want to do this).  You would NOT set
# this to 1 if a recently file is being opened with this proc.
proc ApolTop::openPolicyFile {file recent_flag} {
    variable policy_version_string
    variable policy_type
    variable policy_mls_type
    variable policy_is_open	

    ApolTop::closePolicy

    set file [file nativename $file]
    if {![file exists $file]} {
        tk_messageBox -icon error -type ok -title "Open Policy" -message "File $file does not exist."
        return
    } 
    if {![file readable $file]} {
        tk_messageBox -icon error -type ok -title "Open Policy" -message "File $file was not readable."
        return
    }
    if {[file isdirectory $file]} {
        tk_messageBox -icon error -type ok -title "Open Policy" -message "$file is a directory."
        return
    }

    set policy_is_open 0

    variable openDialogText "$file:\n    Opening policy."
    variable openDialogVal -1
    if {[set dialog_width [string length $file]] < 16} {
        set dialog_width 16
    }
    ProgressDlg .apol_policy_open -title "Open Policy" \
        -type normal -stop {} -separator 1 -parent . -maximum 2 \
        -width $dialog_width -textvariable ApolTop::openDialogText \
        -variable ApolTop::openDialogVal
    set orig_Cursor [. cget -cursor]
    . configure -cursor watch
    update idletasks
    after idle ApolTop::doOpenIdle
    set retval [catch {apol_OpenPolicy $file} err]
    . configure -cursor $orig_Cursor
    destroy .apol_policy_open
    if {$retval} {
        tk_messageBox -icon error -type ok -title "Open Policy" \
            -message "The selected file does not appear to be a valid SE Linux Policy.\n\n$err"
        return
    }

    if {[catch {apol_GetPolicyVersionString} policy_version_string]} {
        tk_messageBox -icon error -type ok -title "Open Policy" -message "Could not determine policy version:\n$policy_version_string"
        return
    }
    foreach {policy_type policy_mls_type} [apol_GetPolicyType] {break}
    ApolTop::showPolicyStats
    if {[catch {open_apol_modules $file} err]} {
        tk_messageBox -icon error -type ok -title "Open Policy" -message $err
        return
    }
    if {[catch {set_initial_open_policy_state} err]} {
        tk_messageBox -icon error -type ok -title "Open Policy" -message $err
        return
    }

    if {$recent_flag == 1} {
        addRecent $file
    }
    set policy_is_open 1
    variable filename $file
    wm title . "SE Linux Policy Analysis - $file"
}

proc ApolTop::doOpenIdle {} {
    variable openDialogText
    if {[set infoString [apol_GetInfoString]] != {}} {
        set openDialogText [lindex [split $openDialogText "\n"] 0]
        append openDialogText "\n    $infoString"
        update idletasks
        after idle ApolTop::doOpenIdle
    }
}

proc ApolTop::openPolicy {} {
    variable filename 

    set file ""
    set types {
        {"All files"		*}
        {"Policy conf files"	{.conf}}
    }
    if {$filename != ""} {
        set file [tk_getOpenFile -filetypes $types -initialdir [file dirname $filename]]
    } else {
        set file [tk_getOpenFile -filetypes $types]
    }

    if {$file != ""} {
        ApolTop::openPolicyFile $file 1
    }
}

proc ApolTop::free_call_back_procs { } {
	Apol_Class_Perms::free_call_back_procs
	Apol_Types::free_call_back_procs	
	Apol_TE::free_call_back_procs
	Apol_Roles::free_call_back_procs
	Apol_RBAC::free_call_back_procs
	Apol_Users::free_call_back_procs
	Apol_Initial_SIDS::free_call_back_procs
	Apol_Analysis::free_call_back_procs
	Apol_PolicyConf::free_call_back_procs
	Apol_Cond_Bools::free_call_back_procs
	Apol_Cond_Rules::free_call_back_procs
	return 0
}

proc ApolTop::apolExit { } {
	variable policy_is_open
	if {$policy_is_open} {
		ApolTop::closePolicy
	}
	if {$ApolTop::libsefs == 1} {
		Apol_File_Contexts::close  
	}
	ApolTop::free_call_back_procs
	ApolTop::writeInitFile
	exit
}

proc ApolTop::load_recent_files { } {
	variable temp_recent_files
	variable most_recent_file
	variable max_recent_files
	
	set most_recent_file 0
	set length [llength $temp_recent_files]
	for {set i 0} {$i < $length} {incr i} {
		ApolTop::addRecent [lindex $temp_recent_files $i]
	}
	
	# No longer need this variable; so, delete.
	unset temp_recent_files
	return 0
}

proc ApolTop::load_fonts { } {
	variable title_font
	variable dialog_font
	variable general_font
	variable text_font
	
	tk scaling -displayof . 1.0
	# First set all fonts in general; then change specific fonts
	if {$general_font == ""} {
		option add *Font "Helvetica 10"
		set general_font "Helvetica 10"
	} else {
		option add *Font $general_font
	}
	if {$title_font == ""} {
		option add *TitleFrame.l.font "Helvetica 10 bold italic" 
		set title_font "Helvetica 10 bold italic"
	} else {
		option add *TitleFrame.l.font $title_font  
	}
	if {$dialog_font == ""} {
		option add *Dialog*font "Helvetica 10" 
		set dialog_font "Helvetica 10"
	} else {
		option add *Dialog*font $dialog_font
	}
    option add *Dialog*TitleFrame.l.font $title_font
	if {$text_font == ""} {
		option add *text*font "fixed"
		set text_font "fixed"
	} else {
		option add *text*font $text_font
	}
	return 0	
}

proc ApolTop::main {} {
	global tk_version
	global tk_patchLevel
	variable top_width
        variable top_height
	variable notebook
	
	# Prevent the application from responding to incoming send requests and sending 
	# outgoing requests. This way any other applications that can connect to our X 
	# server cannot send harmful scripts to our application. 
	rename send {}
	
	# Load BWidget package into the interpreter
    if {[catch {package require BWidget}]} {
        tk_messageBox -icon error -type ok -title "Missing BWidget package" -message \
            "Missing BWidget package.  Ensure that your installed version of Tcl/Tk includes BWidget, which can be found at http://sourceforge.net/projects/tcllib."
        exit
    }

	# Load the apol package into the interpreter
	set rt [catch {package require apol} err]
	if {$rt != 0 } {
		tk_messageBox -icon error -type ok -title "Missing SE Linux package" -message \
			"Missing the SE Linux package.  This script will not\n\
			work correctly using the generic TK wish program.  You\n\
			must either use the apol executable or the awish\n\
			interpreter."
		exit
	}

	wm withdraw .
	wm title . "SE Linux Policy Analysis"
    wm protocol . WM_DELETE_WINDOW ApolTop::apolExit
	
	set rt [catch {ApolTop::check_libsefs} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return
	}
	
	# Read apols' default settings file, gather all font information, create the gui and then load recent files into the menu.
	ApolTop::readInitFile
	ApolTop::load_fonts
    catch {tcl_patch_bwidget}
    bind . <Button-1> {focus %W}
    bind . <Button-2> {focus %W}
    bind . <Button-3> {focus %W}
	ApolTop::create
	ApolTop::load_recent_files
				
	#    # Configure the geometry for the window manager
	#    set x  [winfo screenwidth .]
	#    set y  [winfo screenheight .]
	#    set width  [ expr $x - ($x/10) ]
	#    set height [ expr $y - ($y/4)  ]
	#    BWidget::place . $width $height center

    set ApolTop::top_width [$notebook cget -width]	
    set ApolTop::top_height [$notebook cget -height]
    wm geom . ${top_width}x${top_height}
        
     	update idletasks   
	wm deiconify .
	raise .
	focus -force .
	
	return 0
}

#######################################################
# Start script here
ApolTop::main
