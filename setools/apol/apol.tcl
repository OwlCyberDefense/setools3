#!/bin/sh
# The next line is executed by /bin/sh, but not tcl \
exec awish "$0" ${1+"$@"}

# Copyright (C) 2001-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets



##############################################################
# ::ApolTop
#  
# The top level GUI
##############################################################
namespace eval ApolTop {
	variable status 		""
	variable polversion 		""
	variable filename 		""
	variable policyConf_lineno	""
	variable polstats 		""
	variable gui_ver 		"0.7" 
	variable recent_files
	variable num_recent_files 	0
	variable most_recent_file 	-1
	# The max # can be changed by the .apol file
	variable max_recent_files 	5
	variable dot_apol_file 		"~/.apol"
	variable helpFilename
	variable noDropDown		0
	variable prevCursor		arrow
	variable text_font		"fixed"
	variable goto_line_num
	variable goto_cmd
	
	# Top-level dialog widgets
	variable helpDlg
	set helpDlg .apol_helpDlg
	variable searchDlg
	set searchDlg .searchDlg
	variable goto_Dialog
	set goto_Dialog .goto_Dialog
	variable searchDlg_entryBox
	variable gotoDlg_entryBox
	
	# Other global widgets
	variable notebook
	variable mainframe
	variable textbox_policyConf
	
	# Search-related variables
	variable searchString		""
	variable case_Insensitive	0
	variable regExpr 		0
	variable srch_Direction		"down"
	
	# Notebook tab IDENTIFIERS
	variable types_tab		"ApolTypes"
	variable terules_tab		"ApolTE"
	variable roles_tab		"Apol_Roles"
	variable rbac_tab		"Apol_RBAC"
	variable class_perms_tab	"Apol_Class_Perms"
	variable users_tab		"Apol_Users"
	variable policy_conf_tab	"Apol_PolicyConf"
	
	variable tk_msgBox_Wait

# "contents" indicates which aspects of the policy are included in the current opened policy file
# indicies into this array are:
# 	classes
#	perms			(inlcudes common perms)
#	types			(include attribs)
#	te_rules		(all type enforcement rules)
#	roles			
#	rbac			(all role rules)
#	users
     variable contents

# initialize the recent files list
	for {set i 0} {$i<$max_recent_files } {incr i} {
		set recent_files($i) ""
	}

# below allows separate files for each "tab" on the app
    set pwd [pwd]
    cd [file dirname [info script]]
#    variable MYDIR [pwd]
    foreach script {
	types_tab.tcl terules_tab.tcl \
	roles_tab.tcl rbac_tab.tcl \
	classes_perms_tab.tcl users_tab.tcl policyconf.tcl
    } {
	namespace inscope :: source $script
    }
    cd $pwd    
}

proc ApolTop::call_searchFunction { key } {
	variable notebook
	variable noDropDown
	
	# Make sure that the combobox is not mapped. If so then reset our flag and return.
	if { $noDropDown == 1 } {
		set noDropDown 0
		return
	}
	
	if { $key == "Return" } {
		set raisedPage [$notebook raise]
    		
    		switch $raisedPage {
    			$ApolTop::types_tab {
    				ApolTypes::searchTypes
    			}
    			$ApolTop::terules_tab {    				
				ApolTE::searchTErules newTab
			}
			$ApolTop::roles_tab {
				Apol_Roles::searchRoles
			}
			$ApolTop::rbac_tab {
				Apol_RBAC::searchRoles
			}
			$ApolTop::class_perms_tab {
				Apol_Class_Perms::search_Class_Perms
			}
			$ApolTop::users_tab {
				Apol_Users::searchUsers
			}
			default {
			    return 
			}
		}
	}
	
	return
}

proc ApolTop::set_Focus_to_Text { tab } {
	variable notebook
	
	set ApolTop::policyConf_lineno ""
	switch $tab \
		$ApolTop::types_tab {
			focus $ApolTypes::resultsbox
		} \
		$ApolTop::terules_tab {    
			set raisedPage  [$ApolTE::notebook_results raise]
			if { $raisedPage != "" } {
				set pagePath 	[$ApolTE::notebook_results getframe $raisedPage]
				if { [winfo exists $pagePath.sw.resultsbox] } {
					focus $pagePath.sw.resultsbox
				}
			}
		} \
		$ApolTop::roles_tab {
			focus $Apol_Roles::resultsbox
		} \
		$ApolTop::rbac_tab {
			focus $Apol_RBAC::resultsbox
		} \
		$ApolTop::class_perms_tab {
			focus $Apol_Class_Perms::resultsbox
		} \
		$ApolTop::users_tab {
			focus $Apol_Users::resultsbox
		} \
		$ApolTop::policy_conf_tab {
			focus $Apol_PolicyConf::textbox_policyConf
			set ApolTop::policyConf_lineno "Line [$Apol_PolicyConf::textbox_policyConf index insert]"
		} \
		default { 
			return 
		}
	return 0
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
		vwait $ApolTop::tk_msgBox_Wait
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
	variable notebook
	variable searchString
	variable case_Insensitive	
	variable regExpr 		
	variable srch_Direction
	
	[$notebook raise]::search $searchString $case_Insensitive $regExpr $srch_Direction
	
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
	
	# Checking to see if window already exists. If so, it is destroyed.
	if { [winfo exists $searchDlg] } {
		raise $searchDlg
		focus $searchDlg_entryBox
		$searchDlg_entryBox selection range 0 end
		return
	}
	
	# Create the toplevel dialog window and set its' properties.
	toplevel $searchDlg
	wm protocol $searchDlg WM_DELETE_WINDOW "destroy $searchDlg"
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
	set searchDlg_entryBox [entry $lframe_top.searchDlg_entryBox -bg white -font $ApolTop::text_font -textvariable ApolTop::searchString ]
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
	::tk::PlaceWindow $searchDlg widget center
	wm deiconify $searchDlg
	focus $searchDlg_entryBox 
	$searchDlg_entryBox selection range 0 end
	bind $ApolTop::searchDlg <Return> { ApolTop::search }
	
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
# ::display_goto_line_Dlg
#  	-  
proc ApolTop::display_goto_line_Dlg { } {
	variable notebook
	variable goto_line_num
	variable goto_cmd
	variable goto_Dialog
	variable gotoDlg_entryBox
	global tcl_platform
	
	# create dialog
    	if { [winfo exists $goto_Dialog] } {
    		raise $goto_Dialog
    		focus $gotoDlg_entryBox
    		return 0
    	}
    	toplevel $goto_Dialog
   	wm protocol $goto_Dialog WM_DELETE_WINDOW "destroy $goto_Dialog"
    	wm withdraw $goto_Dialog
    	wm title $goto_Dialog "Goto"
    	
    	if {$tcl_platform(platform) == "windows"} {
		wm resizable $ApolTop::goto_Dialog 0 0
	} else {
		bind $ApolTop::goto_Dialog <Configure> { wm geometry $ApolTop::goto_Dialog {} }
	}
	
    	set goto_line_num ""
    	set goto_cmd "[$notebook raise]::goto_line"

	set gotoDlg_entryBox [entry $goto_Dialog.gotoDlg_entryBox -textvariable ApolTop::goto_line_num -width 10 ]
	set lbl_goto  [label $goto_Dialog.lbl_goto -text "Goto:"]
	set b_ok      [button $goto_Dialog.ok -text "OK" -width 6 -command { $ApolTop::goto_cmd $ApolTop::goto_line_num; destroy $ApolTop::goto_Dialog}]
	set b_cancel  [button $goto_Dialog.cancel -text "Cancel" -width 6 -command { destroy $ApolTop::goto_Dialog }]
	
	pack $lbl_goto $gotoDlg_entryBox -side left -padx 5 -pady 5 -anchor nw
	pack $b_ok $b_cancel -side left -padx 5 -pady 5 -anchor ne
	
	# Place a toplevel at a particular position
    	::tk::PlaceWindow $goto_Dialog widget center
	wm deiconify $goto_Dialog
	focus $gotoDlg_entryBox
	bind $ApolTop::goto_Dialog <Return> { $ApolTop::goto_cmd $ApolTop::goto_line_num; destroy $ApolTop::goto_Dialog }
	
	return 0
}

proc ApolTop::create { } {
    variable notebook 
    variable mainframe  

#    SelectFont::loadfont

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
            {command "&Find...                    (C-s)" {} "Find"  \
            	{} -command ApolTop::display_searchDlg }
            {command "&Goto Line...           (C-g)" {} "Goto Line"  \
            	{} -command ApolTop::display_goto_line_Dlg }
        }
        "&View" {} view 0 {
            {command "Policy Summary" {} "Display summary statics" {} -command ApolTop::popupPolicyStats }
        }
        "&Help" {} help 0 {
	    {command "&Help" {all option} "Show help" {} -command ApolTop::helpDlg}
            {command "&About" {all option} "Show about box" {} -command ApolTop::aboutBox}
        }
    }

    set mainframe [MainFrame .mainframe -menu $descmenu -textvariable ApolTop::status]

    $mainframe addindicator -textvariable ApolTop::policyConf_lineno -width 14
    $mainframe addindicator -textvariable ApolTop::polstats -width 88
    $mainframe addindicator -textvariable ApolTop::polversion -width 19 

    # NoteBook creation
    set frame    [$mainframe getframe]
    set notebook [NoteBook $frame.nb]

    ApolTypes::create $notebook
    ApolTE::create $notebook
    Apol_Roles::create $notebook
    Apol_RBAC::create $notebook
    Apol_Class_Perms::create $notebook
    Apol_Users::create $notebook
    Apol_PolicyConf::create $notebook
        
    $notebook compute_size
    pack $notebook -fill both -expand yes -padx 4 -pady 4
    $notebook raise [$notebook page 0]
    $notebook bindtabs <Button-1> { ApolTop::set_Focus_to_Text }

    bind . <KeyPress>  {ApolTop::call_searchFunction %K}
    bind . <Control-s> {ApolTop::display_searchDlg}
    bind . <Control-g> {ApolTop::display_goto_line_Dlg}
    
    pack $mainframe -fill both -expand yes
    update idletasks
    
    return
}

# Saves user data in their ~/.apol file
proc ApolTop::writeInitFile { } {
	variable dot_apol_file 
	variable num_recent_files
	variable recent_files
	
	set rt [catch {set f [open $dot_apol_file w+]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return
	}
	puts $f "recent_files"
	puts $f $num_recent_files
	for {set i 0 } {$i < $num_recent_files} {incr i } {
		puts $f $recent_files($i)
	}
	
	close $f
	return
}


# Reads in user data from their ~/.apol file 
proc ApolTop::readInitFile { } {
	variable dot_apol_file
	variable max_recent_files 
	variable recent_files
	
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
	
	set got_recent 0
	
	gets $f line
	set tline [string trim $line]
	while {[eof $f] != 1} {
		if {[string compare -length 1 $tline "#"] ==0 } {
			gets $f line
			set tline [string trim $line]
			continue
		}
		switch $tline {
			# The form of [max_recent_file] is a single line that follows
			# containing an integer with the max number of recent files to 
			# keep.  The default is 5 if this is not specified.  A number larger
			# than 10 will be set to 10.  A number of less than 2 is set to 2.
			"max_recent_files" {
				# we shouldn't be getting the max number after reading in the file names
				if {$got_recent == 1 } {
					puts "Key word max_recent_files found after recent file names read; ignored"
					# read next line which should be max num
					gets $ line
					continue
				}
				gets $f line
				if {[eof $f] == 1 } {
					puts "EOF reached trying to read max_recent_file."
					continue
				}
				set tline [string trim $line]
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
				if {$got_recent == 1} {
					puts "Key work recent_files found twice in file!"
					continue
				}
				set got_recent 1
				gets $f line
				if {[eof $f] == 1 } {
					puts "EOF reached trying to read num of recent files."
					continue
				}
				set tline [string trim $line]
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
					if {[eof $f] == 1 } {
						puts "EOF reached trying to read recent file name $num."
						break
					}
					# check if stored num is greater than max; if so just ignore the rest
					if {$i >= $max_recent_files} {
						continue
					}
					set tline [string trim $line]
					ApolTop::addRecent $tline
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
	return
}


# Add a policy file to the recently opened
proc ApolTop::addRecent {file} {
	variable mainframe
	variable recent_files
	variable num_recent_files
    	variable max_recent_files
    	variable most_recent_file
    	
    	if {$num_recent_files<$max_recent_files} {
    		set x $num_recent_files
    		set less_than_max 1
    	} else {
    		set x $max_recent_files 
    		set less_than_max 0
    	}
	
	# First check if already in recent file list
	for {set i 0} {$i<$x } {incr i} {
		if {$file == $recent_files($i) } {
			return
		}
	}
	if {$num_recent_files<$max_recent_files} {
		#list not full, just add to list and insert into menu
		set recent_files($num_recent_files) $file
		[$mainframe getmenu recent] insert 0 command -label "$recent_files($num_recent_files)" -command "ApolTop::openPolicyFile $recent_files($num_recent_files) 0"
		set most_recent_file $num_recent_files
		incr num_recent_files
	} else {
		#list is full, need to replace one
		#find oldest entry
		if {$most_recent_file != 0} {
			set oldest [expr $most_recent_file - 1]
		} else {
			set oldest [expr $max_recent_files - 1]
		}
		[$mainframe getmenu recent] delete $recent_files($oldest)
		set recent_files($oldest) $file
		[$mainframe getmenu recent] insert 0 command -label "$recent_files($oldest)" -command "ApolTop::openPolicyFile $recent_files($oldest) 0"
		set most_recent_file $oldest
	}	
	return	
}

proc ApolTop::helpDlg {} {
    variable contents
    variable helpFilename
    variable helpDlg
    set helpDlg .apol_helpDlg
    
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
    set sw [ScrolledWindow $hbox.sw -auto none]
    set resultsbox [text [$sw getframe].text -bg white -wrap none -font fixed]
    $sw setwidget $resultsbox
    set okButton [Button $hbox.okButton -text "OK" \
		      -command "destroy $helpDlg"]
    # go to the script dir to find the help file
    set script_dir  [apol_GetScriptDir "apol_help.txt"]
    set helpfile "$script_dir/apol_help.txt"
    
    # Placing display widgets
    pack $hbox -expand yes -fill both -padx 5 -pady 5
    pack $okButton -side bottom
    pack $resultsbox -expand yes -fill both
    pack $sw -side left -expand yes -fill both 
    # Place a toplevel at a particular position
    ::tk::PlaceWindow $helpDlg widget center
    wm deiconify $helpDlg
    
    $resultsbox delete 1.0 end
    set f [open $helpfile]
    $resultsbox insert end [read $f]
    close $f
        
    return
}

proc ApolTop::makeTextBoxReadOnly {w} {
	    $w configure -state disabled
	    $w mark set insert 0.0
	    $w mark set anchor insert
	    focus $w
	    
	    return 0
}

proc ApolTop::setBusyCursor {} {
	variable prevCursor
	set prevCursor [. cget -cursor] 
    	. configure -cursor watch
    	update idletasks
	return
}

proc ApolTop::resetBusyCursor {} {
	variable prevCursor
	. configure -cursor $prevCursor
    	update idletasks
	return
}

proc ApolTop::popupPolicyStats {} {
	variable polversion
	variable contents
	set rt [catch {set pstats [apol_GetStats]}]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "No policy file currently opened"
		return 
	}
	foreach item $pstats {
		set rt [scan $item "%s %d" key val]
		if {$rt != 2} {
			tk_messageBox -icon error -type ok -title "Error" -message "apol_GetStats: $rt"
			return
		}
		set stats($key) $val
	}
	
	# Build the output based on what was collected in the policy
	# (for now, only perms and classes are optionally collected (really a compile time option!)
	if {$contents(classes) == 0} {
		set classes "not collected"
	} else {
		set classes $stats(classes)
	}
	if {$contents(perms) == 0 } {
		set perms "not collected"
		set common_perms "not collected"
	} else {
		set common_perms $stats(common_perms)
		set perms $stats(perms)
	}
	
	set w .polstatsbox
	catch {destroy $w}
	toplevel $w
	
	label $w.1 -justify left  -font {helvetica 10 bold}  \
		-text "Policy Summary Statistics\n "
	label $w.2 -justify left -font {helvetica 10} \
		-text "\
Policy Version: $polversion\n\n\
Number of Classes and Permissions\n\
     \tObject Classes:\t$classes\n\
     \tCommon Perms:\t$common_perms\n\
     \tPermissions:\t$perms\n\n\
Number of Types and Attributes: \n\
     \tTypes:\t\t$stats(types)\n\
     \tAttributes:\t$stats(attribs) \n\n\
Number of Type Enforcement Rules: \n\
     \tallow:\t\t$stats(teallow)\n\
     \tneverallow\t$stats(neverallow)\n\
     \tclone (pre v.11):\t$stats(clone)\n\n\
     \ttype_transition.:\t$stats(tetrans)\n\
     \ttype_change:\t$stats(techange)\n\
     \ttype_member:\t$stats(temember)\n\n\
     \tauditallow:\t$stats(auditallow)\n\
     \tauditdeny:\t\t$stats(auditdeny)\n\
     \tdontaudit:\t\t$stats(dontaudit)\n\n\
Number of Roles:\n\
     \tRoles:\t\t$stats(roles)\n\n\
Number of RBAC Rules:\n\
     \tallow:\t\t$stats(roleallow)\n\
     \trole_transition:\t$stats(roletrans)\n\n\
Number of Users:\n\
     \tusers:\t\t$stats(users)\n"
     
     	button $w.close -text Close -command "catch {destroy $w}" -width 10
	
	pack $w.1 -side top
	pack $w.2 -anchor w
	pack $w.close -anchor s -padx 10 -pady 10
	wm title $w "Policy Summary"
	wm iconname $w "policy summary"
	wm geometry $w +50+60
    	return		
}

proc ApolTop::showPolicyStats {} {
	variable polstats 
	variable contents
	set rt [catch {set pstats [apol_GetStats]}]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title \
			-message "No policy file currently opened"
		return 
	}
	foreach item $pstats {
		set rt [scan $item "%s %d" key val]
		if {$rt != 2} {
			tk_messageBox -icon error -type ok -title "Error" -message "apol_GetStats: $rt"
			return
		}
		set stats($key) $val
	}
	set polstats ""
	if {$contents(classes) == 1} {
		append polstats "Classes: $stats(classes)   "
	}
	if {$contents(perms) == 1} {
		append polstats "Perms: $stats(perms)   "
	}
	append polstats "Types: $stats(types)   Attribs: $stats(attribs)   "
	append polstats "TE rules: [expr $stats(teallow) + $stats(neverallow) + 	\
		$stats(auditallow) + $stats(auditdeny) + $stats(clone)  +  $stats(dontaudit) +	\
		$stats(tetrans) + $stats(temember) + $stats(techange)]   "
	append polstats "Roles: $stats(roles)   RBAC rules: [expr $stats(roleallow) + $stats(roletrans)]"
	append polstats "   Users: $stats(users)"
	return
}

proc ApolTop::aboutBox {} {
     variable gui_ver
     set lib_ver [apol_GetVersion]
     
     tk_messageBox -icon info -type ok -title "About SELinux Policy Analysis Tool" -message \
	"Security Policy Analysis Tool for Security Enhanced Linux \n\nCopyright (c) 2001-2003\nTresys Technology, LLC\nwww.tresys.com/selinux\n\nGUI Version ($gui_ver)\nLib Version ($lib_ver)"
	
     return
}

proc ApolTop::unimplemented {} {
	tk_messageBox -icon warning \
		-type ok \
		-title "Unimplemented Command" \
		-message \
		"This command is not currently implemented. \n\n\(Cut & paste from the results windows should be enabled.)"
	
	return
}


proc ApolTop::closePolicy {} {
        variable contents
	variable filename 
	variable polstats
	variable polversion
	
	set polversion ""
	set filename ""
	set polstats ""
	set contents(classes)	0
	set contents(perms)	0
	set contents(types)	0
	set contents(te_tules)	0
	set contents(roles)	0
	set contents(rbac)	0
	set contents(users)	0
	wm title . "SE Linux Policy Analysis"
	Apol_Class_Perms::close
	ApolTypes::close
	ApolTE::close
	Apol_Roles::close
        Apol_RBAC::close
        Apol_Users::close
        Apol_PolicyConf::close        
	ApolTop::set_Focus_to_Text [$ApolTop::notebook raise]                
	apol_ClosePolicy 
}

# Do the work to open a policy file:
# file is file name, and recent_flag indicates whether to add this file to list of
# recently opened files (set to 1 if you want to do this).  You would NOT set this
# to 1 if a recently file is being opened with this proc
proc ApolTop::openPolicyFile {file recent_flag} {
	variable contents
	variable polversion
	
	update 
	
	ApolTop::closePolicy
	wm title . "SE Linux Policy Analysis -\t$file"
	
	
	if { ![file exists $file] } {
		tk_messageBox -icon error \
		-type ok \
		-title "File Does Not Exist" \
		-message "File ($file) does not exist."
		return -1
	} elseif { ![file readable $file] } {
		tk_messageBox -icon error \
		-type ok \
		-title "Permission Problem" \
		-message \
		"You do not have permission to read $file."
		return -1
	}
	# Change the cursor
	set orig_Cursor [. cget -cursor] 
	. configure -cursor watch
	update idletasks
	set rt [catch {apol_OpenPolicy $file}]
	if {$rt == 0} {
		set filename [file tail $file]
	} else {
		tk_messageBox -icon error -type ok -title "Error with policy file" -message \
			"The selected file does not appear to be a valid SE Linux Policy \n\n\
			WARNING: Apol has a bug that will causes it to work improperly once an\
			invalid policy.conf was opened.  Therefore, apol WILL NOW EXIT so you can restart it." 
		# TODO: When we figure out the bug in libapol that corrupts the lib when an invalid policy.conf
		# file is read, we can un comment the following and NOT exit the app.
		#. configure -cursor $orig_Cursor 
		#focus -force .
		#return 
		ApolTop::apolExit
	}
	set rt [catch {set polversion [apol_GetPolicyVersion]}]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "apol_GetPolicyVersion: $rt"
		return 0
	}
	# Set the contents flags to indicate what the opened policy contains
	set rt [catch {set con [apol_GetPolicyContents]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 0
	}
	foreach item $con {
		set rt [scan $item "%s %d" key val]
		if {$rt != 2} {
			tk_messageBox -icon error -type ok -title "Error" -message "openPolicy (getting contents): $rt"
			return
		}
		set contents($key) $val
	}
	
	ApolTop::showPolicyStats
	Apol_Class_Perms::open
	ApolTypes::open	
	ApolTE::open
	Apol_Roles::open
	Apol_RBAC::open
	Apol_Users::open
	Apol_PolicyConf::open $file
	
	if {$recent_flag == 1} {
		ApolTop::addRecent $file
	}
	# Change the cursor back to the original and then set the focus to the toplevel.
	. configure -cursor $orig_Cursor 
	focus -force .
	ApolTop::set_Focus_to_Text [$ApolTop::notebook raise] 
	    	      
	return 0
}

proc ApolTop::openPolicy {} {
	variable filename 
	variable polversion
        set progressval 0
        set file ""
        set types {
		{"Policy conf files"	{.conf}}
		{"All files"		*}
    	}
        catch [set file [tk_getOpenFile -filetypes $types -defaultextension .conf]]
        
        if {$file != ""} {
		ApolTop::openPolicyFile $file 1
	}
	return
}

proc ApolTop::apolExit { } {
	ApolTop::writeInitFile
	exit
}

proc ApolTop::main {} {
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

    option add *TitleFrame.l.font { Helvetica 11 bold italic }   
    option add *Font {Helvetica 11 bold}
    option add *Dialog*font { Helvetica 11 } 
    option add *text*font {Helvetica 11}

    wm withdraw .
    wm title . "SE Linux Policy Analysis"
    wm protocol . WM_DELETE_WINDOW "ApolTop::apolExit"

    ApolTop::create
    ApolTop::readInitFile
    
    # Configure the geometry for the window manager
    set x  [winfo screenwidth .]
    set y  [winfo screenheight .]
    set width  [ expr $x - ($x/10) ]
    set height [ expr $y - ($y/4)  ]
    BWidget::place . $width $height center
    wm geom . ${width}x${height}
    
    #BWidget::place . 0 0 center
    wm deiconify .
    raise .
    focus -force .
    
    # Prevent the application from responding to incoming send requests and sending 
    # outgoing requests. This way any other applications that can connect to our X 
    # server cannot send harmful scripts to our application. 
    rename send {}
    
    return
}


#######################################################
# Start script here
ApolTop::main
wm geom . [wm geom .]

  
  