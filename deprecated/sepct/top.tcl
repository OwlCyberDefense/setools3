################################################################
# top.tcl (top level name space)
#  
# -----------------------------------------------------------
# Copyright (C) 2002-2005 Tresys Technology, LLC	
# see file 'COPYING' for use and warranty information 
#
# Requires tcl and tk 8.3+, with BWidgets
# Author: <don.patterson@tresys.com, mayerf@tresys.com>
# -----------------------------------------------------------
#

##############################################################
# ::Sepct (top-level namespace)
##############################################################
namespace eval Sepct {
	# All capital letters is the convention for variables defined via the Makefile.
	# The version number is defined as a magical string here. This is later configured in the make environment.
	variable gui_ver		SEPCUT_GUI_VERSION
	variable copyright_date		"2002-2004"
	# install_dir is a magical string to be defined via the makefile!
	variable sepcut_install_dir	SEPCUT_INSTALL_DIR
	variable bwidget_version	""
	variable helpFilename		""
	# Global variable to hold name of root directory
	variable policyDir		""	
	# indicates whether a policy dir is currently opened
	variable policyOpened	0		
	# Holds description of menu entries to display in status bar
	variable status 		""	
	
	# Status bar variables for displaying current file information.
	variable file_name		""
	variable file_modTime		""
	variable file_size		""
	variable line_info		""
	
	# Notebook tab IDENTIFIERS; NOTE: We name all tabs after their related namespace qualified names.
	# We use the prefix 'Sepct_' for all notebook tabnames. Note that the prefix must end with an 
	# underscore and that that tabnames may NOT have a colon.
	variable tabName_prefix		"Sepct_"
	variable browse_tab		"Sepct_Browse"
	variable customize_tab		"Sepct_Customize"
	variable test_tab		"Sepct_Test"
	variable disable_customize_tab	0
	variable disable_test_tab	0
	
	# Variables for recent policy directories - env array element HOME is an environment variable
	variable dot_sepcut_file 	"[file join "$::env(HOME)" ".sepcut"]"
	# Temporary list to hold all directories read in after the call to ::readInitFile
	# This variable will be removed once all tool_settings have been configured.
	variable recent_dirs_tmp_list	""
	variable recent_dirs
	variable num_recent_dirs 	0
	variable most_recent_dirs 	-1
	# The max # can be changed by the .sepcut file
	variable max_recent_dirs 	5
	variable text_font		""
	variable title_font		""
	variable dialog_font		""
	variable general_font		""
	variable temp_recent_files	""
        variable top_width             900
        variable top_height            700
        
	# initialize the recent directories list
	for {set i 0} {$i<$max_recent_dirs } {incr i} {
		set recent_dirs($i) ""
	}

	# misc
	variable tool_title		"SePCuT: SE Linux Policy Customization Tool"
	variable saveall_choice		""
	variable goto_line_num
	variable goto_cmd
	variable text_font		"fixed"
	variable searchString		""
	variable cur_srch_pos_length	0
	variable case_Insensitive	0
	variable regExpr 		0
	variable srch_Direction		"down"
	variable saveChanges_Dialog_ans
	variable tk_msgBox_Wait
	# Identifies where the help file is located. 
	variable help_file		"${sepcut_install_dir}/sepcut_help.txt"
	
	# edit mode (0 read only, 1 edit mode)
	variable read_only		0
	variable edit_mode_status	
	
	# This var determines whether the tool starts in edit or read-only mode
	# 	(0 read only, 1 edit mode
	variable initial_edit_mode	1
	# This var, if defined with something other than "", determines
	# what policy directory will open (load) by default.
	variable inital_policy_dir	""
	variable tmp_initial_policy_dir ""
	# This var determines whether modules are listed using descriptive
	# name (0) or file name (1), by default, in the customize tab
	variable show_customize_file_names	0
	
	# Global widgets
	variable mainWindow
	set mainWindow .
	variable goto_Dialog
	variable notebook
	variable mainframe
	variable saveAll_Dialog
	set saveAll_Dialog .saveAll_Dialog
	variable helpDlg
	set helpDlg .helpDlg
	variable searchDlg
	set searchDlg .searchDlg	
	variable mod_FileNames_Dialog
	set mod_FileNames_Dialog .mod_FileNames_Dialog
	variable saveChanges_Dialog
	set saveChanges_Dialog .saveChanges_Dialog
	variable tool_settings_Dialog
	set tool_settings_Dialog .tool_settings_Dialog
	variable searchDlg_entryBox
	variable gotoDlg_entryBox
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
proc Sepct::get_tabname {tab} {	
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

############################################################################
# ::writeConfigFile
#	- Writes out policy configuration information to given config file
# 
proc Sepct::writeConfigFile {config_file used_Modules unUsed_Modules} {
	set rt [catch {set f [open $config_file w+]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return
	}
	puts $f "\[Used_Modules\]"
	puts $f [llength $used_Modules]
	foreach used_mod $used_Modules {
		puts $f $used_mod
	}
	puts $f "\[Unused_Modules\]"
	puts $f [llength $unUsed_Modules]
	foreach unUsed_mod $unUsed_Modules {
		puts $f $unUsed_mod
	}
	close $f
	return 0
}

############################################################################
# ::save_policy_configuration
#	- Top-level function for saving a policy config file.
# 
proc Sepct::save_Configuration {} {	
	set types {
		{"Policy config files"	{.pcfg}}
		{"All files"		*}
    	}
	set filename [tk_getSaveFile -initialdir $Sepct::policyDir \
		-title "Save Module Configuration As?" -filetypes $types \
		-defaultextension ".pcfg"]
	if { $filename != "" } {	
		Sepct_Customize::save_Configuration $filename
	}
	return 0
}

############################################################################
# ::load_Configuration
#	- Top-level function for loading a policy config file.
# 
proc Sepct::load_Configuration {} {
	set filename ""
        set types {
		{"Policy config files"	{.pcfg}}
		{"All files"		*}
    	}
        set filename [tk_getOpenFile -filetypes $types -defaultextension ".pcfg" -initialdir $Sepct::policyDir]
        if {$filename != ""} {	
		if {[file exists $filename] == 0 } {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "File: $filename does not exist."
			return
		}
		set rt [catch {set f [open $filename r]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "Cannot open $filename ($rt: $err)"
			return
		}
		set tag_found 0
		set config_error 0
		set used_Mods ""
		set unUsed_Mods ""
		set missing_used_mods ""
		set num_mods_counter 0
		set num_mods [Sepct_Customize::get_num_mods]
		gets $f line
		set tline [string trim $line]
		while {1} {
			if {[eof $f] && $tline == ""} {
				break
			}
			if {[string compare -length 1 $tline "#"] ==0 } {
				gets $f line
				set tline [string trim $line]
				continue
			}
			switch $tline {
				"[Used_Modules]" {
					if {$tag_found == 1} {
						puts "Key word \[Used_Modules\] found twice in file!"
						continue
					}
					set tag_found 1
					gets $f line
					set tline [string trim $line]
					if {[eof $f] == 1 && $tline == ""} {
						puts "EOF reached trying to read num of used modules."
						continue
					}
					if {[string is integer $tline] != 1} {
						set config_error 1
						puts "number of used modules was not given as an integer ($line) and is ignored"
						# at this point we don't support anything else so just break from loop
						break
					} elseif {$tline < 0} {
						set config_error 1
						puts "number of used modules was less than 0 and is ignored"
						# at this point we don't support anything else so just break from loop
						break
					}
					set num $tline
					# read in the lines with the files
					for {set i 0} {$i<$num} {incr i} {
						gets $f line
						set tline [string trim $line]
						if {[eof $f] == 1 && $tline == ""} {
							set config_error 1
							puts "EOF reached trying to read used module: $num."
							break
						}
						# DEFENSIVE MEASURE:
						# check if current mod counter is greater than the total number of modules
						if {$num_mods_counter > $num_mods} {
							break
						}
						if { [file extension $tline] == ".te" && [Sepct_Customize::is_in_modules_list $tline]} {
							lappend used_Mods $tline
							incr num_mods_counter
						} elseif { [file extension $tline] == ".te" && ![Sepct_Customize::is_in_modules_list $tline] } { 
							lappend missing_used_mods $tline
						} 
					}
					set tag_found 0
				}		
				"[Unused_Modules]" {
					if {$tag_found == 1} {
						puts "Key word \[Unused_Modules\] found twice in file!"
						continue
					}
					set tag_found 1
					gets $f line
					set tline [string trim $line]
					if {[eof $f] == 1 && $tline == ""} {
						puts "EOF reached trying to read num of unused modules."
						continue
					}
					if {[string is integer $tline] != 1} {
						set config_error 1
						puts "number of unused modules was not given as an integer ($line) and is ignored"
						# at this point we don't support anything else so just break from loop
						break
					} elseif {$tline < 0} {
						set config_error 1
						puts "number of unused modules was less than 0 and is ignored"
						# at this point we don't support anything else so just break from loop
						break
					}
					set num $tline
					# read in the lines with the files
					for {set i 0} {$i<$num} {incr i} {
						gets $f line
						set tline [string trim $line]
						if {[eof $f] == 1 && $tline == ""} {
							set config_error 1
							puts "EOF reached trying to read unused module: $num."
							break
						}
						# DEFENSIVE MEASURE:
						# check if current mod counter is greater than the total number of modules
						if {$num_mods_counter > $num_mods} {
							break
						}
						if { [file extension $tline] == ".te" && [Sepct_Customize::is_in_modules_list $tline]} {
							lappend unUsed_Mods $tline
							incr num_mods_counter
						} 
					}
					set tag_found 0
				}
				default {
					puts "Unrecognized line in $filename: $line"
				}
			}
			gets $f line
			set tline [string trim $line]
		}
		if { $config_error == 0 } {
			Sepct_Customize::load_policy_configuration $used_Mods $unUsed_Mods
			if { $missing_used_mods != "" } {
				Sepct::popup_missingModules_list $missing_used_mods [file tail $filename]
			}
		}
		close $f
	}
	
	return 0
}

############################################################################
# ::popup_missingModules_list
#	- Displays a list of missing used .te files, so the user knows  
#	  that some of the files in the used list from a configuration 
#	  file are missing from the policy directory. This proc is called  
#	  after loading a saved policy modules configuration.
# 
proc Sepct::popup_missingModules_list {missing_used_mods config_filename} {
	set w .missingModules_listBox
	catch {destroy $w}
	toplevel $w 
	wm title $w "Missing Used Policy Modules"
	set sf [ScrolledWindow $w.sf  -scrollbar both -auto both]
	set f [text [$sf getframe].f -font {helvetica 10} -wrap none -width 40 -height 10]
	$sf setwidget $f
     	button $w.close -text Close -command "catch {destroy $w}" -width 10
     	$f insert end "Configuration file: $config_filename\n\n"
     	$f insert end "The following required modules were missing from \nthe policy directory:\n"
     	foreach mod $missing_used_mods {
     		$f insert end "\t$mod\n"
     	}
 	wm geometry $w +50+60
	pack $w.close -side bottom -anchor s -padx 5 -pady 5 
	pack $sf -fill both -expand yes
	return 0
}

# Saves user data in their $HOME/.sepcut file
proc Sepct::writeInitFile { } {
	variable dot_sepcut_file
	variable num_recent_dirs
	variable recent_dirs
	variable mainWindow
	variable text_font		
	variable title_font
	variable dialog_font
	variable general_font
	
	set rt [catch {set f [open $dot_sepcut_file w+]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return
	}
	puts $f "\[recent_dirs\]"
	puts $f $num_recent_dirs
	for {set i 0 } {$i < $num_recent_dirs} {incr i} {
		puts $f $recent_dirs($i)
	}
	puts $f "\[initial_edit_mode\]"
	puts $f $Sepct::initial_edit_mode
	puts $f "\[inital_policy_dir\]"
	puts $f $Sepct::inital_policy_dir
	puts $f "\[show_customize_file_names\]"
	puts $f $Sepct::show_customize_file_names
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
        puts $f [winfo height $mainWindow]
        puts $f "\[window_width\]"
        puts $f [winfo width $mainWindow]
        
	close $f
	return 0
}

# Reads in user data from their $HOME/.sepcut file 
proc Sepct::readInitFile { } {
	variable dot_sepcut_file
	variable max_recent_dirs 
	variable recent_dirs
	variable recent_dirs_tmp_list
	variable text_font		
	variable title_font
	variable dialog_font
	variable general_font
	variable top_height
        variable top_width
        
	# if it doesn't exist, we'll create later
	if {[file exists $dot_sepcut_file] == 0 } {
		return
	}
	set rt [catch {set f [open $dot_sepcut_file]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Cannot open .sepcut file ($rt: $err)"
		return
	}
	
	set got_recent 0
	
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
			# The form of [max_recent_dirs] is a single line that follows
			# containing an integer with the max number of recent directories to 
			# keep.  The default is 5 if this is not specified.  A number larger
			# than 10 will be set to 10.  A number of less than 2 is set to 2.
			"[max_recent_dirs]" {
				# we shouldn't be getting the max number after reading in the directory names
				if {$got_recent == 1 } {
					puts "Key word max_recent_dirs found after recent directory names read; ignored"
					# read next line which should be max num
					gets $ line
					continue
				}
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read max_recent_dirs."
					continue
				}
				if {[string is integer $tline] != 1} {
					puts "max_recent_dirs was not given as an integer ($line) and is ignored"
				} else {
					if {$tline>10} {
						set max_recent_dirs 10
					} elseif {$tline < 2} {
						set max_recent_dirs 2
					}
					else {
						set max_recent_dirs $tline
					}
				}
			}
			# The form of this key in the .sepcut file is as such
			# 
			# [recent_dirs]
			# 5			(# indicating how many directory names follows)
			# dirname1
			# dirname2
			# ...			
			"[recent_dirs]" {
				if {$got_recent == 1} {
					puts "Key word recent_dirs found twice in file!"
					continue
				}
				set got_recent 1
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read num of recent directories."
					continue
				}
				if {[string is integer $tline] != 1} {
					puts "number of recent directories was not given as an integer ($line) and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				} elseif {$tline < 0} {
					puts "number of recent directories was less than 0 and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				}
				set num $tline
				# read in the lines with the files
				for {set i 0} {$i<$num} {incr i} {
					gets $f line
					set tline [string trim $line]
					if {[eof $f] == 1 && $tline == ""} {
						puts "EOF reached trying to read recent directory name $num."
						break
					}
					# check if stored num is greater than max; if so just ignore the rest
					if {$i >= $max_recent_dirs} {
						continue
					}
					lappend recent_dirs_tmp_list $tline
				}
			}
			"[initial_edit_mode]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read \[initial_edit_mode\] value at line: $line."
					break
				}
				if {[string is integer $tline] != 1} {
					puts "\[initial_edit_mode\] value was not given as an integer ($line) and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				} 
				set Sepct::initial_edit_mode $tline	
			}
			"[inital_policy_dir]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read \[inital_policy_dir\] value at line: $line."
					break
				}
				if {$tline != "" && [file isdirectory $tline] != 1} {
					puts "\[inital_policy_dir\] value ($line) is not a directory and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				} 
				set Sepct::inital_policy_dir $tline
			}
			"[show_customize_file_names]" {
				gets $f line
				set tline [string trim $line]
				if {[eof $f] == 1 && $tline == ""} {
					puts "EOF reached trying to read \[show_customize_file_names\] value at line: $line."
					break
				}
				if {[string is integer $tline] != 1} {
					puts "\[show_customize_file_names\] was not given as an integer ($line) and is ignored"
					# at this point we don't support anything else so just break from loop
					break
				} 
				set Sepct::show_customize_file_names $tline
			}
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
			default {
				puts "Unrecognized line in .sepcut: $line"
			}
		}
		
		gets $f line
		set tline [string trim $line]
	}
	close $f	
	return
}

# Add a policy dir to the recently opened
proc Sepct::addRecent {dir} {
	variable mainframe
	variable recent_dirs
	variable num_recent_dirs
    	variable max_recent_dirs
    	variable most_recent_dirs
    	
    	if {$num_recent_dirs<$max_recent_dirs} {
    		set x $num_recent_dirs
    		set less_than_max 1
    	} else {
    		set x $max_recent_dirs 
    		set less_than_max 0
    	}
    	# Remove any trailing path seperator.
    	set dir [string trimright $dir "/"]
	# First check if already in recent directories list
	for {set i 0} {$i<$x} {incr i} {
		if {[string equal $dir $recent_dirs($i)]} {
			return
		}
	}
	if {$num_recent_dirs<$max_recent_dirs} {
		#list not full, just add to list and insert into menu
		set recent_dirs($num_recent_dirs) $dir
		[$mainframe getmenu recent] insert 0 command -label "$recent_dirs($num_recent_dirs)" -command "Sepct::open_recent_dir $recent_dirs($num_recent_dirs) 0"
		set most_recent_dirs $num_recent_dirs
		incr num_recent_dirs
	} else {
		#list is full, need to replace one
		#find oldest entry
		if {$most_recent_dirs != 0} {
			set oldest [expr $most_recent_dirs - 1]
		} else {
			set oldest [expr $max_recent_dirs - 1]
		}
		[$mainframe getmenu recent] delete $recent_dirs($oldest)
		set recent_dirs($oldest) $dir
		[$mainframe getmenu recent] insert 0 command -label "$recent_dirs($oldest)" -command "Sepct::open_recent_dir $recent_dirs($oldest) 0"
		set most_recent_dirs $oldest
	}	
	return	
}

########################################################################
# ::open_recent_dir
#	- 
#
proc Sepct::open_recent_dir {policyDir recent_flag} {
	set rt [Sepct::closePolicy]
	if { $rt != 0 } {
		return -1
	}		
	set rt [Sepct::openPolicyDir $policyDir $recent_flag]
	return 0
}

########################################################################
# ::isPolicyOpened
#	- tells whether there is an opened policy 1=yes, 0-no
#
proc Sepct::isPolicyOpened {} {
	return $Sepct::policyOpened
}

########################################################################
# ::inReadOnlyMode
#
proc Sepct::inReadOnlyMode  {} {
	return $Sepct::read_only
}


########################################################################
# ::DisplayEditMode
#
proc Sepct::DisplayEditMode  {} {
	variable edit_mode_status
	variable read_only
	
	if {$read_only} {
		set edit_mode_status "read-only"
	} else {
		set edit_mode_status "edit mode"
	}
	return 0
}

########################################################################
# ::enableAllModules
#
proc Sepct::enableAllModules {} {
	variable notebook
		
	if { [Sepct::inReadOnlyMode] } {
		return 0
	}
	
	set raisedPage [$notebook raise]
	if { $raisedPage == $Sepct::customize_tab } {
		set rt [Sepct_Customize::select_all_CheckButtons]
		return $rt
	}
	return 0
}

########################################################################
# ::addModule
#
proc Sepct::addModule {} {
	variable notebook
	
	if { [Sepct::inReadOnlyMode] } {
		return 0
	}
	
	set raisedPage [$notebook raise]
	if { $raisedPage == $Sepct::customize_tab } {
		set rt [Sepct_Customize::add_Module]
		return $rt
	}
	return 0
}

########################################################################
# ::deleteModule
#
proc Sepct::deleteModule  {} {
	variable notebook
	
	if { [Sepct::inReadOnlyMode] } {
		return 0
	}
	
	set raisedPage [$notebook raise]
	if { $raisedPage == $Sepct::customize_tab } {
		set rt [Sepct_Customize::delete_Module]
		return $rt
	}
	return 0
}

########################################################################
# ::ToggleEditMode
#
proc Sepct::ToggleEditMode  {} {
	variable read_only
	variable notebook
	
	if {$read_only} {
		set read_only 0
		$Sepct::mainframe setmenustate ModEditTag normal
		# re-enter raised tab to allow it to re-disabled these menu items if appropriate
		# If the currently raised tab has been disabled, it will no longer be considered the raised tab.
		# So we must make sure that a raised tab still exists before calling its enter_Tab proc.
		if {[$notebook raise] != ""} {
			[$notebook raise]::enter_Tab
		}
	} else {
		set read_only 1
		$Sepct::mainframe setmenustate ModEditTag disabled
	}
	Sepct::DisplayEditMode
	return 0
}

########################################################################
# ::isValidPolicyDir
#  	- Determine whether a selected policy directory appears to be
#		a valid policy source directory.
#
#	return 1 if valid for everything, 2 if OK except for browse tab, 
#	0 if not at all
# 
proc Sepct::isValidPolicyDir { policyDir parentDlg } {
	if { [file isdirectory $policyDir] != 1} {
		tk_messageBox -icon error \
			-parent $parentDlg \
			-type ok -title "Invalid Directory" \
			-message \
			"Given policy directory is not a directory."
		return 0
	}
	if { [file readable $policyDir] != 1} {
		tk_messageBox -icon error \
			-parent $parentDlg \
			-type ok -title "Directory Permission Problem" \
			-message \
			"You do not have permission to access this directory."
		return 0
	}
	# make sure that the Makefile exists
	set make_exists [expr ([file exists "$policyDir/Makefile"] || [file exists "$policyDir/makefile"] )]
	if { $make_exists != 1 } {
		tk_messageBox -icon error \
			-parent $parentDlg \
			-type ok  \
			-title "Invalid Policy Directory" \
			-message "Selected directory does not appear to be a valid policy directory\n\n\
			Cannot locate Makefile"
		return 0
	}
	
	# make sure that the domains/programs directory exists, otherwise browse tab not supported
	if { [file isdirectory "$policyDir/domains/program"] != 1 } {
		return 2
	}

	
	# TODO other validation (e,g fc programs, Makefile...)
	return 1
}

#################################################################
# ::aboutBox
#  	- Display About dialog 
# 
proc Sepct::aboutBox {} {
     variable gui_ver
     variable copyright_date
     
     tk_messageBox \
     	     -parent $Sepct::mainWindow \
	     -icon info \
	     -type ok \
	     -title "About" \
	     -message \
		"SE Linux Policy Customization Tool\n\nCopyright\
		(c) $copyright_date\nTresys Technology, LLC\nwww.tresys.com/selinux\n\nVersion $gui_ver"
	
     return
}


#################################################################
# ::helpDlg
#  	- Display Help dialog 
# 	
proc Sepct::helpDlg {} {
	variable help_file
	variable helpDlg
	
	# Checking to see if output window already exists. If so, it is destroyed.
	if { [winfo exists $helpDlg] } {
		raise $helpDlg
		return
	}
	
	# Create the toplevel dialog window and set its' properties.
	toplevel $helpDlg
	wm protocol $helpDlg WM_DELETE_WINDOW "destroy $helpDlg"
	wm withdraw $helpDlg
	wm title $helpDlg "Help"
	
	# Display results window
	set hbox [frame $helpDlg.hbox ]
	set sw [ScrolledWindow $hbox.sw -auto none]
	set resultsbox [text [$sw getframe].text -bg white -wrap none -font $Sepct::text_font]
	$sw setwidget $resultsbox
	set okButton [Button $hbox.okButton -text "OK" \
		      -command "destroy $helpDlg"]
		      
	# Find the help file the help file path.
	if { [file readable "./sepcut_help.txt"] } {
		set hfile "./sepcut_help.txt"
	} elseif { [file readable $help_file] } {
		set hfile $help_file
	} else {
		set hfile ""
	}
	
	# Placing display widgets
	pack $hbox -expand yes -fill both -padx 5 -pady 5
	pack $okButton -side bottom
	pack $sw -side left -expand yes -fill both 
	
	# Place a toplevel at a particular position
	::tk::PlaceWindow $helpDlg widget center
	wm deiconify $helpDlg
	
	$resultsbox delete 1.0 end
	if { $hfile != "" } {
		set f [open $hfile]
		$resultsbox insert end [read $f]
		close $f
	} else {
		$resultsbox insert end "Help file could not be found!"
	}
	$resultsbox configure -state disabled
    
    	return 0
}

########################################################################
# ::closePolicyDir
#  	- Method for closing the current policy directory.
# 
proc Sepct::closePolicyDir { } {
	variable policyDir
	variable policyOpened
	variable disable_customize_tab
	variable disable_test_tab
	
	# Need to ensure that any outstanding changes are recorded first
	Sepct::record_outstanding_changes
	
	# Save any changes
	set canceled [Sepct::checkAndSaveChanges]
	if {$canceled < 0 } {
		return -1
	} elseif { $canceled } {
		return 1
	}

	Sepct_Browse::close
	if { !$disable_customize_tab } {
		Sepct_Customize::close
	}
	Sepct_Test::close
	
	set policyDir ""		
	set policyOpened 0
	Sepct::change_tab_state $Sepct::notebook $Sepct::customize_tab enable
	Sepct::change_tab_state $Sepct::notebook $Sepct::test_tab enable
	set disable_customize_tab 0
	set disable_test_tab 0
	
	return 0
}

########################################################################
# :: reloadPolicy menu
#	- reload current policy directory
proc Sepct::reloadPolicy {} {
	variable policyOpened
	variable policyDir
	variable notebook
	
	if { !$policyOpened } {
		return 0
	}
	
	set curr_dir $policyDir
	set rt [Sepct::closePolicy]
	if {$rt != 0 } {
		# cancel
		return 0
	}

	set rt [Sepct::openPolicyDir $curr_dir 0]
	return $rt
}


########################################################################
# :: closePolicy menu
#	- close policy dir and reinitializes GUI
proc Sepct::closePolicy { } {
	variable mainframe 
	variable notebook
	
	if { ![Sepct::isPolicyOpened] } {
		return 0
	}
	set rt [Sepct::closePolicyDir]
	if {$rt == 1 } {
		# canceled save
		# let the displayed tab redisplay to indicate saves if necessary
		# If the currently raised tab has been disabled, it will no longer be considered the raised tab.
		# So we must make sure that a raised tab still exists before calling its enter_Tab proc.
		if {[$notebook raise] != ""} {
			[$notebook raise]::enter_Tab
		}
		return -1
	}

	Sepct::clear_fileStatus
	Sepct::setTitleName ""
    	$mainframe setmenustate DisableOnCloseTag disabled

	return 0
}

##############################################################
# ::revert
#  	- revert file menu
# 
proc Sepct::revert {} {
	variable notebook
	
	[$notebook raise]::revert_file
	return 0
}

##############################################################
# ::show_ModFileNames
#	- 
proc Sepct::show_ModFileNames { } {
	# First, flush out changes in text boxes 
	Sepct::record_outstanding_changes
	Sepct::display_mod_FileNames_Dialog
	
	return 0
}

##############################################################
# ::display_mod_FileNames_Dialog
#  	-  
proc Sepct::display_mod_FileNames_Dialog { } {
	variable mod_FileNames_Dialog	
	variable mainWindow
	
    	if { [winfo exists $mod_FileNames_Dialog] } {
    		raise $mod_FileNames_Dialog
    		return 
    	}
    	
    	# Create the toplevel dialog window and set its' properties.
	toplevel $mod_FileNames_Dialog
	wm protocol $mod_FileNames_Dialog WM_DELETE_WINDOW "destroy $mod_FileNames_Dialog"
	wm withdraw $mod_FileNames_Dialog
	wm title $mod_FileNames_Dialog "Modified Files"
	
	# Display results window
	set frame_a [frame $mod_FileNames_Dialog.frame_a]	
	set f_inner [ScrolledWindow $frame_a.f_inner -auto none]
	pack $frame_a $f_inner -fill both -expand yes
	
	set lbx_mod_FileNames   [listbox [$f_inner getframe].lbx_mod_FileNames -height 10 -width 50 \
				-highlightthickness 0 \
				-listvar Sepct_db::mod_FileNames ] 
	$f_inner setwidget $lbx_mod_FileNames
	set closeButton [Button $frame_a.closeButton -text "Close" \
		      -command "destroy $mod_FileNames_Dialog"]
		      	       	        
	# Placing listbox
	pack $closeButton -side bottom -anchor center -pady 5
	
	# Place a toplevel at a particular position
	::tk::PlaceWindow $mod_FileNames_Dialog widget center
	wm deiconify $mod_FileNames_Dialog
	    		
	return 0
}


##############################################################
# ::display_saveChanges_Dialog
#  	-   This dialog is used when another dialog need to save
#		modified files before going on
proc Sepct::display_saveChanges_Dialog { } {	
	variable saveChanges_Dialog
	global tcl_platform
	
    	if { [winfo exists $saveChanges_Dialog] } {
    		destroy $saveChanges_Dialog 
    	}
    	
    	# Create the toplevel dialog window and set its' properties.
	toplevel $saveChanges_Dialog
	wm protocol $saveChanges_Dialog WM_DELETE_WINDOW "destroy $saveChanges_Dialog"
	wm withdraw $saveChanges_Dialog
	wm title $saveChanges_Dialog "Save unchanged modifications?"
	
	set inner_f [frame $saveChanges_Dialog.inner_f]
    	set inner_f1 [frame $saveChanges_Dialog.inner_f1]
    	set inner_f2 [frame $saveChanges_Dialog.inner_f2]
    	set lbl_save  [label $inner_f1.lbl_save -image [Bitmap::get question]]
    	set lbl_save2  [label $inner_f2.lbl_save2 -text "There are unsaved changes to at least one policy file.\n\Do you want to save changes?" \
    			-font {Helvetica 11}]
    	set b_yes [button $inner_f.b_yes -text "Yes" -width 6 -command {set Sepct::saveChanges_Dialog_ans yes; destroy $Sepct::saveChanges_Dialog} -font {Helvetica 11}]
	set b_no [button $inner_f.b_no -text "No" -width 6 -command {set Sepct::saveChanges_Dialog_ans no; destroy $Sepct::saveChanges_Dialog} -font {Helvetica 11}]
	set b_discard [button $inner_f.b_discard -text "Discard All" -command {set Sepct::saveChanges_Dialog_ans discard; destroy $Sepct::saveChanges_Dialog} -font {Helvetica 11}]
	set b_cancel [button $inner_f.b_cancel -text "Cancel" -width 6 -command {set Sepct::saveChanges_Dialog_ans cancel; destroy $Sepct::saveChanges_Dialog} -font {Helvetica 11}]
	set b_show [button $inner_f.b_show -text "Show Files" -command {Sepct::show_ModFileNames} -font {Helvetica 11}]
	
	pack $inner_f -side bottom -anchor nw
	pack $inner_f1 -side left -anchor n  -pady 10
	pack $inner_f2 -side left -anchor n -pady 10
	pack $lbl_save -side left -anchor center -padx 10
	pack $lbl_save2 -side left -anchor center 
	pack $b_yes $b_no $b_discard $b_cancel $b_show -side left -anchor center -padx 2
	
	# Place a toplevel at a particular position
	::tk::PlaceWindow $saveChanges_Dialog widget center
	wm deiconify $saveChanges_Dialog
	
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $Sepct::::saveChanges_Dialog 0 0
	} else {
		bind $Sepct::::saveChanges_Dialog <Configure> { wm geometry $Sepct::::saveChanges_Dialog {} }
	}
	
	vwait Sepct::saveChanges_Dialog_ans 
		
	return 0
}

###############################
# ::checkAndSaveChanges
#	-   This dialog is used when another dialog need to save
#		modified files before going on
#	- return 0 on success, -1 error, 1 for cancel
proc Sepct::checkAndSaveChanges { } {
	variable saveChanges_Dialog_ans


	if { [Sepct_db::are_there_mod_files] } {
		Sepct::display_saveChanges_Dialog
		switch $saveChanges_Dialog_ans {
			no {	
				return 0
			}
			yes {
				# Save (yes)
				set rt [Sepct::save_all] 
				return $rt
			}
			discard {
				# Discard all
				set rt [Sepct_db::discard_All_File_Changes] 
				return $rt
			}
			default {
				# Cancel or anything else
				return 1
			}
		}		
	} else {
		return 0
	}
}

##############################################################
# ::display_saveAll_Dialog
#  
proc Sepct::display_saveAll_Dialog { path } {
	variable saveAll_Dialog	
	variable mainWindow
	global tcl_platform
	
    	if { [winfo exists $saveAll_Dialog] } {
    		destroy $saveAll_Dialog 
    	}
    	
    	# Create the toplevel dialog window and set its' properties.
	toplevel $saveAll_Dialog
	wm protocol $saveAll_Dialog WM_DELETE_WINDOW "destroy $saveAll_Dialog"
	wm withdraw $saveAll_Dialog
	wm title $saveAll_Dialog "Save Changes?"
	
	# Frames
	set inner_f  [frame $saveAll_Dialog.inner_f]
    	set inner_f1 [frame $saveAll_Dialog.inner_f1]
    	set inner_f2 [frame $saveAll_Dialog.inner_f2]
    	
    	# Labels
    	set lbl_save   [label $inner_f1.lbl_save -image [Bitmap::get question]]
    	set lbl_save2  [label $inner_f2.lbl_save -text "Save changes to $path?" \
    			-font {Helvetica 11}]
    			
    	# Buttons
    	set b_yes [button $inner_f.b_yes -text "Yes" -width 6 -command {set Sepct::saveall_choice "Yes"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	set b_no [button $inner_f.b_no -text "No" -width 6 -command {set Sepct::saveall_choice "No"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	set b_discard [button $inner_f.b_discard -text "Discard" -command {set Sepct::saveall_choice "Discard"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	set b_cancel [button $inner_f.b_cancel -text "Cancel" -width 6 -command {set Sepct::saveall_choice "Cancel"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	set b_show [button $inner_f.b_show -text "ShowFiles" -command {Sepct::show_ModFileNames} -font {Helvetica 11}]
	set b_discard_all [button $inner_f.b_discard_all -text "Discard All" -command {set Sepct::saveall_choice "Discard All"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	set b_no_all [button $inner_f.b_no_all -text "No to All" -width 6 -command {set Sepct::saveall_choice "No to All"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	set b_save_all [button $inner_f.b_save_all -text "Save All" -width 6 -command {set Sepct::saveall_choice "Save All"; destroy $Sepct::saveAll_Dialog} -font {Helvetica 11}]
	
	pack $inner_f -side bottom -anchor nw
	pack $inner_f1 -side left -anchor n  -pady 10 
	pack $inner_f2 -side left -anchor n -pady 10 
	pack $lbl_save -side left -anchor center -padx 20 
	pack $lbl_save2 -side left -anchor center -expand yes -padx 5 -pady 10
	pack $b_yes $b_no $b_discard $b_save_all $b_no_all $b_discard_all $b_cancel $b_show -side left -anchor center -padx 2
	
	# Place a toplevel at a particular position
	::tk::PlaceWindow $saveAll_Dialog widget center
	wm deiconify $saveAll_Dialog
	
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $Sepct::::saveAll_Dialog 0 0
	} else {
		bind $Sepct::::saveAll_Dialog <Configure> { wm geometry $Sepct::::saveAll_Dialog {} }
	}
	
	vwait Sepct::saveall_choice
	
	return 0
}

##############################################################
# ::save_allFiles
#  	- local funciton to save  all modified files without prompt
proc Sepct::save_allFiles {} {
	# Get all pathnames to modified files.
	set mod_File_Paths [Sepct_db::getModFileNames]
	
	# If there are modified files, then save each
	foreach path $mod_File_Paths {
		set rt [Sepct_db::saveFile $path ]
		if { $rt == -1 } {
			puts stderr "Unexpected error in saving file $path in save_allFiles"
			# just keep going!!!
		}
	}
	return 0
}

##############################################################
# ::save_All
#	- ensure any outstanding changes are recorded in mod list
#	- return 0 for success, 1 if cancel was selected
proc Sepct::record_outstanding_changes { } {
	variable disable_customize_tab
	Sepct_Browse::record_outstanding_changes 
	if {!$disable_customize_tab} {
		Sepct_Customize::record_outstanding_changes 
	}
	# NOTE: no need to call test tab; it doesn't mod files yet
	return 0
}

##############################################################
# ::save_All
#  	- Save all modified files.
#	- return 0 for success, 1 if cancel was selected
proc Sepct::save_all { } {
	variable save_Dialog	
	variable mainWindow
	variable notebook
	variable saveall_choice
	
	# First, flush out changes in text boxes 
	Sepct::record_outstanding_changes
  	
	# Get all pathnames to modified files.
	set mod_File_Paths [Sepct_db::getModFileNames]
    	
    	if { $mod_File_Paths != "" } {
		foreach mod_file $mod_File_Paths {
			Sepct::display_saveAll_Dialog $mod_file
			switch $saveall_choice {
				"Yes" {	
					# save (yes)
					Sepct_db::saveFile $mod_file
					continue
				}
				"No" {
					# don't save (no)
					# don't do anything with the file; in particular, don't revert it!
					continue
				}
				"Discard" {
					# Discard changes for this particular file
					Sepct_db::discard_Single_File_Changes $mod_file
					continue
				}
				"Save All" {
					# save all
					Sepct::save_allFiles
					break
					
				}
				"No to All" {
					# no to all
					# don't do anything with the files; in particular, don't revert them!
					break
				}
				"Discard All" {
					# Discard all
					set canceled [Sepct_db::discard_All_File_Changes]
					break
				}
				default {
					# cancel
					return 1
				}
			}		
		}
	}  
    	# now let the displayed tab redisplay to indicate saves if necessary
	# If the currently raised tab has been disabled, it will no longer be considered the raised tab.
	# So we must make sure that a raised tab still exists before calling its enter_Tab proc.
	if {[$notebook raise] != ""} {
		[$notebook raise]::enter_Tab
	}
	return 0
}

##############################################################
# ::exitApp
#  	- Exit the application.
# 
proc Sepct::exitApp {} {
	
	set rt [Sepct::save_all]
	
	if { $rt == 1 } {
		# cancel
		return 1
	}
	Sepct::closePolicy
	Sepct_db::close
	Sepct::writeInitFile
	exit

}

##############################################################
# ::display_searchDlg
#  	- Display the search dialog
# 
proc Sepct::display_searchDlg {} {
	variable searchDlg
	variable searchDlg_entryBox
	global tcl_platform
	
	# Checking to see if window already exists. If so, it is destroyed.
	if { [winfo exists $searchDlg] } {
		raise $searchDlg
		focus $searchDlg_entryBox
		$searchDlg_entryBox selection range 0 end
		return 0
	}
	
	# Create the toplevel dialog window and set its' properties.
	toplevel $searchDlg
	wm protocol $searchDlg WM_DELETE_WINDOW "destroy $searchDlg"
	wm withdraw $searchDlg
	wm title $searchDlg "Search"
	
	if {$tcl_platform(platform) == "windows"} {
		wm resizable $Sepct::searchDlg 0 0
	} else {
		bind $Sepct::searchDlg <Configure> { wm geometry $Sepct::searchDlg {} }
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
	set searchDlg_entryBox [entry $lframe_top.searchDlg_entryBox -bg white -font $Sepct::text_font -textvariable Sepct::searchString ]
	set b_findNext [button $rframe.b_findNext -text "Find Next" \
		      -command { Sepct::search }]
	set b_cancel [button $rframe.b_cancel -text "Cancel" \
		      -command "destroy $searchDlg"]
	set cb_case [checkbutton $lframe_bot_left.cb_case -text "Case Insensitive" -variable Sepct::case_Insensitive]
	set cb_regExpr [checkbutton $lframe_bot_left.cb_regExpr -text "Regular Expressions" -variable Sepct::regExpr]
	set directionBox [TitleFrame $lframe_bot_right.directionBox -text "Direction" ]
	set dir_up [radiobutton [$directionBox getframe].dir_up -text "Up" -variable Sepct::srch_Direction \
			 -value up ]
    	set dir_down [radiobutton [$directionBox getframe].dir_down -text "Down" -variable Sepct::srch_Direction \
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
	bind $Sepct::searchDlg <Return> { Sepct::search }
	
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
proc Sepct::textSearch { w str case_Insensitive regExpr srch_Direction } {
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
		tk_messageBox -icon error -type ok -title "Search Error" -message \
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
		set Sepct::tk_msgBox_Wait  \
			[tk_messageBox -parent $Sepct::searchDlg -icon warning -type ok -title "Search Failed" -message \
					"Search string not found!"]
		vwait Sepct::tk_msgBox_Wait
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
proc Sepct::search {} {
	variable notebook
	variable searchString
	variable case_Insensitive	
	variable regExpr 		
	variable srch_Direction
	
	[$notebook raise]::search $searchString $case_Insensitive $regExpr $srch_Direction
	
	return 0
}

##############################################################
# ::save
#  	- Save file menu
# 
proc Sepct::save {} {
	variable notebook
	
	[$notebook raise]::save
	return 0
}


##############################################################
# ::save_as
#  	- 
# 
proc Sepct::save_as {} {
	variable notebook
	
	[$notebook raise]::save_as
	
	return 0
}


##############################################################
# ::goto_line
#  	-  
proc Sepct::goto_line { } {
	variable notebook
	variable goto_line_num
	variable goto_cmd
	variable goto_Dialog
	variable gotoDlg_entryBox
	global tcl_platform
	
	# creat dialog
	set goto_Dialog .goto_Dialog
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
		wm resizable $Sepct::goto_Dialog 0 0
	} else {
		bind $Sepct::goto_Dialog <Configure> { wm geometry $Sepct::goto_Dialog {} }
	}
	
    	set goto_line_num ""
    	set goto_cmd "[$notebook raise]::goto_line"
    	
	set gotoDlg_entryBox [entry $goto_Dialog.gotoDlg_entryBox -textvariable Sepct::goto_line_num -width 10 ]
	set lbl_goto  [label $goto_Dialog.lbl_goto -text "Goto:"]
	set b_ok      [button $goto_Dialog.ok -text "OK" -width 6 -command { $Sepct::goto_cmd [string trim $Sepct::goto_line_num]; destroy $Sepct::goto_Dialog}]
	set b_cancel  [button $goto_Dialog.cancel -text "Cancel" -width 6 -command { destroy $Sepct::goto_Dialog }]
	
	pack $lbl_goto $gotoDlg_entryBox -side left -padx 5 -pady 5 -anchor nw
	pack $b_ok $b_cancel -side left -padx 5 -pady 5 -anchor ne
	
	# Place a toplevel at a particular position
    	::tk::PlaceWindow $goto_Dialog widget center
	wm deiconify $goto_Dialog
	focus $gotoDlg_entryBox
	bind $Sepct::goto_Dialog <Return> { $Sepct::goto_cmd $Sepct::goto_line_num; destroy $Sepct::goto_Dialog }
	
	return 0	

}

##############################################################
# ::loadPolicy
#  	- Initialize the GUI on open
# 
proc Sepct::loadPolicy {} {
	variable disable_customize_tab
	variable policyDir

	set rt [Sepct_Browse::initialize $policyDir]
	if { $rt != 0 } {
		tk_messageBox \
		     -icon error \
		     -type ok \
		     -title "Initialize Error" \
		     -message \
			"There was an error configuring the widgets for the Browser tab"
		return -1
	}
	# customize tab might be disabled
	if {!$disable_customize_tab} {
		set rt [Sepct_Customize::initialize $policyDir]
		if { $rt != 0 } {
			tk_messageBox \
			     -icon error \
			     -type ok \
			     -title "Initialize Error" \
			     -message \
				"There was an error configuring the widgets for the Customizer tab"
			return -1
		}
	}
	set rt [Sepct_Test::initialize ]
	if { $rt != 0 } {
		tk_messageBox \
		     -icon error \
		     -type ok \
		     -title "Initialize Error" \
		     -message \
			"There was an error configuring the widgets for the Test tab"
		return -1
	}
	return 0    		
}

############################################################################
# ::setTitleName
#  	- updates cursor title status infor
# 
proc Sepct::setTitleName { { name ""} } {
	variable tool_title
	
	if {$name != "" } {
		set tname "$tool_title - $name"
	} else {
		set tname $tool_title
	}
	wm title $Sepct::mainWindow $tname
   	return 0
}

############################################################################
# ::update_positionStatus
#  	- updates cursor position status infor
# 
proc Sepct::update_positionStatus { pos } { 
	variable line_info
	if { [catch {scan $pos" %d.%d" line col} err ] } {
		puts stderr "update_positionStatus: Problem scanning position ($pos): $err"
		return -1
	}
	set line_info "Ln: $line, Col: $col"
	return 0
}


############################################################################
# ::clear_fileStatus
#	- clear all data from status line
proc Sepct::clear_fileStatus { } {
	variable file_name
	variable file_modTime
	variable file_size
	variable line_info
	
	set file_name ""
	set file_modTime ""
	set file_size ""
	set line_info ""
	return 0
}

##############################################################
# ::switch_tab
#	 - called when a tab is selected...lets current
#		tab do leaving processing and new tab
#		do entering processing
#
proc Sepct::switch_tab { tabID } {
	variable notebook
	variable mainframe
	
	set tabID [Sepct::get_tabname $tabID]
	set raisedPage [$notebook raise]
	#if selecting same tab do nothing
	if { $raisedPage == $tabID } {
    		return 0
    	}
    	
    	# Disabled tabs will return a NULL value for raisedPage.
    	# First let the current tab to any processing it needs to on leaving
    	if {$raisedPage != ""} {
 		${raisedPage}::leave_Tab
 	}
	
	if {[$notebook itemcget $tabID -state] == "disabled"} {
		return 
	}
	
	# clean up GUI
    	Sepct::clear_fileStatus
	
	# Second let the entering tab do its processing
	${tabID}::enter_Tab
	
	# enable/disable menu items	
 	if { $tabID == $Sepct::browse_tab } {
		$mainframe setmenustate AddTag disabled
		$mainframe setmenustate DeleteTag disabled
	} elseif { $tabID == $Sepct::customize_tab } {
		$mainframe setmenustate AddTag normal
		$mainframe setmenustate DeleteTag normal
	} elseif { $tabID== $Sepct::test_tab } {
		$mainframe setmenustate AddTag disabled
		$mainframe setmenustate DeleteTag disabled
	} else {
		puts stderr "update_Widgets had an unexpected error on new tab id ($pageID)...exiting"
		exit
	}
	
	$Sepct::notebook raise $tabID
	return 0
}


############################################################################
# ::update_fileStatus
#  	- update info on status bar based on filename provided
#	- do_pos is a boolean indicating whether we should update the line pos or not
#		if not provided, default to 0 (false)
# 
proc Sepct::update_fileStatus { fn {do_pos 0 }} {
	variable policyDir
	
	set sz [string length $policyDir] 
	if {[string length $fn] >= $sz && [string compare -length $sz $policyDir $fn] == 0 } {
		set relativePath [string replace $fn 0 [expr $sz - 1]]
		set Sepct::file_name ".$relativePath"
	} else {
		set Sepct::file_name $fn 
	}
	
	# last file mod date
	if { [catch {set Sepct::file_modTime [clock format [file mtime $fn] -format "%b %d, %Y %I:%M:%S %p"  -gmt 0]} err] } {
		puts stderr "Problem getting file mod time for $fn: $err"
		set Sepct::file_modTime "????"
	}
	
	# file size as of last save
	if { [catch {set Sepct::file_size  "Sz: [file size $fn]"} err ] } {
		puts stderr "Prolem getting file size for $fn: $err"
		set Sepct::file_size "????"
	}
	if { $do_pos } {
		set pos [Sepct_db::get_pos $fn]
		if { $pos == "" } {
			puts stderr "update_fileStatus: Error getting position info for $fn" 
		} else {
	    		Sepct::update_positionStatus $pos
	    	}
	}
    	return 0
}

####################################################################
# ::change_tab_state
#
#	Called to enable or disable customize tab
#
proc Sepct::change_tab_state { nb tab cmd } {
	if {$cmd == "disable" } {
		$nb itemconfigure  $tab -state disabled
	} else {
		$nb itemconfigure  $tab -state normal
	}
	return 0
}


########################################################################
# ::openPolicy
#  	- Method for opening the specified policy directory.
# 
proc Sepct::openPolicyDir { policyDir recent_flag } {
	variable disable_customize_tab
	variable disable_test_tab
	variable notebook
	variable mainframe

	if {$policyDir != ""} {
		set Sepct::policyDir [file nativename $policyDir]
		set dir_type [Sepct::isValidPolicyDir $policyDir $Sepct::mainWindow]
		if { $dir_type } {
			if { $dir_type == 1 } {
				set disable_customize_tab 0
			} else {
				tk_messageBox \
				     -icon warning \
				     -parent $Sepct::mainWindow \
				     -type ok \
				     -title "Disabling Tabs" \
				     -message \
					"The policy directory does not appear to be configured for customization (i.e., there\
					is no policy/domains/program directory).  \n\nThe cause may be that you are opening an older\
					policy directory or a non-conventional policy directory.\n\nSePCuT will still\
					work, but the Policy Modules tab and Test Policy tab will be disabled."
					
				Sepct::change_tab_state $Sepct::notebook $Sepct::customize_tab disable
				Sepct::change_tab_state $Sepct::notebook $Sepct::test_tab disable
				set disable_customize_tab 1
				set disable_test_tab 1
			}
			if { [Sepct::loadPolicy] != 0} {
				# convince close that the policy is really opened so it will clean up
				set Sepct::policyOpened 1
				Sepct::closePolicy
				return -1
			}
			if {$recent_flag == 1} {
				Sepct::addRecent $policyDir
			}
			set Sepct::policyOpened 1
			$mainframe setmenustate DisableOnCloseTag normal
			# Allow raised tab to initalize
			# If the currently raised tab has been disabled, it will no longer be considered the raised tab.
			# So we must make sure that a raised tab still exists before calling its enter_Tab proc.
			if {[$notebook raise] != ""} {
				[$notebook raise]::enter_Tab
			} else {
				# Look for an enabled tab (if any) and raise the first one found.
				foreach tab [$notebook pages 0 end] {
					if {[$notebook itemcget $tab -state] == "normal"} { 
						# Call its enter_Tab proc.
						set raisedTab [$notebook raise $tab]
						${raisedTab}::enter_Tab
						break
					}
				}
			}
		 	Sepct::setTitleName $policyDir
		} else {
			return -1
		}
	}  
	return 0
}

#######################################################################
# ::openPolicy menu
#	- Function called by menu
#
proc Sepct::openPolicy { } {
	variable notebook
		
	set policyDir [tk_chooseDirectory -title "Choose Policy Directory" \
		-mustexist 1 -initialdir $Sepct::inital_policy_dir]
	if {$policyDir == ""} {
		return -1
	}
	set rt [Sepct::closePolicy]
	if { $rt != 0 } {
		return -1
	}
	set rt [Sepct::openPolicyDir $policyDir 1]
	return $rt
}

#################################################################
# ::create
#  	- Create Mainframe and menus
# 
proc Sepct::create {} {
    variable notebook 
    variable mainframe  
    variable top_width
    variable top_height
        
    # Menu description
    set descmenu {
        "&Policy" PolicyTag policy 0 {
            {command "&Choose policy directory..." {OpenPolicyTag} "Choose policy directory"  \
            	{} -command Sepct::openPolicy }
            {command "&Reload current policy " {DisableOnCloseTag ReloadPolicyTag} "Re-open current policy directory"  \
            	{} -command Sepct::reloadPolicy }
            {command "C&lose policy" {DisableOnCloseTag ClosePolicyTag} "Close opened policy directory" \
            	{} -command Sepct::closePolicy }
            {separator}
            {command "Sa&ve All " { DisableOnCloseTag SaveAllTag } "Save All Modified Files"  \
            	{} -command Sepct::save_all }
            {separator}
            {command "Save Module Conf&iguration..." { DisableOnCloseTag ConfigTag } "Save module configuration"  \
            	{} -command Sepct::save_Configuration }
            {command "L&oad Module Configuration..." { DisableOnCloseTag ConfigTag } "Load module configuration"  \
            	{} -command Sepct::load_Configuration }
            {separator}
            {command "E&xit                      (C-x C-c)" {} "Exit" \
            	{} -command Sepct::exitApp }
            {separator}
            {cascad "Rece&nt directories" {} recent 0 {}}     
        }
        "&File" FileTag file 0 {
            {command "&Save                     (C-x C-s)" {DisableOnCloseTag SaveFileTag} "Save"  \
            	{} -command Sepct::save }
            {command "Save &As...            (C-x C-w)" {DisableOnCloseTag SaveFileAsTag } "Save File As..."  \
            	{} -command Sepct::save_as }
            {command "Sa&ve All " { DisableOnCloseTag SaveAllTag } "Save All Modified Files"  \
            	{} -command Sepct::save_all }
            {separator}
            {command "&Revert to Saved" {DisableOnCloseTag RevertTag} "Revert to Saved"  \
            	{} -command Sepct::revert }
            {command "Show &modified files..." {DisableOnCloseTag ShowModFilesTag} "Show modified files"  \
            	{} -command Sepct::show_ModFileNames }
        }
        "&Edit" EditTag edit 0 {
            {command "&Add Module..." {DisableOnCloseTag AddTag ModEditTag } "Add a New Policy Module" {} -command Sepct::addModule }
            {command "&Delete Module" { DisableOnCloseTag DeleteTag ModEditTag} "Delete a Policy Module"  \
            	{} -command Sepct::deleteModule } 
            {command "Ena&ble All Modules" {DisableOnCloseTag EnableModTag ModEditTag} "Enable All Modules" {}\
            	 -command Sepct::enableAllModules }
            {separator}
            {command "&Toggle Edit Mode" {DisableOnCloseTag EditModeTag} "Toggle between read-only and editable mode." {} \
            		-command Sepct::ToggleEditMode  }
            {separator}
            {command "&Goto Line...           (C-g)" {DisableOnCloseTag GotoTag} "Goto Line"  \
            	{} -command Sepct::goto_line }      
            {command "&Search...               (C-s)" {DisableOnCloseTag SearchTag} "Search"  \
            	{} -command Sepct::display_searchDlg }	
        }
        "&Options" all options 0 {
            {command "Defa&ult tool settings..." {all option} "Set tool default settings." {}
                -command  Sepct::display_default_settings_Dlg
            }
        }
        "&Help" {} helpmenu 0 {
	    {command "&Help"  {all option} "Show help" {} -command Sepct::helpDlg}
	    {command "&About" {all option} "Show about box" {} -command Sepct::aboutBox}
        }
    }

    set mainframe [MainFrame .mainframe -menu $descmenu -textvariable Sepct::status]
    $mainframe addindicator -textvariable Sepct::line_info -width 18 -anchor w -padx 2
    $mainframe addindicator -textvariable Sepct::file_size -width 12 -anchor w -padx 2
    $mainframe addindicator -textvariable Sepct::file_modTime -width 25 -anchor c -padx 2
    $mainframe addindicator -textvariable Sepct::edit_mode_status -width 9 -anchor c -padx 2
    $mainframe addindicator -textvariable Sepct::file_name -width 35 -anchor e -padx 2
    $mainframe setmenustate DisableOnCloseTag disabled
    $mainframe setmenustate ConfigTag disabled
                      
    # Main NoteBook creation
    set frame    [$mainframe getframe]
    set notebook [NoteBook $frame.nb]
           
    # Create tabs: put a call for each tab here
    Sepct_Browse::create $notebook
    Sepct_Customize::create $notebook
    Sepct_Test::create $notebook
    
    bind $Sepct::mainWindow <Control-x><s> {Sepct::save}
    bind $Sepct::mainWindow <Control-x><w> {Sepct::save_as}
    bind $Sepct::mainWindow <Control-s> {Sepct::display_searchDlg}
    bind $Sepct::mainWindow <Control-g> {Sepct::goto_line}
       
    $notebook compute_size
    $notebook bindtabs <Button-1> { Sepct::switch_tab }
    pack $notebook -fill both -expand yes -padx 4 -pady 4
    $notebook raise [$notebook page 0]
    
    pack $mainframe -fill both -expand yes  
    update idletasks	
    
    return 0
}

#################################################################
# ::save_default_settings
# 
proc Sepct::save_default_settings {} {
	variable inital_policy_dir
	variable tmp_initial_policy_dir
	
	set dir_type [Sepct::isValidPolicyDir $tmp_initial_policy_dir $Sepct::tool_settings_Dialog]
	if {$dir_type != 1} {	
		if { $dir_type == 2 } {
			set ans [tk_messageBox \
				     -icon warning \
				     -type yesno \
				     -parent $Sepct::tool_settings_Dialog \
				     -title "Non-conventional Policy Directory" \
				     -message \
					"The policy directory does not appear to be configured for customization (i.e., there\
					is no policy/domains/program directory).  \n\nThis may because you are specifying an older\
					policy directory or a non-conventional policy directory.  \n\nSePCuT will still\
					work, but the Policy Modules tab will be disabled at start-up. \n\nWould you still like\
					to save these settings?"]
			switch $ans {
				no {return -1}
				yes {}
			}
		} else {
			return -1
		}
	}
	
	set inital_policy_dir $tmp_initial_policy_dir
	Sepct::writeInitFile
	return 0	
}

#################################################################
# ::browse_for_init_directory 
# 
proc Sepct::browse_for_init_directory {} {
	set dir [tk_chooseDirectory -initialdir $Sepct::inital_policy_dir -title "Choose initial directory" \
		-mustexist 1 -parent $Sepct::tool_settings_Dialog]
	if { $dir != "" } {
		set Sepct::tmp_initial_policy_dir $dir	
	}
	return 0
}

#################################################################
# ::display_default_settings_Dlg 
# 
proc Sepct::display_default_settings_Dlg {} {
	variable inital_policy_dir
	variable tmp_initial_policy_dir
	variable tool_settings_Dialog	
	variable mainWindow
	
    	if { [winfo exists $tool_settings_Dialog] } {
    		raise $tool_settings_Dialog
    		return 
    	}
    	
    	# Create the toplevel dialog window and set its' properties.
	toplevel $tool_settings_Dialog
	wm protocol $tool_settings_Dialog WM_DELETE_WINDOW "destroy $tool_settings_Dialog"
	wm withdraw $tool_settings_Dialog
	wm title $tool_settings_Dialog "Default Tool Settings"
	
	# Frames	
	set title_f [TitleFrame $tool_settings_Dialog.title_f -text "Tool Options"]
	set frame_a [frame [$title_f getframe].frame_a]
	set frame_edit_mode [frame $frame_a.frame_edit_mode]
	set frame_initDir [frame $frame_a.frame_initDir]	
	set frame_b [frame [$title_f getframe].frame_b]
	pack $title_f -side left -expand yes -fill both -padx 5 -pady 5
	pack $frame_a -fill both -expand yes -side top -anchor nw -pady 5 -padx 5
	pack $frame_edit_mode -fill both -side top -anchor nw 
	pack $frame_initDir -fill both -side top -anchor nw -pady 5
	pack $frame_b -side bottom -anchor center
	
	set tmp_initial_policy_dir $inital_policy_dir
	# Other widgets
	set cb_show_file_names [checkbutton $frame_a.cb_show_file_names -text "Display program modules by file name at start-up" \
					-variable Sepct::show_customize_file_names]
	set rb_read_only [radiobutton $frame_edit_mode.rb_read_only -variable Sepct::initial_edit_mode -value 0 -text "Read-Only"]
	set rb_edit_mode [radiobutton $frame_edit_mode.rb_edit_mode -variable Sepct::initial_edit_mode -value 1 -text "Edit Mode"]
	set entry_initDir [Entry $frame_initDir.entry_initDir -textvariable Sepct::tmp_initial_policy_dir -bg white]
	set lbl_edit_mode [Label $frame_edit_mode.lbl_edit_mode -text "Initial edit mode:"]
	set lbl_initDir [Label $frame_initDir.lbl_initDir -text "Initial policy directory:"]
	
	# Buttons
	set b_initDir [button $frame_initDir.applyButton -text "Browse..." \
		      -command  {Sepct::browse_for_init_directory}]
	set okButton [Button $frame_b.okButton -text "OK" \
		      -command  {
		      		set rt [Sepct::save_default_settings]
		      		if { $rt == 0 } {
		      			destroy $Sepct::tool_settings_Dialog
		      		}
		      	}]
	set applyButton [Button $frame_b.applyButton -text "Apply" \
		      -command  {Sepct::save_default_settings}]
	set cancelButton [Button $frame_b.cancelButton -text "Cancel" \
		      -command {destroy $Sepct::tool_settings_Dialog}]
	
	pack $cb_show_file_names -side top -anchor nw 	
	pack $lbl_edit_mode $rb_read_only $rb_edit_mode -side left -anchor nw -padx 5
	pack $lbl_initDir -side left -anchor nw -padx 5 -fill y     	     	        
	pack $entry_initDir -side left -expand yes -anchor nw -fill both
	pack $b_initDir -side left -anchor ne -padx 2 
	pack $okButton $applyButton $cancelButton -side left -anchor center -expand yes -padx 2
	
	set width 450
	set height 150
	wm geom $tool_settings_Dialog ${width}x${height}
	# Place a toplevel at a particular position
	#::tk::PlaceWindow $tool_settings_Dialog widget center
	wm deiconify $tool_settings_Dialog	  		
	return 0
}

#################################################################
# ::configure_tool_settings 
# 
proc Sepct::configure_tool_settings {} {
	variable recent_dirs_tmp_list
	
	if { $Sepct::initial_edit_mode == 0 } {
		set Sepct::read_only	1
	} else {
		set Sepct::read_only	0
	}
	Sepct::DisplayEditMode
	if { $recent_dirs_tmp_list != "" } {
		# Configure the recent dirs menu list
		foreach dir $recent_dirs_tmp_list {
			# Make sure file is a directory before adding to recent dirs list.
			if { [file isdirectory $dir] } {
				Sepct::addRecent $dir
			}
		}
		# No longer need temporary list, since we have now loaded all the directories. 
		unset recent_dirs_tmp_list 
	}
	return 0
}

proc Sepct::load_fonts { } {
	variable title_font
	variable dialog_font
	variable general_font
	variable text_font
	
	tk scaling -displayof . 1.0
	# First set all fonts in general; then change specific fonts
	if {$general_font == ""} {
		option add *Font "Helvetica 10"
	} else {
		option add *Font $general_font
	}
	if {$title_font == ""} {
		option add *TitleFrame.l.font "Helvetica 10 bold italic" 
	} else {
		option add *TitleFrame.l.font $title_font  
	}
	if {$dialog_font == ""} {
		option add *Dialog*font "Helvetica 10" 
	} else {
		option add *Dialog*font $dialog_font
	}
	if {$text_font == ""} {
		option add *text*font "fixed"
		set text_font "fixed"
	} else {
		option add *text*font $text_font
	}
	return 0	
}

#################################################################
# ::main
#  	- Main application function. Loads packages, sets window
#	  options, and arranges the window.
# 	- Calls ::create method  
# 
proc Sepct::main {} {
	global argv0 argv
	global tk_version
	global tk_patchLevel
	variable mainWindow
	variable top_width
        variable top_height
        variable bwidget_version
        
	# Prevent the application from responding to incoming send requests and sending 
	# outgoing requests. This way any other applications that can connect to our X 
	# server cannot send harmful scripts to our application. 
	rename send {}
		
	# Load BWidget package into the interpreter
	set rt [catch {set bwidget_version [package require BWidget]} err]
	if {$rt != 0 } {
		tk_messageBox -icon error -type ok -title "Missing BWidgets package" -message \
			"Missing BWidgets package.  Ensure that your installed version of \n\
			TCL/TK includes BWidgets, which can be found at\n\n\
			http://sourceforge.net/projects/tcllib"
		exit
	}
	if {[package vcompare $bwidget_version "1.4.1"] == -1} {
		tk_messageBox -icon warning -type ok -title "Package Version" -message \
			"This tool requires BWidgets 1.4.1 or later. You may experience problems\
			while running the application. It is recommended that you upgrade your BWidgets\
			package to version 1.4.1 or greater. See 'Help' for more information."	
	}
	
	# Provide the user with a warning if incompatible Tk and BWidget libraries are being used.
	if {[package vcompare $bwidget_version "1.4.1"] && $tk_version == "8.3"} {
		tk_messageBox -icon error -type ok -title "Warning" -message \
			"Your installed Tk version $tk_version includes an incompatible BWidgets $bwidget_version package version. \
			This has been known to cause a tk application to crash.\n\nIt is recommended that you either upgrade your \
			Tk library to version 8.4 or greater or use BWidgets 1.4.1 instead. See the README for more information."	
		exit
	}
			
	wm withdraw $mainWindow
	wm title $mainWindow $Sepct::tool_title
	wm protocol $mainWindow WM_DELETE_WINDOW "Sepct::exitApp"
	
	bind $mainWindow <Control-x><c> {Sepct::exitApp}
	
	Sepct::readInitFile
	Sepct::load_fonts
	# Create the main application container window
	Sepct::create
	Sepct::configure_tool_settings
	
#	# Configure the geometry for the window manager
#	set x  [winfo screenwidth .]
#	set y  [winfo screenheight .]
#	set width  [ expr $x - ($x/4) ]
#	set height [ expr $y - ($y/3) ]
#	BWidget::place $mainWindow $width $height center
	wm geom . ${top_width}x${top_height}
	
	# Display the window; Raise the window's position in the stacking order; Set the focus 
	wm deiconify $mainWindow
	raise $mainWindow
	focus -force $mainWindow
		
   	# If a policy dir is given at the command line, over-ride opening the default initial policy dir.
	set argv1 [lindex $argv 0]
	if { $argv1 != "" } {
		Sepct::openPolicyDir $argv1 1
	} else {
		# Attempt to open default directory.
		if { $Sepct::inital_policy_dir != "" } {
			Sepct::openPolicyDir $Sepct::inital_policy_dir 1
		}
	}
	return 0
}
