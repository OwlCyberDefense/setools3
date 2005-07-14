#############################################################
#  sepct_browser.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2002-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com, mayerf@treys.com>
# -----------------------------------------------------------
#

##############################################################
# ::Sepct_Browse namespace
##############################################################
namespace eval Sepct_Browse {
    # name of file displayed in text box
    variable curr_file			""	
    # dirty bit for text box
    variable text_dBit			0	
    # mod cntr for curr_file
    variable text_mcntr			0	
    # mod cntr for selected tree node
    variable node_mcntr			0
    # this is set on on leaving and checked on entering the tab
    variable selected_node		"" 	
    variable max_Filename_Length	255	
    
    # contains name of policy root dir
    variable home_node			
    
    variable file_context_tab_name	"File Contents"
    
    # Global widgets
    variable notebook
    variable mainframe
    variable tree
    variable list_b
    variable text_c	
    variable text_wrap_proc  "Sepct_Browse::wrap_proc"	# This is hard coded and shouldn't be changed
    						# see ::browse_text_widget proc below
}


##############################################################
# ::initialize_App_Vars
#  	- Re-initialize application variables.
#
proc Sepct_Browse::initialize_App_Vars {  } {
	set Sepct_Browse::curr_file			""
	set Sepct_Browse::text_mcntr			0
	Sepct_Browse::reset_dirtyState
	return 0
}

###############################################################################
# ::reset_dirtyState
#  	-
# 
proc Sepct_Browse::reset_dirtyState { } {	    		
	set Sepct_Browse::text_dBit 0
	return 0
}

##############################################################
# ::remove_modIndicators
#  	- 
proc Sepct_Browse::remove_modIndicators  {} {
	variable notebook
	$notebook itemconfigure Contents -text $Sepct_Browse::file_context_tab_name
	return 0
}

##############################################################
# ::set_modIndicators
#  	- 
proc Sepct_Browse::set_modIndicators {} {
	variable notebook
	$notebook itemconfigure Contents -text "$Sepct_Browse::file_context_tab_name*"
	return 0
}


##################################################################
# ::wrap_proc
#  	- This overrides the default cmds
#		for text so we can track dirty bit
# NOTE: This proc MUST have same name as $text_wrap_prob var; it will
# be renamed in create
proc Sepct_Browse::wrap_proc { cmd args } {
	if { $Sepct_Browse::curr_file != "" } {
		switch $cmd {
			insert	-
			delete	{ 
				if { [Sepct::inReadOnlyMode] } {
					return 0
				} else {
					if { $Sepct_Browse::text_dBit == 0 }  {
						Sepct_Browse::set_modIndicators
						set Sepct_Browse::text_dBit 1
					}
					Sepct::update_positionStatus [$Sepct_Browse::text_c index insert]
				}
			}
			mark {
				if { [string compare -length 10 $args "set insert"]  == 0 } {
					# in this case, go ahead and directly call the upleve cmd so that
					# the insertion mark is set, allowing us to determine its location.
					# Because we call uplevel, we MUST return from this case.
					uplevel "::${Sepct_Browse::text_c}_" $cmd $args
					Sepct::update_positionStatus [$Sepct_Browse::text_c index insert]
					return
				}
			}
		}
	}
	# don't use a return after this!
	uplevel "::${Sepct_Browse::text_c}_" $cmd $args

}


###############################################################################
# ::insert_Data
#	- inserts data into text box, checking for changes
# 
proc Sepct_Browse::insert_Data { path textBox line col} {	
	# If the file is in our mod_FileArray, then we simply insert 
	# the data from the mod_FileArray. 
	if { [Sepct_db::is_in_mod_FileArray $path] } {
		$textBox delete 0.0 end
		if {[Sepct_db::getModFile_Data $path data] != 0 } {
			return -1
		}
		$textBox insert end $data
		# Add the mod indicator to the notebook tab.
		Sepct_Browse::set_modIndicators
	} else {
		# If the file has not been modified, then insert the data from disk.
    		if { [Sepct_db::read_fileContents_fromDisk $path data] != 0 } {
    			return -1
    		}
		$textBox insert end $data
		Sepct_Browse::remove_modIndicators 

	}
        
        # Set the focus and the mark.
	focus -force $textBox
	$textBox mark set insert $line.$col 
	$textBox see $line.$col 
		
	return 0	
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Sepct_Browse::search { str case_Insensitive regExpr srch_Direction } {
	variable text_c
	
	Sepct::textSearch $text_c $str $case_Insensitive $regExpr $srch_Direction
}

########################################################################
# ::record_outstanding_changes
#  	- makes sure any outstanding changes are sent to mod list
#	- return mod counter for curr_file, -1 for error, -2 if no changes occured
# 
proc Sepct_Browse::record_outstanding_changes { } {
	variable curr_file
	variable text_dBit
    	variable text_c
    	variable text_mcntr
	
	if { $curr_file != "" } {
		if {$text_dBit } {
			set cntr [Sepct_db::add_to_mod_List $curr_file [$text_c get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
			Sepct_Browse::reset_dirtyState
			set text_mcntr $cntr
			# we want to record position changes when we add to mod array
			Sepct_db::update_pos $curr_file [$text_c index insert]
			return $cntr
		}
	}
	# -2 means no changes
	return -2
}


########################################################################
# ::revert_file
#  	- functions to revert file to last saved, discarding any current
#	- changes
# 
proc Sepct_Browse::revert_file { } {
	variable text_mcntr	
	variable curr_file
	variable list_b
	variable text_c
	
	if {$curr_file == "" } {
		return 0
	}
	
	# discard any changes
	set cntr [Sepct_db::discard_Single_File_Changes $curr_file ]
	if {$cntr >= 0 } {
		# record the new counter
		set text_mcntr $cntr
	} elseif {$cntr == -1} {
		puts stderr "Problem displaying file in revert_file"
		return -1
	}
	# else is -2 which mean no changes needed to record

	# redisplay file
	# reset curr_file to fool displayFile that a new file is selected
	set fn $curr_file
	set curr_file ""
	set rt [Sepct_Browse::displayFile $list_b $text_c $fn]

	return $rt
}

############################################################################
# ::leave_Tab
#  	- called when Test tab is raised and about to be left
#
proc Sepct_Browse::leave_Tab { } {
	variable node_mcntr	
    	variable selected_node
 	Sepct_Browse::record_outstanding_changes
 	# record the mod cntr for selected node
	set node_mcntr [Sepct_db::get_node_mod_cntr $selected_node]
	return 0
}
############################################################################
# ::enter_Tab
#  	- called when Test tab is about to be raised
#
proc Sepct_Browse::enter_Tab { } {
	variable text_c
	variable text_mcntr
	variable curr_file
	variable list_b
	variable node_mcntr	
	variable selected_node
	variable tree
	
    	
    	# Display updates immediately and set the focus to the text widget.
    	focus  $text_c
    	
	if { [Sepct::isPolicyOpened] } {
		$Sepct::mainframe setmenustate ModEditTag disabled
		$Sepct::mainframe setmenustate SaveFileTag normal
		$Sepct::mainframe setmenustate SaveFileAsTag normal
		$Sepct::mainframe setmenustate RevertTag normal
		$Sepct::mainframe setmenustate ConfigTag disabled
	}

    	if { $curr_file != "" && [ Sepct_db::does_fileExists $curr_file ] && [file exists $curr_file]} {
    		set cntr [Sepct_db::get_cntr $curr_file]
		if {$cntr != $text_mcntr } {
			# reset curr_file to fool displayFile
			set fn $curr_file
			set curr_file ""
    			set rt [Sepct_Browse::displayFile $list_b $text_c $fn]
    			if {$rt != 0} {
    				# problem displaying (e.g., file doesn't exist)
    				Sepct::clear_fileStatus   
    				return -1  				
    			}
	    	} else {
	    		#just need to update status info and reset cursor
	    		Sepct::update_fileStatus $curr_file 1
	    	}
	} else {
		# no file current opened or was moved/removed
		set curr_file ""
		$text_c delete 0.0 end
		Sepct::clear_fileStatus
		Sepct_Browse::reset_dirtyState
		Sepct_Browse::remove_modIndicators
	}	
	
	# Determine whether the selected tree node needs to redisplay directory contents
	if { $selected_node != "" } {
		set cur_mcntr [Sepct_db::get_node_mod_cntr $selected_node]
		if { $node_mcntr != $cur_mcntr || [Sepct_Browse::validate_directory_structure $selected_node] == 0} {
			set node_mcntr $cur_mcntr
			# reset selected_node to trick treeSelect into re-drawing listbox
			set node $selected_node
			set selected_node ""
			set rt [Sepct_Browse::treeSelect $tree $list_b $node]
			if { $rt != 0 } {
				return -1
			}
		} 
	} else {
		set node_mcntr 0
	}

    	return 0
}


########################################################################
# ::close
#  	- functions to perform on policy close
# 
proc Sepct_Browse::close {} {
	# let the db handle the tree
	Sepct_db::close
	$Sepct_Browse::list_b delete [$Sepct_Browse::list_b items]
	$Sepct_Browse::text_c delete 0.0 end
	set Sepct_Browse::selected_node ""
	set Sepct_Browse::node_mcntr 0
	Sepct_Browse::initialize_App_Vars
	Sepct_Browse::remove_modIndicators
	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Sepct_Browse::goto_line { line_num} {
	variable text_c
	variable curr_file
	
	if {$curr_file == "" } {
		return 0
	}
	if {[string is integer -strict $line_num] != 1 || [string is digit -strict $line_num] != 1 || [regexp "\[A-Z\]" $line_num]} {
		tk_messageBox -icon error \
			-type ok  \
			-title "Invalid line number" \
			-message "$line_num is not a valid line number"
		return 0
	}
	$text_c mark set insert ${line_num}.0 
	Sepct_db::update_pos $curr_file ${line_num}.0
	$text_c see ${line_num}.0 
	focus -force $text_c
	
	return 0
}


##################################################################
# ::save: saves the current file 
#  	- Save
# 
proc Sepct_Browse::save { } {
	variable curr_file
    	variable text_c
    	variable text_dBit
    	variable text_mcntr
	
	if { $curr_file != "" } {
		if {$text_dBit } {
			# Need to flush out the current text window to the mod list
			set cntr [Sepct_db::add_to_mod_List $curr_file [$text_c get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
			set mod 1
			Sepct_Browse::reset_dirtyState
		} else {
			set mod [Sepct_db::is_in_mod_FileArray $curr_file]
		}
		# Now save the file if modified
		if {$mod} {
			set cntr [Sepct_db::saveFile $curr_file [$text_c index insert]]
			if {$cntr == -1 } {
				return -1
			}
			Sepct_Browse::remove_modIndicators 
			Sepct::update_fileStatus $curr_file
			set text_mcntr $cntr
		} 
	}
    	return 0
}

##################################################################
# ::save_as
# 
proc Sepct_Browse::save_as { } {
    	variable text_c
    	variable tree
    	variable list_b
    	variable text_mcntr
    	variable text_dBit
    	variable curr_file	
	
	if { $curr_file != "" } {
		set fileExt [file extension $curr_file]
		set types {
			{"All files"		*}
    		}
		set filename [tk_getSaveFile -initialdir $Sepct::policyDir \
			-title "Save As?" -filetypes $types]
		
		# If the filename is the same, this means we just simply save the current file.
		if { [string equal $filename $curr_file] } {	
			return [Sepct_Browse::save]
		} 
		if { $filename != "" } {
			set parent [file dirname $filename]
			# Currently we dont support saving above the policy root dir
			# TODO: Fix this to be more general, and not restrict within directory
			if { ![Sepct_db::existsTree_node  $parent] } {
				tk_messageBox -icon warning \
					-type ok  \
					-title "Save As Warning" \
					-message \
					"Can't save to $parent\n\nCurrently, this tool does not support saving
					outside the policy root directory."
				return 0
			}
			
			# save to new file
			set rt [Sepct_db::file_write [$text_c get 0.0 end] $filename]
			if {$rt != 0 } {
				return -1
			}

			# remove the old file from mod list
			set cntr [Sepct_db::remove_from_mod_List $curr_file]
			if { $cntr >= 0 } {
				set text_mcntr $cntr
			} elseif {$cntr == -1 } {
				return -1
			}
			# else $rt == -2, which means wasn't in mod list 
  			
			# add new file to our database
			if { [Sepct_db::existsTree_node $parent] } {
				set position [$text_c index insert]
				set cntr [Sepct_db::add_file $filename 0 $position] 
				if { $cntr == -1 } {
					return -1
				}

				set text_mcntr $cntr
				# First we have to trick ::treeSelect and ::displayFile 
				# by resetting the global selected_node and curr_file variable. 
				set Sepct_Browse::selected_node ""
				set curr_file 	""
				# Update view.
				Sepct_Browse::treeSelect $tree $list_b $parent
				$tree itemconfigure $parent -open 1
				$tree see $parent
				
				# Display and select the new file 
				set rt [Sepct_Browse::displayFile $list_b $text_c $filename]
	    			if {$rt != 0} {
	    				# problem displaying (e.g., file doesn't exist)
	    				Sepct::clear_fileStatus   
	    				return -1  				
	    			}

	    			# indicate that current file has changed
				set curr_file $filename				
				Sepct::update_fileStatus $filename	
				Sepct_Browse::remove_modIndicators 
				Sepct_Browse::reset_dirtyState
				$list_b see $filename
				update idletasks
			} else {
				# TODO: this shouldn't be reached, since we don't support files outside policy dir
				puts stderr "Problem, saving as file outside policy dir!"
				set text_mcntr 0
				$list_b selection clear
				return -1
			}
		}	
	}
	
    	return 0
}


###############################################################################
# ::displayFile
#  	- Method for displaying a selected files' contents.
#	- Invoked when a user selects a file in the directory contents listbox.
# 
proc Sepct_Browse::displayFile { list_box text_c selected_file } {
	variable curr_file
	variable text_dBit
	variable text_mcntr
	
	# if selecting same file, do nothing
	if {$curr_file == $selected_file } {
		return 0
	}
	#  make sure that the selected list node exists.
	if { $selected_file == "" || ![Sepct_db::does_fileExists $selected_file]} {
		return 0
	}
	
	# Before changing current file, make sure any outstanding changes are recorded
	if { $curr_file != "" } {
		if {$text_dBit} {
			set cntr [Sepct_db::add_to_mod_List $curr_file [$text_c get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
		}
		Sepct_db::update_pos $curr_file [$text_c index insert]
	} 
	set curr_file ""
	$text_c delete 0.0 end
	Sepct_Browse::reset_dirtyState 

	# Set the selection in the listbox.
	$list_box selection set $selected_file
	
	# First, make sure that the file still exist. If so, then insert the data into the text
	# widget. Then change the file name in the status bar to the  newly selected file.
	if { [Sepct_db::does_fileExists $selected_file] && [file exists $selected_file] } {
		set fdata [Sepct_db::getFileData $selected_file]
		if { [llength $fdata] < $Sepct_db::lfiles_num_data } {
			puts stderr "problem with fdata ($fdata: [llength $fdata] ) for file $selected_file"
			return -1
		}
		# record the current mod counter
		set text_mcntr [lindex $fdata 0]		
		set line [lindex $fdata 1]
		set col	[lindex $fdata 2]
		Sepct_Browse::insert_Data $selected_file $text_c $line $col
		# need to reset dirty bit since insert will set it (and its not dirty on initial load)
		Sepct_Browse::reset_dirtyState
		# Keep track of the current selected file information.
		set curr_file $selected_file
		Sepct::update_fileStatus $selected_file 1
	} else {
		# Prompt the user that the file no longer exists and that the application
		# will now be updated.
		set ans [tk_messageBox -icon error \
			-type yesnocancel  \
			-title "File Error" \
			-message \
			"In-memory and disk directory structure out of sync for $selected_file\n\n\
			Press YES to re-load the policy directory\n\
			or NO to remove file and continue"]
		
		if {$ans == "yes" } {
			Sepct::reloadPolicy
		} elseif {$ans == "no" } {
			$list_box delete $selected_file 
		} 
		# else (i.e., cancel) do nothing
	}
	return 0	
}

###########################################################################
# ::validate_directory_structure
#  	- 
#
proc Sepct_Browse::validate_directory_structure { node } {
	# Get the files associated with the node. 
	set files_in_mem [Sepct_db::getFileNames $node]
	if { $files_in_mem  == "-1" } {
		return -1
	}
	set files_in_mem [lsort $files_in_mem]
	set files_on_disk [glob -nocomplain [file join $node "*"]]
	# Using the Tcl principle that everything is a string, simply compare 
	# the two lists as strings.to see if they match. If they do, then this
	# means that the the selected node's in-memory and on-disk structure 
	# are in sync.
	if {[string equal "$files_in_mem" "$files_on_disk"]} {
		return 1
	}
	return 0	
}

###########################################################################
# ::select
#  	- Method is invoked when the user selects a node in the tree widget.
#
proc Sepct_Browse::treeSelect { tree list_b node } {
	variable selected_node
	variable curr_file
	
	# If the user has selected a node that is already selected then we just return.
	if { $selected_node == $node } {
		return 0
	}
	
	# Set the tree selection to the current node.
	$tree selection set $node
	
	# Delete the current list contents.
	$list_b delete [$list_b items]
	
	# Get the files associated with the node. 
	set files_in_mem [Sepct_db::getFileNames $node ]
	if { $files_in_mem  == "-1" } {
		return -1
	}
	set files_in_mem [lsort $files_in_mem]

	# Make sure in-memory files still exist on disk before inserting into listbox.
	# If it no longer exists on disk, then we need to sync the in-memory database
	# with the files on disk. 
	foreach file_in_mem $files_in_mem {
		if { [file exists [file join $node $file_in_mem]] } {
			# Insert the file item into the directory contents listbox. 
			$list_b insert end [file join $node $file_in_mem] \
			  	-text  $file_in_mem \
			  	-image [Bitmap::get file] 
		} else { 
			# Remove from the mod list, if this file has been modified.
			if { [Sepct_db::is_in_mod_FileArray [file join $node $file_in_mem]] } {
				Sepct_db::remove_from_mod_List [file join $node $file_in_mem]
			}
			# No longer exists on disk, so remove the file from its' parent node 
			# in the tree 
			if { [Sepct_db::remove_file [file join $node $file_in_mem]] == -1 } {
				puts stderr "Problem removing [file join $node $file_in_mem]"
				return -1
			}
		}
	} 
	
	# Reset our local variable to updated files in memory 
	set files_in_mem [Sepct_db::getFileNames $node]
	# Now, check to see if there are any new files on disk in the selected directory.
	# Retrieve path names of dirs/files in the selected directory.
	set files_on_disk [glob -nocomplain [file join $node "*"]]

	foreach file_on_disk $files_on_disk {
		if {[file isfile $file_on_disk] && ![Sepct_db::does_fileExists $file_on_disk]} {
			# Add the new file to parent node in the tree 
			if {[Sepct_db::add_file $file_on_disk 0 "1.0"] == -1}  {
				puts stderr "Problem adding $file_on_disk"
				return -1
			}
			# Insert the file item into the directory contents listbox. 
			$list_b insert end $file_on_disk \
			  	-text  [file tail $file_on_disk] \
			  	-image [Bitmap::get file] \
		}	
	}
	
	# Redraw the tree and listbox
	$tree configure -redraw 1
	$list_b configure -redraw 1

	# Check to see if we've re-entered the dir node of the currently displayed
	# file, and if so re-select the file  in the listbox.
	if {$curr_file != ""} {
		set curr_dirname [file dirname $curr_file]
		if {$curr_dirname == $node} {
			$list_b selection set $curr_file
			$list_b see $curr_file
		}
	}
	
	# recorded the selected node 
	set selected_node $node
	return 0
}

##################################################################################
# ::readDir
#	- Reads the given policy directory and loadds the tree widget accordingly.
# 
proc Sepct_Browse::readDir { tree parent_node } {
	variable max_Filename_Length	
	
	# Retrieving ALL path names of dirs/files.
	set lentries [glob -nocomplain [file join $parent_node "*"]]
	
	foreach file $lentries {
		# Returns all of the characters in $file after the last directory separator.
		# If $file contains no separators then returns $file. 
		set tail [file tail $file]
		
		# Prevent a buffer overflow by checking the size of the filename. 
		if { [string length $tail] > $max_Filename_Length } {
			 tk_messageBox -icon error \
				-type ok  \
				-title "File Problem" \
				-message \
				"A filename is too long. Maximum length for a filename \
				is $max_Filename_Length characters. Please rename the file correctly. "
			 return 1
		}
			
		if { [file isdirectory $file] } {
			if { [file readable $file] } {
				# Add new node to the CURRENT subtreem via recursive call
				Sepct_db::addTree_node $file 0 0
        			# recurse
				Sepct_Browse::readDir $tree $file
	    		} else {
	    			tk_messageBox -icon warning \
					-type ok  \
					-title "Directory Permission Problem" \
					-message \
					"The directory $file is not readable. It will be skipped."
	    		}
		} elseif { [file isfile $file] } {
	    		if { [Sepct_db::add_file $file 0 "1.0"]  == 1 } {
	    			puts stderr "Problem adding file $file to directory node $parent_node."
	    			return 1
	    		}
		} 
		# else ignore non files and directories
		# TODO: do we need to handle non-files better??
	}
	return 0
}


########################################################################
# ::configure_Widgets
#  	- performs most functions in support of an open
# 
proc Sepct_Browse::configure_Widgets { tree list_b policyDir} {
	variable home_node
	
	# insert the root node into the tree.
	Sepct_db::addTree_node $policyDir 1 1
	set home_node $policyDir
	
	# Recursive function for retrieving all names of dirs/files 
	set rt [Sepct_Browse::readDir $tree $home_node ] 
	if {$rt != 0} {
		return -1
	}
	set rt [$tree configure -redraw 1]
	if {$rt != ""} {
		return -1
	}
	Sepct_Browse::treeSelect $tree $list_b $home_node
	return 0
}

########################################################################
# ::initialize
#  	- Initializes the application variables and redraws all widgets
#		during open
# 
proc Sepct_Browse::initialize { policyDir } {
	variable tree 
	variable list_b

    	set res [Sepct_Browse::configure_Widgets $tree $list_b $policyDir]
    	return $res
}

##############################################################
# ::createNoteBook
#  	- Creates the notebook widget and all related widgets.
# 	- Used by ::createMainFrame method
#
proc Sepct_Browse::createNoteBook { tabsBox } {
	variable text_c
	variable notebook
	
	set notebook [NoteBook $tabsBox.nb -side top]
	set c_frame  [$notebook insert end Contents -text "File Contents"]
	
	# File contents tab widgets.
	set sw_c [ScrolledWindow $c_frame.sw_c -auto none]
	set text_c [text $sw_c.text -bg white -wrap none -font $Sepct::text_font]
	# set up wrap functions
	$sw_c setwidget $text_c
	rename $text_c "::${text_c}_"
	rename $Sepct_Browse::text_wrap_proc "::$text_c"
	
	# Placing display widgets
	pack $sw_c -side left -expand yes -fill both  
	
	$notebook compute_size
	pack $notebook -fill both -expand yes -padx 4 -pady 4
	$notebook raise [$notebook page 0]
	
	return 0
}

###################################################################
# ::create
#  	- Creates all major widgets and frames.
#	- Calls ::createNoteBook method
# 
proc Sepct_Browse::create { nb } {
    variable tree
    variable list_b
    
    # Layout frames
    set frame [$nb insert end $Sepct::browse_tab -text "Browse Policy"]
    set topf  [frame $frame.topf -width 100 -height 200]

    # Paned Windows
    set pw1   [PanedWindow $topf.pw -side top]
    set pane  [$pw1 add ]
    set spane [$pw1 add -weight 4]
    set pw2   [PanedWindow $pane.pw -side left]
    set active [$pw2 add -weight 2]
    set contents [$pw2 add -weight 2]
    
    # Major subframes
    set tabsBox [frame $spane.tabsBox]
    set activeBox [TitleFrame $active.abox -text "Policy Directory"]
    set contentsBox [TitleFrame $contents.abox -text "Directory Contents"]

    # Placing layout frames and major subframes
    pack $tabsBox -pady 2 -padx 2 -fill both -expand yes -anchor ne 
    pack $activeBox -padx 2 -side left -fill both -expand yes
    pack $contentsBox -padx 2 -side left -fill both -expand yes
    
    pack $pw1 -fill both -expand yes
    pack $pw2 -fill both -expand yes	
    pack $topf -fill both -expand yes 
              
    # Active Policy Files listbox
    set sw_t  [ScrolledWindow [$activeBox getframe].sw -auto none]		 
    set tree  [Tree $sw_t.tree \
                   -relief flat -borderwidth 0 -width 15 -highlightthickness 0 \
		   -redraw 0 -bg white -showlines 1 
              ]
    # make sure that Sepct_db:: name space has the tree widget
    set Sepct_db::tree $tree
    $sw_t setwidget $tree 
        
    # Policy contents listbox
    set sw_c   	[ScrolledWindow [$contentsBox getframe].sw_c -auto none]
    set list_b 	[ListBox $sw_c.lb \
                  -relief flat -borderwidth 0 -bg white \
                  -width 20 -highlightthickness 2 \
                  -redraw 0 -selectmode single ]
    $sw_c setwidget $list_b
        	        
    # Placing listbox frames
    pack $sw_t -fill both -expand yes
    pack $sw_c -fill both -expand yes 
    
    # NoteBook creation
    Sepct_Browse::createNoteBook $tabsBox
    
    # Bindings
    $tree bindText  <ButtonPress-1>        {Sepct_Browse::treeSelect $Sepct_Browse::tree $Sepct_Browse::list_b}
    $tree bindText  <Double-ButtonPress-1> {Sepct_Browse::treeSelect $Sepct_Browse::tree $Sepct_Browse::list_b}
    $tree bindImage <ButtonPress-1> 	   {Sepct_Browse::treeSelect $Sepct_Browse::tree $Sepct_Browse::list_b}
    $list_b bindText  <ButtonPress-1>        {Sepct_Browse::displayFile $Sepct_Browse::list_b $Sepct_Browse::text_c}
    $list_b bindText  <Double-ButtonPress-1> {Sepct_Browse::displayFile $Sepct_Browse::list_b $Sepct_Browse::text_c}
    $list_b bindImage <Double-ButtonPress-1> {Sepct_Browse::displayFile $Sepct_Browse::list_b $Sepct_Browse::text_c}
    $list_b bindImage <ButtonPress-1>        {Sepct_Browse::displayFile $Sepct_Browse::list_b $Sepct_Browse::text_c}
    
    Sepct_Browse::initialize_App_Vars
    
    return $frame
}
   