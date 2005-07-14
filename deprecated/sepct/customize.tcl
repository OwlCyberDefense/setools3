#############################################################
#  customize.tcl

# -----------------------------------------------------------
#  Copyright (C) 2002-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com>
# -----------------------------------------------------------
#

##############################################################
# ::Sepct_Customize namespace
#  
##############################################################
namespace eval Sepct_Customize {
	# Variables for ListBox widget.
	variable curr_TE_file		""
	variable curr_FC_file		""
	# dirty bit for text box in the currently raised tab
	variable text_te_dBit			0	
	variable text_fc_dBit			0
	# mod cntr for file in the currently raised tab
	variable text_te_mcntr			0
	variable text_fc_mcntr			0
	
	# module vars
	variable used_Modules_Dir		""
	variable unUsed_Modules_Dir		""
	variable fc_path			""
	# .te files in ./domains/program
	variable unUsed_Modules			""
	# .te files in ./domains/program/unused
	variable used_Modules			""
	# combine above two lists
	variable all_Modules			""
	# list of .fc files from ./file_context/program that are expected (because of a matching
	# .te file in one of the above lists) but is missing
	variable missing_fc_files		""
	
	# misc
	variable desc_ID			"#DESC"
	variable max_Label_Length		255
	variable show_Filenames
	# contains list of all modules
	variable all_Modules			""
	# cb_value_array is used to store the used/unused value for each list box entry (i.e., module)
	# it is indexed by module name (i.e., name.te).
	variable cb_value_array
	# used to pass module name to checkbutton comman
	variable cb_ID				""
	# Counter used to create distinct window pathnames for each embedded checkbutton
	variable num_cbuttons		0
	# Variables used by add_Module_Dlg
	variable newModuleName		""
    	variable module_Desc		""
	variable add_Module_Flag	0
	
	# Variables for Notebook widget
	variable te_tabName			"Type Enforcement Rules"
	variable fc_tabName			"File Context"
	variable te_tabID			"Sepct_TERules"
	variable fc_tabID			"Sepct_FileContext"
	
	# Global widgets
	variable notebook
	variable list_b
	variable text_te
	variable text_fc
	variable add_Dialog
    	variable cb_show_Filenames
    	variable add_Module_Dlg
    	variable duplicate_mods_dlg
    	set duplicate_mods_dlg .duplicate_mods_dlg
    	
    	# This is hard coded and shouldn't be changed
    	# see ::browse_text_widget proc below
    	variable text_TE_wrap_proc  "Sepct_Customize::wrap_proc_te"
    	variable text_FC_wrap_proc  "Sepct_Customize::wrap_proc_fc"	
}

##############################################################
#							     #
# 		GUI functions			    	     #
##############################################################

##############################################################
# ::embed_checkbutton
#  	- Creates an embedded checkbutton in the text widget.
#
proc Sepct_Customize::embed_checkbutton { te_file is_used } {
	variable list_b
	variable cb_value_array
	variable cb_ID
	variable num_cbuttons
	
	# Here we embed the entry (file) name of the item being inserted 
	# into the widgets pathname, so that we can access it later.
	# Our split character is ":", which we will use in 
	# to retrieve the name of entry in the listbox. We also handle 
	# files with multiple dots in its' name which would cause
	# invalid tk widget name errors.
	set rootname [file rootname $te_file]
	set split_list [split $rootname "."]
	if {$split_list != ""} {
		set rootname [join $split_list ":"]	
	}
	set te_file "${rootname}.te"
	set cb_value_array($te_file) $is_used
	incr num_cbuttons
	set cb_name [checkbutton $list_b.cb$num_cbuttons:$rootname -bg white \
		-onvalue 1 -offvalue 0 \
		-variable Sepct_Customize::cb_value_array($te_file) \
		-command {Sepct_Customize::change_module_status $Sepct_Customize::cb_ID} ]
		
	# Make sure that the user has write access to the active directory. 
	# If this access is denied, then disable all checkbuttons and 
	# associated bindings.
	if { [file writable $Sepct_Customize::used_Modules_Dir] } {
		bind $cb_name <Button-1> {
			# Send widet pathname in order to retrieve 
			# the module name of the selected list item.
			set Sepct_Customize::cb_ID %W
		}
		$cb_name configure -state normal
	} else {
		bind $cb_name <Button-1> { 
			tk_messageBox -icon warning \
			-type ok \
			-title "Permission Problem" \
			-message \
			"You don't have permission to Activate or\
			De-activate policy files."
		}
		$cb_name configure -state disabled
	}

	return $cb_name
}

###########################################################################################
# ::display_duplicate_modules_Dlg
# 	- Description: Displays a dialog listing the duplicate modules found.
#
proc Sepct_Customize::display_duplicate_modules_Dlg {duplicate_modules_list} {
	variable duplicate_mods_dlg
	
	if {[winfo exists $duplicate_mods_dlg]} {
		catch {destroy $duplicate_mods_dlg}
	}
	toplevel $duplicate_mods_dlg
	wm title $duplicate_mods_dlg "Duplicate modules!"
	wm protocol $duplicate_mods_dlg WM_DELETE_WINDOW "catch {destroy $duplicate_mods_dlg}"
	
     	set close_b [button $duplicate_mods_dlg.close -text "OK" -command "catch {destroy $duplicate_mods_dlg}" -width 10]
     	set lbl_f [frame $duplicate_mods_dlg.lbl_f]
     	set txt_f [frame $duplicate_mods_dlg.txt_f]
	set sw_c [ScrolledWindow $txt_f.sw_c -auto none]
	set dlg_txt [text [$sw_c getframe].dlg_txt -wrap none]
	$sw_c setwidget $dlg_txt
	
	set lbl_img [label $lbl_f.img -justify left \
		-image [Bitmap::get warning]]
	set lbl_txt [label $lbl_f.txt -justify left \
		-text "Duplicate modules were found in the program directory and have been ignored.\
	\nPlease be aware that these files will be overwritten when disabling the module.\
	\nThe following are the duplicate modules found:"]
		
	$dlg_txt insert end "$duplicate_modules_list\n"  
	$dlg_txt configure -state disabled
		
	pack $close_b -side bottom -anchor center 
	pack $lbl_f -side top -anchor nw -pady 4 -padx 4
	pack $txt_f -side top -anchor nw -pady 4 -padx 4 -fill both -expand yes
	pack $lbl_img -side left -anchor nw -expand yes -padx 2
	pack $lbl_txt -side left -anchor nw -fill x -expand yes
	pack $sw_c -side left -expand yes -fill both 
	
	wm geometry $duplicate_mods_dlg +30+40
	focus -force $duplicate_mods_dlg
	wm transient $duplicate_mods_dlg $Sepct::mainframe
        catch {grab $duplicate_mods_dlg}
   
	return 0
}

###########################################################################################
# ::insert_ListBox_Items
#	- This method inserts items into the listbox and performs other checking.
# 
proc Sepct_Customize::insert_ListBox_Items { } {
	variable list_b
	variable item_count
	variable all_Modules
	variable displayList
	variable show_Filenames
	
	# Now, we insert all sorted items into the listbox widget
	set duplicate_modules ""
	foreach te_file $all_Modules { 
		if {[$list_b exists $te_file]} {
			set duplicate_modules [append duplicate_modules "$te_file\n"]
			continue
		}
		# get descriptive name
		set is_used [Sepct_Customize::is_module_used $te_file]
		set dscp_name [Sepct_Customize::store_mod_descrptive_name $te_file $is_used]
		if {$dscp_name == "-1"} {
			puts stderr "Insert: problem getting descriptive label for $te_file"
			return -1
		}
		# we will set the -text option later 
		# Insert item into listbox and a checkbox at the left of the label of the item.
		$list_b insert end $te_file \
		 	 -data $dscp_name \
		 	 -window [Sepct_Customize::embed_checkbutton $te_file $is_used ]  
	} 
	
	if {$duplicate_modules != ""} {
		Sepct_Customize::display_duplicate_modules_Dlg $duplicate_modules
	}
		
	return 0
}


###############################################################################
# ::draw_list_and_set_buttons
#	-
# 
proc Sepct_Customize::draw_list_and_set_buttons { use_filenames} {  
    	variable list_b
    	variable curr_file
    	
    	update idletasks
    	# Get the current selection 
    	set curr_sel [$list_b selection get]   
    	
    	# Get all items from the listbox
    	set items [$list_b items]
    	
    	# If the show Filenames checkbutton is ON, then use the filename as the label.
    	if { $Sepct_Customize::show_Filenames == 1 } {	
		foreach item $items {
			$list_b itemconfigure $item -text "  $item"
		}
		
		# Sort the items and then reorder according to the sorted list.
		set items [lsort -dictionary $items]
		$list_b reorder $items
	} else {
		set items ""
		
		# If checkbuton is OFF, then we use descriptive labels for each items' text.
		foreach item_text $displayList {
			$list_b itemconfigure $displayList_Array($item_text) -text " $item_text"
			lappend items $displayList_Array($item_text)
		}
		
		# Reorder according to our local items list.
		$list_b reorder $items
	}
	$list_b configure -redraw 1
	
	# Indicate which files are missing an associated FC file?
	# Sepct_Customize::indicate_Missing_FC
	
	# Reset the selection to the previous one
    	if { [$list_b exists $curr_sel] } {
	    	$list_b selection set $curr_sel
	    	$list_b see $curr_sel 
	    	set curr_file $curr_sel
	} else { 
		set curr_file ""
	}
	
    	# Adjust the view so that no part of the canvas is off-screen to the left.
    	# Finally, we display updates immediately.
    	$list_b.c xview moveto 0
    	update idletasks
    	
	return 0	
}

###############################################################################
# ::label_and_order_list
#
proc Sepct_Customize::label_and_order_list { } {
	variable list_b
	variable show_Filenames
		
	#get modules from list
	set mods [$list_b items]
	
	foreach mod $mods {
		if {$show_Filenames} {
			set text_label $mod
		} else {
			set text_label [$list_b itemcget $mod -data]
		}
		# needed to do this because first char was not being displayed!
		set text_label "  $text_label"
		$list_b itemconfigure $mod -text $text_label
	}
		
	# Sort the display list. 
	set module_List [$list_b items]
	
	# Order by descrptive names
	if {$show_Filenames} {
		set module_List [lsort -dictionary $module_List]		
	} else {	
		set module_List [Sepct_Customize::order_Modules_by_Description $module_List]
	}
	
	$list_b reorder $module_List

	return 0
}


########################################################################
# ::configure_ListBox
#  	- loads policy into widgets
proc Sepct_Customize::configure_ListBox { } {
	variable list_b
	
	# Get all used and un-used programs from the ./domains/program directory. 
	set rt [Sepct_Customize::get_all_Modules]
		if { $rt == -1} {
		puts stderr "Customize problem: getting all modules"
		return -1
	}
	
	# Perform consistency checks to obtain array of inconsistent files.
	set rt [Sepct_Customize::check_fc_consistency ]
	if { $rt == -1} {
		puts stderr "Customize problem: getting all modules"
		return -1
	}
	
	# Insert items into the listbox 
	set rt [Sepct_Customize::insert_ListBox_Items]
	if { $rt == -1} {
		puts stderr "Customize problem: getting all modules"
		return -1
	}	

	Sepct_Customize::label_and_order_list

	# Adjust the view so that no part of the canvas is off-screen to the left.
    	# Finally, we display updates immediately.
	$list_b configure -redraw 1
    	$list_b.c xview moveto 0
	
	return 0
}

########################################################################
# ::initialize
#  	- Initializes the the customize tab on open
proc Sepct_Customize::initialize { policyDir } {
	variable list_b
	variable item_count
	
	# Set all necessary path variables.
	set Sepct_Customize::used_Modules_Dir 		"$policyDir/domains/program"
	set Sepct_Customize::fc_path			"$policyDir/file_contexts/program"

	#NOTE: originally we had "Unused" as the unused directory, but it really should have ben
	#	"unused".  So for backwards compatability, we will only use "Unused" if it already
	#	exists and "unused" does not exists.
	if {[file isdirectory "$policyDir/domains/program/Unused"] && ![file isdirectory "$policyDir/domains/program/unused"]} {
		set Sepct_Customize::unUsed_Modules_Dir "$policyDir/domains/program/Unused"
	} else {
		set Sepct_Customize::unUsed_Modules_Dir "$policyDir/domains/program/unused"
	}

	
	# TODO: check in DB not on disk. Add a does_dirExist proc
	if {![file isdirectory $Sepct_Customize::used_Modules_Dir] } {
		set err_dir  $Sepct_Customize::used_Modules_Dir 
	} elseif {![file isdirectory $Sepct_Customize::fc_path] } {
		set err_dir $Sepct_Customize::fc_path
	} else {
		set err_dir ""
	}

	if {$err_dir != "" } {	
		tk_messageBox \
		     -icon error \
		     -type ok \
		     -title "Open Error (Customizer)" \
		     -message \
			"The policy dir ($policyDir)\ndoes not appear to be valid.\n\n\
			The subdirectory ($err_dir) is missing or not readable.  Perhaps \
			you are using a policy directory that pre-dates the modular \
			policy model.  This policy directory cannot be opened by this tool."
		return -1    
		
	}
	set rt [Sepct_Customize::configure_ListBox]
	
	return $rt
}

###############################################################################
# ::displayModule
#  	- Method for displaying a selected modules' contents.
#	- Invoked when a user selects a module in the program modules listbox.
# 
proc Sepct_Customize::displayModule { list_b text_te text_fc selected_module } {
	variable curr_TE_file		
	variable curr_FC_file	
	variable text_te_dBit				
	variable text_fc_dBit			
	variable text_te_mcntr			
	variable text_fc_mcntr	
	variable used_Modules_Dir		
	variable unUsed_Modules_Dir		
	variable fc_path
	variable notebook
	
	# if selecting same file, do nothing
	if { [file tail $curr_TE_file] == $selected_module } {
		return 0
	}
	
	if {$curr_TE_file != ""} {	
		# First, flush any changes in the current TE file to the db
		if { [Sepct_db::does_fileExists $curr_TE_file]} {		
			if {$text_te_dBit} {
				set cntr [Sepct_db::add_to_mod_List $curr_TE_file [$text_te get 0.0 end]]
				if { $cntr == -1 } {
					return -1
				}
			}
			Sepct_db::update_pos $curr_TE_file [$text_te index insert]
		}
		
		if {$curr_FC_file != ""} {
			# Next, flush any changes in the current FC file to the db
			if { [Sepct_db::does_fileExists $curr_FC_file]} {
				if {$text_fc_dBit} {
					set cntr [Sepct_db::add_to_mod_List $curr_FC_file [$text_fc get 0.0 end]]
					if { $cntr == -1 } {
						return -1
					}
				}
				Sepct_db::update_pos $curr_FC_file [$text_fc index insert]
			}
		}
	}	
	
	set curr_TE_file ""
	set curr_FC_file ""
	$text_te delete 0.0 end
	$text_fc delete 0.0 end
	Sepct_Customize::reset_dirtyState 
	
	# Set the selection in the listbox.
	$list_b selection set $selected_module
	
	# Set full pathname for the te file
	if { [Sepct_Customize::is_module_used $selected_module] } {
		set te_file [file join $used_Modules_Dir $selected_module]
	} else {
		set te_file [file join $unUsed_Modules_Dir $selected_module]
	}

	# First, make sure that the module still exists. If so, then insert the data into the text
	# widget. Then change the file name in the status bar to the  newly selected file.
	if { [Sepct_db::does_fileExists $te_file] && [file exists $te_file] } {
		set fdata_te [Sepct_db::getFileData $te_file]
		if { [llength $fdata_te] < $Sepct_db::lfiles_num_data } {
			puts stderr "problem with fdata_te ($fdata_te: [llength $fdata_te] ) for file $te_file"
			return -1
		}
		# record the current mod counter
		set text_te_mcntr [lindex $fdata_te 0]		
		set line [lindex $fdata_te 1]
		set col	[lindex $fdata_te 2]
		Sepct_Customize::insert_Data $te_file $text_te $line $col $Sepct_Customize::te_tabID
	
		# Keep track of the current selected file information.
		set curr_TE_file $te_file
		
		# Set full pathname for the .fc file
		set fc_file [file join $fc_path "[file rootname [file tail $curr_TE_file]].fc"]
		if { [Sepct_db::does_fileExists $fc_file] && [file exists $fc_file] } {
			set fdata_fc [Sepct_db::getFileData $fc_file]
			if { [llength $fdata_fc] < $Sepct_db::lfiles_num_data } {
				puts stderr "problem with fdata_fc ($fdata_fc: [llength $fdata_fc] ) for file $fc_file"
				return -1
			}
			# record the current mod counter
			set text_fc_mcntr [lindex $fdata_fc 0]		
			set line [lindex $fdata_fc 1]
			set col	[lindex $fdata_fc 2]
			Sepct_Customize::insert_Data $fc_file $text_fc $line $col $Sepct_Customize::fc_tabID
			# Keep track of the current selected file information.
			set curr_FC_file $fc_file
		} else { 
			# Prompt the user that the FC file no longer exists.
			set curr_FC_file ""
			# TODO: Change this box to allow user to create a .fc file
			set ans [tk_messageBox -icon warning \
				-type ok \
				-title "Missing File Context File Warning" \
				-message \
				"This module does not appear to have an assoicated file context (.fc)\
				 file.  The tool will continue without the .fc file.  You may want to \
				 create the .fc file from outside this tool and re-load the policy."]
				
			#if { $ans == "yes" } {
				# TODO: create an empty .fc file
			#} elseif {$ans == "no" } {
				# Go ahead without .fc file
			#} 
			# else (i.e., cancel) do nothing
		} 
		# need to reset dirty bit since insert will set it (and its not dirty on initial load)
		Sepct_Customize::reset_dirtyState
		set raisedTab [$notebook raise]
		if { $raisedTab == $Sepct_Customize::te_tabID } {
			Sepct::update_fileStatus $curr_TE_file 1
		} else {
			if { $curr_FC_file != "" } {
				Sepct::update_fileStatus $curr_FC_file 1 
			} else {
				Sepct_Customize::remove_modIndicator $raisedTab
				Sepct::clear_fileStatus
			}
		} 
	} else {
		# Prompt the user that the TE file no longer exists and that the application
		# will now be updated.
		set ans [tk_messageBox -icon error \
			-type yesno  \
			-title "File Error" \
			-message \
			"In-memory and disk directory structure out of sync for $selected_module\n\n\
			Press YES to re-load the policy directory\n\
			or NO to continue leaving the problem."]
		
		if { $ans == "yes" } {
			Sepct::reloadPolicy
		} else  {
			# else NO (i.e., cancel) do nothing
			return -1
		} 
	}
			
	return 0	
}

###############################################################################
# ::remove_CheckButtons
#  	- Method for remove all embedded check buttons.
# 
proc Sepct_Customize::remove_CheckButtons { } {   
	variable list_b
	
	set items [$list_b items]
	
	foreach module $items { 
		# Get the associated checkbutton pathname for the module.
		set cb [$list_b itemcget $module -window]
    		if { [winfo exists $cb] } {
			set rt [catch {destroy $cb} err]
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err"
				return -1
			}
		}
	} 
	set Sepct_Customize::num_cbuttons 0
	return 0	
}

###############################################################################
# ::select_all_CheckButtons
#  	- Method for selecting all embedded check buttons.
# 
proc Sepct_Customize::select_all_CheckButtons { } {   
	variable list_b
	
	set items [$list_b items]
	
	foreach module $items { 
		if { $Sepct_Customize::cb_value_array($module) == 0 } {
			# Get the associated checkbutton pathname for the module.
			set cb [$list_b itemcget $module -window] 
			set Sepct_Customize::cb_ID $cb
			$cb invoke
		}
	} 
	
	return 0	
}

##############################################################
# ::set_modIndicator
#  	- 
proc Sepct_Customize::set_modIndicator { tabID } {
	variable notebook
	variable te_tabID
	variable fc_tabID	
	
	if { [Sepct::inReadOnlyMode] } {
		return 0
	}
	
	if { $tabID == $te_tabID } {
		$notebook itemconfigure $tabID -text "$Sepct_Customize::te_tabName*"
	} elseif { $tabID == $fc_tabID } {
		$notebook itemconfigure $tabID -text "$Sepct_Customize::fc_tabName*"
	} 
	
	return 0
}

############################################################################
# ::remove_modIndicator
#  	- 
# 
proc Sepct_Customize::remove_modIndicator { tabID } {
	variable notebook
	variable te_tabName			
	variable fc_tabName	
	variable fc_tabID
	variable te_tabID	
	
	if { $tabID == $te_tabID } {
		$notebook itemconfigure $tabID -text $Sepct_Customize::te_tabName
	} elseif { $tabID == $fc_tabID } {
		$notebook itemconfigure $tabID -text $Sepct_Customize::fc_tabName
	} 
	
	return 0	
}

#################################################################################
# ::change_module_status
#  	- Determine if the file is used or unused. A currently unused file will 
# 	  be moved to the ./domains/programs directory. A currently used file
# 	  will be moved to the ./domains/program/Unused directory.
# 
proc Sepct_Customize::change_module_status { cb } {
	variable list_b
	variable notebook
	variable curr_TE_file
	
	# Do nothing if we're in read-only mode
	if { [Sepct::inReadOnlyMode] } {
		# in read-only case, just toggle the state
		# back to its previous state, the command will
		# do nothing in this case
		$cb toggle
		return 0
	}
	
	# Get the rootname of the module, which has been embedded into the pathname of the 
	# checkbutton widget by using the split character.
	set splitPath [split $cb ":"]
	# Get the index of the last element from splitPath, which is the rootname portion.
	set module "[lindex $splitPath end].te"
	
	if { $Sepct_Customize::cb_value_array($module) } {
		set source_Path [file join $Sepct_Customize::unUsed_Modules_Dir $module]
		set target_Path	[file join $Sepct_Customize::used_Modules_Dir $module]
		set rt [Sepct_Customize::set_Module_As_Used $module $source_Path $target_Path]
	} else {
		set source_Path [file join $Sepct_Customize::used_Modules_Dir $module]
		set target_Path	[file join $Sepct_Customize::unUsed_Modules_Dir $module]
		set rt [Sepct_Customize::set_Module_As_Unused $module $source_Path $target_Path]
	}
    	    	
    	if { $rt == 0 } {
	    	set raisedPage [$notebook raise]
	    	# Need to update the status bar if the current selection is the current module
		if { $raisedPage == $Sepct_Customize::te_tabID && [$list_b selection get] == $module } {
			set curr_TE_file $target_Path
	    		Sepct::update_fileStatus $curr_TE_file 0
	    	} 
    	}
    	
	return 0
}

###############################################################################
# ::order_Modules_by_Description
#	-
# 
proc Sepct_Customize::order_Modules_by_Description { module_List } {  
	set desc_Labels_List ""
		
	foreach module $module_List {
		lappend desc_Labels_List "{[Sepct_Customize::get_mod_descp_label $module]} {$module}"
	}
	set desc_Labels_List [lsort -dictionary $desc_Labels_List]
	
	set module_List ""
	foreach module $desc_Labels_List {
		lappend module_List [lindex $module end]
	}
	
	return $module_List
}
	
###############################################################################
# ::change_Module_Labels
#	-
# 
proc Sepct_Customize::change_Module_Labels { } {  
    	variable list_b
    	variable curr_TE_file
    	    	
    	# Get the current selection 
    	set curr_sel [$list_b selection get]  
    	
    	# Get all items from the listbox
    	set module_List [$list_b items]
    	
    	# If the show Filenames checkbutton is ON, then use the filename as the label.
    	if { $Sepct_Customize::show_Filenames == 1 } {	
		foreach module $module_List {
			$list_b itemconfigure $module -text "  $module"
		}
		
		# Sort the items and then reorder according to the sorted list.
		set module_List [lsort -dictionary $module_List]
		$list_b reorder $module_List
	} else {
		foreach module $module_List {
			$list_b itemconfigure [lindex $module end] -text " [Sepct_Customize::get_mod_descp_label $module]"
		}
				
		set module_List [Sepct_Customize::order_Modules_by_Description $module_List]
				
		# Reorder according to our local items list.
		$list_b reorder $module_List
	}
	$list_b configure -redraw 1
	
	# Reset the selection to the previous one
    	if { [$list_b exists $curr_sel] } {
	    	$list_b selection set $curr_sel
	    	$list_b see $curr_sel 
	} 
	
    	# Adjust the view so that no part of the canvas is off-screen to the left.
    	# Finally, we display updates immediately.
    	$list_b.c xview moveto 0
    	update idletasks
    	
	return 0	
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Sepct_Customize::goto_line { line_num } {
	variable text_te
	variable text_fc
	variable curr_TE_file
	variable curr_FC_file
	variable notebook
	
	if { $curr_TE_file == "" } {
		return 0
	}
	if {[string is integer -strict $line_num] != 1 || [string is digit -strict $line_num] != 1 || [regexp "\[A-Z\]" $line_num]} {
		tk_messageBox -icon error \
			-type ok  \
			-title "Invalid line number" \
			-message "$line_num is not a valid line number"
		return 0
	}
	set raisedPage [$notebook raise]
	if { $raisedPage == $Sepct_Customize::te_tabID } {
    		set text_c $text_te
    		set curr_file $curr_TE_file
    	} elseif { $raisedPage == $Sepct_Customize::fc_tabID } {
    		if { $curr_FC_file == "" } {
			return 0
		}
    		set text_c $text_fc
    		set curr_file $curr_FC_file
    	} else {
    		return 0
    	}
	
	$text_c mark set insert ${line_num}.0 
	Sepct_db::update_pos $curr_file ${line_num}.0
	$text_c see ${line_num}.0 
	focus -force $text_c
	return 0
}

############################################################################
# ::leave_Tab
#  	- called when Test tab is raised and about to be left
#
proc Sepct_Customize::leave_Tab { } {
	Sepct_Customize::record_outstanding_changes
	return 0
}

############################################################################
# ::enter_Tab
#  	- called when Customize tab is about to be raised
#
proc Sepct_Customize::enter_Tab { } {
	variable list_b
	variable curr_TE_file		
	variable curr_FC_file	
	variable text_te_dBit				
	variable text_fc_dBit			
	variable text_te_mcntr			
	variable text_fc_mcntr	
	variable text_te
	variable text_fc
	variable notebook

	if { [Sepct::isPolicyOpened] } {
		if { ![Sepct::inReadOnlyMode] } {	
			$Sepct::mainframe setmenustate ModEditTag normal
		}
		$Sepct::mainframe setmenustate SaveFileTag normal
		$Sepct::mainframe setmenustate RevertTag normal
		$Sepct::mainframe setmenustate SaveFileAsTag disabled
		$Sepct::mainframe setmenustate ConfigTag normal
	}
    	
    	# Display updates immediately and set the focus to the the raised text widget.
    	set raisedPage [$notebook raise]
    	if { $raisedPage == $Sepct_Customize::te_tabID } {
    		focus $text_te
    	} elseif { $raisedPage == $Sepct_Customize::fc_tabID } {
    		focus $text_fc
    	} else {
    		return
    	}
    	
    	if { $curr_TE_file != "" } {
    		set updated 0
    		set te_cntr [Sepct_db::get_cntr $curr_TE_file]
    		if { $curr_FC_file != "" } {
    			set fc_cntr [Sepct_db::get_cntr $curr_FC_file]
    		}
		if { $te_cntr != $text_te_mcntr || ($curr_FC_file != "" && ($fc_cntr != $text_fc_mcntr))} {
			# reset curr_file to fool displayFile
			set fn $curr_TE_file
			set curr_TE_file ""
    			set rt [Sepct_Customize::displayModule $list_b $text_te $text_fc [file tail $fn]]
    			if {$rt != 0} {
    				return $rt
    			}
    			set updated 1
	    	} 
		
    		# Update status bar info based upon the currently raised tab.
		if { $raisedPage == $Sepct_Customize::te_tabID } {
	    		Sepct::update_fileStatus $curr_TE_file 1
	    	} else {
			if { $curr_FC_file != "" } {
				Sepct::update_fileStatus $curr_FC_file 1 
			} else {
				Sepct_Customize::remove_modIndicator $raisedPage
				Sepct::clear_fileStatus
			}
	    	}
	} else {
		# no file current opened
		$text_te delete 0.0 end
		$text_fc delete 0.0 end
		Sepct::clear_fileStatus
		Sepct_Customize::reset_dirtyState
	}	
	
	
	return 0
}

##############################################################
# ::display_add_Dialog
#  	- display_add_Dialog 
# 
proc Sepct_Customize::display_add_Module_Dlg {} {
	variable add_Module_Dlg 
	global tcl_platform
	
	set Sepct_Customize::newModuleName  	""
	set Sepct_Customize::module_Desc 	""
			
	# Checking to see if add_Module_Dlg already exists. If so, it is destroyed.
    	if { [winfo exists .add_Module_Dlg] } {
    		destroy .add_Module_Dlg
    	}
    	
    	set add_Module_Dlg [Dialog .add_Module_Dlg -parent $Sepct::mainWindow \
    		-title "Add Policy Module" -side right]
    		
    	if {$tcl_platform(platform) == "windows"} {
		wm resizable $Sepct_Customize::::add_Module_Dlg 0 0
	} else {
		bind $Sepct_Customize::::add_Module_Dlg <Configure> { wm geometry $Sepct_Customize::::add_Module_Dlg {} }
	}
	
    	set l_frame 	[frame $add_Module_Dlg.left -relief flat] 
    	set r_frame 	[frame $add_Module_Dlg.right -relief flat] 
    	set lbl_fName  	[label $l_frame.lbl_fName -text "Module Name:"]
    	set lbl_desc  	[label $l_frame.lbl_desc -text "Module Description:"]
    	set name_Entry 	[Entry $r_frame.name_Entry  -textvariable Sepct_Customize::newModuleName -width 40 \
		    		-helptext "Enter a name for the module to be added." -bg white]
	set desc_Entry 	[Entry $r_frame.desc_Entry  -textvariable Sepct_Customize::module_Desc -width 40 \
		    		-helptext "Enter a description for the module to be added." -bg white]
		    	
	pack $l_frame $r_frame -side left -anchor center -fill both -expand yes
	pack $lbl_fName $lbl_desc -side top -padx 5 -pady 5 -anchor ne
	pack $name_Entry $desc_Entry -side top -padx 5 -pady 5 -anchor ne
	focus -force $name_Entry
	
	$add_Module_Dlg add -text "OK" -width 6 -command {set Sepct_Customize::add_Module_Flag 1; $Sepct_Customize::add_Module_Dlg enddialog 1} 		
	$add_Module_Dlg add -text "Cancel" -width 6 -command {set Sepct_Customize::add_Module_Flag 0; $Sepct_Customize::add_Module_Dlg enddialog 0}
	$add_Module_Dlg draw  
			
	return 0
}

############################################################################
# ::switch_internal_tabs
#  	- called when internal tabs are changed
#
proc Sepct_Customize::switch_internal_tabs { tabID } {
	variable fc_tabID
	variable te_tabID
	variable text_te
	variable text_fc		
	
	set tabID [Sepct::get_tabname $tabID]
	if { $tabID == $te_tabID } {
		focus $text_te
		set file_displayed $Sepct_Customize::curr_TE_file
	} elseif { $tabID == $fc_tabID } {
		focus $text_fc
		set file_displayed $Sepct_Customize::curr_FC_file
	} 
	
	if { $file_displayed != "" } {
		Sepct::update_fileStatus $file_displayed 1 
	} else {
		 Sepct::clear_fileStatus
	}
		
	return 0
}

##################################################################
# ::wrap_proc_te
#  	- This overrides the default cmds
#		for text so we can track dirty bit
# NOTE: This proc MUST have same name as $text_wrap_prob var; it will
# be renamed in create
proc Sepct_Customize::wrap_proc_te { cmd args } {
	if { $Sepct_Customize::curr_TE_file != "" } {
		switch $cmd {
			insert	-
			delete	{ 
				if { [Sepct::inReadOnlyMode] } {
					return 0
				} else {
					if { $Sepct_Customize::text_te_dBit == 0 }  {
						Sepct_Customize::set_modIndicator $Sepct_Customize::te_tabID
						set Sepct_Customize::text_te_dBit 1
					}
					Sepct::update_positionStatus [$Sepct_Customize::text_te index insert]
					}
				}
			mark {
				if { [string compare -length 10 $args "set insert"]  == 0 } {
					# in this case, go ahead and directly call the upleve cmd so that
					# the insertion mark is set, allowing us to determine its location.
					# Because we call uplevel, we MUST return from this case.
					uplevel "::${Sepct_Customize::text_te}_" $cmd $args
					Sepct::update_positionStatus [$Sepct_Customize::text_te index insert]
					return
				}
			}
		}
	}
	uplevel "::${Sepct_Customize::text_te}_" $cmd $args
}

##################################################################
# ::wrap_proc_fc
#  	- This overrides the default cmds
#		for text so we can track dirty bit
# NOTE: This proc MUST have same name as $text_wrap_prob var; it will
# be renamed in create
proc Sepct_Customize::wrap_proc_fc { cmd args } {
	if { $Sepct_Customize::curr_FC_file != "" } {
		switch $cmd {
			insert	-
			delete	{ 
				if { [Sepct::inReadOnlyMode] } {
					return 0
				} else {
					if { $Sepct_Customize::text_fc_dBit == 0 }  {
						Sepct_Customize::set_modIndicator $Sepct_Customize::fc_tabID
						set Sepct_Customize::text_fc_dBit 1
					}
					Sepct::update_positionStatus [$Sepct_Customize::text_fc index insert]
					}
				}
			mark {
				if { [string compare -length 10 $args "set insert"]  == 0 } {
					# in this case, go ahead and directly call the upleve cmd so that
					# the insertion mark is set, allowing us to determine its location.
					# Because we call uplevel, we MUST return from this case.
					uplevel "::${Sepct_Customize::text_fc}_" $cmd $args
					Sepct::update_positionStatus [$Sepct_Customize::text_fc index insert]
					return
				}
			}
		}
	}
	uplevel "::${Sepct_Customize::text_fc}_" $cmd $args
}

##############################################################
# ::createNoteBook
#  	- Creates the notebook widget and all related widgets.
#
proc Sepct_Customize::createNoteBook { tabsBox } {
	variable text_te
	variable text_fc
	variable notebook
	variable te_tabName
	variable fc_tabName
	variable te_tabID			
	variable fc_tabID			
	
	set notebook [NoteBook $tabsBox.nb -side top]
	set c_frame [$notebook insert end $te_tabID -text $te_tabName]
	set fc_frame [$notebook insert end $fc_tabID -text $fc_tabName]
	
	# Trying to HACK into the -container option for the frame of the notebook page in order
	# to possibly embed a XEmacs editor inside the frame to perform text editing. However,
	# currently not able to modify this option after a tab is inserted. 
	set f [frame $c_frame.fc -container 1]
	pack $f
	
	# a) pack [frame .foo -container true]
	# b) winfo id .foo
	# c) pass the hex return code into C and use it as an X window
	# identifier (bypassing XCreateWindow) and draw away. 
	# xterms generate a WM_COMMAND property which is the
	# application's command line.Many applications don't supply a WM_COMMAND property.  
	# But you may be able to use their WM_NAME property.
	#exec xterm -name  
	
	# TE file contents tab widgets.
	set sw_c [ScrolledWindow $c_frame.sw_c -auto none]
	set text_te [text [$sw_c getframe].text -bg white -wrap none -font $Sepct::text_font]
	$sw_c setwidget $text_te
	rename $text_te "::${text_te}_"
	rename $Sepct_Customize::text_TE_wrap_proc "::$text_te"
	
	# FC file contents tab widgets.
	set sw_fc [ScrolledWindow $fc_frame.sw_fc -auto none]
	set text_fc [text [$sw_fc getframe].text -bg white -wrap none -font $Sepct::text_font]
	$sw_fc setwidget $text_fc
	rename $text_fc "::${text_fc}_"
	rename $Sepct_Customize::text_FC_wrap_proc "::$text_fc"
	
	# Placing display widgets
	pack $sw_c -side left -expand yes -fill both  
	pack $sw_fc -side left -expand yes -fill both
	
	$notebook bindtabs <Button-1> { Sepct_Customize::switch_internal_tabs }
	$notebook compute_size
	pack $notebook -fill both -expand yes -padx 4 -pady 4
	$notebook raise [$notebook page 0]
	
	return 0
}

###################################################################
# ::create
#  	- Creates all major widgets and frames.
# 
proc Sepct_Customize::create { nb } {
	variable list_b
	#    variable listbox_popupMenu
	variable cb_show_Filenames
	
	# Layout frames
	set frame [$nb insert end $Sepct::customize_tab -text "Policy Modules"]
	set topf  [frame $frame.topf -width 100 -height 200]
	
	# Paned Windows
	set pw1   [PanedWindow $topf.pw -side top]
	set pane  [$pw1 add -weight 2]
	set spane [$pw1 add -weight 4]
	set pw2   [PanedWindow $pane.pw -side left]
	set contents [$pw2 add -weight 2]
	
	# Major subframes
	set tabsBox 	[frame $spane.tabsBox]
	set contentsBox 	[TitleFrame $contents.cbox -text "Program Policy Modules"]
	
	# Placing layout frames and major subframes
	pack $tabsBox -pady 2 -padx 2 -fill both -expand yes -anchor ne 
	pack $contentsBox -padx 2 -side left -fill both -expand yes
	
	pack $pw1 -fill both -expand yes
	pack $pw2 -fill both -expand yes	
	pack $topf -fill both -expand yes 
	  
	# Policy contents listbox
	set sw_list [ScrolledWindow [$contentsBox getframe].sw_c -auto none]
	set list_b [ListBox [$contentsBox getframe].lb \
	          -relief flat -borderwidth 0 -bg white \
	          -selectmode single -deltay 25 \
	          -width 20 -highlightthickness 0 \
	          -redraw 0 -padx 25]
	$sw_list setwidget $list_b
	
	set cb_show_Filenames [checkbutton [$contentsBox getframe].cb_showf \
		-text "Display File Names Only" \
		-command { Sepct_Customize::change_Module_Labels } \
		-variable Sepct_Customize::show_Filenames]
	
	# Placing listbox and checkbutton
	pack $sw_list -fill both -expand yes 
	pack $cb_show_Filenames -anchor nw -side bottom -pady 1
	
	# NoteBook creation
	Sepct_Customize::createNoteBook $tabsBox
	
	# Bindings
	$list_b bindText  <ButtonPress-1>        { Sepct_Customize::displayModule $Sepct_Customize::list_b $Sepct_Customize::text_te $Sepct_Customize::text_fc}
	$list_b bindText  <Double-ButtonPress-1> { Sepct_Customize::displayModule $Sepct_Customize::list_b $Sepct_Customize::text_te $Sepct_Customize::text_fc}
	
	# Initialize tab variables
	Sepct_Customize::initialize_Tab_Vars
	
	# Set up global defaults
	set Sepct_Customize::show_Filenames $Sepct::show_customize_file_names
	
	return $frame
}

##############################################################
#							     #
# 		Utility functions			     #
##############################################################

############################################################################
# ::delete_Module
# 
proc Sepct_Customize::delete_Module { } {	
	variable notebook
	variable list_b	
	variable curr_TE_file
	variable curr_FC_file
	variable fc_extension
	variable unUsed_Modules			
	variable used_Modules			
	variable all_Modules
	variable missing_fc_files
	

	# Check to see if there is a current selection. If not, simply return.
	if { $curr_TE_file != "" } {	
		set rt [tk_messageBox -icon warning -type yesno -title "Warning!" \
			-message "About to delete a module.\n\nIt is recommended that you\
				DISABLE the module instead by deselecting the checkbutton\
				next to the module in the listbox.\n\nWould you still like\
				to continue?"]
				
		if { $rt == "yes" } {
			set rt [tk_messageBox -icon warning -type yesno -title "Warning!" \
				-message "Deleting $curr_TE_file and $curr_FC_file.\n\n\
				Are you sure you want to continue?"]
			
			if { $rt == "yes" } {
				# Delete te file from disk and update necessary objects
				set rt [catch {file delete $curr_TE_file} err]
				if { $rt != 0 } {
					tk_messageBox -icon error -type ok -title "Error" \
						-message "$err"
					return -1 
				}
				# Update internal module lists	 			
				Sepct_Customize::remove_From_All_Module_Lists [file tail $curr_TE_file]
			    	
			    	# Update our internal tree database to have these changes.
				set rt [Sepct_db::remove_from_mod_List $curr_TE_file ]
			    	if { $rt == -1 } {
			    		tk_messageBox -icon error -type ok -title "Error" \
						-message "Error removing module TE file from internal mod list."			
				}
			    	set rt [Sepct_db::remove_file $curr_TE_file]
			    	if { $rt == -1 } {
			    		tk_messageBox -icon error -type ok -title "Error" \
						-message "Error removing module TE file from internal database."			
				}
								
				# Must destroy the embedded checkbutton explicitly.
				set cb [$list_b itemcget [file tail $curr_TE_file] -window]
		    		if { [winfo exists $cb] } {
					set rt [catch {destroy $cb} err]
					if {$rt != 0} {
						tk_messageBox -icon error -type ok -title "Error" \
							-message "$err"
						return -1
					}
				}
				# Delete the item from the listbox and then delete any text in the text widget.
				$list_b delete [file tail $curr_TE_file]
				$Sepct_Customize::text_te delete 0.0 end
					
					
				# Now remove the assoicated FC file if it exists			
				if { $curr_FC_file != "" } {
					# Next delete fc file from disk and update necessary objects.
					set rt [catch {file delete $curr_FC_file} err]
					if { $rt != 0 } {
						tk_messageBox -icon error -type ok -title "Error" \
							-message "$err"				
					}
					
					# At this point, since the associated te file is now gone, simply need to 
					# discard all references to the fc file.
					set missing_fc_files [Sepct_Customize::remove_Module_from_List $missing_fc_files $curr_FC_file]
					# Update our internal database to have these changes.
					set rt [Sepct_db::remove_from_mod_List $curr_TE_file ]
				    	if { $rt == -1 } {
				    		tk_messageBox -icon error -type ok -title "Error" \
							-message "Error removing module FC from internal mod list."			
					}
				    	set rt [Sepct_db::remove_file $curr_FC_file]
				    	if { $rt == -1 } {
				    		tk_messageBox -icon error -type ok -title "Error" \
							-message "Error removing module FC file from internal database."			
					}

				}
				$Sepct_Customize::text_fc delete 0.0 end

				# reset dirty bits 
				Sepct_Customize::reset_dirtyState
				set curr_TE_file ""
				set curr_FC_file ""
				# Clear the status bar
				Sepct::clear_fileStatus
				# Remove mod indicators from tabs
				Sepct_Customize::remove_modIndicator $Sepct_Customize::te_tabID
				Sepct_Customize::remove_modIndicator $Sepct_Customize::fc_tabID
			}
		} 
	}
	
	return 0
}

############################################################################
# ::add_Module
# 
proc Sepct_Customize::add_Module { } {   
	variable list_b
	variable used_Modules 
	variable all_Modules			
	variable text_te_mcntr			
	variable text_fc_mcntr			
	variable fc_path
	variable newModuleName
	variable module_Desc
	variable text_te
	variable text_fc

	
	# Display the dialog for adding a new module.
	Sepct_Customize::display_add_Module_Dlg

	if { $Sepct_Customize::add_Module_Flag } {
		# Perform validation for the new module name.
		while { $newModuleName == "" } {
			tk_messageBox -icon error -type ok -title "Error" \
			     -message "Module name cannot be empty."
			Sepct_Customize::add_Module
			return -1
		}
		
		if { $newModuleName != "" } {
			# Check the length of the specified file name.
			while { [string length $newModuleName] > $Sepct_Customize::max_Label_Length } {
				tk_messageBox -icon error -type ok -title "Error" \
			     		-message "Module name cannot contain more than 255 characters."
			     	Sepct_Customize::add_Module
			     	return -1
			} 
			
			set rootName [file rootname $newModuleName]		
			while { [string is digit $rootName] || [string is punct $rootName] || [string is space $rootName] } {
				tk_messageBox -icon error -type ok -title "Error" \
			     		-message "Module root name cannot be a digit, punctuation or space."
			     	Sepct_Customize::add_Module
			     	return -1
			} 
						
			# Make sure that the string is a valid Unicode word character.
			while { [string is wordchar $rootName] == 0 } {
				tk_messageBox -icon error -type ok -title "Error" \
			     		-message "Module root name can only contain alphanumeric characters\
			     		 and any Unicode connector punctuation characters."
			     	Sepct_Customize::add_Module
			     	return -1
			} 
			
			# Make sure that the specified file has an extension.
			if { [file extension $newModuleName] == "" } {
				append newModuleName ".te"
			} else {					
				# Make sure that the user specifies the APPROPRIATE extension.
				while { [file extension $newModuleName] != ".te" } {
					tk_messageBox -icon error -type ok -title "Error" \
				     		-message "The given file extension is incorrect. Must be .te"
				     	Sepct_Customize::add_Module
				     	return -1
				}
			}
	        }
	        
	        # At this point, the given new module name has passed validation. Now, set description info.							
		set module_Desc    [string trim $module_Desc]
		# If there was no description specified, then just use the file name.
		if { $module_Desc == "" } {
			set module_Desc $newModuleName
		} 
		# Use this standard header information as the initial data for the file.
		set data "#DESC $module_Desc\n#\n# File: $newModuleName\n# Author(s):\n#\n"
		
		set newModulePath  [file join $Sepct_Customize::used_Modules_Dir $newModuleName]
		# If the file DOES NOT exist on disk., then create it along with its' .fc file.
		if { [file exists $newModulePath] == 0 } {
			# Save file to disk
			set rt 	[Sepct_db::file_write $data $newModulePath]
							
			# If the file saved correctly, then continue
			if { $rt == 0 } {
				# Add the new module to used_Modules and all_Modules lists.
				# During an add, we set the module status to be used. The user can choose to
				# set it to unused later.
				set used_Modules [Sepct_Customize::add_Module_to_List $used_Modules $newModuleName]
				set all_Modules  [Sepct_Customize::add_Module_to_List $all_Modules $newModuleName]
				
				# Get the parent dir for the new module and verify that it exists in the db.
				set parent [file dirname $newModulePath]
				# add new module to our database
				if {[Sepct_db::existsTree_node $parent] } {
					set cntr [Sepct_db::add_file $newModulePath 0 "1.0"] 
					if { $cntr == -1 } {
						return -1
					}
					set text_te_mcntr $cntr
				} else {
					# The parent directory $parent does not exist in the db
					puts stderr "Problem, The parent directory $parent does not exist in the db!"
					return -1
				}
								
				# Now create the associated FC file
				set fcpath 	[file join $Sepct_Customize::fc_path "[file rootname $newModuleName].fc"]
				set fc_data  	"#DESC $module_Desc\n#\n# File: [file tail $fcpath]\n# Author(s):\n#\n"
				
				# Create the new FC file if it doesn't already exist on disk.
				if { [file exists $fcpath] == 0 } {
					# Save the FC data to disk.
					set rt 	[Sepct_db::file_write $fc_data $fcpath]	
					
					# If the file saved correctly, then continue
					if { $rt == 0 } {
						set parent [file dirname $fcpath]
						# add new file to our database
						if {[Sepct_db::existsTree_node $parent] } {
							# Do not need to send the position. Will default to 1.0
							set cntr [Sepct_db::add_file $fcpath 0 "1.0"] 
							if { $cntr == -1 } {
								return -1
							}
							set text_fc_mcntr $cntr
						} else {
							# The parent directory $parent does not exist in the db
							puts stderr "Problem, The parent directory $parent does not exist in the db!"
							return -1
						}
					}
				} else {
					tk_messageBox -icon info  \
						-type ok \
						-parent $Sepct::mainWindow \
						-title "File Exists" \
						-message \
						"$fcpath already exists."
				}
				
				# Insert item into listbox and a checkbox at the left of the label of the item.
				# The module is set to used(1) as the default. User can change this later
				# by deselecting the checkbutton next to the module in the listbox.
				$list_b insert end $newModuleName \
				 	 -data $module_Desc \
				 	 -window [Sepct_Customize::embed_checkbutton $newModuleName 1]  
		 	 
				# Reorder the listbox					
				Sepct_Customize::label_and_order_list
			
				# Adjust the view so that no part of the canvas is off-screen to the left.
			    	# Finally, we display updates immediately.
				$list_b configure -redraw 1
			    	$list_b.c xview moveto 0
				update idletasks
				
				# Make sure that the newly created file is now in the list.If so, then display the new module.
				if { [$list_b exists $newModuleName] } {
					$list_b see $newModuleName
					Sepct_Customize::displayModule $list_b $text_te $text_fc $newModuleName
				} else {
					set ans [tk_messageBox \
					     -icon error \
					     -type ok \
					     -title "Error" \
					     -message \
						"After updating the listbox, an error occurred\
						while trying to locate the new module $newModuleName in the listbox.\n\
						Press YES to re-load the policy directory or NO to continue."]
					
					if {$ans == "yes" } {
						Sepct::reloadPolicy
					} 
				}
			}
		} else { 
			tk_messageBox \
			     -icon error \
			     -type ok \
			     -parent $Sepct::mainWindow \
			     -title "Error" \
			     -message \
				"$newModuleName already exists."
		}		
	}
	
	return 0
}

############################################################################
# ::is_module_used
#  	returns  1 if used,  0 if not used or error
# 
proc Sepct_Customize::is_module_used { mod_name } {
	variable used_Modules
	
	if {[lsearch -exact $used_Modules $mod_name] < 0 } {
		return 0
	} else {
		return 1
	}
}

###########################################################################################
# ::get_mod_descp_label
#	- This method gets descriptive labels for a module 
# 
proc Sepct_Customize::get_mod_descp_label { te_file } {
	variable list_b
    
	if {![$list_b exists $te_file]} {
		return -1
	}
	set idx [$list_b index $te_file]
	set label [$list_b itemcget $te_file -data]
		  
	return $label
}

###############################################################################
# ::insert_Data
#	- inserts data into text boxes for TE Rules and File Context tabs, 
#	  checking for changes. Needs pageID for tab
# 
proc Sepct_Customize::insert_Data { path textBox line col tabID } {
	# If the file is in our mod_FileArray, then we simply insert 
	# the data from the mod_FileArray. 
	if { [Sepct_db::is_in_mod_FileArray $path] } {
		$textBox delete 0.0 end
		if {[Sepct_db::getModFile_Data $path data] != 0 } {
			puts stderr "Problem with getting file ($path) data in insert_Data"
			return -1
		}
		$textBox insert end $data
		# Add the mod indicator to the notebook tab.
		Sepct_Customize::set_modIndicator $tabID
	} else {
		# If the file has not been modified, then insert the data from disk.
    		if { [Sepct_db::read_fileContents_fromDisk $path data] != 0 } {
    			puts stderr "Problem reading file ($path) from disk."
    			return -1
    		}
		$textBox insert end $data
		Sepct_Customize::remove_modIndicator $tabID

	}
        
        # Set the focus and the mark.
	focus -force $textBox
	$textBox mark set insert $line.$col 
	$textBox see $line.$col 
		
	return 0	
}

############################################################################
# ::save_as
# 	- TODO: No completely implemented; for now save_as is not enabled
#		for this tab abyway, so we'll just return
proc Sepct_Customize::save_as { } {
	variable curr_TE_file		
	variable curr_FC_file	
	variable text_te_dBit				
	variable text_fc_dBit			
	variable text_te_mcntr			
	variable text_fc_mcntr	
	variable text_te
	variable text_fc
	variable notebook	
	
	# TODO: for now just return....no save as for this tab
	return 0
	
	set raisedPage [$notebook raise]
	if { $raisedPage == $Sepct_Customize::te_tabID } {
    		set curr_file $curr_TE_file
    		set text_c $text_te
    		set text_mcntr $text_te_mcntr
    	} elseif { $raisedPage == $Sepct_Customize::fc_tabID } {
    		set curr_file $curr_FC_file
    		set text_c $text_fc
    		set text_mcntr $text_fc_mcntr
    	}
    	
	if { $curr_file != "" } {
		set fileExt [file extension $curr_file]
		set types {
			{"All files"		*}
    		}
		set filename [tk_getSaveFile -initialdir $Sepct::policyDir \
			-title "Save As?" -filetypes $types]
		
		# If the filename is the same, this means we just simply save the current file.
		if { [string equal $filename $curr_file] } {	
			return [Sepct_Customize::save]
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
  
  			# indicate that current file has changed
			set curr_file $filename				
			Sepct::update_fileStatus $filename	
			Sepct_Customize::remove_modIndicator $raisedPage
			Sepct_Customize::reset_dirtyState
			
			# TODO: Handle adding to tree database and/or our list db.
		}	
	}
	
	return 0
}

############################################################################
# ::save_policy_configuration
#	- 
# 
proc Sepct_Customize::save_Configuration {filename} {			
	# .te files in ./domains/program
	variable unUsed_Modules			
	# .te files in ./domains/program/unused
	variable used_Modules		

	Sepct::writeConfigFile $filename $used_Modules $unUsed_Modules			
	return 0
}

############################################################################
# ::load_policy_configuration
#	- 
# 
proc Sepct_Customize::load_policy_configuration {used_Mods unUsed_Mods} {
	variable used_Modules_Dir	
	variable unUsed_Modules_Dir
	
	foreach used_Mod $used_Mods {
		set source_Path [file join $unUsed_Modules_Dir $used_Mod]
		set target_Path	[file join $used_Modules_Dir $used_Mod]
		if { [file exists $source_Path] } {
			set rt [Sepct_Customize::set_Module_As_Used $used_Mod $source_Path $target_Path]
			if {[array get Sepct_Customize::cb_value_array "$used_Mod"] != ""} {
				set Sepct_Customize::cb_value_array($used_Mod) 1
			}
		} elseif {[file exists $target_Path] == 0} {
			puts "$used_Mod does not exist in $used_Modules_Dir or $unUsed_Modules_Dir and will be ignored."
		}
	}
	foreach unUsed_Mod $unUsed_Mods {
		set source_Path [file join $used_Modules_Dir $unUsed_Mod]
		set target_Path	[file join $unUsed_Modules_Dir $unUsed_Mod]
		if { [file exists $source_Path] } {
			set rt [Sepct_Customize::set_Module_As_Unused $unUsed_Mod $source_Path $target_Path]
			if {[array get Sepct_Customize::cb_value_array "$unUsed_Mod"] != ""} {
				set Sepct_Customize::cb_value_array($unUsed_Mod) 0
			}
		} elseif {[file exists $target_Path] == 0} {
			puts "$used_Mod does not exist in $used_Modules_Dir or $unUsed_Modules_Dir and will be ignored."
		}
	}
	return 0
}

############################################################################
# ::is_in_modules_list
#	- 
# 
proc Sepct_Customize::is_in_modules_list {mod_name} {
	variable all_Modules
	
	set idx [lsearch -exact $all_Modules $mod_name]
	if {$idx != -1} {
		return 1
	}
	return 0
}

############################################################################
# ::get_num_mods
#	- 
# 
proc Sepct_Customize::get_num_mods {} {
	variable all_Modules
	return [llength $all_Modules]
}

############################################################################
# ::save
# 
proc Sepct_Customize::save { } {
	variable curr_TE_file		
	variable curr_FC_file	
	variable text_te_dBit				
	variable text_fc_dBit			
	variable text_te_mcntr			
	variable text_fc_mcntr	
	variable text_te
	variable text_fc
	variable notebook
	
	if { $curr_TE_file == "" } {
		return 0
	} else {
		if { $text_te_dBit } {
			# Need to flush out the current text window to the mod list
			set cntr [Sepct_db::add_to_mod_List $curr_TE_file [$text_te get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
			set mod 1
			
		} else {
			set mod [Sepct_db::is_in_mod_FileArray $curr_TE_file]
		}
		# Now save the file if modified
		if {$mod} {
			set cntr [Sepct_db::saveFile $curr_TE_file [$text_te index insert]]
			if {$cntr == -1 } {
				return -1
			}
			set text_te_mcntr $cntr
			Sepct_Customize::remove_modIndicator $Sepct_Customize::te_tabID
		} 
	}
	
	if { $curr_FC_file != "" } {
		if { $text_fc_dBit } {
			# Need to flush out the current text window to the mod list
			set cntr [Sepct_db::add_to_mod_List $curr_FC_file [$text_fc get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
			set mod 1
			
		} else {
			set mod [Sepct_db::is_in_mod_FileArray $curr_FC_file]
		}
		# Now save the file if modified
		if {$mod} {
			set cntr [Sepct_db::saveFile $curr_FC_file [$text_fc index insert]]
			if {$cntr == -1 } {
				return -1
			}
			set text_te_mcntr $cntr
			Sepct_Customize::remove_modIndicator $Sepct_Customize::fc_tabID
		} 
	}
		
	Sepct_Customize::reset_dirtyState
	set raisedPage [$notebook raise]
	if { $raisedPage == $Sepct_Customize::te_tabID } {
    		Sepct::update_fileStatus $curr_TE_file 1
    	} elseif { $raisedPage == $Sepct_Customize::fc_tabID } {
    		Sepct::update_fileStatus $curr_FC_file 1
    	}
	
	return 0
}

############################################################################
# ::revert_file
# 
proc Sepct_Customize::revert_file { } {
	variable curr_TE_file		
	variable curr_FC_file				
	variable text_te_mcntr			
	variable text_fc_mcntr	
	variable list_b
	variable text_te
	variable text_fc
	variable notebook
	
	if { $curr_TE_file == "" } {
		return 0
	}
	
	# discard any changes
	set cntr [Sepct_db::discard_Single_File_Changes $curr_TE_file ]
	if { $cntr >= 0 } {
		# record the new counter
		set text_te_mcntr $cntr
	} elseif {$cntr == -1} {
		puts stderr "Problem displaying file in revert_file"
		return -1
	}
	# else is -2 which mean no changes needed to record
	
	if { $curr_FC_file != "" } {
		# discard any changes
		set cntr [Sepct_db::discard_Single_File_Changes $curr_FC_file ]
		if { $cntr >= 0 } {
			# record the new counter
			set text_fc_mcntr $cntr
		} elseif {$cntr == -1} {
			puts stderr "Problem displaying file in revert_file"
			return -1
		}
		# else is -2 which mean no changes needed to record
	}
	
	# redisplay file
	# reset curr_file to fool displayFile that a new file is selected
	set fn $curr_TE_file
	set curr_TE_file ""
	set rt [Sepct_Customize::displayModule $list_b $text_te $text_fc [file tail $fn]]

	return $rt
}

############################################################################
# ::close
#  	- functions to do on close
# 
proc Sepct_Customize::close { } {		
	variable list_b
	variable text_te
	variable text_fc
	
	# Delete all embedded checkbuttons in the listbox.
	set rt [Sepct_Customize::remove_CheckButtons]
	if {$rt != 0} {
		return -1
	}
	
	# Delete all listbox items and text widget contents
	$list_b delete [$list_b items]
	$text_te delete 0.0 end
	$text_fc delete 0.0 end
	
	# Re-initialize tab variables	
	Sepct_Customize::initialize_Tab_Vars
	
	Sepct_Customize::remove_modIndicator $Sepct_Customize::te_tabID
	Sepct_Customize::remove_modIndicator $Sepct_Customize::fc_tabID
	
	return 0
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Sepct_Customize::search { str case_Insensitive regExpr srch_Direction } {
	variable text_te
	variable text_fc
	variable notebook
	variable te_tabID		
	variable fc_tabID	
	
	set raisedPage [$notebook raise]
	
	if { $raisedPage == $te_tabID } {
		Sepct::textSearch $text_te $str $case_Insensitive $regExpr $srch_Direction
	} elseif { $raisedPage == $fc_tabID } {
		Sepct::textSearch $text_fc $str $case_Insensitive $regExpr $srch_Direction
	} else {
		return
	}
	
	return 0
}

########################################################################
# ::record_TE_outstanding_changes
#  	- makes sure any outstanding changes are sent to mod list
#	- return mod counter for curr_file, -1 for error, -2 if no changes occured
# 
proc Sepct_Customize::record_TE_outstanding_changes { } {
	variable curr_TE_file	
	variable text_te_dBit			
	variable text_te_mcntr	
	variable text_te
	
	if { $curr_TE_file != "" } {
		if { $text_te_dBit } {
			set cntr [Sepct_db::add_to_mod_List $curr_TE_file [$text_te get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
			
			set text_te_mcntr $cntr
			# we want to record position changes when we add to mod array
			Sepct_db::update_pos $curr_TE_file [$text_te index insert]
			return $cntr
		}
	}	
	
	# -2 means no changes
	return -2
}

########################################################################
# ::record_FC_outstanding_changes
#  	- makes sure any outstanding changes are sent to mod list
#	- return mod counter for curr_file, -1 for error, -2 if no changes occured
# 
proc Sepct_Customize::record_FC_outstanding_changes { } {		
	variable curr_FC_file				
	variable text_fc_dBit			
	variable text_fc_mcntr	
	variable text_fc
	
	if { $curr_FC_file != "" } {
		if { $text_fc_dBit } {
			set cntr [Sepct_db::add_to_mod_List $curr_FC_file [$text_fc get 0.0 end]]
			if { $cntr == -1 } {
				return -1
			}
			
			set text_fc_mcntr $cntr
			# we want to record position changes when we add to mod array
			Sepct_db::update_pos $curr_FC_file [$text_fc index insert]
			return $cntr
		}
	}
	
	# -2 means no changes
	return -2
}

############################################################################
# ::record_outstanding_changes
#  	- makes sure any outstanding changes are sent to mod list
#	- return mod counter for curr_file, -1 for error, -2 if no changes occured
#
proc Sepct_Customize::record_outstanding_changes { } {
	Sepct_Customize::record_TE_outstanding_changes
	Sepct_Customize::record_FC_outstanding_changes
	return 0
}

############################################################################
# ::create_unUsed_Modules_Dir
# 
proc Sepct_Customize::create_unUsed_Modules_Dir {} {
	# First, check to see if the unUsed directory exists. 
	if { [file exists $Sepct_Customize::used_Modules_Dir] } {
		set rt [catch {file mkdir $Sepct_Customize::unUsed_Modules_Dir} err]
		if {$rt != 0} {
			return -code error $err
		}
		set rt [Sepct_db::addTree_node $Sepct_Customize::unUsed_Modules_Dir 0 0]
		if {$rt != 0} {
			return -code error "Problem adding unused directory node in tree."
		}
	} else { 
		return -code error "$Sepct_Customize::used_Modules_Dir is not a directory"
	}	
		
	return 0
}

############################################################################
# ::move_file_on_disk
# 
proc Sepct_Customize::move_file_on_disk { source_Path target_dir overwrite } {
	if {$overwrite} {
		set rt [catch {file rename -force $source_Path $target_dir} err]
	} else {
		set rt [catch {file rename $source_Path $target_dir} err]
	}
	if { $rt != 0 } {
		return -code $err
	}
	return 0
}

############################################################################
# ::set_Module_As_Unused
# 
proc Sepct_Customize::set_Module_As_Unused { module source_Path target_Path } {
	variable list_b
	variable curr_TE_file
	
	set cb [$list_b itemcget $module -window]
	set overwrite 0		   	
	# Handle target path already existing.
	if { [file exists $target_Path] && ![file exists $source_Path]} {
		set ans [tk_messageBox -icon error -type yesno -title "File Error" -message \
				"File $target_Path already exists.\n\
				Press YES to re-load the policy directory \
				or NO to do nothing and continue."]
		if {$ans == "yes" } {
			Sepct::reloadPolicy
		} else {
			# Reset the check button to its' original state. 
			$cb toggle
		}
		return -1 
	} 
	
	# Check for duplicate modules	
	if { [file exists $target_Path] && [file exists $source_Path] } {
		set ans [tk_messageBox -icon error -type yesno -title "File Error" -message \
				"Duplicate $module modules exists.\n\n\
				Press YES to overwrite $target_Path with $source_Path or NO to do nothing and continue."]
		if {$ans != "yes" } {
			# Reset the check button to its' original state.
			$cb toggle
			return -1 
		} else {
			set overwrite 1
		}
	} 
	
	# Create the unused directory if necessary.
	if { ![file exists $Sepct_Customize::unUsed_Modules_Dir] } {
		set rt [catch {Sepct_Customize::create_unUsed_Modules_Dir} err]
		if { $rt != 0 } {
			tk_messageBox -icon error \
				-type ok \
				-title "Error" \
				-message \
				"Error creating unused modules directory: $err"
				
			# Reset the check button to its' original state.
			$cb toggle
			return -1
		}
	}
			
	set rt [catch {Sepct_Customize::move_file_on_disk $source_Path $Sepct_Customize::unUsed_Modules_Dir $overwrite} err]
	if { $rt != 0 } {
		tk_messageBox -icon error \
			-type ok \
			-title "Error" \
			-message \
			"Error moving $module: $err"
			
		# Reset the check button to its' original state.
		$cb toggle
		return -1
	}
	# Update the used_Modules and unUsed_Modules global list variables.
    	set rt [catch {Sepct_Customize::move_Module_to_Unused_List $module} err]
	if {$rt == -1} {
		set ans [tk_messageBox -icon error -type yesno -title "Error" -message \
				"Problem moving file to new tree node.\n\
				Press YES to re-load the policy directory\
				or NO to continue"]
				
		if { $ans == "yes" } {
			Sepct::reloadPolicy
			return -1
		} else {
			# Reset the check button to its' original state.
			$cb toggle	
		}
	}	    		
	return 0
}

############################################################################
# ::set_Module_As_Used
# 
proc Sepct_Customize::set_Module_As_Used { module source_Path target_Path } {
	variable list_b
	variable curr_TE_file
    	
    	set cb [$list_b itemcget $module -window]
    	set overwrite 0
    	# Handle target path already existing.
	if { [file exists $target_Path] && ![file exists $source_Path] } {
		set ans [tk_messageBox -icon error -type yesno -title "File Error" -message \
				"File $target_Path already exists.\n\
				Press YES to re-load the policy directory \
				or NO to do nothing and continue."]
		if {$ans == "yes" } {
			Sepct::reloadPolicy
		} else {
			# Reset the check button to its' original state. 
			$cb toggle
		}
		return -1 
	} 
	
	# Check for duplicate modules 
	if { [file exists $target_Path] && [file exists $source_Path] } {
		set overwrite 0	
		set ans [tk_messageBox -icon error -type yesno -title "File Error" -message \
				"Duplicate $module modules exists.\n\n\
				Press YES to overwrite $target_Path with $source_Path or NO to do nothing and continue."]
		if {$ans != "yes" } {
			# Reset the check button to its' original state.
			$cb toggle
			return -1 
		} else {
			set overwrite 1
		}
	} 

	# First, check to see if the used directory exists.
	# If so, then move the file to the unused directory.
	if { ![file exists $Sepct_Customize::used_Modules_Dir] } {
		tk_messageBox -icon error \
			-type ok \
			-title "Directory Problem" \
			-message \
			"The directory $Sepct_Customize::used_Modules_Dir\
			DOES NOT exist. Cannot move $source_Path to this directory."
			
		# Reset the check button to its' original state.
		$cb toggle
		return	
	} 
	
	set rt [catch {Sepct_Customize::move_file_on_disk $source_Path $Sepct_Customize::used_Modules_Dir $overwrite} err]
	if { $rt != 0 } {
		tk_messageBox -icon error \
			-type ok \
			-title "Error" \
			-message \
			"$err"
		
		# Reset the check button to its' original state.
		$cb toggle
		return -1
	}
	
	# Update the used_Modules and unUsed_Modules global list variables.
    	set rt [catch {Sepct_Customize::move_Module_to_Used_List $module} err]
        if { $rt == -1 } {
    		set ans [tk_messageBox -icon error -type yesno -title "Error" -message \
			"Problem moving file to new tree node.\n\
			Press YES to re-load the policy directory\
			or NO to continue"]
				
		if { $ans == "yes" } {
			Sepct::reloadPolicy
			return -1
		} else {
			# Reset the check button to its' original state.
			$cb toggle			
		}
	}	
	return 0
}

##############################################################
#							     #
# 		Internal data functions			     #
##############################################################

##############################################################
# ::initialize_Tab_Vars
#  	- Initialize tab variables.
#
proc Sepct_Customize::initialize_Tab_Vars {  } {
	set Sepct_Customize::text_te_dBit		0	
	set Sepct_Customize::text_fc_dBit		0
	set Sepct_Customize::text_te_mcntr		0
	set Sepct_Customize::text_fc_mcntr		0
	set Sepct_Customize::add_Module_Flag		0
	set Sepct_Customize::curr_TE_file		""
	set Sepct_Customize::curr_FC_file		""
	set Sepct_Customize::used_Modules_Dir 		""
	set Sepct_Customize::unUsed_Modules_Dir 	""
	set Sepct_Customize::fc_path 			""
	set Sepct_Customize::all_Modules 		""
	set Sepct_Customize::unUsed_Modules 		""
	set Sepct_Customize::used_Modules 		""
	set Sepct_Customize::missing_fc_files 		""
	set Sepct_Customize::cb_ID			""
	set Sepct_Customize::newModuleName		""
    	set Sepct_Customize::module_Desc		""
	array unset Sepct_Customize::cb_value_array
	
	return 0
}

##################################################################
# ::reset_dirtyState
#  	-
# 
proc Sepct_Customize::reset_dirtyState { } {
	variable text_te_dBit	
	variable text_fc_dBit
		    		
	set text_te_dBit 0
	set text_fc_dBit 0
	
	return 0
}

###################################################################
# ::get_all_Modules
#  	- Gets all used and un-used modules, 
#	 and sets assoicated global lists
# 
proc Sepct_Customize::get_all_Modules { } {
	variable used_Modules_Dir
	variable unUsed_Modules_Dir
	variable used_Modules 
	variable unUsed_Modules
	variable all_Modules

	# Get $used_Modules_Dir modules. 
	set used [Sepct_db::getFileNames $used_Modules_Dir]
	if { [llength $used] == 1 && $used == "-1" } {
		puts stderr "Problem getting used modules; used dir ($used_Modules_Dir)"
		return -1
	}
	foreach fn $used {	
		if { [file extension $fn] == ".te" } {
			lappend used_Modules $fn
			lappend all_Modules $fn
		}
	}
	
	# Get $unUsed_Modules_Dir modules
	set unused [Sepct_db::getFileNames $unUsed_Modules_Dir]
	if { [llength $unused] == 1 && $unused == "-1" } {
		# doesn't exists; not an error just no unused modules
		set unUsed_Modules ""
	}
	foreach fn $unused {	
		if { [file extension $fn] == ".te" } {
			lappend unUsed_Modules $fn
			lappend all_Modules $fn
		}
	}
	
	set all_Modules [lsort -dictionary $all_Modules]
			
	return 0
}

###############################################################################
# ::store_mod_descrptive_name
#  	- Method for getting the description from the first line of the TE file.
#	  The description line is identified by our global desc_ID variable.
#	  If the desc_ID value isn't on the first line, simply returns the file name.
# 
proc Sepct_Customize::store_mod_descrptive_name { mod_name is_used } {
	variable max_Label_Length
	if {$is_used} {
		set path [file join $Sepct_Customize::used_Modules_Dir $mod_name]
	} else {
		set path [file join $Sepct_Customize::unUsed_Modules_Dir $mod_name]
	}
	
	if { [file exists $path] } {
		if { [file readable $path] } {
			# Open the file and simply read the first line.
			set file_channel [::open $path r]
			set data ""
			gets $file_channel data
			::close $file_channel
			
			# Tokenize the string on the first line using spaces.
			# Then retrieve the first token from the list and see
			# if it matches our global desc_ID variable.
			set split_s [split $data " "]
			
			set first [lindex $split_s 0]
			if { [string match "$Sepct_Customize::desc_ID" $first] } {
				# From the first character of the description, get the decp string
				set d_string [string range $data \
					[expr {[string length $Sepct_Customize::desc_ID] + 1}] end]	
				# Validate the length of the descriptive text that we are storing
				if { [string length $d_string] > $max_Label_Length } {
					set d_string [string range $d_string 0 $max_Label_Length]
				}
				return [string trim $d_string]
			} else {
				return $mod_name
			}
		} else {
			# if not readable just return file name with appropriate indicator
			return "$mod_name (unreadable)"
		}
	} else {
		puts stderr "Can't store module label: canot find $path "
		return -1
	}
		
}

###########################################################################################
# ::check_fc_consistency
#	- This method performs a consistency check to see if each .te file (all_Modules) has an 
#	  associated.fc file, and build a list (missing_fc_files) of those missing .fc files.  It
#	 will ignore extra .fc files.
#	 
# 
proc Sepct_Customize::check_fc_consistency {} {
	variable all_Modules
	variable fc_path
	variable missing_fc_files
	
	# get the files from $fc_path directory
	set fc_dir_files [Sepct_db::getFileNames $fc_path]
	if { [llength $fc_dir_files] == 1 && $fc_dir_files == "-1" } {
		puts stderr "Problem getting module .fc files; fc_path ($fc_path)"
		return -1
	}
	
	# build list of all .fc files
	set fc_files ""
	foreach fn $fc_dir_files {	
		if { [file extension $fn] == ".fc" } {
			lappend fc_files $fn
		}
	}

	# Now check each file in all_Modules, and if there is NOT an assoicated .fc
	# file, add the .fc file name to the missing_fc_files list
	set missing_fc_files ""
	foreach te_file $all_Modules {
		set fcname "[file rootname $fn].fc"
		if { [lsearch -exact $fc_files $fcname] == -1 } {
			lappend missing_fc_files $fcname
		}
	}
	
	return 0
}

############################################################################
# ::remove_Module_from_List
# 
proc Sepct_Customize::remove_Module_from_List { moduleList module } {	
	set idx [lsearch -exact $moduleList $module]
	if { $idx == -1 } {
		#no error, already doesn't exist
		return 0	
	}
	# remove name and its 3 data elements
	set moduleList [lreplace $moduleList $idx $idx]
	
	return $moduleList
}

############################################################################
# ::add_Module_to_List
# 
proc Sepct_Customize::add_Module_to_List { moduleList module } {	
	set idx [lsearch -exact $moduleList $module]
	if { $idx == -1 } {
		# append new module to the given list
		lappend moduleList $module
	}
	
	return $moduleList
}

############################################################################
# ::move_Module_to_Unused_List
# 
proc Sepct_Customize::move_Module_to_Unused_List { module source_Path target_Path } {
	variable used_Modules 
	variable unUsed_Modules
	
	set used_Modules   [Sepct_Customize::remove_Module_from_List $used_Modules $module]
	set unUsed_Modules [Sepct_Customize::add_Module_to_List $unUsed_Modules $module]
	
	# Update our internal database to have these changes.
    	set rt [Sepct_db::move_file $source_Path $target_Path]
	return $rt
}

############################################################################
# ::move_Module_to_Used_List
# 
proc Sepct_Customize::move_Module_to_Used_List { module source_Path target_Path } {
	variable used_Modules 
	variable unUsed_Modules
	
	set unUsed_Modules [Sepct_Customize::remove_Module_from_List $unUsed_Modules $module]
	set used_Modules   [Sepct_Customize::add_Module_to_List $used_Modules $module]
	
	# Update our internal database to have these changes.
    	set rt [Sepct_db::move_file $source_Path $target_Path]	
	return $rt
}

############################################################################
# ::remove_From_All_Module_Lists
# 
proc Sepct_Customize::remove_From_All_Module_Lists { module } {
	variable used_Modules 
	variable unUsed_Modules
	variable all_Modules
	
	# Update the used_Modules, unUsed_Modules and all_Modules global list variables.
	if { [Sepct_Customize::is_module_used $module] } {
		set used_Modules   [Sepct_Customize::remove_Module_from_List $used_Modules $module]
	} else {
		set unUsed_Modules [Sepct_Customize::remove_Module_from_List $unUsed_Modules $module]
	}		    	
    	set all_Modules [Sepct_Customize::remove_Module_from_List $all_Modules $module]
	    		
	return 0
}
