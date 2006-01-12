#############################################################
#  analysis_tab.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com> 
#  Modified by: <kcarr@tresys.com>
# -----------------------------------------------------------

##############################################################
# ::Apol_Analysis
#  
# The Analysis tab
##############################################################
namespace eval Apol_Analysis {
	# Global widgets 
	variable results_notebook
	variable analysis_listbox
	variable opts_frame
	variable newButton
	variable updateButton
	# Global widget variable for the close button located beneath results notebook.
	variable bClose
	variable popupTab_Menu
	variable descrp_text
	variable info_Dlg
	set info_Dlg .info_Dlg
	
	# Other
	variable analysis_modules	""
	variable curr_analysis_module	""
	variable raised_tab_analysis_type ""
	
	# VARIABLES FOR INSERTING, DELETING AND RENAMING RESULTS TABS
	variable new_tab_name		""
	variable totalTabCount		10
	variable currTabCount		0
	variable pageNums		0
	# We use the prefix 'Apol_' for all notebook tabnames. Also, tabnames may not have a colon.
	variable tabName		"Apol_ResultsTab"
	variable emptyTabID		"Apol_Emptytab"	
	variable pageID			""
	variable results		""
	variable enableUpdate		0
	variable initTab		0
	variable tab_deleted_flag	0
        variable keepmodselect          0
 	variable analysis_results_array
 	# callback procedures for the tab menu. Each element in this list is an embedded list of 2 items.
 	# The 2 items consist of the command label and the function name. The tabname will be added as an
 	# argument to the callback procedure.
 	variable tab_menu_callbacks	""
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::mod_select
# ------------------------------------------------------------------------------
proc Apol_Analysis::mod_select { mod_name } {     
	variable opts_frame
	variable curr_analysis_module
	variable analysis_listbox
	variable raised_tab_analysis_type
	variable results_notebook
        variable updateButton
        variable newButton
	
	# Return if the user selects the same analysis type currently selected	
	if { $mod_name == $curr_analysis_module } {
		return 
	} 
	
	# Set the selection and update the current analysis module variable
	$analysis_listbox selection set $mod_name
     	set curr_analysis_module $mod_name
     	
	# Redraw the options frame 
	Apol_Analysis::clear_options_frame $opts_frame
     	Apol_Analysis::display_mod_options $mod_name $opts_frame
     	
	set tab_frame [$results_notebook index $Apol_Analysis::emptyTabID]
	$results_notebook raise [$results_notebook page $tab_frame]
        $updateButton configure -state disabled
	$newButton configure -state normal
        
        if { [winfo exists $Apol_Analysis::info_Dlg] } {
		set descriptive_text [Apol_Analysis::get_analysis_info $curr_analysis_module]
		$Apol_Analysis::descrp_text config -state normal
		$Apol_Analysis::descrp_text delete 0.0 end
		$Apol_Analysis::descrp_text insert 0.0 $descriptive_text
		$Apol_Analysis::descrp_text config -state disabled
    		raise $Apol_Analysis::info_Dlg
    	}
     	return 0
} 

proc Apol_Analysis::free_call_back_procs { } {
       	variable tab_menu_callbacks	
    		
	set tab_menu_callbacks ""
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::delete_ResultsTab
# ------------------------------------------------------------------------------
proc Apol_Analysis::delete_ResultsTab { pageID } {
	variable results_notebook
	variable currTabCount
	variable tab_deleted_flag
	variable analysis_results_array
	variable curr_analysis_module
	variable opts_frame
        variable updateButton
        variable bClose
        variable keepmodselect
		
        if { [$results_notebook index $Apol_Analysis::emptyTabID] != [$results_notebook index $pageID] } {
		$bClose configure -state disabled
		update
		# Get previous page index.
		set prevPageIdx [expr [$results_notebook index $pageID] - 1]
		set results_frame [Apol_Analysis::get_results_frame $pageID]
		Apol_Analysis::clear_results_frame $results_frame $pageID
		# Remove tab and its' widgets; then decrement current tab counter
		$results_notebook delete $pageID 
		set currTabCount [expr $currTabCount - 1]
		
		# Remove the deleted tabs information from the content array
		array unset analysis_results_array "$pageID,*"
		     		
		# Raise the empty tab.  
		set raised [$results_notebook raise [$results_notebook page 0]]
		# The following 2 lines are disabled in this release to prevent reinitializing query criteria.
		#Apol_Analysis::clear_options_frame $opts_frame
		#Apol_Analysis::display_mod_options $curr_analysis_module $opts_frame
		$updateButton configure -state disabled
		
		set tab_deleted_flag 1
		Apol_Analysis::switch_results_tab $raised
		set tab_deleted_flag 0
		$bClose configure -state normal
	} 
     	update
    	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::close_All_ResultsTabs
# ------------------------------------------------------------------------------
proc Apol_Analysis::close_All_ResultsTabs { } {
	variable analysis_results_array
	variable results_notebook
	variable currTabCount
	
        set tabList [$results_notebook pages]
        # The following 'for loop' goes through each tab from left to right in the 
        # notebook and deletes each tab.
        foreach tab $tabList {
        	if {![string equal $tab $Apol_Analysis::emptyTabID]} {
        		set results_frame [Apol_Analysis::get_results_frame $tab]
			Apol_Analysis::clear_results_frame $results_frame $tab
		}
		$results_notebook delete $tab
	} 
	# Reset the result tab variables.
	set Apol_Analysis::pageNums 		0
	set Apol_Analysis::currTabCount		0
	set Apol_Analysis::pageID		""	
	set Apol_Analysis::results		""
	set Apol_Analysis::initTab		0
	set Apol_Analysis::enableUpdate 	0		
	# 1. Unset the entire analysis_results_array, which is used to store information for each search result.
        # 2. Retrieve all existing tabs and set it to our local tabList variable.
	array unset analysis_results_array
	
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::clear_results_frame
# ------------------------------------------------------------------------------
proc Apol_Analysis::clear_results_frame {results_frame tabID} { 
	variable analysis_results_array
	
	set curr_analysis_module $analysis_results_array($tabID,mod_name)
	set query_options $analysis_results_array($tabID,query)
	set rt [catch {${curr_analysis_module}::free_results_data $query_options} err] 
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error freeing results tab data."
		return -1
	}
	destroy $results_frame
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::create_results_frame
# ------------------------------------------------------------------------------
proc Apol_Analysis::create_results_frame { parent } {  	
	set tmp [frame $parent.results_frame]
	pack $tmp -side left -fill both -anchor nw -expand yes 
     	return $tmp
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::get_results_frame
# ------------------------------------------------------------------------------
proc Apol_Analysis::get_results_frame { tabID } {  
	variable results_notebook
	set parent [$results_notebook getframe $tabID]	
     	return "$parent.results_frame"
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::create_New_ResultsTab
# ------------------------------------------------------------------------------
proc Apol_Analysis::create_New_ResultsTab { } {
	variable results_notebook
	variable currTabCount
	variable totalTabCount
	variable pageNums
	variable tabName
        variable updateButton
        variable bClose
        variable curr_analysis_module
	
	if { $currTabCount >= $totalTabCount } {		
		tk_messageBox -icon error -type ok -title "Attention" \
			-message "You have reached the maximum amount of tabs. Please delete a tab and try again."
		return ""
	}
	
	# Increment the global tab count and pageNum variables
	incr currTabCount
    	incr pageNums

	# Create tab and its' widgets
	set resultNums [expr $pageNums-1]
        set tab_name "($resultNums) [${curr_analysis_module}::get_short_name]"
	$results_notebook insert end $tabName$pageNums -text $tab_name
    	# Create explicit inner frame
    	set tab_frame [$results_notebook getframe $tabName$pageNums]
    	set results_frame [Apol_Analysis::create_results_frame $tab_frame]
    	# Here we use a flag variable to determine if this is the first tab created.
    	# If it is, then we can set the NoteBook size here, instead of repeatedly
    	# computing the notebook size every time Apol_Analysis::create_New_ResultsTab is called.
    	if { $Apol_Analysis::initTab == 0 } {	
    		$results_notebook compute_size
    		set Apol_Analysis::initTab 1
    	}   
    					
    	# Raise the new tab
    	set newPageIdx 	[expr $currTabCount - 1]
    	set raisedPage 	[$results_notebook raise [$results_notebook page $newPageIdx]]
	$updateButton configure -state normal
	$bClose configure -state normal
    	return $results_frame
}

#----------------------------------------------------------------------------------
#Apol_Analysis::create_empty_resultsTab
#----------------------------------------------------------------------------------
proc Apol_Analysis::create_empty_resultsTab { } {
        variable results_notebook
	variable currTabCount
	variable totalTabCount
	variable pageNums
	variable tabName
        variable updateButton
	
	if { $currTabCount >= $totalTabCount } {		
		tk_messageBox -icon error -type ok -title "Attention" \
			-message "You have reached the maximum amount of tabs. Please delete a tab and try again."
		return ""
	}
	
	# Increment the global tab count and pageNum variables
	incr currTabCount
    	incr pageNums

	# Create tab and its' widgets
	$results_notebook insert end $Apol_Analysis::emptyTabID -text "Empty Tab"
    	# Create explicit inner frame
    	set tab_frame [$results_notebook getframe $Apol_Analysis::emptyTabID]
    	set results_frame [Apol_Analysis::create_results_frame $tab_frame]
    	# Here we use a flag variable to determine if this is the first tab created.
    	# If it is, then we can set the NoteBook size here, instead of repeatedly
    	# computing the notebook size every time Apol_Analysis::create_New_ResultsTab is called.
    	if { $Apol_Analysis::initTab == 0 } {	
    		$results_notebook compute_size
    		set Apol_Analysis::initTab 1
    	}   
    					
    	# Raise the new tab
    	set newPageIdx 	[expr $currTabCount - 1]
    	set raisedPage 	[$results_notebook raise [$results_notebook page $newPageIdx]]
	
     	$updateButton configure -state disabled
    	return $results_frame

}

##############################################################
# Apol_Analysis::display_rename_tab_Dlg
#  	-  
proc Apol_Analysis::display_rename_tab_Dlg {pageID} {
	variable new_tab_name
	global tcl_platform
	
	if {$pageID == $Apol_Analysis::emptyTabID} {
		tk_messageBox -icon error -type ok -title "Rename Error" -message "Cannot rename the empty tab."
		return -1
	}
    	set rename_tab_Dlg [toplevel .rename_tab_Dlg]
   	wm protocol $rename_tab_Dlg WM_DELETE_WINDOW " "
    	wm withdraw $rename_tab_Dlg
    	wm title $rename_tab_Dlg "Rename results tab"
    	
    	if {$tcl_platform(platform) == "windows"} {
		wm resizable $rename_tab_Dlg 0 0
	} else {
		bind $rename_tab_Dlg <Configure> "wm geometry $rename_tab_Dlg {}"
	}
	# Clear the previous line number
	set new_tab_name ""
	set rename_tab_entryBox [entry $rename_tab_Dlg.gotoDlg_entryBox -bg white -textvariable Apol_Analysis::new_tab_name -width 10 ]
	set lbl_goto  [label $rename_tab_Dlg.lbl_goto -text "Tab name:"]
	set b_ok      [button $rename_tab_Dlg.ok -text "OK" -width 6 \
		-command "Apol_Analysis::rename_ResultsTab $pageID; destroy $rename_tab_Dlg"]
	set b_cancel  [button $rename_tab_Dlg.cancel -text "Cancel" -width 6 -command "destroy $rename_tab_Dlg"]
	
	pack $lbl_goto $rename_tab_entryBox -side left -padx 5 -pady 5 -anchor nw
	pack $b_ok $b_cancel -side left -padx 5 -pady 5 -anchor ne
	
	# Place a toplevel at a particular position
    	#::tk::PlaceWindow $rename_tab_Dlg widget center
	wm deiconify $rename_tab_Dlg
	focus $rename_tab_entryBox
	bind $rename_tab_Dlg <Return> "Apol_Analysis::rename_ResultsTab $pageID; destroy $rename_tab_Dlg"
	wm protocol $rename_tab_Dlg WM_DELETE_WINDOW "destroy $rename_tab_Dlg"
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::rename_ResultsTab
# ------------------------------------------------------------------------------
proc Apol_Analysis::rename_ResultsTab {pageID} {
	variable results_notebook
	variable new_tab_name
	
	if {$pageID == ""} {
		return -1	
	} elseif {$new_tab_name == ""} {
		tk_messageBox -icon error -type ok -title "Rename Error" -message "Must provide a tab name."
		return -1
	} elseif {$pageID == $Apol_Analysis::emptyTabID} {
		tk_messageBox -icon error -type ok -title "Rename Error" -message "Cannot rename the empty tab."
		return -1
	}
	$results_notebook itemconfigure $pageID -text $new_tab_name
	return 0
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis::create_options_frame
# ------------------------------------------------------------------------------
proc Apol_Analysis::create_options_frame { parent } {  	
	set tmp [frame $parent.inner_opt_frame]
	pack $tmp -side left -fill both -anchor nw -expand yes 
     	return $tmp
} 


# ------------------------------------------------------------------------------
#  Command Apol_Analysis::clear_options_frame
# ------------------------------------------------------------------------------
proc Apol_Analysis::clear_options_frame { opts_frame } {  
	set parent [winfo parent $opts_frame]
	destroy $opts_frame
	Apol_Analysis::create_options_frame $parent
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::switch_results_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis::switch_results_tab { tabID } {   
	variable opts_frame
        variable opts_frame
	variable analysis_results_array
	variable results_notebook
	variable tab_deleted_flag
	variable curr_analysis_module
     	variable raised_tab_analysis_type 
        variable updateButton
        variable newButton
     	variable bClose
	variable tabName
	
	set tabID [ApolTop::get_tabname $tabID]
        # First check to see if the user has selected the Empty tab.  If so
	# do not switch tabs
	if { $tabID == $Apol_Analysis::emptyTabID } {
		# Only redraw the options frame if this is a new analysis type. 
		if { $curr_analysis_module != [$Apol_Analysis::analysis_listbox selection get]} {
			Apol_Analysis::clear_options_frame $opts_frame
			Apol_Analysis::display_mod_options $curr_analysis_module $opts_frame
		}
		$results_notebook raise $tabID
		$updateButton configure -state disabled
		$newButton configure -state normal
		return 0
	}
	$updateButton configure -state normal
	$bClose configure -state normal
     	set raised [$results_notebook raise]

	# Next check a flag to determine if the user has simply selected the 
	# currently raised tab and if so just return without updating options.
	if { $raised == $tabID && $tab_deleted_flag == 0 } {
		return 0
	} 
	
        # Only redraw the options frame if this is a new analysis type. 
	if { $curr_analysis_module != $analysis_results_array($tabID,mod_name) } {
	    set curr_analysis_module $analysis_results_array($tabID,mod_name)
	    $Apol_Analysis::analysis_listbox selection set $curr_analysis_module
	    Apol_Analysis::clear_options_frame $opts_frame
	    Apol_Analysis::display_mod_options $curr_analysis_module $opts_frame 	 	
	}
	set raised_tab_analysis_type $curr_analysis_module
   	$results_notebook raise $tabID
	Apol_Analysis::set_display_to_results_state $curr_analysis_module $analysis_results_array($tabID,query)
   	Apol_Analysis::set_Focus_to_Text $tabID
} 

# ----------------------------------------------------------------------------------------
#  Command Apol_Analysis::set_Focus_to_Text
# ----------------------------------------------------------------------------------------
proc Apol_Analysis::set_Focus_to_Text { tab } {
	variable results_notebook
	variable analysis_results_array
	
	if {$tab == $Apol_Analysis::emptyTabID} {
		return	
	}
	if {[array exists analysis_results_array]} {
		set curr_analysis_module $analysis_results_array($tab,mod_name)
	   	set txt [${curr_analysis_module}::get_results_raised_tab]
	   	focus $txt
	}
		
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::store_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis::store_current_results_state { raisedPage } {     	
	variable curr_analysis_module
     	variable analysis_results_array

     	set query_options [Apol_Analysis::get_current_results_state]
	# Unsets all of the elements in the array that match $raisedPage 
	array unset analysis_results_array "$raisedPage,*"
     	set analysis_results_array($raisedPage,query) $query_options
     	set analysis_results_array($raisedPage,mod_name) $curr_analysis_module
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::display_new_content
# ------------------------------------------------------------------------------
proc Apol_Analysis::display_new_content { } {     	
     	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis::display_mod_options { mod_name opts_frame } { 
     	${mod_name}::display_mod_options $opts_frame
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::reset_results_options
# ------------------------------------------------------------------------------
proc Apol_Analysis::reset_results_options { } {     	
     	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::close_results_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis::close_results_tab { } {     	
     	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::remove_from_content_array
# ------------------------------------------------------------------------------
proc Apol_Analysis::remove_from_content_array { } {     	
     	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::remove_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis::remove_tab { } {     	
     	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis::get_current_results_state { } {     	
     	variable curr_analysis_module
     	
     	return [${curr_analysis_module}::get_current_results_state]
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::save_query_options
#	- 
# ------------------------------------------------------------------------------
proc Apol_Analysis::save_query_options {file_channel query_file} {
	variable curr_analysis_module
	variable apol_analysis_query_id
	
	set rt [catch {${curr_analysis_module}::save_query_options $curr_analysis_module $file_channel $query_file} err]
	if {$rt != 0} {
		return -code error $err
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::load_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis::load_query_options {file_channel parentDlg} {  
	variable curr_analysis_module
	variable analysis_listbox
	
	# Search for the module name 
	while {[eof $file_channel] != 1} {
		gets $file_channel line
		set tline [string trim $line]
		# Skip empty lines and comments
		if {[string compare -length 1 $tline "#"] == 0 || $tline == ""} {
			continue
		}
		break
	}
	# Set the analysis module name and verify that this is a valid analysis module name 
	set module_name $tline
	# Search to see if this analysis module exists. 
	if {[lsearch -exact [$analysis_listbox items] $module_name] != -1} {
		# If the module is not the currently selected module, then select it.
		if {![string equal $curr_analysis_module $module_name]}  {
			Apol_Analysis::mod_select $module_name
		}
		set rt [catch {${module_name}::load_query_options $file_channel $parentDlg} err]
		if {$rt != 0} {
			return -code error $err
		}
	} else {
		return -code error "The specified query is not a valid analysis module."
	}
		
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis::set_display_to_results_state { mod_name query_options } { 
	variable analysis_listbox
	$analysis_listbox selection set $mod_name    	
     	${mod_name}::set_display_to_results_state $query_options
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::register_analysis_modules
# ------------------------------------------------------------------------------
proc Apol_Analysis::register_analysis_modules { mod_name desc_name } {     	
     	variable analysis_modules
   	
   	set item_list [list $mod_name "$desc_name" ]
     	set analysis_modules [lappend analysis_modules $item_list]
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::get_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis::get_analysis_info {mod_name} {
	set d_text [${mod_name}::get_analysis_info]
     	return $d_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::get_results_raised_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis::get_results_raised_tab {} {
	variable results_notebook
	
     	return [$results_notebook raise]
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::display_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis::display_analysis_info {} {
	variable info_Dlg
	variable curr_analysis_module
	variable descrp_text
	
	if { [winfo exists $info_Dlg] } {
    		destroy $info_Dlg
    	}
    		
	set descriptive_text [Apol_Analysis::get_analysis_info $curr_analysis_module]
	# Create the top-level dialog and subordinate widgets
    	toplevel $info_Dlg 
   	wm protocol $info_Dlg WM_DELETE_WINDOW " "
    	wm withdraw $info_Dlg
    	wm title $info_Dlg "Analysis Description"
    	set topf  [frame $info_Dlg.topf]
    	set botf  [frame $info_Dlg.botf]
    	set sw [ScrolledWindow $topf.sw  -auto none]
	set descrp_text [text $sw.descrp_text -height 5 -width 20 -font $ApolTop::text_font \
		-bg white -wrap word]
	$sw setwidget $descrp_text
	set b_ok [button $botf.b_ok -text "OK" -width 6 -command "destroy $Apol_Analysis::info_Dlg"]
	pack $topf -side top -fill both -expand yes -padx 5 -pady 5
	pack $botf -side bottom -anchor center 
	pack $b_ok -side left -anchor center -pady 2
	pack $sw -side top -anchor nw -expand yes -fill both 
	
	$descrp_text insert 0.0 $descriptive_text
	$descrp_text config -state disable
	        
        # Configure top-level dialog specifications
        set width 600
	set height 440
	wm geom $info_Dlg ${width}x${height}
	wm deiconify $info_Dlg
	wm protocol $info_Dlg WM_DELETE_WINDOW "destroy $Apol_Analysis::info_Dlg"
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis::do_analysis { which } {
	variable results_notebook
    	variable totalTabCount
    	variable currTabCount
	variable enableUpdate
	variable curr_analysis_module
	variable raised_tab_analysis_type
	variable analysis_listbox
        variable keepmodselect

	if { $curr_analysis_module == "" } {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "You must select an analysis type."
		return -1
	}

	# Hold the currently raised tab.
	set prev_raisedTab [$results_notebook raise]
	#hack: check the filter options of Transitive infoflow before clearing result tab so as not to lose them
	if {$curr_analysis_module == "Apol_Analysis_fulflow"} {
		set rt [catch {Apol_Analysis_fulflow::verify_options} err]
		if {$rt != 0} {
			return -1
		}
	}
	switch $which {
		new_analysis {
			$Apol_Analysis::newButton configure -state disabled
			update idletasks
		        # If the update button is disabled, then enable it.
			if { $enableUpdate == 0 } {
				$Apol_Analysis::updateButton configure -state normal
				set enableUpdate 1
			}
			# Create the new results tab.
			set results_frame [Apol_Analysis::create_New_ResultsTab]
		}
		update_analysis {
			$Apol_Analysis::updateButton configure -state disabled
			update idletasks
			# Destroy results tab subwidgets and free any data associated with them.
			set results_frame [Apol_Analysis::get_results_frame [$results_notebook raise]]
			set parent [winfo parent $results_frame]
			Apol_Analysis::clear_results_frame $results_frame [$results_notebook raise]
			Apol_Analysis::create_results_frame $parent
		}
		default {
			return -1
		}
	} 
	if {$results_frame != ""} {
		ApolTop::disable_DeleteWindow_event
                ApolTop::setBusyCursor
		set rt [catch {${curr_analysis_module}::do_analysis $results_frame} err] 
                $Apol_Analysis::newButton configure -state normal
		ApolTop::enable_DeleteWindow_event
                ApolTop::resetBusyCursor
		# Handle an error.
		if {$rt != 0 && $which == "new_analysis"} { 
			puts $err
			# Remove the bad tab and then decrement current tab counter
			$results_notebook delete [$results_notebook raise]
	    		incr currTabCount -1
	    		# Raise the previously raise tab.
			Apol_Analysis::switch_results_tab $prev_raisedTab
			return -1
		} elseif {$rt != 0} {
                        # Remove the bad tab since the results frame has been cleared
	    		set prev_Tab [$results_notebook pages \
				[expr [$results_notebook index $prev_raisedTab] - 1]]
			if {$prev_raisedTab != $Apol_Analysis::emptyTabID} {
                                $results_notebook delete $prev_raisedTab
                                incr currTabCount -1
                                Apol_Analysis::switch_results_tab $prev_Tab
			}
                        return -1
		}
	    	set raised_tab_analysis_type $curr_analysis_module
	    	# Here store the current content of the new tab.
		Apol_Analysis::store_current_results_state [$results_notebook raise] 
                # Re-enable buttons
                $Apol_Analysis::updateButton configure -state normal
	} 
     	return 0
} 

###############################################################################
# ::order_analysis_listbox
#
proc Apol_Analysis::order_analysis_listbox { analysis_listbox } {		
	#get modules from list	
        set labels ""		
	foreach module [$analysis_listbox items] {
		lappend labels "{[$analysis_listbox itemcget $module -text]} {$module}"
	}
	set labels [lsort -dictionary $labels]
	
	set module_List ""
	foreach module $labels {
		lappend module_List [lindex $module end]
	}
	$analysis_listbox reorder $module_List

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::configure_analysis_listbox
# ------------------------------------------------------------------------------
proc Apol_Analysis::configure_analysis_listbox { analysis_modules analysis_listbox } {      	
     	foreach mod_name $analysis_modules { 
		$analysis_listbox insert end [lindex $mod_name 0] \
			-text [lindex $mod_name 1] 
	}   
	
	#Apol_Analysis::order_analysis_listbox $analysis_listbox
	# Redraw the listbox
	$analysis_listbox configure -redraw 1
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis::initialize { } {     	
     	variable analysis_modules
     	variable analysis_listbox
    	
    	# Register any analysis modules
     	foreach mod_name $analysis_modules {
     		set mod_name [lindex $mod_name 0]
     		${mod_name}::initialize
     	}
     	Apol_Analysis::configure_analysis_listbox $analysis_modules $analysis_listbox
     	$analysis_listbox selection set [$analysis_listbox items 0]
	if { [$analysis_listbox selection get] != "" } {
		Apol_Analysis::mod_select [$analysis_listbox selection get]	
	}
	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::reset_to_initial_state
# ------------------------------------------------------------------------------
proc Apol_Analysis::reset_to_initial_state { } {	 	
    	$Apol_Analysis::updateButton configure -state disabled
    	Apol_Analysis::close_All_ResultsTabs
     	set Apol_Analysis::raised_tab_analysis_type ""
        Apol_Analysis::create_empty_resultsTab
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::open
# ------------------------------------------------------------------------------
proc Apol_Analysis::open { } { 
	variable analysis_listbox
	
        set selected_module [$analysis_listbox selection get]
	if {$selected_module != ""} {
		set rt [catch {${selected_module}::open} err]
		if {$rt != 0} {
			return -code error $err
		}
	}
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::close
# ------------------------------------------------------------------------------
proc Apol_Analysis::close { } {	
	variable analysis_modules
    	variable analysis_listbox 
	
     	foreach mod_name $analysis_modules {
	       set mod_name [lindex $mod_name 0]
	       if {[$analysis_listbox selection get] == $mod_name} {
		   ${mod_name}::close
               }
	}
	Apol_Analysis::reset_to_initial_state
    	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::discard_analysis_modules
# ------------------------------------------------------------------------------
proc Apol_Analysis::discard_analysis_modules { } {	
	variable analysis_modules
    	set analysis_modules ""
    	return 0	
}

########################################################################
#  Command Apol_Analysis::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Analysis::goto_line { line_num } {
	return 0
}

##############################################################
#  Command Apol_Analysis::search
#  	- Search text widget for a string
# 
proc Apol_Analysis::search { str case_Insensitive regExpr srch_Direction } {
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis::create
# ------------------------------------------------------------------------------
proc Apol_Analysis::create { nb } {
	variable results_notebook
	variable analysis_listbox
	variable opts_frame
	variable newButton
	variable updateButton
	variable bClose
	variable popupTab_Menu
 	variable tab_menu_callbacks
 	
	# Layout frames
        set frame [$nb insert end $ApolTop::analysis_tab -text "Analysis"]
        set analysis_top_pane [PanedWindow $frame.pw1 -side left -weights available]
        $analysis_top_pane add -weight 1
        $analysis_top_pane add
	set analysis_top_f  [frame [$analysis_top_pane getframe 0].topf]
	set botf  [frame [$analysis_top_pane getframe 1].botf]
        set pw2   [PanedWindow $analysis_top_f.pw -side top -weights available]
	$pw2 add -weight 1 
        $pw2 add -weight 3
	# Major subframes
	set t_left_f [TitleFrame [$pw2 getframe 0].t_left_f -text "Analysis Type"]
	set title_opts_f [TitleFrame [$pw2 getframe 1].opts_frame -text "Analysis Options"]
	set buttons_f [frame $analysis_top_f.buttons_f]
	set b_title_f [TitleFrame $botf.b_title_f -text "Analysis Results"]
	set b_topf [frame [$b_title_f getframe].b_topf]
	set b_botf [frame [$b_title_f getframe].b_botf -relief sunken -bd 1]
	
	# Placing layout frames and major subframes
	pack $buttons_f -side right -fill y -anchor ne -padx 2 -pady 2
        pack $analysis_top_pane -fill both -expand yes
        pack $pw2 -fill both -expand 1
	pack $analysis_top_f -side top -fill both -expand 1
	pack $botf -side top -fill both -expand yes 
	pack $title_opts_f -side right -fill both -anchor ne -expand yes -padx 2
	pack $t_left_f -side left -anchor nw -fill both -expand yes
	pack $b_title_f -side left -fill both -anchor n -expand yes
	pack $b_topf -side top -fill both -anchor nw -expand yes
	pack $b_botf -side bottom -anchor center -fill x -padx 4 -pady 1

	# Action buttons
	set newButton 	 [button $buttons_f.new -text "New" \
		-width 6 \
		-command {Apol_Analysis::do_analysis "new_analysis"}]
	set updateButton [button $buttons_f.upDate -text "Update" \
		-width 6 \
		-command {Apol_Analysis::do_analysis "update_analysis"} \
		-state disabled] 
	set infoButton [button $buttons_f.infoButton -text "Info" \
		-width 6 \
		-command {Apol_Analysis::display_analysis_info}] 
		
	# Pack the buttons first, so we don't lose them on a window resize event
	pack $newButton $updateButton $infoButton -side top -pady 5 -anchor ne 
		
	set opts_frame [Apol_Analysis::create_options_frame [$title_opts_f getframe]]
	# Analysis type listbox
	set sw_t     [ScrolledWindow [$t_left_f getframe].sw -auto none]
	set analysis_listbox [ListBox $sw_t.analysis_listbox \
                  -relief flat -borderwidth 0 -bg white \
                  -height 10 -highlightthickness 2 -width 25 -padx 0 \
                  -redraw 0 -selectmode single]
	$sw_t setwidget $analysis_listbox 
	
    	$analysis_listbox bindText <ButtonPress-1> { Apol_Analysis::mod_select }
    	
    	# Popup menu widget
	set popupTab_Menu [menu .analysis_popup_Menu -tearoff 0]
	set tab_menu_callbacks [lappend tab_menu_callbacks {"Delete Tab" "Apol_Analysis::delete_ResultsTab"}]
	set tab_menu_callbacks [lappend tab_menu_callbacks {"Rename Tab" "Apol_Analysis::display_rename_tab_Dlg"}]
	 
	# Results notebook
	set results_notebook [NoteBook $b_topf.nb_results]
	# All callbacks will take the tab id as an argument. This argument is added in the callback procedure.
	$results_notebook bindtabs <Button-3> {ApolTop::popup_Tab_Menu \
		%W %x %y $Apol_Analysis::popupTab_Menu $Apol_Analysis::tab_menu_callbacks} 
    	$results_notebook bindtabs <Button-1> {Apol_Analysis::switch_results_tab}
       	
    	# Add button bar at bottom of results section for closing tabs.
	set bClose [button $b_botf.bClose -text "Close Tab" -command { 
		Apol_Analysis::delete_ResultsTab [$Apol_Analysis::results_notebook raise] }]
	pack $bClose -side bottom -anchor center -fill x -padx 1 -pady 1
    		   
	# Placing widgets    
	$results_notebook compute_size
	pack $results_notebook -fill both -expand yes -padx 4
    	pack $sw_t -fill both -expand yes

 	Apol_Analysis::initialize
	Apol_Analysis::create_empty_resultsTab
 
	return $frame
}

