# Copyright (C) 2001-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets


##############################################################
# ::ApolTE
#  
# The TE Rules page
##############################################################
namespace eval ApolTE {
# opts(opt), where opt =
# teallow		type allow rules
# neverallow		
# clone 
# auallow		audit allow
# audeny		audit deny
# audont		dont audit 		
# ttrans		type trans
# tmember		type member
# tchange		type change
# use_1st_list		whether to use 1st typ/attrib arg
# use_2nd_list		whether to use 2nd typ/attrib arg
# use_3rd_list		whether to use 3rd type
# which_1               indicates whether ta1 is used for source, or any location
# indirect_1		indirect search for source
# indirect_2		" " target
# indirect_3		" " default
# perm_union		whether to use union or intersect
# perm_select		whether to show ALL permissions OR only show permissions for 
#			selected object classes

        # PARAMETERS FOR SEARCHTERULES FUNCTION
	variable opts
	set opts(teallow)		1
	set opts(neverallow)		1
	set opts(clone)			0
	set opts(auallow)		0
	set opts(audeny)		0
	set opts(ttrans)		1		
	set opts(tmember)		0
	set opts(tchange)		0
	set opts(audont)        	0
	set opts(use_1st_list)		0
	set opts(use_2nd_list)		0
	set opts(use_3rd_list)  	0
	set opts(which_1)		source
	set opts(indirect_1)		0
	set opts(indirect_2)		0
	set opts(indirect_3)		0
	variable ta1 			""
	variable ta2 			""
	variable ta3 			""
	variable allow_regex		1
	variable ta1_opt 		"both"
	variable ta2_opt 		"both"

	# GLOBAL WIDGETS FOR RULE SELECTION 
	variable teallow 
	variable neverallow 
	variable auallow 
	variable audeny
	variable audont
	variable ttrans 
	variable tmember 
	variable tchange 
	variable clone
	
	# GLOBAL WIDGETS AND VARIABLES FOR TYPE/ATTRIBS TAB
	variable source_list	
	variable target_list
	variable dflt_type_list
	variable global_asSource 
        variable global_any
	variable use_1st_list
	variable use_2nd_list
	variable use_3rd_list
	variable incl_indirect1
	variable incl_indirect2
	variable list_types_1 
	variable list_attribs_1 
	variable list_types_2  
	variable list_attribs_2 
	variable src_list_type_1	1
	variable src_list_type_2	0
	variable tgt_list_type_1	1
	variable tgt_list_type_2	0
	variable ta_state_Array	
				
	# GLOBAL WIDGETS AND VARIABLES FOR OBJS/CLASSES TAB
	variable objslistbox
    	variable permslistbox	
	set opts(perm_union)		union
	set opts(perm_select)		selected
	variable selObjectsList		""
    	variable selPermsList		""
	variable objectslist 		""
	variable permslist 		""
	# Below used as master perm list to avoid repeated calls to apol_GetNames
	variable master_permlist 	""
	
	# OTHER GLOBAL WIDGETS AND VARIABLES
	variable cb_RegExp
	variable notebook_searchOpts
	variable notebook_results
	variable popupTab_Menu
	variable updateButton
			
	# VARIABLES FOR INSERTING AND DELETING RESULTS TABS
	variable totalTabCount		10
	variable currTabCount		0
	variable pageNums		0
	variable emptyTabID		"Emptytab"
	variable tabName		"ResultsTab"
	variable tabText		"Results "
	variable pageID			""	
	variable results		""
	variable enableUpdate		0
	variable tab_deleted_flag	0
	variable optionsArray		
	
	# GLOBAL VARIABLES FOR NAMING THE CLASSES/PERMISSIONS AND TYPES/ATTRIBUTES TABS
	variable cp_TabID		"ClassPermsTab"
	variable ta_TabID		"TypesAttibsTab"
	
	# INTERACTIVE LABEL MESSAGES
	variable m_use_tgt_ta          "Use Target Type/Attrib"
	variable m_disable_tgt_ta      "Target Type/Attrib (Disabled)"
	variable m_disable_dflt_type   "Default Type (Disabled)"
	variable m_use_dflt_type       "Use Default Type"
	variable m_use_src_ta          "Use Source Type/Attrib"
	variable m_disable_src_ta      "Source Type/Attrib (Disabled)"
	variable m_incl_indirect       "Include Indirect Matches"
	variable m_ta_tab	       "Types/Attributes"
	variable m_obj_perms_tab       "Classes/Permissions" 
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc ApolTE::goto_line { line_num } {
	variable notebook_results
	
	if { [$notebook_results pages] != "" } {
		if {[string is integer -strict $line_num] != 1} {
			tk_messageBox -icon error \
				-type ok  \
				-title "Invalid line number" \
				-message "$line_num is not a valid line number"
			return 0
		}
		set raisedPage 	[ $notebook_results raise ]
		
		ApolTop::goto_line $line_num $ApolTE::optionsArray($raisedPage,textbox)
	}
	return 0
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc ApolTE::search { str case_Insensitive regExpr srch_Direction } {
	variable notebook_results
	
	if { [$notebook_results pages] != "" } {
		set raisedPage 	[ $notebook_results raise ]
		ApolTop::textSearch $ApolTE::optionsArray($raisedPage,textbox) $str $case_Insensitive $regExpr $srch_Direction
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::searchTErules
# ------------------------------------------------------------------------------
proc ApolTE::searchTErules { whichButton } {
	variable opts
	variable ta1
	variable ta2
        variable ta3
        variable objslistbox
    	variable permslistbox
    	variable selObjectsList
    	variable selPermsList
    	variable totalTabCount
    	variable currTabCount
	variable notebook_results
	variable enableUpdate
	variable allow_regex
	variable ta1_opt
	variable ta2_opt
			
	if { $whichButton == "newTab" && $currTabCount >= $totalTabCount } {		
		tk_messageBox -icon error -type ok -title "Attention" \
			-message "You have reached the maximum amount of tabs. Please delete a tab and try again."
		return 
	}
	if {$allow_regex && $opts(use_1st_list) && $ta1 == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided for Source Type/Attrib!"
		return
	}
	if {$allow_regex && $opts(use_2nd_list) && $ta2 == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided for Target Type/Attrib!"
		return
	}
	if {$allow_regex && $opts(use_3rd_list) && $ta3 == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided for Default Type!"
		return
	}
	
	# Getting all selected objects. 
	set selObjectsList [ApolTE::get_Selected_ListItems $objslistbox]

	# Getting all selected permissions
	set selPermsList [ApolTE::get_Selected_ListItems $permslistbox]
		
	# Making the call to apol_GetTErules to search for rules with given options
	ApolTop::setBusyCursor
	set rt [catch {set results [apol_SearchTErules $opts(teallow) $opts(neverallow) \
		$opts(clone) $opts(auallow) $opts(audeny) $opts(audont) $opts(ttrans) \
		$opts(tmember) $opts(tchange) $opts(use_1st_list) $opts(indirect_1) \
		$ta1 $opts(which_1) $opts(use_2nd_list) $opts(indirect_2) \
		$ta2 $opts(use_3rd_list) $opts(indirect_3) $ta3 $selObjectsList $selPermsList\
		$allow_regex $ta1_opt $ta2_opt]} err]
	
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		ApolTop::resetBusyCursor
		return 
	} 

	switch $whichButton {
		newTab {
			# If the update button is disabled, then enable it.
			if { $enableUpdate == 0 } {
				$ApolTE::updateButton configure -state normal
				set enableUpdate 1
			}
			# Create the new results tab and set optionsArray.
			set raisedPage [ApolTE::create_New_ResultsTab $results]
			ApolTE::set_OptionsArray $raisedPage $selObjectsList $selPermsList
		}
		updateTab {
			set raisedPage 	[ $notebook_results raise ]
			$ApolTE::optionsArray($raisedPage,textbox) configure -state normal
			# Remove any custom tags.
			Apol_PolicyConf::remove_HyperLink_tags $ApolTE::optionsArray($raisedPage,textbox)
    			$ApolTE::optionsArray($raisedPage,textbox) delete 0.0 end
			ApolTE::insertTERules $ApolTE::optionsArray($raisedPage,textbox) $results 
    			ApolTop::makeTextBoxReadOnly $ApolTE::optionsArray($raisedPage,textbox)
			ApolTE::set_OptionsArray $raisedPage $selObjectsList $selPermsList
		}
		default {
			return -code error
		}
	} 
        
        ApolTop::resetBusyCursor
        
        return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::insertTERules
#	takes a results list (from apol_SearchTERules) and explodes it into
#	a provided text box
# ------------------------------------------------------------------------------
proc ApolTE::insertTERules { tb results } {	
	# Determine number of rules returned (1/2 size of llength)
	set num [expr { [llength $results] / 2 }]
	$tb insert end "$num rules match the search criteria\n\n"
		
	for {set x 0} {$x < [llength $results]} {incr x} { 
		set cur_line_pos [$tb index insert]
		set line_num [lindex [split $cur_line_pos "."] 0]
		set rule [lindex $results $x]
		incr x
		set lineno [lindex $results $x]
		$tb insert end "($lineno"
		# NOTE: The character at index2 isn't tagged, so must add 1 to index2 argument.
		Apol_PolicyConf::insertHyperLink $tb $line_num.1 $line_num.end
		$tb insert end ") $rule\n"
	}	
	Apol_PolicyConf::configure_HyperLinks $tb
	update idletasks
	
	return 
}

# ------------------------------------------------------------------------------
#  Command ApolTE::set_OptionsArray
# ------------------------------------------------------------------------------
proc ApolTE::set_OptionsArray { raisedPage selObjectsList selPermsList } {
	variable optionsArray
	variable opts
	variable ta1
	variable ta2
        variable ta3
	variable permslist
	variable allow_regex
	variable src_list_type_1	
	variable src_list_type_2	
	variable tgt_list_type_1	
	variable tgt_list_type_2
		
	# Unsets all of the elements in the array that match $raisedPage 
	array unset optionsArray $raisedPage			
	
        set optionsArray($raisedPage,teallow) 		$opts(teallow)
	set optionsArray($raisedPage,neverallow) 	$opts(neverallow)
	set optionsArray($raisedPage,clone) 		$opts(clone)
	set optionsArray($raisedPage,auallow) 		$opts(auallow)
	set optionsArray($raisedPage,audeny) 		$opts(audeny)
	set optionsArray($raisedPage,audont) 		$opts(audont)
	set optionsArray($raisedPage,ttrans) 		$opts(ttrans)		
	set optionsArray($raisedPage,tmember) 		$opts(tmember)
	set optionsArray($raisedPage,tchange) 		$opts(tchange)
	set optionsArray($raisedPage,use_1st_list)	$opts(use_1st_list)
	set optionsArray($raisedPage,indirect_1)	$opts(indirect_1)
	set optionsArray($raisedPage,ta1) 		$ta1
	set optionsArray($raisedPage,which_1) 		$opts(which_1)
        set optionsArray($raisedPage,use_2nd_list) 	$opts(use_2nd_list)
        set optionsArray($raisedPage,indirect_2) 	$opts(indirect_2)
        set optionsArray($raisedPage,ta2) 		$ta2
        set optionsArray($raisedPage,use_3rd_list) 	$opts(use_3rd_list)
	set optionsArray($raisedPage,indirect_3) 	$opts(indirect_3)
	set optionsArray($raisedPage,ta3) 		$ta3
	set optionsArray($raisedPage,selObjectsList) 	$selObjectsList
	set optionsArray($raisedPage,selPermsList) 	$selPermsList
	set optionsArray($raisedPage,ta1) 		$ta1
	set optionsArray($raisedPage,ta2) 		$ta2
	set optionsArray($raisedPage,ta3) 		$ta3
	set optionsArray($raisedPage,perm_union) 	$opts(perm_union)
	set optionsArray($raisedPage,perm_select) 	$opts(perm_select)
	set optionsArray($raisedPage,permslist) 	$permslist
	set optionsArray($raisedPage,allow_regex) 	$allow_regex
	set optionsArray($raisedPage,src_list_type_1) 	$src_list_type_1
	set optionsArray($raisedPage,src_list_type_2) 	$src_list_type_2
	set optionsArray($raisedPage,tgt_list_type_1) 	$tgt_list_type_1
	set optionsArray($raisedPage,tgt_list_type_2) 	$tgt_list_type_2
		
	return 0
}

#----------------------------------------------------------------------------------
# ApolTE::create_empty_resultsTab
#----------------------------------------------------------------------------------
proc ApolTE::create_empty_resultsTab { } {
        variable notebook_results
	variable currTabCount
	variable pageNums
	variable totalTabCount
	
	if {$currTabCount >= $totalTabCount} {		
		tk_messageBox -icon error -type ok -title "Attention" \
			-message "You have reached the maximum amount of tabs. Please delete a tab and try again."
		return -1
	}
	
	# Increment the global tab count and pageNum variables
	incr currTabCount
    	incr pageNums

	# Create tab and its' widgets
	$notebook_results insert end $ApolTE::emptyTabID -text "Empty Tab"
    	    	
    	# Set the NoteBook size
    	$notebook_results compute_size
    				
    	# Raise the new tab
    	set raisedPage 	[$notebook_results raise $ApolTE::emptyTabID]
	
    	return 0

}

# ------------------------------------------------------------------------------
#  Command ApolTE::create_New_ResultsTab
# ------------------------------------------------------------------------------
proc ApolTE::create_New_ResultsTab { results } {
	variable notebook_results
	variable currTabCount
	variable pageNums
	variable tabName
	variable tabText
	variable totalTabCount
	variable optionsArray
	
	if {$currTabCount >= $totalTabCount} {		
		tk_messageBox -icon error -type ok -title "Attention" \
			-message "You have reached the maximum amount of tabs. Please delete a tab and try again."
		return -1
	}
	
	# Increment the global tab count and pageNum variables
	incr currTabCount
    	incr pageNums

	# Create tab and its' widgets
	$notebook_results insert end $tabName$pageNums -text $tabText$pageNums
    	set sw [ScrolledWindow [$notebook_results getframe $tabName$pageNums].sw -auto none]
    	set resultsbox [text [$sw getframe].resultsbox -bg white -wrap none -font $ApolTop::text_font]
    	$sw setwidget $resultsbox
    	pack $sw -side left -expand yes -fill both 
        					
    	# Raise the new tab; get its' pathname and then insert the results data into the resultsbox
    	set raisedPage 	[$notebook_results raise $tabName$pageNums]
	$resultsbox delete 0.0 end
	ApolTE::insertTERules $resultsbox $results
	ApolTop::makeTextBoxReadOnly $resultsbox 
	# Hold a reference to the results tab text widget
	set optionsArray($raisedPage,textbox) $resultsbox
	
    	return $raisedPage
}

# ------------------------------------------------------------------------------
#  Command ApolTE::delete_ResultsTab
# ------------------------------------------------------------------------------
proc ApolTE::delete_ResultsTab { pageID } {
	variable notebook_results
	variable currTabCount
	variable tab_deleted_flag
	variable optionsArray
	
	# Do not delete the emtpy tab!!
	if { [$notebook_results index $ApolTE::emptyTabID] != [$notebook_results index $pageID]} {
		# Get Previous page index
		set prevPageIdx [expr [$notebook_results index $pageID] - 1]
		# Remove tab and its' widgets; then decrement current tab counter 
		$notebook_results delete $pageID 
		array unset optionsArray($pageID)
		set currTabCount [expr $currTabCount - 1]
		# ::set_Widget_SearchOptions uses this flag
		set tab_deleted_flag 1
		
		if { $prevPageIdx >= 0} { 
			set raisedPage [$notebook_results raise [$notebook_results page $prevPageIdx]]
		} else {
			set raisedPage [$notebook_results raise [$notebook_results page 0]]
		}
		if {$raisedPage == $ApolTE::emptyTabID} {
			ApolTE::reset_search_criteria
		} else {
			# Set the search option widgets according to the now raised results tab.
			ApolTE::set_Widget_SearchOptions $raisedPage
			set tab_deleted_flag 0
		}
	}
     		
    	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::resetObjsPerms_Selections
# ------------------------------------------------------------------------------
proc ApolTE::resetObjsPerms_Selections { selObjectsList selPermsList } {
	variable objslistbox
    	variable permslistbox
	
	# Clear the selections in the listboxes.
	$objslistbox selection clear 0 end
	$permslistbox selection clear 0 end
	# Now get the number of elements in each listbox 
	set objectsCount [$objslistbox index end]
	set permsCount 	 [$permslistbox index end]
	
	# This loop goes through each element in the objects listbox and sets the selection 
	# for any items that match an item from the selObjectsList.
    	for { set idx 0 } { $idx != $objectsCount} { incr idx } {	
		foreach sel_item $selObjectsList {
			set object [$objslistbox get $idx]
			if { $sel_item == $object } {
    				$objslistbox selection set $idx
    			} else {
    				continue
    			}
		}	
    	}
    	
    	# This loop goes through each element in the perms list box and sets the selection 
	# for any items that match an item from the selPermsList.
    	for { set idx 0 } { $idx != $permsCount} { incr idx } {	
		foreach sel_item $selPermsList {
			set perm [$permslistbox get $idx]
			if { $sel_item == $perm } {
    				$permslistbox selection set $idx
    			} else {
    				continue
    			}
		}	
    	}
    	
    	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::set_Indicator
# ------------------------------------------------------------------------------
proc ApolTE::set_Indicator { pageID } {
	variable notebook_searchOpts     
	variable opts 
	variable objslistbox
    	variable permslistbox	
    	variable cp_TabID		
	variable ta_TabID			 		
	
	if { $pageID == $cp_TabID } {
		# Reset the tab text to the initial value and then get the raised tab.
		$notebook_searchOpts itemconfigure $cp_TabID -text $ApolTE::m_obj_perms_tab
		set objText 	[$notebook_searchOpts itemcget $cp_TabID -text]
		# Getting all selected objects. 
		set selObjectsList [ApolTE::get_Selected_ListItems $objslistbox]

		# Getting all selected permissions
		set selPermsList [ApolTE::get_Selected_ListItems $permslistbox]
		
		if { $selObjectsList != "" || $selPermsList != "" } {
			append objText " *"
			$notebook_searchOpts itemconfigure $cp_TabID -text $objText 
		} else {
			$notebook_searchOpts itemconfigure $cp_TabID -text $ApolTE::m_obj_perms_tab
		}
	} else {
		# Reset the tab text to the initial value and then get the raised tab.
		$notebook_searchOpts itemconfigure $ta_TabID -text $ApolTE::m_ta_tab
		set taText  	[$notebook_searchOpts itemcget $ta_TabID -text]
		if { $opts(use_1st_list) || $opts(use_2nd_list) || $opts(use_3rd_list) } {
			append taText " *"
			$notebook_searchOpts itemconfigure $ta_TabID -text $taText
		} else {
			$notebook_searchOpts itemconfigure $ta_TabID -text $ApolTE::m_ta_tab
		}
	}
	
    	set objText ""
    	set taText  ""
    	set selObjectsList ""
    	set selPermsList   ""
    	
    	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::set_Widget_SearchOptions
# ------------------------------------------------------------------------------
proc ApolTE::set_Widget_SearchOptions { pageID } {
	variable opts
	variable optionsArray
	variable ta1
	variable ta2
        variable ta3
	variable permslist
	variable allow_regex
	variable notebook_results
	variable src_list_type_1	
	variable src_list_type_2	
	variable tgt_list_type_1	
	variable tgt_list_type_2
	variable tab_deleted_flag
	
	set raised [$notebook_results raise]
	
	# First check flag to determine if the user has simply selected the 
	# currently raised tab and so just return without updating search options.
	if { $raised == $pageID && $tab_deleted_flag == 0 } {
		return
	}
	if { $pageID == $ApolTE::emptyTabID } {
		ApolTE::reset_search_criteria
		return
	}
	    
        # reinitialize original options
        set opts(teallow)	$optionsArray($pageID,teallow)
	set opts(neverallow)	$optionsArray($pageID,neverallow)
	set opts(clone)		$optionsArray($pageID,clone)
	set opts(auallow)	$optionsArray($pageID,auallow)
	set opts(audeny)	$optionsArray($pageID,audeny)
	set opts(audont)        $optionsArray($pageID,audont)
	set opts(ttrans)	$optionsArray($pageID,ttrans)
	set opts(tmember)	$optionsArray($pageID,tmember)
	set opts(tchange)	$optionsArray($pageID,tchange)
	set opts(use_1st_list)	$optionsArray($pageID,use_1st_list)
	set opts(indirect_1)	$optionsArray($pageID,indirect_1)
	set opts(which_1)	$optionsArray($pageID,which_1)
        set opts(use_2nd_list)	$optionsArray($pageID,use_2nd_list)
        set opts(indirect_2)	$optionsArray($pageID,indirect_2)
        set opts(use_3rd_list)  $optionsArray($pageID,use_3rd_list)
	set opts(indirect_3)	$optionsArray($pageID,indirect_3)
	set opts(perm_union)	$optionsArray($pageID,perm_union) 	
	set opts(perm_select)	$optionsArray($pageID,perm_select) 	
	set permslist		$optionsArray($pageID,permslist) 	
	set selObjectsList	$optionsArray($pageID,selObjectsList) 	
	set selPermsList	$optionsArray($pageID,selPermsList) 
	set allow_regex		$optionsArray($pageID,allow_regex) 
	set src_list_type_1	$optionsArray($pageID,src_list_type_1) 
	set src_list_type_2	$optionsArray($pageID,src_list_type_2) 
	set tgt_list_type_1	$optionsArray($pageID,tgt_list_type_1) 
	set tgt_list_type_2	$optionsArray($pageID,tgt_list_type_2) 
			
	# Re-configure list items for type/attributes tab combo boxes
	ApolTE::populate_ta_list 1
	ApolTE::populate_ta_list 2
	set ta1			$optionsArray($pageID,ta1)
        set ta2			$optionsArray($pageID,ta2)
	set ta3			$optionsArray($pageID,ta3)	
	
	# Reset Objects and Permissions selections 
	ApolTE::resetObjsPerms_Selections $selObjectsList $selPermsList
    		
	# check enable/disable status
        ApolTE::enable_listbox $ApolTE::source_list 1 $ApolTE::list_types_1 $ApolTE::list_attribs_1
        ApolTE::enable_listbox $ApolTE::target_list 2 $ApolTE::list_types_2 $ApolTE::list_attribs_2
        ApolTE::defaultType_Enable_Disable
        ApolTE::change_tgt_dflt_state
          
        # Check the search criteria for the Classes/Permissions and Types/Attributes tabs
        # and then set the indicator  accordingly.
        ApolTE::set_Indicator [$ApolTE::notebook_searchOpts page 0]
        ApolTE::set_Indicator [$ApolTE::notebook_searchOpts page 1]
	
	ApolTE::set_Focus_to_Text $pageID 
	              	
	return 0	
}

# ------------------------------------------------------------------------------
#  Command ApolTE::get_Selected_ListItems
# ------------------------------------------------------------------------------
proc ApolTE::get_Selected_ListItems { listname } {
	set indicesList [$listname curselection]
	set length [llength $indicesList] 
	
	if { $indicesList != "" } {
		for {set i 0} {$i < $length} {incr i} {
			set listItem_Index [lindex $indicesList $i]
			set item [$listname get $listItem_Index]	
			lappend itemsList $item		
		}	
	} else {
		return "";
	}
	return $itemsList
}

# ------------------------------------------------------------------------------
#  Command ApolTE::open
# ------------------------------------------------------------------------------
proc ApolTE::open { } {
	variable objectslist
	variable permslist
	variable master_permlist
	variable src_list_type_1	
	variable src_list_type_2	
	variable tgt_list_type_1	
	variable tgt_list_type_2	
	variable cb_RegExp
	variable ta_state_Array 
	variable objslistbox
		
	# Set the original state of the type/attribs buttons.		
	set ta_state_Array($ApolTE::list_types_1)   $src_list_type_1
	set ta_state_Array($ApolTE::list_attribs_1) $src_list_type_2
	set ta_state_Array($ApolTE::list_types_2)   $tgt_list_type_1
	set ta_state_Array($ApolTE::list_attribs_2) $tgt_list_type_2
	
	# Populate the type/attribs combo-boxes
	ApolTE::populate_ta_list 1
        ApolTE::populate_ta_list 2
        $ApolTE::dflt_type_list configure -values $ApolTypes::typelist
                
        # Check whether "classes" are included in the current opened policy file
        if {$ApolTop::contents(classes) == 1} {
        	set rt [catch {set objectslist [apol_GetNames classes]} err]
		if {$rt != 0} {	
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return 
		}
		set objectslist [lsort $objectslist]
		if {$objectslist != ""} {
			$objslistbox configure -bg white
		}
	}
	# Check whether "perms" are included in the current opened policy file
	if {$ApolTop::contents(perms) == 1} {
		set rt [catch {set master_permlist [apol_GetNames perms]} err]
		if {$rt != 0} {	
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return 
		} 
		set master_permlist [lsort $master_permlist]
		set permslist $master_permlist
	}
	ApolTE::configure_perms
	
        return 0
}
	
# ------------------------------------------------------------------------------
#  Command ApolTE::close
# ------------------------------------------------------------------------------
proc ApolTE::close { } {
	variable opts
	variable source_list
	variable target_list
	variable list_types_1
	variable list_attribs_1
	variable list_types_2  
	variable list_attribs_2 
	variable results
	variable ta_state_Array
	        
	ApolTE::reset_search_criteria
	
        # Close all results tabs.
        ApolTE::close_All_ResultsTabs
        
        # Reset objects/permissions lists
        set ApolTE::objectslist 	""
	set ApolTE::permslist 		""
	set ApolTE::master_permlist 	""
	$ApolTE::permslistbox configure -bg $ApolTop::default_bg_color
	$ApolTE::objslistbox configure -bg $ApolTop::default_bg_color
    	array unset ta_state_Array
     	
	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::reset_search_criteria
# ------------------------------------------------------------------------------
proc ApolTE::reset_search_criteria { } {
	variable source_list
	variable target_list
	variable list_types_1
	variable list_attribs_1
	variable list_types_2  
	variable list_attribs_2 
	variable objslistbox
    	variable permslistbox
    	
	ApolTE::reinitialize_default_search_options
	
	# check enable/disable status
        ApolTE::enable_listbox $source_list 1 $list_types_1 $list_attribs_1
        ApolTE::enable_listbox $target_list 2 $list_types_2 $list_attribs_2
        ApolTE::defaultType_Enable_Disable
        ApolTE::change_tgt_dflt_state
    	$ApolTE::b_union configure -state disabled
    	$ApolTE::b_intersection configure -state disabled
        
        # Reset Classes/Permissions and Types/Attributes tabs text to the initial value.
        set objText 	[$ApolTE::notebook_searchOpts itemcget $ApolTE::cp_TabID -text]
        set taText  	[$ApolTE::notebook_searchOpts itemcget $ApolTE::ta_TabID -text]
	if { $objText != $ApolTE::m_obj_perms_tab } {
		$ApolTE::notebook_searchOpts itemconfigure $ApolTE::cp_TabID -text $ApolTE::m_obj_perms_tab
	}
	if { $taText != $ApolTE::m_ta_tab } {
		$ApolTE::notebook_searchOpts itemconfigure $ApolTE::ta_TabID -text $ApolTE::m_ta_tab
	}
	
	# Clear the selections in the listboxes.
	$objslistbox selection clear 0 end
	$permslistbox selection clear 0 end
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::reinitialize_default_search_options
# ------------------------------------------------------------------------------
proc ApolTE::reinitialize_default_search_options { } {
	variable opts
	variable ta1_opt
	variable ta2_opt
	variable source_list
	variable target_list
	variable list_types_2  
	variable list_attribs_2 
		
	# reinitialize default options
        set opts(teallow)	1
	set opts(neverallow)	1
	set opts(clone)		0
	set opts(auallow)	0
	set opts(audeny)	0
	set opts(ttrans)	1		
	set opts(tmember)	0
	set opts(tchange)	0
	set opts(audont)        0
	set opts(use_1st_list)	0
        set opts(use_2nd_list)	0
        set opts(use_3rd_list)  0
	set opts(which_1)	source
	set opts(indirect_1)	0
	set opts(indirect_2)	0
	set opts(indirect_3)	0
	set opts(perm_union)	union
	set opts(perm_select)	selected
	set ApolTE::allow_regex		1
	set ApolTE::src_list_type_1	1
	set ApolTE::src_list_type_2	0
	set ApolTE::tgt_list_type_1	1
	set ApolTE::tgt_list_type_2	0 
	set ta1_opt 	"types"
	set ta2_opt 	"types"	
	set ApolTE::ta1 ""
	set ApolTE::ta2 ""
        set ApolTE::ta3 ""
	set ApolTE::selObjectsList  ""
    	set ApolTE::selPermsList    ""
    	
        return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::close_All_ResultsTabs
# ------------------------------------------------------------------------------
proc ApolTE::close_All_ResultsTabs { } {
	variable optionsArray
	variable notebook_results
	variable currTabCount
		
	# 1. Unset the entire optionsArray, which is used to gather the options for each search result.
        # 2. Retrieve all existing tabs and set it to our local tabList variable.
	array unset optionsArray
	# Get tabs 1 - currentTabCount in order to skip the empty tab.
        set tabList [$notebook_results pages 1 $currTabCount]

        # The following 'for loop' goes through each tab in the local tabList variable
        # and deletes each tab.
        foreach tab $tabList {
	    	$notebook_results delete $tab
	} 
	$notebook_results raise $ApolTE::emptyTabID
	# Disable the update button.
	$ApolTE::updateButton configure -state disabled
				
	# Reset the result tab variables.
	set ApolTE::pageNums 		0
	set ApolTE::currTabCount	0
	set ApolTE::pageID		""	
	set ApolTE::results		""
	set ApolTE::enableUpdate 	0
			
        return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::populate_ta_list
# ------------------------------------------------------------------------------
proc ApolTE::populate_ta_list { list } {
        variable incl_indirect1
	variable incl_indirect2
	variable src_list_type_1
	variable src_list_type_2	
	variable tgt_list_type_1
	variable tgt_list_type_2
	variable ta1_opt
	variable ta2_opt
	variable ta_state_Array

	if { $list == 1 } {
		# Make sure that either "Types" OR "Attribs", OR Both checkbuttons are selected
		# and set the variable ta1_opt accordingly. ta_state_Array variable holds the 
		# previous state before a checkbutton was invoked. We use this array variable
		# to make sure that the user cannot DESELECT both checkbuttons. 
		if { $src_list_type_1 == 1 && $src_list_type_2 == 1} {
			set ta1_opt "both"
			set ta_state_Array($ApolTE::list_types_1) 	1
			set ta_state_Array($ApolTE::list_attribs_1) 	1
		} elseif { $src_list_type_1 == 1 && $src_list_type_2 == 0 } {
			set ta1_opt "types"
			set ta_state_Array($ApolTE::list_types_1) 	1
			set ta_state_Array($ApolTE::list_attribs_1) 	0
		} elseif { $src_list_type_1 == 0 && $src_list_type_2 == 1 } {
			set ta1_opt "attribs"
			set ta_state_Array($ApolTE::list_types_1) 	0
			set ta_state_Array($ApolTE::list_attribs_1) 	1
		} elseif { $src_list_type_1 == 0 && $src_list_type_2 == 0} {
			if { $ta_state_Array($ApolTE::list_types_1) == 1 } {
				$ApolTE::list_types_1 invoke
			} elseif { $ta_state_Array($ApolTE::list_attribs_1) == 1 } {
				$ApolTE::list_attribs_1 invoke
			}
		}
		set which $ta1_opt
		set uselist $ApolTE::source_list
		set ta ApolTE::ta1
	        set cBox $incl_indirect1
	        set useStatus $ApolTE::opts(use_1st_list)
	} elseif { $list == 2 } {
		# Make sure that either "Types" OR "Attribs", OR Both checkbuttons are selected
		# and set the variable ta2_opt accordingly. ta_state_Array variable holds the 
		# previous state before a checkbutton was invoked. We use this array variable
		# to make sure that the user cannot DESELECT both checkbuttons.
		if { $tgt_list_type_1 == 1 && $tgt_list_type_2 == 1} {
			set ta2_opt "both"
			set ta_state_Array($ApolTE::list_types_2) 	1
			set ta_state_Array($ApolTE::list_attribs_2) 	1
		} elseif { $tgt_list_type_1 == 1 && $tgt_list_type_2 == 0 } {
			set ta2_opt "types"
			set ta_state_Array($ApolTE::list_types_2) 	1
			set ta_state_Array($ApolTE::list_attribs_2) 	0
		} elseif { $tgt_list_type_1 == 0 && $tgt_list_type_2 == 1 } {
			set ta2_opt "attribs"
			set ta_state_Array($ApolTE::list_types_2) 	0
			set ta_state_Array($ApolTE::list_attribs_2) 	1
		} elseif { $tgt_list_type_1 == 0 && $tgt_list_type_2 == 0} {
			if { $ta_state_Array($ApolTE::list_types_2) == 1 } {
				$ApolTE::list_types_2 invoke
			} elseif { $ta_state_Array($ApolTE::list_attribs_2) == 1 } {
				$ApolTE::list_attribs_2 invoke
			}
		}
		set which $ta2_opt
		set uselist $ApolTE::target_list
		set ta ApolTE::ta2
	        set cBox $incl_indirect2
	        set useStatus $ApolTE::opts(use_2nd_list)
	} elseif { $list == 3 } {
		set which $Apol_RBAC::opts(list_type)
		set uselist $Apol_RBAC::list_tgt
		set ta ApolTE::ta3
	        set useStatus $ApolTE::opts(use_3rd_list)
	} else {
		return -code error
	}
	
	# Clear the value in the ComboBox
	#set $ta ""
		
	switch $which {
		types {
			$uselist configure -values $ApolTypes::typelist
			if { $useStatus } {
		        	$cBox configure -state normal	    
		        }
		}
		attribs {
			$uselist configure -values $ApolTypes::attriblist
		        $cBox configure -state disabled
		        $cBox deselect
		}
		both {
			set bothlist [concat $ApolTypes::typelist $ApolTypes::attriblist]
			set bothlist [lsort -dictionary $bothlist]
			$uselist configure -values $bothlist
			$cBox configure -state disabled
			$cBox deselect
		}
   	        roles {
		        $uselist configure -values $Apol_Roles::role_list
		}
		default {
			$uselist configure -values ""
			$cBox configure -state normal
		}
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::configure_perms
# ------------------------------------------------------------------------------
proc ApolTE::configure_perms { } {
	variable permslist
	variable objslistbox
    	variable permslistbox
	variable master_permlist
	
	# First clear the selection in the permissions listbox and then get the selected items
	# from the objects listbox.
	$ApolTE::permslistbox selection clear 0 end
	set objectsList [ApolTE::get_Selected_ListItems $objslistbox]
	
	if { $ApolTE::opts(perm_select) == "all" } {
		$ApolTE::b_union configure -state disabled
    		$ApolTE::b_intersection configure -state disabled
		set permslist $master_permlist
		if {$permslist != ""} {
			$permslistbox configure -bg white
		}
	} elseif { $ApolTE::opts(perm_select) == "selected" && $objectsList != ""} {
		# If items from the objects list have been selected and the selected radio
		# button is selected, enable and invoke union and intersect radio buttons.
		$ApolTE::b_union configure -state normal
    		$ApolTE::b_intersection configure -state normal
    		if { $ApolTE::opts(perm_union) == "union"} {
    			set rt [catch {set permslist [lsort [apol_GetPermsByClass $objectsList 1]]} err]
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" -message "$err"
				return     			
    			} 
    		} else {
    			set rt [catch {set permslist [lsort [apol_GetPermsByClass $objectsList 0]]} err]
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" -message "$err"
				return     			
    			} 
    		}
    		if {$permslist != ""} {
    			$permslistbox configure -bg white
    		}
    	} else {
    		# Clear button has been invoked OR no selection has been made in the objects listbox.
    		# So, clear permissions listbox items.
    		set permslist "" 
    		$permslistbox configure -bg  $ApolTop::default_bg_color
    		if { $ApolTE::opts(perm_select) == "selected" } {
    			$ApolTE::b_union configure -state disabled
    			$ApolTE::b_intersection configure -state disabled
    		}
    		return
    	}
     	set objectsList ""
     		
    	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::enable_listbox
# ------------------------------------------------------------------------------
proc ApolTE::enable_listbox { cBox list_number b1 b2 } {
    variable global_asSource 
    variable global_any
    variable incl_indirect1
    variable incl_indirect2
    variable opts

    # Set/unset indicator on raised tab to indicate search critera has been selected/deselected.
    ApolTE::set_Indicator [$ApolTE::notebook_searchOpts raise]
	    
    if { $list_number == 1 } {
	set which list1
    } elseif {$list_number == 2} {
	set which list2
    } else {
	return -code error
    }
    switch $which {
	list1 {	    
	    if { $ApolTE::opts(use_1st_list) } {
		if { $ApolTE::opts(which_1) == "source"} {
		    $cBox configure -state normal -entrybg white
		    $b1 configure -state normal
		    $b2 configure -state normal
		    $ApolTE::global_asSource configure -state normal
		    $ApolTE::global_any configure -state normal	
		    $ApolTE::incl_indirect1 configure -state normal
		} else {
		    $cBox configure -state normal -entrybg white
		    $b1 configure -state normal
		    $b2 configure -state normal
		    $ApolTE::global_asSource configure -state normal
		    $ApolTE::global_any configure -state normal	
		    ApolTE::change_tgt_dflt_state
		}
		if {$ApolTE::src_list_type_1 == 0 && $ApolTE::src_list_type_2 == 1} {
		    $incl_indirect1 configure -state disabled
		    $incl_indirect1 deselect
		}
		if {$ApolTE::src_list_type_1 == 1 && $ApolTE::src_list_type_2 == 1} {
			$incl_indirect1 configure -state disabled
		    	$incl_indirect1 deselect
		}
	    } else { 
		$cBox configure -state disabled -entrybg  $ApolTop::default_bg_color
		selection clear -displayof $cBox
		$b1 configure -state disabled
		$b2 configure -state disabled
		$ApolTE::global_asSource configure -state disabled
		$ApolTE::global_any configure -state disabled
		$incl_indirect1 configure -state disabled
		$incl_indirect1 deselect
		ApolTE::change_tgt_dflt_state
	    }
	}
	list2 {
	    if { $ApolTE::opts(use_2nd_list) } {
		$cBox configure -state normal -entrybg white
		$b1 configure -state normal
		$b2 configure -state normal
		$ApolTE::incl_indirect2 configure -state normal
		
		if {$ApolTE::tgt_list_type_1 == 0 && $ApolTE::tgt_list_type_2 == 1} {
		    $incl_indirect2 configure -state disabled
		    $incl_indirect2 deselect
		}
		if {$ApolTE::tgt_list_type_1 == 1 && $ApolTE::tgt_list_type_2 == 1} {
			$incl_indirect2 configure -state disabled
		    	$incl_indirect2 deselect
		}
	    } else {
		$cBox configure -state disabled  -entrybg  $ApolTop::default_bg_color
		selection clear -displayof $cBox
		$b1 configure -state disabled
		$b2 configure -state disabled
		$incl_indirect2 configure -state disabled
		$incl_indirect2 deselect
	    }
	}	   
	default {
			return -code error
	}
    }
    
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::determine_CheckedRules
# ------------------------------------------------------------------------------
proc ApolTE::determine_CheckedRules { } {
    # Any type rules are checked
    set bool1 [expr ($ApolTE::opts(ttrans) == 1 ||  $ApolTE::opts(tmember) == 1 || $ApolTE::opts(tchange) == 1)]
    # All type rules are checked 
    set bool2 [expr ($ApolTE::opts(ttrans) == 1 &&  $ApolTE::opts(tmember) == 1 && $ApolTE::opts(tchange) == 1)]
    # All other rules are NOT checked 
    set bool3 [expr ($ApolTE::opts(teallow) == 0 && $ApolTE::opts(neverallow) == 0 && \
			 $ApolTE::opts(auallow) == 0 && $ApolTE::opts(audeny) == 0 && \
			 $ApolTE::opts(audont) == 0 && $ApolTE::opts(clone) == 0)]
    # Logic: ONLY if ANY type rules are checked or ALL type rules are checked, enable default role checkbutton
    set bool [expr ( ($bool1 || $bool2) && $bool3 )]
    
    return $bool
}

# ------------------------------------------------------------------------------
#  Command ApolTE::defaultType_Enable_Disable
# ------------------------------------------------------------------------------
proc ApolTE::defaultType_Enable_Disable { } {
    variable dflt_type_list
    variable use_3rd_list
    
    # Set/unset indicator on raised tab to indicate search critera has been selected/deselected.
    ApolTE::set_Indicator [$ApolTE::notebook_searchOpts raise]
    
    if { $ApolTE::opts(use_3rd_list) } {
	$ApolTE::dflt_type_list configure -state normal -entrybg white
    } else {
	$ApolTE::dflt_type_list configure -state disabled  -entrybg  $ApolTop::default_bg_color
	selection clear -displayof $ApolTE::dflt_type_list
    }
    # Determine the checked rules
    set bool [ApolTE::determine_CheckedRules]
    
    if { $bool } {
	if { $ApolTE::opts(use_1st_list) && $ApolTE::opts(which_1) == "source"} {
	    $ApolTE::use_3rd_list configure -state normal -text $ApolTE::m_use_dflt_type
	} elseif { !$ApolTE::opts(use_1st_list) } {
	    $ApolTE::use_3rd_list configure -state normal -text $ApolTE::m_use_dflt_type
	}
    } else {
    	    # Disable default type section
	    $ApolTE::dflt_type_list configure -state disabled -entrybg  $ApolTop::default_bg_color
	    selection clear -displayof $ApolTE::dflt_type_list
	    $ApolTE::use_3rd_list configure -state disabled -text $ApolTE::m_disable_dflt_type
	    $ApolTE::use_3rd_list deselect
    }
    return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::change_tgt_dflt_state
# ------------------------------------------------------------------------------	
proc ApolTE::change_tgt_dflt_state { } {
    variable source_list
    variable target_list
    variable dflt_type_list
    variable use_1st_list
    variable use_2nd_list
    variable use_3rd_list
    variable list_types_1 
    variable list_attribs_1 
    variable list_types_2  
    variable list_attribs_2 
    variable global_asSource 
    variable global_any
    
    # Determine the checked rules
    set bool [ApolTE::determine_CheckedRules]
    
    if { $ApolTE::opts(use_1st_list) == 1 && $ApolTE::opts(which_1) == "either" } {
    	# Disable default type section
	$ApolTE::dflt_type_list configure -state disabled -entrybg  $ApolTop::default_bg_color
	selection clear -displayof $ApolTE::dflt_type_list
	$ApolTE::use_3rd_list configure -state disabled -text $ApolTE::m_disable_dflt_type
	$ApolTE::use_3rd_list deselect
	# Disable target type/attrib section
	$ApolTE::target_list configure -state disabled -entrybg  $ApolTop::default_bg_color
	selection clear -displayof $ApolTE::target_list
	$ApolTE::use_2nd_list configure -state disabled -text $ApolTE::m_disable_tgt_ta
	$ApolTE::use_2nd_list deselect
	$ApolTE::incl_indirect2 configure -state disabled
	$ApolTE::incl_indirect2 deselect
	$ApolTE::list_types_2 configure -state disabled
	$ApolTE::list_attribs_2 configure -state disabled
    } elseif { $ApolTE::opts(use_1st_list) == 1 && $bool && $ApolTE::opts(which_1) == "source"} {
	# Logic: if use_1st_list is selected AND (ONLY if ANY type rules are checked or ALL type 
	# rules are checked) AND source option is selected, enable default and target listboxes
	$ApolTE::use_3rd_list configure -state normal -text $ApolTE::m_use_dflt_type
	$ApolTE::use_2nd_list configure -state normal -text $ApolTE::m_use_tgt_ta
    } else {
	$ApolTE::use_2nd_list configure -state normal -text $ApolTE::m_use_tgt_ta
	if { $bool } {
	    $ApolTE::use_3rd_list configure -state normal -text $ApolTE::m_use_dflt_type
	}
    }
    return 0
}			     

# ------------------------------------------------------------------------------
#  Command ApolTE::reverseSelection
# ------------------------------------------------------------------------------
proc ApolTE::reverseSelection {listname} {
	# Returns a list of all the indices of the selected items in the listbox
	set indicesList [$listname curselection]
		
	if { $indicesList != "" } {
		# Returns a count of the number of elements in the listbox (not the index of the last element). 
    		set elementCount [$listname index end]
   
		# This loop goes through each element in the listbox and compares its' index to the indicesList items.
		# If a match is found, then it will clear the selection for that element in the listbox and 
		# then continue to the next element in the listbox, else it sets the selection for non-matching indices.
    		for { set idx 0 } { $idx != $elementCount} { incr idx } {	
			foreach selectedItem_Index $indicesList {
	    			if { $selectedItem_Index == $idx } {
					$listname selection clear $idx
					break
	    			} else {
	    				$listname selection set $idx
	    			}
			}	
    		}
	} else {
		return
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::load_query_options
# ------------------------------------------------------------------------------
proc ApolTE::load_query_options {file_channel parentDlg} {
	# search parameter variables to save
        variable opts
	variable ta1
	variable ta2
        variable ta3
        variable objslistbox
    	variable permslistbox
	variable allow_regex
	variable permslist
	variable selObjectsList
	variable selPermsList

	set query_options ""
        while {[eof $file_channel] != 1} {
		gets $file_channel line
		set tline [string trim $line]
		# Skip empty lines and comments
		if {$tline == "" || [string compare -length 1 $tline "#"] == 0} {
			continue
		}
		set query_options [lappend query_options $tline]
	}
	if {$query_options == ""} {
		return -code error "No query parameters were found."
	}
	# Re-format the query options list into a string where all elements are seperated
	# by a single space. Then split this string into a list using the space as the delimeter.	
	set query_options [split [join $query_options " "]]
	
	# set search parameter options
        set opts(teallow)	[lindex $query_options 0]
	set opts(neverallow)	[lindex $query_options 1]
	set opts(clone)		[lindex $query_options 2]
	set opts(auallow)	[lindex $query_options 3]
	set opts(audeny)	[lindex $query_options 4]
	set opts(audont)        [lindex $query_options 5]
	set opts(ttrans)	[lindex $query_options 6]
	set opts(tmember)	[lindex $query_options 7]
	set opts(tchange)	[lindex $query_options 8]
	set opts(use_1st_list)	[lindex $query_options 9]
	set opts(indirect_1)	[lindex $query_options 10]
	set opts(which_1)	[lindex $query_options 11]
        set opts(use_2nd_list)	[lindex $query_options 12]
        set opts(indirect_2)	[lindex $query_options 13]
        set opts(use_3rd_list)  [lindex $query_options 14]
	set opts(indirect_3)	[lindex $query_options 15]
	set opts(perm_union)	[lindex $query_options 18] 	
	set opts(perm_select)	[lindex $query_options 19]
	
	set i 20
	set invalid_perms ""
	# Parse the list of permissions
	if {[lindex $query_options $i] != "\{\}"} {
	        # we have to pretend to parse a list here since this is a string and not a TCL list.
	        set split_list [split [lindex $query_options $i] "\{"]
	        # If this is not a list of elements, then just get the single element
	        if {[llength $split_list] == 1} {
	        	# Validate that the permission exists in the loaded policy.
     			if {[lsearch -exact $ApolTE::master_permlist [lindex $query_options $i]] != -1} {
	        		set permslist [lappend permslist [lindex $query_options $i]]
	        	} else {
	        		set invalid_perms [lappend invalid_perms [lindex $query_options $i]]
	        	}
	        } else {
		        # An empty list element will be generated because the first character of string 
		        # is in splitChars, so we ignore the first element of the split list.
		        # Validate that the permission exists in the loaded policy.
     			if {[lsearch -exact $ApolTE::master_permlist [lindex $split_list 1]] != -1} {
		        	set permslist [lappend permslist [lindex $split_list 1]]
		        } else {
	        		set invalid_perms [lappend invalid_perms [lindex $split_list 1]]
	        	}
		        incr i
		        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
		        	if {[lsearch -exact $ApolTE::master_permlist [lindex $query_options $i]] != -1} {
		        		set permslist [lappend permslist [lindex $query_options $i]]
		        	} else {
		        		set invalid_perms [lappend invalid_perms [lindex $query_options $i]]
		        	}
		        	incr i
		        }
		        # This is the end of the list, so grab the first element of the split list, since the last 
		        # element of split list is an empty list element. See Previous comment.
			set end_element [lindex [split [lindex $query_options $i] "\}"] 0]
			if {[lsearch -exact $ApolTE::master_permlist $end_element] != -1} {
				set permslist [lappend permslist $end_element]
			} else {
				set invalid_perms [lappend invalid_perms $end_element]
			}
		}
	}
	# Display a popup with a list of invalid permissions
	if {$invalid_perms != ""} {
		foreach perm $invalid_perms {
			set perm_str [append perm_str "$perm\n"]	
		}
		tk_messageBox -icon warning -type ok -title "Invalid Permissions" \
			-message "The following permissions do not exist in the currently \
			loaded policy and were ignored.\n\n$perm_str" \
			-parent $parentDlg
	}
	# Now we're ready to parse the selected objects list
      	incr i
	if {[lindex $query_options $i] != "\{\}"} {
	        # we have to pretend to parse a list here since this is a string and not a TCL list.
	        set split_list [split [lindex $query_options $i] "\{"]
	        # If this is not a list of elements, then just get the single element
	        if {[llength $split_list] == 1} {
	        	set selObjectsList [lappend selObjectsList [lindex $query_options $i]]
	        } else {
		        # An empty list element will be generated because the first character of string 
		        # is in splitChars, so we ignore the first element of the split list.
		        set selObjectsList [lappend selObjectsList [lindex $split_list 1]]
		        incr i
		        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
		        	set selObjectsList [lappend selObjectsList [lindex $query_options $i]]
		        	incr i
		        }
		        # This is the end of the list, so grab the first element of the split list, since the last 
		        # element of split list is an empty list element. See Previous comment.
			set end_element [lindex [split [lindex $query_options $i] "\}"] 0]
			set selObjectsList [lappend selObjectsList $end_element]
		}
	}
	# Now we're ready to parse the selected objects list
      	incr i
	if {[lindex $query_options $i] != "\{\}"} {
	        # we have to pretend to parse a list here since this is a string and not a TCL list.
	        set split_list [split [lindex $query_options $i] "\{"]
	        # If this is not a list of elements, then just get the single element
	        if {[llength $split_list] == 1} {
	        	set selPermsList [lappend selPermsList [lindex $query_options $i]]
	        } else {
		        # An empty list element will be generated because the first character of string 
		        # is in splitChars, so we ignore the first element of the split list.
		        set selPermsList [lappend selPermsList [lindex $split_list 1]]
		        incr i
		        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
		        	set selPermsList [lappend selPermsList [lindex $query_options $i]]
		        	incr i
		        }
		        # This is the end of the list, so grab the first element of the split list, since the last 
		        # element of split list is an empty list element. See Previous comment.
			set end_element [lindex [split [lindex $query_options $i] "\}"] 0]
			set selPermsList [lappend selPermsList $end_element]
		}
	}
	
	# Now we're ready to parse the selected objects list
      	incr i
      	if {[lindex $query_options $i] != "\{\}"} {
		set allow_regex	[string trim [lindex $query_options $i] "\{\}"]
	}
	incr i
	if {[lindex $query_options $i] != "\{\}"} {
		set src_list_type_1 [string trim [lindex $query_options $i] "\{\}"] 
	}
	incr i
	if {[lindex $query_options $i] != "\{\}"} {
		set src_list_type_2 [string trim [lindex $query_options $i] "\{\}"] 
	}
	incr i
	if {[lindex $query_options $i] != "\{\}"} {
		set tgt_list_type_1 [string trim [lindex $query_options $i] "\{\}"]
	}
	incr i
	if {[lindex $query_options $i] != "\{\}"} {
		set tgt_list_type_2 [string trim [lindex $query_options $i] "\{\}"]
	}
	
	# Re-configure list items for type/attributes tab combo boxes
	ApolTE::populate_ta_list 1
	ApolTE::populate_ta_list 2
	incr i
      	if {[lindex $query_options $i] != "\{\}"} {
		set ta1	[string trim [lindex $query_options $i] "\{\}"]
	}
	incr i
      	if {[lindex $query_options $i] != "\{\}"} {
		set ta2	[string trim [lindex $query_options $i] "\{\}"]
	}
	incr i
      	if {[lindex $query_options $i] != "\{\}"} {
		set ta3	[string trim [lindex $query_options $i] "\{\}"]
	}
	
	# Reset Objects and Permissions selections 
	ApolTE::resetObjsPerms_Selections $selObjectsList $selPermsList
    		
	# check enable/disable status
        ApolTE::enable_listbox $ApolTE::source_list 1 $ApolTE::list_types_1 $ApolTE::list_attribs_1
        ApolTE::enable_listbox $ApolTE::target_list 2 $ApolTE::list_types_2 $ApolTE::list_attribs_2
        ApolTE::defaultType_Enable_Disable
        ApolTE::change_tgt_dflt_state
          
        # Check the search criteria for the Classes/Permissions and Types/Attributes tabs
        # and then set the indicator  accordingly.
        ApolTE::set_Indicator [$ApolTE::notebook_searchOpts page 0]
        ApolTE::set_Indicator [$ApolTE::notebook_searchOpts page 1]
        
	return 0
} 

# ------------------------------------------------------------------------------
#  Command ApolTE::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc ApolTE::save_query_options {file_channel query_file} {
        # search parameter variables to save
        variable opts
	variable ta1
	variable ta2
        variable ta3
        variable objslistbox
    	variable permslistbox
	variable allow_regex
	variable permslist
	variable src_list_type_1 
	variable src_list_type_2 	
	variable tgt_list_type_1 	
	variable tgt_list_type_2
				
	# Getting all selected objects. 
	set selObjectsList [ApolTE::get_Selected_ListItems $objslistbox]

	# Getting all selected permissions
	set selPermsList [ApolTE::get_Selected_ListItems $permslistbox]
	
	set options [list \
		$opts(teallow) \
		$opts(neverallow) \
		$opts(clone) \
		$opts(auallow) \
		$opts(audeny) \
		$opts(audont) \
		$opts(ttrans) \
		$opts(tmember) \
		$opts(tchange) \
		$opts(use_1st_list) \
		$opts(indirect_1) \
		$opts(which_1) \
	        $opts(use_2nd_list) \
	        $opts(indirect_2) \
	        $opts(use_3rd_list) \
		$opts(indirect_3) \
		$opts(perm_union) \
		$opts(perm_select) \
		$permslist \
		$selObjectsList \
		$selPermsList \
		$allow_regex \
		$src_list_type_1 \
		$src_list_type_2 \
		$tgt_list_type_1 \
		$tgt_list_type_2 $ta1 $ta2 $ta3]
			
	puts $file_channel "$options"
	
     	return 0
} 

# ----------------------------------------------------------------------------------------
#  Command ApolTE::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc ApolTE::set_Focus_to_Text { tab } {
	variable notebook_results
	
	if {$tab == $ApolTE::emptyTabID} {
		return	
	}
	if {[array exists ApolTE::optionsArray] && [winfo exists $ApolTE::optionsArray($tab,textbox)] } {
		focus $ApolTE::optionsArray($tab,textbox)
	}
	
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command ApolTE::enable_RegExpr
#
#  Description: This function is called when the user selects/deselects the "Enable Regular
#		Expressions" checkbutton. It is also called when the user modifies the value 
#		of the ComboBox by selecting it in the listbox. 
# ----------------------------------------------------------------------------------------
proc ApolTE::enable_RegExpr { which } {
	variable allow_regex
	variable source_list
    	variable target_list
    	variable dflt_type_list
    
	# Check to see if the "Enable Regular Expressions" checkbutton is ON. If not, then return.
	if { $ApolTE::allow_regex == 1 } {
		# If the current value of the ComboBox does not already contain our initial
		# regular expression string, then we need to prepend the string to the 
		# current value. 
		if { $which == 1 } {
        		set ApolTE::ta1 	"^$ApolTE::ta1$"
        		set ta $source_list
		} elseif { $which == 2 } {
			set ApolTE::ta2 	"^$ApolTE::ta2$"
			set ta $target_list
		} elseif { $which == 3 } {
			set ApolTE::ta3		"^$ApolTE::ta3$"
			set ta $dflt_type_list
		} 
		selection clear -displayof $ta
        }
        
	focus -force .
		    			
   	return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::popupResultsTab_Menu
# ------------------------------------------------------------------------------
proc ApolTE::popupResultsTab_Menu { window x y popupMenu page } {
	variable pageID
	set pageID $page
        # Getting global coordinates of the application window (of position 0, 0)
	set gx [winfo rootx $window]	
	set gy [winfo rooty $window]
	
	# Add the global coordinates for the application window to the current mouse coordinates
	# of %x & %y
	set cmx [expr $gx + $x]
	set cmy [expr $gy + $y]

	# Posting the popup menu
   	tk_popup $popupMenu $cmx $cmy
   	
   	return 0
}

# ----------------------------------------------------------------------------------------
#  Command ApolTE::createObjsClassesTab
#
#  Description: This function is called by ApolTE::create.
# ----------------------------------------------------------------------------------------
proc ApolTE::createObjsClassesTab {notebook_objects_tab} {
    variable opts
    variable objslistbox
    variable permslistbox
    variable b_union
    variable b_intersection
    variable b_allPerms
    variable b_selObjsPerms
    
    # Define Object-Classes and Permissions section subframes
    set fm_objs [frame $notebook_objects_tab.objectsFrame -relief flat -borderwidth 1]
    set fm_objs_frame [TitleFrame $fm_objs.objs_frame -text "Object Classes"]
    set fm_perms_frame [TitleFrame $fm_objs.perms_frame -text "Permissions"]
   
    # Define permissions section subframes
    set fm_perm_buttons [frame [$fm_perms_frame getframe].perm_buttonsFrame -relief flat -borderwidth 1]
    set fm_permissions [frame [$fm_perms_frame getframe].permissionsFrame -relief flat -borderwidth 1]
    set fm_permissions_bot [frame $fm_permissions.bottomf -relief flat -borderwidth 1]
    set fm_permissions_mid [frame $fm_permissions.middlef -relief flat -borderwidth 1]
    set fm_perm_buttons_bot [frame $fm_perm_buttons.botf -relief flat -borderwidth 1]
    
    # Placing all frames
    pack $fm_objs -side left -anchor n -padx 2 -fill both -expand yes
    pack $fm_objs_frame -padx 2 -side left -fill y -anchor nw
    pack $fm_perms_frame -padx 2 -side left -fill both -expand yes -anchor nw
    pack $fm_perm_buttons -side left -anchor n -padx 2 -fill both -expand yes
    pack $fm_permissions -side left -anchor n -padx 2 -fill y -expand yes
    pack $fm_perm_buttons_bot -side bottom -anchor nw -fill y -expand yes
    pack $fm_permissions_mid -side top -anchor n -fill both -expand yes
    pack $fm_permissions_bot -side bottom -anchor n -fill both -expand yes
    
    # Define widgets for Object-Classes Section 
    set clearSelectButton [button [$fm_objs_frame getframe].clear -text "Clear" -width 6 \
    		      	-command { 
    		      		$ApolTE::objslistbox selection clear 0 end
    		      		ApolTE::configure_perms 
    		      		ApolTE::set_Indicator [$ApolTE::notebook_searchOpts raise]}]
    set sw_objs       [ScrolledWindow [$fm_objs_frame getframe].sw -auto both]
    set objslistbox [listbox [$sw_objs getframe].lb -height 5 -width 20 -highlightthickness 0 \
		      -listvar ApolTE::objectslist -selectmode multiple -exportselection 0] 
    $sw_objs setwidget $objslistbox
    
    # Set binding when selecting an item in the objects listbox to configure the permissions listbox items.
    bindtags $objslistbox [linsert [bindtags $objslistbox] 3 objects_list_Tag]
    bind objects_list_Tag <<ListboxSelect>> { 
    		ApolTE::configure_perms
    		ApolTE::set_Indicator [$ApolTE::notebook_searchOpts raise] } 
    
    # Define widgets for Permissions Section
    set b_allPerms [radiobutton $fm_perm_buttons.allPerms -text "Show all permissions" \
    			-variable ApolTE::opts(perm_select) -value all \
    			-command { ApolTE::configure_perms }]
    set b_selObjsPerms [radiobutton $fm_perm_buttons.selObjsPerms -text "Only show permissions for\nselected object classes" \
    			-justify left -variable ApolTE::opts(perm_select) -value selected \
    			-command { ApolTE::configure_perms }] 
    set b_union [radiobutton $fm_perm_buttons_bot.union -text "Union" \
    			-variable ApolTE::opts(perm_union) -value union -state disabled \
    			-command { ApolTE::configure_perms }]
    set b_intersection [radiobutton $fm_perm_buttons_bot.intersection -text "Intersection" \
    			-variable ApolTE::opts(perm_union) -value intersection -state disabled \
    			-command { ApolTE::configure_perms }]
    set sw_perms       [ScrolledWindow $fm_permissions_mid.sw -auto both]
    set permslistbox [listbox [$sw_perms getframe].lb -height 5 -width 20 -highlightthickness 0 \
		      -listvar ApolTE::permslist -selectmode multiple -exportselection 0] 
    $sw_perms setwidget $permslistbox
    
    # Set binding when selecting an item in the perms listbox to indicate search critera 
    # has been selected/deselected.
    bindtags $permslistbox [linsert [bindtags $permslistbox] 3 perms_list_Tag]
    bind perms_list_Tag <<ListboxSelect>> { ApolTE::set_Indicator [$ApolTE::notebook_searchOpts raise] } 
    
    # Define Clear and Reverse buttons for the permissions listbox	
    set b_clearReverse [button $fm_permissions_bot.clear -text "Clear" -width 6 -anchor center \
    		      	-command { 
    		      		$ApolTE::permslistbox selection clear 0 end
    		      		ApolTE::set_Indicator [$ApolTE::notebook_searchOpts raise] }]
    set b_reverseSel [button $fm_permissions_bot.reverse -text "Reverse" -width 6 -anchor center \
    		      	-command { ApolTE::reverseSelection $ApolTE::permslistbox }]
    
    # Placing all widgets
    pack $sw_objs -fill both -expand yes
    pack $clearSelectButton -side bottom -pady 2
    pack $b_allPerms $b_selObjsPerms -side top -anchor nw -pady 2 -padx 2
    pack $b_union -side top -anchor nw -padx 18
    pack $b_intersection -side top -anchor nw -padx 18
    pack $sw_perms -side bottom -fill both -expand yes 
    pack $b_clearReverse $b_reverseSel -side left -pady 2 -padx 1 -anchor center -fill x -expand yes 
    
    return 0
}

# ----------------------------------------------------------------------------------------
#  Command ApolTE::createTypesAttribsTab
#
#  Description: This function is called by ApolTE::create.
# ----------------------------------------------------------------------------------------
proc ApolTE::createTypesAttribsTab {notebook_ta_tab} {
    variable opts
    variable source_list
    variable target_list
    variable dflt_type_list
    variable use_1st_list
    variable use_2nd_list
    variable use_3rd_list
    variable incl_indirect1
    variable incl_indirect2
    variable list_types_1 
    variable list_attribs_1 
    variable list_types_2  
    variable list_attribs_2 
    variable global_asSource 
    variable global_any
    
    # Search options section subframes used to group the widget items under the Source Type/Attrib section
    set fm_src [frame $notebook_ta_tab.1st_ta_1ist -relief flat -borderwidth 1]
    set fm_top1 [frame $fm_src.top -relief flat -borderwidth 1]
    set fm_bottom1 [frame $fm_src.bottom -relief sunken -borderwidth 2]

    set fm_inner [frame $fm_bottom1.fm_inner -relief flat -borderwidth 1]
    set fm_incl_cBox [frame $fm_inner.fm_incl_cBox -relief flat -borderwidth 1]
    set fm_src_radio_buttons [frame $fm_inner.fm_src_radio_buttons -relief flat -borderwidth 1]
    set fm_inner_ta [frame $fm_inner.fm_inner_ta -relief ridge -borderwidth 3]
    set fm_ta_buttons [frame $fm_inner_ta.fm_inner_top -relief flat -borderwidth 1]
    set fm_comboBox [frame $fm_inner_ta.fm_inner_bottom -relief flat -borderwidth 1]

    pack $fm_src -side left -anchor nw -padx 2 -fill both -expand yes
    pack $fm_top1 -side top -anchor w -fill x
    pack $fm_bottom1 -side bottom -fill y -expand yes
    pack $fm_inner -padx 5 -fill x
    pack $fm_incl_cBox -fill x
    pack $fm_src_radio_buttons -anchor center
    pack $fm_inner_ta -pady 5
    pack $fm_ta_buttons -side top -padx 5 
    pack $fm_comboBox -side bottom -padx 5 -pady 5

    # Search options section subframes used to group the widget items under the Target Type/Attrib section
    set fm_tgt [frame $notebook_ta_tab.ta2 -relief flat -borderwidth 1]
    set fm_top2 [frame $fm_tgt.top -relief flat -borderwidth 1]
    set fm_bottom2 [frame $fm_tgt.bottom -relief sunken -borderwidth 2]

    set fm_inner2 [frame $fm_bottom2.fm_inner -relief flat -borderwidth 1]
    set fm_incl_cBox2 [frame $fm_inner2.fm_incl_cBox2 -relief flat -borderwidth 1]
    set fm_src_radio_buttons2 [frame $fm_inner2.fm_src_radio_buttons -relief flat -borderwidth 1]
    set fm_inner_ta2 [frame $fm_inner2.fm_inner_ta2 -relief ridge -borderwidth 3]
    set fm_ta_buttons2 [frame $fm_inner_ta2.fm_inner_top -relief flat -borderwidth 1]
    set fm_comboBox2 [frame $fm_inner_ta2.fm_inner_bottom -relief flat -borderwidth 1]

    pack $fm_tgt -side left -anchor nw -padx 2 -fill both -expand yes
    pack $fm_top2 -side top -fill x  
    pack $fm_bottom2 -side bottom -fill y -expand yes
    pack $fm_inner2 -padx 5 -fill x 
    pack $fm_incl_cBox2 -fill x -ipady 10.5
    pack $fm_src_radio_buttons2 -anchor center -expand yes
    pack $fm_inner_ta2 -pady 5 -anchor s -side bottom -expand yes
    pack $fm_ta_buttons2 -side top -padx 5 
    pack $fm_comboBox2 -side bottom -padx 5 -pady 5

    # Search options section subframes used to group the widget items under the Default Type section
    set fm_dflt [frame $notebook_ta_tab.ta3 -relief flat -borderwidth 1]
    set fm_top3 [frame $fm_dflt.top -relief flat -borderwidth 1]
    set fm_bottom3 [frame $fm_dflt.bottom -relief sunken -borderwidth 2]

    set fm_inner3 [frame $fm_bottom3.fm_inner -relief flat -borderwidth 1]
    set fm_incl_cBox3 [frame $fm_inner3.fm_incl_cBox2 -relief flat -borderwidth 1]
    set fm_src_radio_buttons3 [frame $fm_inner3.fm_src_radio_buttons -relief flat -borderwidth 1]
    set fm_inner_ta3 [frame $fm_inner3.fm_inner_ta2 -relief ridge -borderwidth 3]
    set fm_ta_buttons3 [frame $fm_inner_ta3.fm_inner_top -relief flat -borderwidth 1]
    set fm_comboBox3 [frame $fm_inner_ta3.fm_inner_bottom -relief flat -borderwidth 1]

    pack $fm_dflt -side left -anchor nw -padx 2 -fill both -expand yes
    pack $fm_top3 -side top -fill x
    pack $fm_bottom3 -side bottom -fill y -expand yes
    pack $fm_inner3 -padx 5 -fill x 
    pack $fm_incl_cBox3 -fill x -ipady 10.5
    pack $fm_src_radio_buttons3 -anchor center -expand yes -ipady 10.5
    pack $fm_inner_ta3 -pady 5 -anchor s -side bottom -expand yes
    pack $fm_ta_buttons3 -side top -padx 5 -ipady 10
    pack $fm_comboBox3 -side bottom -padx 5 -pady 5 -expand yes -fill x

    # Widget items for Source Type/Attrib section          
    set source_list [ComboBox $fm_comboBox.cb -width 22 \
    	-textvariable ApolTE::ta1 -helptext "Type or select a type or attribute" \
    	-modifycmd {ApolTE::enable_RegExpr 1} ]  
    	 
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list. 
    bindtags $source_list.e [linsert [bindtags $source_list.e] 3 source_list_Tag]
    bind source_list_Tag <KeyPress> { Apol_Users::_create_popup $ApolTE::source_list %W %K }
        
    # Radio buttons and check buttons for Source Type/Attrib section
    set list_types_1 [checkbutton $fm_ta_buttons.list_types_1 -text "Types" \
    	-variable ApolTE::src_list_type_1 \
    	-command "ApolTE::populate_ta_list 1"]
    set list_attribs_1 [checkbutton $fm_ta_buttons.list_attribs_1 -text "Attribs" \
    	-variable ApolTE::src_list_type_2 \
    	-command "ApolTE::populate_ta_list 1"]
    set global_asSource [radiobutton $fm_src_radio_buttons.source_1 -text "As source" -variable ApolTE::opts(which_1) \
			 -value source \
			 -command "ApolTE::change_tgt_dflt_state"]
    set global_any [radiobutton $fm_src_radio_buttons.any_1 -text "Any" -variable ApolTE::opts(which_1) \
			 -value either \
		         -command "ApolTE::change_tgt_dflt_state"]
    set use_1st_list [checkbutton $fm_top1.use_1st_list -text $ApolTE::m_use_src_ta \
			 -variable ApolTE::opts(use_1st_list) \
			 -command "ApolTE::enable_listbox $source_list 1 $list_types_1 $list_attribs_1" \
		         -offvalue 0 \
		         -onvalue  1 ]
    set incl_indirect1 [checkbutton $fm_incl_cBox.incl_indirect -text $ApolTE::m_incl_indirect \
			 -variable ApolTE::opts(indirect_1) \
			 -onvalue 1 \
			 -offvalue 0]
	     
    # Widget items for Target Type/Attrib section
    set target_list [ComboBox $fm_comboBox2.cb -width 22 \
    	-textvariable ApolTE::ta2 -helptext "Type or select a type or attribute" \
    	-modifycmd {ApolTE::enable_RegExpr 2} ] 
    	
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $target_list.e [linsert [bindtags $target_list.e] 3 target_list_Tag]
    bind target_list_Tag <KeyPress> { Apol_Users::_create_popup $ApolTE::target_list %W %K }
    
    # Radio buttons and check buttons for Target Type/Attrib section
    set list_types_2 [checkbutton $fm_ta_buttons2.list_types_2 -text "Types" \
	-variable ApolTE::tgt_list_type_1 \
    	-command "ApolTE::populate_ta_list 2" ]
    set list_attribs_2 [checkbutton $fm_ta_buttons2.list_attribs_2 -text "Attribs" \
	-variable ApolTE::tgt_list_type_2 \
	-command "ApolTE::populate_ta_list 2" ]
	
    set use_2nd_list [checkbutton $fm_top2.use_2nd_list -text $ApolTE::m_disable_tgt_ta \
	-variable ApolTE::opts(use_2nd_list) \
	-offvalue 0 \
        -onvalue  1 \
        -command "ApolTE::enable_listbox $target_list 2 $list_types_2 $list_attribs_2"]
    set incl_indirect2 [checkbutton $fm_incl_cBox2.incl_indirect -text $ApolTE::m_incl_indirect \
			    -variable ApolTE::opts(indirect_2) \
			    -onvalue 1 \
			    -offvalue 0]
    
    # Widget items for Default Type section
    set dflt_type_list [ComboBox $fm_comboBox3.cb -width 22 -helptext "Third type search parameter"  \
    	-textvariable ApolTE::ta3 -helptext "Type or select a type" \
    	-modifycmd {ApolTE::enable_RegExpr 3} ]
    	
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $dflt_type_list.e [linsert [bindtags $dflt_type_list.e] 3 dflt_type_list_Tag]
    bind dflt_type_list_Tag <KeyPress> { Apol_Users::_create_popup $ApolTE::dflt_type_list %W %K }
    
    # Radio buttons and check buttons for Default Type section
    set use_3rd_list [checkbutton $fm_top3.use_3rd_list -text $ApolTE::m_disable_dflt_type \
			     -variable ApolTE::opts(use_3rd_list) \
			     -offvalue 0 \
			     -onvalue  1 \
			     -command "ApolTE::defaultType_Enable_Disable" ]

    # Placing Source Type/Attrib widget items 
    pack $use_1st_list -side top -anchor nw 
    pack $incl_indirect1 -side top -anchor w 
    pack $global_asSource $global_any -side left -anchor center 
    pack $list_types_1 $list_attribs_1 -side left -anchor center
    pack $source_list -anchor w -expand yes -fill x -side bottom

    # Placing Target Type/Attrib widget items
    pack $use_2nd_list -side top -anchor nw
    pack $incl_indirect2 -side top -anchor w 
    pack $list_types_2  $list_attribs_2 -side left
    pack $target_list -anchor w -expand yes -fill x

    # Placing Default Type widget items
    pack $use_3rd_list -side top -anchor w
    pack $dflt_type_list -anchor w -fill x -expand yes
    
    # Check enable/disable status
    ApolTE::enable_listbox $source_list 1 $list_types_1 $list_attribs_1
    ApolTE::enable_listbox $target_list 2 $list_types_2 $list_attribs_2
    ApolTE::defaultType_Enable_Disable
    ApolTE::change_tgt_dflt_state
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command ApolTE::create
# ------------------------------------------------------------------------------
proc ApolTE::create {nb} {
    variable notebook_searchOpts
    variable teallow 
    variable neverallow 
    variable auallow 
    variable audeny
    variable audont
    variable ttrans 
    variable tmember 
    variable tchange 
    variable clone
    variable notebook_results
    variable currTabCount
    variable pageNums
    variable tabName
    variable tabText
    variable results
    variable popupTab_Menu
    variable updateButton
    variable cb_RegExp

    # Layout Frames
    set frame [$nb insert end $ApolTop::terules_tab -text "TE Rules"]
    set pw2 [PanedWindow $frame.pw2 -side left -weights available]
    $pw2 add -minsize 200
    $pw2 add
    set topf  [frame [$pw2 getframe 0].topf]
    set bottomf [frame [$pw2 getframe 1].bottomf]

    set pw1 [PanedWindow $topf.pw1 -side top -weights available]
    $pw1 add -minsize 225
    $pw1 add -weight 3

    # Major SubFrames:
    # tbox - holds rule selection widgets
    # obox - holds search options widgets
    # dbox - holds display window widgets
    # bBox - holds action buttons widgets
    set tbox [TitleFrame [$pw1 getframe 0].tbox -text "Rule Selection"]
    set obox [frame [$pw1 getframe 1].obox]
    set dbox [TitleFrame $bottomf.dbox -text "Type Enforcement Rules Display"]
    
    # Placing the layout frames
    pack $pw2 -fill both -expand yes
    pack $pw1 -fill both -expand yes
    pack $topf -fill both -expand yes
    pack $bottomf -fill both -expand yes

    
    # Search options section subframe
    set frame_search $obox
    
    # Action Buttons subframe
    set bBox [frame $frame_search.bBox]
    
    # Placing major subframes
    pack $bBox -side right -anchor ne -fill both -expand yes -padx 5
    pack $obox -side right -anchor w -fill both -padx 5 -expand yes
    pack $tbox -side top -anchor nw -fill both -expand yes -padx 5
    pack $dbox -side left -fill both -expand yes -anchor e -padx 5 -pady 5
               
    # Rule types section subframes
    set fm_rules [$tbox getframe]
    set optsfm [frame $fm_rules.optsfm]
    set tefm [frame $optsfm.tefm]
    set ttfm [frame $optsfm.ttfm]

    # First column of checkbuttons under rule selection subframe
    set teallow [checkbutton $tefm.teallow -text "allow" -variable ApolTE::opts(teallow) \
	    -command "ApolTE::defaultType_Enable_Disable"]
    set neverallow [checkbutton $tefm.neverallow -text "neverallow" -variable ApolTE::opts(neverallow) \
            -command "ApolTE::defaultType_Enable_Disable" ]
    set auallow [checkbutton $tefm.auallow -text "auditallow" -variable ApolTE::opts(auallow) \
            -command "ApolTE::defaultType_Enable_Disable" ]
    set audeny [checkbutton $tefm.audeny -text "auditdeny" -variable ApolTE::opts(audeny) \
            -command "ApolTE::defaultType_Enable_Disable" ]
    set audont [checkbutton $tefm.audont -text "dontaudit"  -variable ApolTE::opts(audont) \
    	    -command "ApolTE::defaultType_Enable_Disable" ]
    
    # Second column of checkbuttons under rule selection subframe
    set ttrans [checkbutton $ttfm.ttrans -text "type_trans" -variable ApolTE::opts(ttrans) \
	    -command "ApolTE::defaultType_Enable_Disable"]
    set tmember [checkbutton $ttfm.tmember -text "type_member" -variable ApolTE::opts(tmember) \
            -command "ApolTE::defaultType_Enable_Disable"]
    set tchange [checkbutton $ttfm.tchange -text "type_change" -variable ApolTE::opts(tchange) \
            -command "ApolTE::defaultType_Enable_Disable" ]
    set clone [checkbutton $ttfm.clone -text "clone" -variable ApolTE::opts(clone) \
            -command "ApolTE::defaultType_Enable_Disable" ]
    
    # Checkbutton to Enable/Disable Regular Expressions option.
    set cb_RegExp [checkbutton [$pw1 getframe 0].cb_RegExp -text "Enable Regular Expressions" \
    		-variable ApolTE::allow_regex]
            	    
    # NoteBook creation for search options subframe
    set notebook_searchOpts [NoteBook $frame_search.nb]
    set notebook_ta_tab [$notebook_searchOpts insert end $ApolTE::ta_TabID -text $ApolTE::m_ta_tab]
    set notebook_objects_tab [$notebook_searchOpts insert end $ApolTE::cp_TabID -text $ApolTE::m_obj_perms_tab]
    ApolTE::createTypesAttribsTab $notebook_ta_tab
    ApolTE::createObjsClassesTab $notebook_objects_tab
    
    # Action buttons
    set newButton [button $bBox.new -text "New" -width 6 -command { ApolTE::searchTErules newTab }]
    set updateButton [button $bBox.upDate -text "Update" -width 6 -state disabled \
    		-command { ApolTE::searchTErules updateTab }]
    #set printButton [button $bBbox.print -text "Print" -width 6 -command {ApolTop::unimplemented}]
	             
    # Popup menu widget
    set popupTab_Menu [menu .popupTab_Menu]
    $popupTab_Menu add command -label "Delete Tab" \
	-command { ApolTE::delete_ResultsTab $ApolTE::pageID }
	
    # Notebook creation for results
    set notebook_results [NoteBook [$dbox getframe].nb_results]
    $notebook_results bindtabs <Button-3> {ApolTE::popupResultsTab_Menu %W %x %y $ApolTE::popupTab_Menu} 
    $notebook_results bindtabs <Button-1> {ApolTE::set_Widget_SearchOptions}
    
    # Add button bar at bottom of results section for closing tabs.
    set bFrame [frame [$dbox getframe].bFrame -relief sunken -bd 1]
    set bClose [button $bFrame.bClose -text "Close Tab" -command { 
    		set raisedPage [$ApolTE::notebook_results raise]
    		ApolTE::delete_ResultsTab $raisedPage }]
    pack $bFrame -side bottom -anchor center -fill x -padx 4 -pady 1
    pack $bClose -side bottom -anchor center -fill x -padx 1 -pady 1
       
    # Placing action buttons
    pack $newButton $updateButton -side top -pady 5 -anchor se 
    
    # Placing rule selection section widgets
    pack $teallow $neverallow $auallow $audeny $audont -anchor w 
    pack $ttrans $tmember $tchange $clone -anchor w 
    pack $tefm $ttfm -side left -anchor nw 
    pack $cb_RegExp -side bottom -anchor center -pady 2
    pack $optsfm -side top -fill x -expand yes -anchor nw
    
    # Placing the search options notebook frame within the search options section    
    $notebook_searchOpts compute_size
    pack $notebook_searchOpts -fill both -expand yes -padx 4
    set raisedPage [$notebook_searchOpts raise [$notebook_searchOpts page 0]]
    ApolTE::set_Indicator $raisedPage
    ApolTE::create_empty_resultsTab
           
    # Placing the results notebook frame within the results section    
    pack $notebook_results -fill both -expand yes -padx 4
       
    return $frame	
}
