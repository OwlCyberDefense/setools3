# Copyright (C) 2001-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets


##############################################################
# ::Apol_TE
#  
# The TE Rules page
##############################################################
namespace eval Apol_TE {
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
	variable show_enabled_rules	1
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
	# We use the prefix 'Apol_' for all notebook tabnames. Also, tabnames may not have a colon.
	variable emptyTabID		"Apol_Emptytab"
	variable tabName		"Apol_ResultsTab"
	variable tabText		"Results "
	variable pageID			""	
	variable results		""
	variable tab_deleted_flag	0
	variable optionsArray		
	# callback procedures for the tab menu. Each element in this list is an embedded list of 2 items.
 	# The 2 items consist of the command label and the function name. The tabname will be added as an
 	# argument to the callback procedure.
 	variable tab_menu_callbacks	""
 	
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
	
	variable disabled_rule_tag     DISABLE_RULE
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_TE::goto_line { line_num } {
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
		
		ApolTop::goto_line $line_num $Apol_TE::optionsArray($raisedPage,textbox)
	}
	return 0
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_TE::search { str case_Insensitive regExpr srch_Direction } {
	variable notebook_results
	
	if { [$notebook_results pages] != "" } {
		set raisedPage 	[ $notebook_results raise ]
		ApolTop::textSearch $Apol_TE::optionsArray($raisedPage,textbox) $str $case_Insensitive $regExpr $srch_Direction
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::searchTErules
# ------------------------------------------------------------------------------
proc Apol_TE::searchTErules { whichButton } {
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
	variable allow_regex
	variable show_enabled_rules
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
	set selObjectsList [Apol_TE::get_Selected_ListItems $objslistbox]

	# Getting all selected permissions
	set selPermsList [Apol_TE::get_Selected_ListItems $permslistbox]
		
	# Making the call to apol_GetTErules to search for rules with given options
	ApolTop::setBusyCursor
	set rt [catch {set results [apol_SearchTErules $opts(teallow) $opts(neverallow) \
		$opts(clone) $opts(auallow) $opts(audeny) $opts(audont) $opts(ttrans) \
		$opts(tmember) $opts(tchange) $opts(use_1st_list) $opts(indirect_1) \
		$ta1 $opts(which_1) $opts(use_2nd_list) $opts(indirect_2) \
		$ta2 $opts(use_3rd_list) $opts(indirect_3) $ta3 $selObjectsList $selPermsList\
		$allow_regex $ta1_opt $ta2_opt $show_enabled_rules]} err]
	
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		ApolTop::resetBusyCursor
		return 
	} 

	switch $whichButton {
		newTab {
			# Enable the update button.
			$Apol_TE::updateButton configure -state normal
			
			# Create the new results tab and set optionsArray.
			set raisedPage [Apol_TE::create_New_ResultsTab $results]
			Apol_TE::set_OptionsArray $raisedPage $selObjectsList $selPermsList
		}
		updateTab {
			set raisedPage 	[ $notebook_results raise ]
			$Apol_TE::optionsArray($raisedPage,textbox) configure -state normal
			# Remove any custom tags.
			Apol_PolicyConf::remove_HyperLink_tags $Apol_TE::optionsArray($raisedPage,textbox)
    			$Apol_TE::optionsArray($raisedPage,textbox) delete 0.0 end
			Apol_TE::insertTERules $Apol_TE::optionsArray($raisedPage,textbox) $results 
    			ApolTop::makeTextBoxReadOnly $Apol_TE::optionsArray($raisedPage,textbox)
			Apol_TE::set_OptionsArray $raisedPage $selObjectsList $selPermsList
		}
		default {
			return -code error
		}
	} 
        
        ApolTop::resetBusyCursor
        
        return 0
}

# --------------------------------------
#  Command Apol_TE::disable_te_rule {}
# --------------------------------------
proc Apol_TE::disable_te_rule {tb} {
	$tb tag configure $Apol_TE::disabled_rule_tag -foreground red 
	return 0
}

# -----------------------------------------------------------
#  Command Apol_TE::insert_disabled_rule_tag { tb start end}
# 		- start and end are l.c line positions
# -----------------------------------------------------------
proc Apol_TE::insert_disabled_rule_tag { tb start end } {
	$tb tag add $Apol_TE::disabled_rule_tag $start $end
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::insertTERules
#	takes a results list (from apol_SearchTERules) and explodes it into
#	a provided text box
# ------------------------------------------------------------------------------
proc Apol_TE::insertTERules { tb results } {	
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
		$tb insert end ") "
		set cur_line_pos [$tb index insert]
		$tb insert end "$rule"
		incr x
		# The next element should be the enabled boolean flag.
		if {[lindex $results $x] == 0} {
			$tb insert end "   "
			set cur_line_pos [$tb index insert]
			$tb insert end "\[Disabled\]\n"
			# NOTE: The character at index2 isn't tagged, so must add 1 to index2 argument.
			Apol_TE::insert_disabled_rule_tag $tb $cur_line_pos $line_num.end
		} else {
			$tb insert end "\n"
		}
	}	
	Apol_PolicyConf::configure_HyperLinks $tb
	Apol_TE::disable_te_rule $tb
	update idletasks
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::set_OptionsArray
# ------------------------------------------------------------------------------
proc Apol_TE::set_OptionsArray { raisedPage selObjectsList selPermsList } {
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
	variable show_enabled_rules
		
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
	set optionsArray($raisedPage,show_enabled_rules) $show_enabled_rules
		
	return 0
}

#----------------------------------------------------------------------------------
# Apol_TE::create_empty_resultsTab
#----------------------------------------------------------------------------------
proc Apol_TE::create_empty_resultsTab { } {
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
	$notebook_results insert end $Apol_TE::emptyTabID -text "Empty Tab"
    	    	
    	# Set the NoteBook size
    	$notebook_results compute_size
    				
    	# Raise the new tab
    	set raisedPage 	[$notebook_results raise $Apol_TE::emptyTabID]
	
    	return 0

}

# ------------------------------------------------------------------------------
#  Command Apol_TE::create_New_ResultsTab
# ------------------------------------------------------------------------------
proc Apol_TE::create_New_ResultsTab { results } {
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
	Apol_TE::insertTERules $resultsbox $results
	ApolTop::makeTextBoxReadOnly $resultsbox 
	# Hold a reference to the results tab text widget
	set optionsArray($raisedPage,textbox) $resultsbox
	
    	return $raisedPage
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::delete_ResultsTab
# ------------------------------------------------------------------------------
proc Apol_TE::delete_ResultsTab { pageID } {
	variable notebook_results
	variable currTabCount
	variable tab_deleted_flag
	variable optionsArray
	
	# Do not delete the emtpy tab!!
	if { [$notebook_results index $Apol_TE::emptyTabID] != [$notebook_results index $pageID]} {
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
		if {$raisedPage == $Apol_TE::emptyTabID} {
			Apol_TE::reset_search_criteria
			$Apol_TE::updateButton configure -state disabled
		} else {
			# Set the search option widgets according to the now raised results tab.
			Apol_TE::set_Widget_SearchOptions $raisedPage
			set tab_deleted_flag 0
		}
	}
     		
    	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::resetObjsPerms_Selections
# ------------------------------------------------------------------------------
proc Apol_TE::resetObjsPerms_Selections { selObjectsList selPermsList } {
	variable objslistbox
    	variable permslistbox
	
	# Now get the number of elements in each listbox 
	set objectsCount [$objslistbox index end]
	set permsCount 	 [$permslistbox index end]
	# Clear the selections in the listboxes.
	$objslistbox selection clear 0 end
	$permslistbox selection clear 0 end
	
	if {$selObjectsList != ""} {
		$permslistbox configure -bg white
	} else { 
		$permslistbox configure -bg $ApolTop::default_bg_color
	}
		
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
#  Command Apol_TE::set_Indicator
# ------------------------------------------------------------------------------
proc Apol_TE::set_Indicator { pageID } {
	variable notebook_searchOpts     
	variable opts 
	variable objslistbox
    	variable permslistbox	
    	variable cp_TabID		
	variable ta_TabID			 		
	
	if { $pageID == $cp_TabID } {
		# Reset the tab text to the initial value and then get the raised tab.
		$notebook_searchOpts itemconfigure $cp_TabID -text $Apol_TE::m_obj_perms_tab
		set objText 	[$notebook_searchOpts itemcget $cp_TabID -text]
		# Getting all selected objects. 
		set selObjectsList [Apol_TE::get_Selected_ListItems $objslistbox]

		# Getting all selected permissions
		set selPermsList [Apol_TE::get_Selected_ListItems $permslistbox]
		
		if { $selObjectsList != "" || $selPermsList != "" } {
			append objText " *"
			$notebook_searchOpts itemconfigure $cp_TabID -text $objText 
		} else {
			$notebook_searchOpts itemconfigure $cp_TabID -text $Apol_TE::m_obj_perms_tab
		}
	} else {
		# Reset the tab text to the initial value and then get the raised tab.
		$notebook_searchOpts itemconfigure $ta_TabID -text $Apol_TE::m_ta_tab
		set taText  	[$notebook_searchOpts itemcget $ta_TabID -text]
		if { $opts(use_1st_list) || $opts(use_2nd_list) || $opts(use_3rd_list) } {
			append taText " *"
			$notebook_searchOpts itemconfigure $ta_TabID -text $taText
		} else {
			$notebook_searchOpts itemconfigure $ta_TabID -text $Apol_TE::m_ta_tab
		}
	}
	
    	set objText ""
    	set taText  ""
    	set selObjectsList ""
    	set selPermsList   ""
    	
    	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::set_Widget_SearchOptions
# ------------------------------------------------------------------------------
proc Apol_TE::set_Widget_SearchOptions { pageID } {
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
	variable show_enabled_rules
	
	set pageID [ApolTop::get_tabname $pageID]
	set raised [$notebook_results raise]
	# First check flag to determine if the user has simply selected the 
	# currently raised tab and so just return without updating search options.
	if { $raised == $pageID && $tab_deleted_flag == 0 } {
		return
	}
	if { $pageID == $Apol_TE::emptyTabID } {
		Apol_TE::reset_search_criteria
		$Apol_TE::updateButton configure -state disabled
		return
	}
	$Apol_TE::updateButton configure -state normal
	    
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
	set show_enabled_rules 	$optionsArray($pageID,show_enabled_rules)
			
	# Re-configure list items for type/attributes tab combo boxes
	Apol_TE::populate_ta_list 1
	Apol_TE::populate_ta_list 2
	set ta1			$optionsArray($pageID,ta1)
        set ta2			$optionsArray($pageID,ta2)
	set ta3			$optionsArray($pageID,ta3)	
	
	# Reset Objects and Permissions selections 
	Apol_TE::resetObjsPerms_Selections $selObjectsList $selPermsList
    		
	# check enable/disable status
        Apol_TE::enable_listbox $Apol_TE::source_list 1 $Apol_TE::list_types_1 $Apol_TE::list_attribs_1
        Apol_TE::enable_listbox $Apol_TE::target_list 2 $Apol_TE::list_types_2 $Apol_TE::list_attribs_2
        Apol_TE::defaultType_Enable_Disable
        Apol_TE::change_tgt_dflt_state
          
        # Check the search criteria for the Classes/Permissions and Types/Attributes tabs
        # and then set the indicator  accordingly.
        Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts page 0]
        Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts page 1]
	
	Apol_TE::set_Focus_to_Text $pageID 
	              	
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::get_Selected_ListItems
# ------------------------------------------------------------------------------
proc Apol_TE::get_Selected_ListItems { listname } {
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
#  Command Apol_TE::open
# ------------------------------------------------------------------------------
proc Apol_TE::open { } {
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
	set ta_state_Array($Apol_TE::list_types_1)   $src_list_type_1
	set ta_state_Array($Apol_TE::list_attribs_1) $src_list_type_2
	set ta_state_Array($Apol_TE::list_types_2)   $tgt_list_type_1
	set ta_state_Array($Apol_TE::list_attribs_2) $tgt_list_type_2
	
	# Populate the type/attribs combo-boxes
	Apol_TE::populate_ta_list 1
        Apol_TE::populate_ta_list 2
        $Apol_TE::dflt_type_list configure -values $Apol_Types::typelist
                
        # Check whether "classes" are included in the current opened policy file
        if {$ApolTop::contents(classes) == 1} {
        	set rt [catch {set objectslist [apol_GetNames classes]} err]
		if {$rt != 0} {	
			return -code error $err 
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
			return -code error $err 
		} 
		set master_permlist [lsort $master_permlist]
		set permslist $master_permlist
	}
	Apol_TE::configure_perms
	
        return 0
}
	
# ------------------------------------------------------------------------------
#  Command Apol_TE::close
# ------------------------------------------------------------------------------
proc Apol_TE::close { } {
	variable opts
	variable source_list
	variable target_list
	variable list_types_1
	variable list_attribs_1
	variable list_types_2  
	variable list_attribs_2 
	variable results
	variable ta_state_Array
	        
	Apol_TE::reset_search_criteria
	
        # Close all results tabs.
        Apol_TE::close_All_ResultsTabs
        # Reset objects/permissions lists
        set Apol_TE::objectslist 	""
	set Apol_TE::permslist 		""
	set Apol_TE::master_permlist 	""
	$Apol_TE::permslistbox configure -bg $ApolTop::default_bg_color
	$Apol_TE::objslistbox configure -bg $ApolTop::default_bg_color
    	array unset ta_state_Array
     	
	return 0
}

proc Apol_TE::free_call_back_procs { } {
       	variable tab_menu_callbacks	
    		
	set tab_menu_callbacks ""
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::reset_search_criteria
# ------------------------------------------------------------------------------
proc Apol_TE::reset_search_criteria { } {
	variable source_list
	variable target_list
	variable list_types_1
	variable list_attribs_1
	variable list_types_2  
	variable list_attribs_2 
	variable objslistbox
    	variable permslistbox
    	
	Apol_TE::reinitialize_default_search_options
	
	# check enable/disable status
        Apol_TE::enable_listbox $source_list 1 $list_types_1 $list_attribs_1
        Apol_TE::enable_listbox $target_list 2 $list_types_2 $list_attribs_2
        Apol_TE::defaultType_Enable_Disable
        Apol_TE::change_tgt_dflt_state
    	$Apol_TE::b_union configure -state disabled
    	$Apol_TE::b_intersection configure -state disabled
        
        # Reset Classes/Permissions and Types/Attributes tabs text to the initial value.
        set objText 	[$Apol_TE::notebook_searchOpts itemcget $Apol_TE::cp_TabID -text]
        set taText  	[$Apol_TE::notebook_searchOpts itemcget $Apol_TE::ta_TabID -text]
	if { $objText != $Apol_TE::m_obj_perms_tab } {
		$Apol_TE::notebook_searchOpts itemconfigure $Apol_TE::cp_TabID -text $Apol_TE::m_obj_perms_tab
	}
	if { $taText != $Apol_TE::m_ta_tab } {
		$Apol_TE::notebook_searchOpts itemconfigure $Apol_TE::ta_TabID -text $Apol_TE::m_ta_tab
	}
	
	# Clear the selections in the listboxes.
	$objslistbox selection clear 0 end
	$permslistbox selection clear 0 end
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::reinitialize_default_search_options
# ------------------------------------------------------------------------------
proc Apol_TE::reinitialize_default_search_options { } {
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
	set Apol_TE::allow_regex	1
	set Apol_TE::show_enabled_rules	1
	set Apol_TE::src_list_type_1	1
	set Apol_TE::src_list_type_2	0
	set Apol_TE::tgt_list_type_1	1
	set Apol_TE::tgt_list_type_2	0 
	set ta1_opt 	"types"
	set ta2_opt 	"types"	
	set Apol_TE::ta1 ""
	set Apol_TE::ta2 ""
        set Apol_TE::ta3 ""
	set Apol_TE::selObjectsList  ""
    	set Apol_TE::selPermsList    ""
    	
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::close_All_ResultsTabs
# ------------------------------------------------------------------------------
proc Apol_TE::close_All_ResultsTabs { } {
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
	$notebook_results raise $Apol_TE::emptyTabID
	# Disable the update button.
	$Apol_TE::updateButton configure -state disabled
				
	# Reset the result tab variables.
	set Apol_TE::pageNums 		0
	set Apol_TE::currTabCount	0
	set Apol_TE::pageID		""	
	set Apol_TE::results		""
			
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::populate_ta_list
# ------------------------------------------------------------------------------
proc Apol_TE::populate_ta_list { list } {
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
			set ta_state_Array($Apol_TE::list_types_1) 	1
			set ta_state_Array($Apol_TE::list_attribs_1) 	1
		} elseif { $src_list_type_1 == 1 && $src_list_type_2 == 0 } {
			set ta1_opt "types"
			set ta_state_Array($Apol_TE::list_types_1) 	1
			set ta_state_Array($Apol_TE::list_attribs_1) 	0
		} elseif { $src_list_type_1 == 0 && $src_list_type_2 == 1 } {
			set ta1_opt "attribs"
			set ta_state_Array($Apol_TE::list_types_1) 	0
			set ta_state_Array($Apol_TE::list_attribs_1) 	1
		} elseif { $src_list_type_1 == 0 && $src_list_type_2 == 0} {
			if { $ta_state_Array($Apol_TE::list_types_1) == 1 } {
				$Apol_TE::list_types_1 invoke
			} elseif { $ta_state_Array($Apol_TE::list_attribs_1) == 1 } {
				$Apol_TE::list_attribs_1 invoke
			}
		}
		set which $ta1_opt
		set uselist $Apol_TE::source_list
		set ta Apol_TE::ta1
	        set cBox $incl_indirect1
	        set useStatus $Apol_TE::opts(use_1st_list)
	} elseif { $list == 2 } {
		# Make sure that either "Types" OR "Attribs", OR Both checkbuttons are selected
		# and set the variable ta2_opt accordingly. ta_state_Array variable holds the 
		# previous state before a checkbutton was invoked. We use this array variable
		# to make sure that the user cannot DESELECT both checkbuttons.
		if { $tgt_list_type_1 == 1 && $tgt_list_type_2 == 1} {
			set ta2_opt "both"
			set ta_state_Array($Apol_TE::list_types_2) 	1
			set ta_state_Array($Apol_TE::list_attribs_2) 	1
		} elseif { $tgt_list_type_1 == 1 && $tgt_list_type_2 == 0 } {
			set ta2_opt "types"
			set ta_state_Array($Apol_TE::list_types_2) 	1
			set ta_state_Array($Apol_TE::list_attribs_2) 	0
		} elseif { $tgt_list_type_1 == 0 && $tgt_list_type_2 == 1 } {
			set ta2_opt "attribs"
			set ta_state_Array($Apol_TE::list_types_2) 	0
			set ta_state_Array($Apol_TE::list_attribs_2) 	1
		} elseif { $tgt_list_type_1 == 0 && $tgt_list_type_2 == 0} {
			if { $ta_state_Array($Apol_TE::list_types_2) == 1 } {
				$Apol_TE::list_types_2 invoke
			} elseif { $ta_state_Array($Apol_TE::list_attribs_2) == 1 } {
				$Apol_TE::list_attribs_2 invoke
			}
		}
		set which $ta2_opt
		set uselist $Apol_TE::target_list
		set ta Apol_TE::ta2
	        set cBox $incl_indirect2
	        set useStatus $Apol_TE::opts(use_2nd_list)
	} elseif { $list == 3 } {
		set which $Apol_RBAC::opts(list_type)
		set uselist $Apol_RBAC::list_tgt
		set ta Apol_TE::ta3
	        set useStatus $Apol_TE::opts(use_3rd_list)
	} else {
		return -code error
	}
	
	# Clear the value in the ComboBox
	#set $ta ""
		
	switch $which {
		types {
			$uselist configure -values $Apol_Types::typelist
			if { $useStatus } {
		        	$cBox configure -state normal	    
		        }
		}
		attribs {
			$uselist configure -values $Apol_Types::attriblist
		        $cBox configure -state disabled
		        $cBox deselect
		}
		both {
			set bothlist [concat $Apol_Types::typelist $Apol_Types::attriblist]
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
#  Command Apol_TE::configure_perms
# ------------------------------------------------------------------------------
proc Apol_TE::configure_perms { } {
	variable permslist
	variable objslistbox
    	variable permslistbox
	variable master_permlist
	
	# First clear the selection in the permissions listbox and then get the selected items
	# from the objects listbox.
	$Apol_TE::permslistbox selection clear 0 end
	set objectsList [Apol_TE::get_Selected_ListItems $objslistbox]
	
	if { $Apol_TE::opts(perm_select) == "all" } {
		$Apol_TE::b_union configure -state disabled
    		$Apol_TE::b_intersection configure -state disabled
		set permslist $master_permlist
		if {$permslist != ""} {
			$permslistbox configure -bg white
		}
	} elseif { $Apol_TE::opts(perm_select) == "selected" && $objectsList != ""} {
		# If items from the objects list have been selected and the selected radio
		# button is selected, enable and invoke union and intersect radio buttons.
		$Apol_TE::b_union configure -state normal
    		$Apol_TE::b_intersection configure -state normal
    		if { $Apol_TE::opts(perm_union) == "union"} {
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
    		if { $Apol_TE::opts(perm_select) == "selected" } {
    			$Apol_TE::b_union configure -state disabled
    			$Apol_TE::b_intersection configure -state disabled
    		}
    		return
    	}
     	set objectsList ""
     		
    	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::enable_listbox
# ------------------------------------------------------------------------------
proc Apol_TE::enable_listbox { cBox list_number b1 b2 } {
    variable global_asSource 
    variable global_any
    variable incl_indirect1
    variable incl_indirect2
    variable opts

    # Set/unset indicator on raised tab to indicate search critera has been selected/deselected.
    Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts raise]
	    
    if { $list_number == 1 } {
	set which list1
    } elseif {$list_number == 2} {
	set which list2
    } else {
	return -code error
    }
    switch $which {
	list1 {	    
	    if { $Apol_TE::opts(use_1st_list) } {
		if { $Apol_TE::opts(which_1) == "source"} {
		    $cBox configure -state normal -entrybg white
		    $b1 configure -state normal
		    $b2 configure -state normal
		    $Apol_TE::global_asSource configure -state normal
		    $Apol_TE::global_any configure -state normal	
		    $Apol_TE::incl_indirect1 configure -state normal
		} else {
		    $cBox configure -state normal -entrybg white
		    $b1 configure -state normal
		    $b2 configure -state normal
		    $Apol_TE::global_asSource configure -state normal
		    $Apol_TE::global_any configure -state normal	
		    Apol_TE::change_tgt_dflt_state
		}
		if {$Apol_TE::src_list_type_1 == 0 && $Apol_TE::src_list_type_2 == 1} {
		    $incl_indirect1 configure -state disabled
		    $incl_indirect1 deselect
		}
		if {$Apol_TE::src_list_type_1 == 1 && $Apol_TE::src_list_type_2 == 1} {
			$incl_indirect1 configure -state disabled
		    	$incl_indirect1 deselect
		}
	    } else { 
		$cBox configure -state disabled -entrybg  $ApolTop::default_bg_color
		selection clear -displayof $cBox
		$b1 configure -state disabled
		$b2 configure -state disabled
		$Apol_TE::global_asSource configure -state disabled
		$Apol_TE::global_any configure -state disabled
		$incl_indirect1 configure -state disabled
		$incl_indirect1 deselect
		Apol_TE::change_tgt_dflt_state
	    }
	}
	list2 {
	    if { $Apol_TE::opts(use_2nd_list) } {
		$cBox configure -state normal -entrybg white
		$b1 configure -state normal
		$b2 configure -state normal
		$Apol_TE::incl_indirect2 configure -state normal
		
		if {$Apol_TE::tgt_list_type_1 == 0 && $Apol_TE::tgt_list_type_2 == 1} {
		    $incl_indirect2 configure -state disabled
		    $incl_indirect2 deselect
		}
		if {$Apol_TE::tgt_list_type_1 == 1 && $Apol_TE::tgt_list_type_2 == 1} {
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
#  Command Apol_TE::determine_CheckedRules
# ------------------------------------------------------------------------------
proc Apol_TE::determine_CheckedRules { } {
    # Any type rules are checked
    set bool1 [expr ($Apol_TE::opts(ttrans) == 1 ||  $Apol_TE::opts(tmember) == 1 || $Apol_TE::opts(tchange) == 1)]
    # All type rules are checked 
    set bool2 [expr ($Apol_TE::opts(ttrans) == 1 &&  $Apol_TE::opts(tmember) == 1 && $Apol_TE::opts(tchange) == 1)]
    # All other rules are NOT checked 
    set bool3 [expr ($Apol_TE::opts(teallow) == 0 && $Apol_TE::opts(neverallow) == 0 && \
			 $Apol_TE::opts(auallow) == 0 && $Apol_TE::opts(audeny) == 0 && \
			 $Apol_TE::opts(audont) == 0 && $Apol_TE::opts(clone) == 0)]
    # Logic: ONLY if ANY type rules are checked or ALL type rules are checked, enable default role checkbutton
    set bool [expr ( ($bool1 || $bool2) && $bool3 )]
    
    return $bool
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::defaultType_Enable_Disable
# ------------------------------------------------------------------------------
proc Apol_TE::defaultType_Enable_Disable { } {
    variable dflt_type_list
    variable use_3rd_list
    
    # Set/unset indicator on raised tab to indicate search critera has been selected/deselected.
    Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts raise]
    
    if { $Apol_TE::opts(use_3rd_list) } {
	$Apol_TE::dflt_type_list configure -state normal -entrybg white
    } else {
	$Apol_TE::dflt_type_list configure -state disabled  -entrybg  $ApolTop::default_bg_color
	selection clear -displayof $Apol_TE::dflt_type_list
    }
    # Determine the checked rules
    set bool [Apol_TE::determine_CheckedRules]
    
    if { $bool } {
	if { $Apol_TE::opts(use_1st_list) && $Apol_TE::opts(which_1) == "source"} {
	    $Apol_TE::use_3rd_list configure -state normal -text $Apol_TE::m_use_dflt_type
	} elseif { !$Apol_TE::opts(use_1st_list) } {
	    $Apol_TE::use_3rd_list configure -state normal -text $Apol_TE::m_use_dflt_type
	}
    } else {
    	    # Disable default type section
	    $Apol_TE::dflt_type_list configure -state disabled -entrybg  $ApolTop::default_bg_color
	    selection clear -displayof $Apol_TE::dflt_type_list
	    $Apol_TE::use_3rd_list configure -state disabled -text $Apol_TE::m_disable_dflt_type
	    $Apol_TE::use_3rd_list deselect
    }
    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::change_tgt_dflt_state
# ------------------------------------------------------------------------------	
proc Apol_TE::change_tgt_dflt_state { } {
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
    set bool [Apol_TE::determine_CheckedRules]
    
    if { $Apol_TE::opts(use_1st_list) == 1 && $Apol_TE::opts(which_1) == "either" } {
    	# Disable default type section
	$Apol_TE::dflt_type_list configure -state disabled -entrybg  $ApolTop::default_bg_color
	selection clear -displayof $Apol_TE::dflt_type_list
	$Apol_TE::use_3rd_list configure -state disabled -text $Apol_TE::m_disable_dflt_type
	$Apol_TE::use_3rd_list deselect
	# Disable target type/attrib section
	$Apol_TE::target_list configure -state disabled -entrybg  $ApolTop::default_bg_color
	selection clear -displayof $Apol_TE::target_list
	$Apol_TE::use_2nd_list configure -state disabled -text $Apol_TE::m_disable_tgt_ta
	$Apol_TE::use_2nd_list deselect
	$Apol_TE::incl_indirect2 configure -state disabled
	$Apol_TE::incl_indirect2 deselect
	$Apol_TE::list_types_2 configure -state disabled
	$Apol_TE::list_attribs_2 configure -state disabled
    } elseif { $Apol_TE::opts(use_1st_list) == 1 && $bool && $Apol_TE::opts(which_1) == "source"} {
	# Logic: if use_1st_list is selected AND (ONLY if ANY type rules are checked or ALL type 
	# rules are checked) AND source option is selected, enable default and target listboxes
	$Apol_TE::use_3rd_list configure -state normal -text $Apol_TE::m_use_dflt_type
	$Apol_TE::use_2nd_list configure -state normal -text $Apol_TE::m_use_tgt_ta
    } else {
	$Apol_TE::use_2nd_list configure -state normal -text $Apol_TE::m_use_tgt_ta
	if { $bool } {
	    $Apol_TE::use_3rd_list configure -state normal -text $Apol_TE::m_use_dflt_type
	}
    }
    return 0
}			     

# ------------------------------------------------------------------------------
#  Command Apol_TE::reverseSelection
# ------------------------------------------------------------------------------
proc Apol_TE::reverseSelection {listname} {
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
#  Command Apol_TE::load_query_options
# ------------------------------------------------------------------------------
proc Apol_TE::load_query_options {file_channel parentDlg} {
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
	variable show_enabled_rules
	
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
	set query_options [split [join $query_options " "] " :"]

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
	set opts(perm_union)	[lindex $query_options 16] 	
	set opts(perm_select)	[lindex $query_options 17]
	set src_list_type_1 	[lindex $query_options 18]
	set src_list_type_2 	[lindex $query_options 19]
	set tgt_list_type_1 	[lindex $query_options 20]
	set tgt_list_type_2 	[lindex $query_options 21]
	set allow_regex		[lindex $query_options 22]
	
      	if {[lindex $query_options 23] != "\{\}"} {
		set ta1	[string trim [lindex $query_options 23] "\{\}"]
	}
      	if {[lindex $query_options 24] != "\{\}"} {
		set ta2	[string trim [lindex $query_options 24] "\{\}"]
	}
      	if {[lindex $query_options 25] != "\{\}"} {
		set ta3	[string trim [lindex $query_options 25] "\{\}"]
	}
	
	set i 26
	set invalid_perms ""
	# Parse the list of permissions
	if {[lindex $query_options $i] != "\{\}"} {
	        # we have to pretend to parse a list here since this is a string and not a TCL list.
	        set split_list [split [lindex $query_options $i] "\{"]
	        # If this is not a list of elements, then just get the single element
	        if {[llength $split_list] == 1} {
	        	# Validate that the permission exists in the loaded policy.
     			if {[lsearch -exact $Apol_TE::master_permlist [lindex $query_options $i]] != -1} {
	        		set permslist [lappend permslist [lindex $query_options $i]]
	        	} else {
	        		set invalid_perms [lappend invalid_perms [lindex $query_options $i]]
	        	}
	        } else {
		        # An empty list element will be generated because the first character of string 
		        # is in splitChars, so we ignore the first element of the split list.
		        # Validate that the permission exists in the loaded policy.
     			if {[lsearch -exact $Apol_TE::master_permlist [lindex $split_list 1]] != -1} {
		        	set permslist [lappend permslist [lindex $split_list 1]]
		        } else {
	        		set invalid_perms [lappend invalid_perms [lindex $split_list 1]]
	        	}
		        incr i
		        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
		        	if {[lsearch -exact $Apol_TE::master_permlist [lindex $query_options $i]] != -1} {
		        		set permslist [lappend permslist [lindex $query_options $i]]
		        	} else {
		        		set invalid_perms [lappend invalid_perms [lindex $query_options $i]]
		        	}
		        	incr i
		        }
		        # This is the end of the list, so grab the first element of the split list, since the last 
		        # element of split list is an empty list element. See Previous comment.
			set end_element [lindex [split [lindex $query_options $i] "\}"] 0]
			if {[lsearch -exact $Apol_TE::master_permlist $end_element] != -1} {
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
	
	incr i
        while {$i != [llength $query_options]} {
        	# This means that there are more saved options to parse. As of apol version 1.3, all newly 
        	# added options are name:value pairs. This will make this proc more readable and easier to
        	# extend should we add additional query options in future releases.
        	switch -exact -- [lindex $query_options $i] {
        		"show_enabled_rules" { 
        			incr i
				set show_enabled_rules [lindex $query_options $i]
			}
			default {
				puts "Error: Unknown query option name encountered ([lindex $query_options $i])."
				break
			}
        	}
        	incr i
        }
        	
	# Re-configure list items for type/attributes tab combo boxes
	Apol_TE::populate_ta_list 1
	Apol_TE::populate_ta_list 2
	
	# Reset Objects and Permissions selections 
	Apol_TE::resetObjsPerms_Selections $selObjectsList $selPermsList
    		
	# check enable/disable status
        Apol_TE::enable_listbox $Apol_TE::source_list 1 $Apol_TE::list_types_1 $Apol_TE::list_attribs_1
        Apol_TE::enable_listbox $Apol_TE::target_list 2 $Apol_TE::list_types_2 $Apol_TE::list_attribs_2
        Apol_TE::defaultType_Enable_Disable
        Apol_TE::change_tgt_dflt_state
          
        # Check the search criteria for the Classes/Permissions and Types/Attributes tabs
        # and then set the indicator  accordingly.
        Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts page 0]
        Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts page 1]
        
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_TE::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc Apol_TE::save_query_options {file_channel query_file} {
        # search parameter variables to save
        variable opts
	variable ta1
	variable ta2
        variable ta3
        variable objslistbox
    	variable permslistbox
	variable allow_regex
	variable show_enabled_rules
	variable permslist
	variable src_list_type_1 
	variable src_list_type_2 	
	variable tgt_list_type_1 	
	variable tgt_list_type_2
				
	# Getting all selected objects. 
	set selObjectsList [Apol_TE::get_Selected_ListItems $objslistbox]

	# Getting all selected permissions
	set selPermsList [Apol_TE::get_Selected_ListItems $permslistbox]
	
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
		$src_list_type_1 \
		$src_list_type_2 \
		$tgt_list_type_1 \
		$tgt_list_type_2 \
		$allow_regex \
		$ta1 $ta2 $ta3 \
		$permslist \
		$selObjectsList \
		$selPermsList "show_enabled_rules:$show_enabled_rules"]
		
	# As of apol version 1.3, all newly added options are name:value pairs		
	puts $file_channel "$options"
	
     	return 0
} 

# ----------------------------------------------------------------------------------------
#  Command Apol_TE::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_TE::set_Focus_to_Text { tab } {
	variable notebook_results
	
	if {$tab == $Apol_TE::emptyTabID} {
		return	
	}
	if {[array exists Apol_TE::optionsArray] && [winfo exists $Apol_TE::optionsArray($tab,textbox)] } {
		focus $Apol_TE::optionsArray($tab,textbox)
	}
	
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_TE::enable_RegExpr
#
#  Description: This function is called when the user selects/deselects the "Enable Regular
#		Expressions" checkbutton. It is also called when the user modifies the value 
#		of the ComboBox by selecting it in the listbox. 
# ----------------------------------------------------------------------------------------
proc Apol_TE::enable_RegExpr { which } {
	variable allow_regex
	variable source_list
    	variable target_list
    	variable dflt_type_list
    
	# Check to see if the "Enable Regular Expressions" checkbutton is ON. If not, then return.
	if { $Apol_TE::allow_regex == 1 } {
		# If the current value of the ComboBox does not already contain our initial
		# regular expression string, then we need to prepend the string to the 
		# current value. 
		if { $which == 1 } {
        		set Apol_TE::ta1 	"^$Apol_TE::ta1$"
        		set ta $source_list
		} elseif { $which == 2 } {
			set Apol_TE::ta2 	"^$Apol_TE::ta2$"
			set ta $target_list
		} elseif { $which == 3 } {
			set Apol_TE::ta3		"^$Apol_TE::ta3$"
			set ta $dflt_type_list
		} 
		selection clear -displayof $ta
        }
        
	focus -force .
		    			
   	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_TE::createObjsClassesTab
#
#  Description: This function is called by Apol_TE::create.
# ----------------------------------------------------------------------------------------
proc Apol_TE::createObjsClassesTab {notebook_objects_tab} {
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
    		      		$Apol_TE::objslistbox selection clear 0 end
    		      		Apol_TE::configure_perms 
    		      		Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts raise]}]
    set sw_objs       [ScrolledWindow [$fm_objs_frame getframe].sw -auto both]
    set objslistbox [listbox [$sw_objs getframe].lb -height 5 -width 20 -highlightthickness 0 \
		      -listvar Apol_TE::objectslist -selectmode multiple -exportselection 0] 
    $sw_objs setwidget $objslistbox
    
    # Set binding when selecting an item in the objects listbox to configure the permissions listbox items.
    bindtags $objslistbox [linsert [bindtags $objslistbox] 3 objects_list_Tag]
    bind objects_list_Tag <<ListboxSelect>> { 
    		Apol_TE::configure_perms
    		Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts raise] } 
    
    # Define widgets for Permissions Section
    set b_allPerms [radiobutton $fm_perm_buttons.allPerms -text "Show all permissions" \
    			-variable Apol_TE::opts(perm_select) -value all \
    			-command { Apol_TE::configure_perms }]
    set b_selObjsPerms [radiobutton $fm_perm_buttons.selObjsPerms -text "Only show permissions for\nselected object classes" \
    			-justify left -variable Apol_TE::opts(perm_select) -value selected \
    			-command { Apol_TE::configure_perms }] 
    set b_union [radiobutton $fm_perm_buttons_bot.union -text "Union" \
    			-variable Apol_TE::opts(perm_union) -value union -state disabled \
    			-command { Apol_TE::configure_perms }]
    set b_intersection [radiobutton $fm_perm_buttons_bot.intersection -text "Intersection" \
    			-variable Apol_TE::opts(perm_union) -value intersection -state disabled \
    			-command { Apol_TE::configure_perms }]
    set sw_perms       [ScrolledWindow $fm_permissions_mid.sw -auto both]
    set permslistbox [listbox [$sw_perms getframe].lb -height 5 -width 20 -highlightthickness 0 \
		      -listvar Apol_TE::permslist -selectmode multiple -exportselection 0] 
    $sw_perms setwidget $permslistbox
    
    # Set binding when selecting an item in the perms listbox to indicate search critera 
    # has been selected/deselected.
    bindtags $permslistbox [linsert [bindtags $permslistbox] 3 perms_list_Tag]
    bind perms_list_Tag <<ListboxSelect>> { Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts raise] } 
    
    # Define Clear and Reverse buttons for the permissions listbox	
    set b_clearReverse [button $fm_permissions_bot.clear -text "Clear" -width 6 -anchor center \
    		      	-command { 
    		      		$Apol_TE::permslistbox selection clear 0 end
    		      		Apol_TE::set_Indicator [$Apol_TE::notebook_searchOpts raise] }]
    set b_reverseSel [button $fm_permissions_bot.reverse -text "Reverse" -width 6 -anchor center \
    		      	-command { Apol_TE::reverseSelection $Apol_TE::permslistbox }]
    
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
#  Command Apol_TE::createTypesAttribsTab
#
#  Description: This function is called by Apol_TE::create.
# ----------------------------------------------------------------------------------------
proc Apol_TE::createTypesAttribsTab {notebook_ta_tab} {
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
    	-textvariable Apol_TE::ta1 -helptext "Type or select a type or attribute" \
    	-modifycmd {Apol_TE::enable_RegExpr 1} ]  
    	 
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list. 
    bindtags $source_list.e [linsert [bindtags $source_list.e] 3 source_list_Tag]
    bind source_list_Tag <KeyPress> { ApolTop::_create_popup $Apol_TE::source_list %W %K }
        
    # Radio buttons and check buttons for Source Type/Attrib section
    set list_types_1 [checkbutton $fm_ta_buttons.list_types_1 -text "Types" \
    	-variable Apol_TE::src_list_type_1 \
    	-command "Apol_TE::populate_ta_list 1"]
    set list_attribs_1 [checkbutton $fm_ta_buttons.list_attribs_1 -text "Attribs" \
    	-variable Apol_TE::src_list_type_2 \
    	-command "Apol_TE::populate_ta_list 1"]
    set global_asSource [radiobutton $fm_src_radio_buttons.source_1 -text "As source" -variable Apol_TE::opts(which_1) \
			 -value source \
			 -command "Apol_TE::change_tgt_dflt_state"]
    set global_any [radiobutton $fm_src_radio_buttons.any_1 -text "Any" -variable Apol_TE::opts(which_1) \
			 -value either \
		         -command "Apol_TE::change_tgt_dflt_state"]
    set use_1st_list [checkbutton $fm_top1.use_1st_list -text $Apol_TE::m_use_src_ta \
			 -variable Apol_TE::opts(use_1st_list) \
			 -command "Apol_TE::enable_listbox $source_list 1 $list_types_1 $list_attribs_1" \
		         -offvalue 0 \
		         -onvalue  1 ]
    set incl_indirect1 [checkbutton $fm_incl_cBox.incl_indirect -text $Apol_TE::m_incl_indirect \
			 -variable Apol_TE::opts(indirect_1) \
			 -onvalue 1 \
			 -offvalue 0]
	     
    # Widget items for Target Type/Attrib section
    set target_list [ComboBox $fm_comboBox2.cb -width 22 \
    	-textvariable Apol_TE::ta2 -helptext "Type or select a type or attribute" \
    	-modifycmd {Apol_TE::enable_RegExpr 2} ] 
    	
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $target_list.e [linsert [bindtags $target_list.e] 3 target_list_Tag]
    bind target_list_Tag <KeyPress> { ApolTop::_create_popup $Apol_TE::target_list %W %K }
    
    # Radio buttons and check buttons for Target Type/Attrib section
    set list_types_2 [checkbutton $fm_ta_buttons2.list_types_2 -text "Types" \
	-variable Apol_TE::tgt_list_type_1 \
    	-command "Apol_TE::populate_ta_list 2" ]
    set list_attribs_2 [checkbutton $fm_ta_buttons2.list_attribs_2 -text "Attribs" \
	-variable Apol_TE::tgt_list_type_2 \
	-command "Apol_TE::populate_ta_list 2" ]
	
    set use_2nd_list [checkbutton $fm_top2.use_2nd_list -text $Apol_TE::m_disable_tgt_ta \
	-variable Apol_TE::opts(use_2nd_list) \
	-offvalue 0 \
        -onvalue  1 \
        -command "Apol_TE::enable_listbox $target_list 2 $list_types_2 $list_attribs_2"]
    set incl_indirect2 [checkbutton $fm_incl_cBox2.incl_indirect -text $Apol_TE::m_incl_indirect \
			    -variable Apol_TE::opts(indirect_2) \
			    -onvalue 1 \
			    -offvalue 0]
    
    # Widget items for Default Type section
    set dflt_type_list [ComboBox $fm_comboBox3.cb -width 22 -helptext "Third type search parameter"  \
    	-textvariable Apol_TE::ta3 -helptext "Type or select a type" \
    	-modifycmd {Apol_TE::enable_RegExpr 3} ]
    	
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $dflt_type_list.e [linsert [bindtags $dflt_type_list.e] 3 dflt_type_list_Tag]
    bind dflt_type_list_Tag <KeyPress> { ApolTop::_create_popup $Apol_TE::dflt_type_list %W %K }
    
    # Radio buttons and check buttons for Default Type section
    set use_3rd_list [checkbutton $fm_top3.use_3rd_list -text $Apol_TE::m_disable_dflt_type \
			     -variable Apol_TE::opts(use_3rd_list) \
			     -offvalue 0 \
			     -onvalue  1 \
			     -command "Apol_TE::defaultType_Enable_Disable" ]

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
    Apol_TE::enable_listbox $source_list 1 $list_types_1 $list_attribs_1
    Apol_TE::enable_listbox $target_list 2 $list_types_2 $list_attribs_2
    Apol_TE::defaultType_Enable_Disable
    Apol_TE::change_tgt_dflt_state
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_TE::create
# ------------------------------------------------------------------------------
proc Apol_TE::create {nb} {
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
    variable tab_menu_callbacks
    
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
    set other_opts_box [TitleFrame [$pw1 getframe 0].other_opts_box -text "Options"]
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
    pack $tbox $other_opts_box -side top -anchor nw -fill both -padx 5 -expand yes
    pack $dbox -side left -fill both -expand yes -anchor e -padx 5 -pady 5
               
    # Rule types section subframes
    set fm_rules [$tbox getframe]
    set optsfm [frame $fm_rules.optsfm]
    set tefm [frame $optsfm.tefm]
    set ttfm [frame $optsfm.ttfm]
    set enabled_fm [frame [$other_opts_box getframe].enabled_fm]
    
    # First column of checkbuttons under rule selection subframe
    set teallow [checkbutton $tefm.teallow -text "allow" -variable Apol_TE::opts(teallow) \
	    -command "Apol_TE::defaultType_Enable_Disable"]
    set neverallow [checkbutton $tefm.neverallow -text "neverallow" -variable Apol_TE::opts(neverallow) \
            -command "Apol_TE::defaultType_Enable_Disable" ]
    set auallow [checkbutton $tefm.auallow -text "auditallow" -variable Apol_TE::opts(auallow) \
            -command "Apol_TE::defaultType_Enable_Disable" ]
    set audeny [checkbutton $tefm.audeny -text "auditdeny" -variable Apol_TE::opts(audeny) \
            -command "Apol_TE::defaultType_Enable_Disable" ]
    set audont [checkbutton $tefm.audont -text "dontaudit"  -variable Apol_TE::opts(audont) \
    	    -command "Apol_TE::defaultType_Enable_Disable" ]
    
    # Second column of checkbuttons under rule selection subframe
    set ttrans [checkbutton $ttfm.ttrans -text "type_trans" -variable Apol_TE::opts(ttrans) \
	    -command "Apol_TE::defaultType_Enable_Disable"]
    set tmember [checkbutton $ttfm.tmember -text "type_member" -variable Apol_TE::opts(tmember) \
            -command "Apol_TE::defaultType_Enable_Disable"]
    set tchange [checkbutton $ttfm.tchange -text "type_change" -variable Apol_TE::opts(tchange) \
            -command "Apol_TE::defaultType_Enable_Disable" ]
    set clone [checkbutton $ttfm.clone -text "clone" -variable Apol_TE::opts(clone) \
            -command "Apol_TE::defaultType_Enable_Disable" ]
    
    set cb_show_enabled_rules [checkbutton $enabled_fm.cb_show_enabled_rules -text "Only show enabled rules" \
    		-variable Apol_TE::show_enabled_rules -onvalue 1 -offvalue 0]
    		
    set cb_fm [frame $enabled_fm.cb_fm]
    # Checkbutton to Enable/Disable Regular Expressions option.
    set cb_RegExp [checkbutton $cb_fm.cb_RegExp -text "Enable Regular Expressions" \
    		-variable Apol_TE::allow_regex -onvalue 1 -offvalue 0]
                	    
    # NoteBook creation for search options subframe
    set notebook_searchOpts [NoteBook $frame_search.nb]
    set notebook_ta_tab [$notebook_searchOpts insert end $Apol_TE::ta_TabID -text $Apol_TE::m_ta_tab]
    set notebook_objects_tab [$notebook_searchOpts insert end $Apol_TE::cp_TabID -text $Apol_TE::m_obj_perms_tab]
    Apol_TE::createTypesAttribsTab $notebook_ta_tab
    Apol_TE::createObjsClassesTab $notebook_objects_tab
    
    # Action buttons
    set newButton [button $bBox.new -text "New" -width 6 -command { Apol_TE::searchTErules newTab }]
    set updateButton [button $bBox.upDate -text "Update" -width 6 -state disabled \
    		-command { Apol_TE::searchTErules updateTab }]
    #set printButton [button $bBbox.print -text "Print" -width 6 -command {ApolTop::unimplemented}]
	             
    # Popup menu widget
    set popupTab_Menu [menu .popupTab_Menu]
    set tab_menu_callbacks [lappend tab_menu_callbacks {"Delete Tab" "Apol_TE::delete_ResultsTab"}]
    		
    # Notebook creation for results
    set notebook_results [NoteBook [$dbox getframe].nb_results]
    $notebook_results bindtabs <Button-3> {ApolTop::popup_Tab_Menu \
    	%W %x %y $Apol_TE::popupTab_Menu $Apol_TE::tab_menu_callbacks} 
    $notebook_results bindtabs <Button-1> {Apol_TE::set_Widget_SearchOptions}
    
    # Add button bar at bottom of results section for closing tabs.
    set bFrame [frame [$dbox getframe].bFrame -relief sunken -bd 1]
    set bClose [button $bFrame.bClose -text "Close Tab" -command { 
    		set raisedPage [$Apol_TE::notebook_results raise]
    		Apol_TE::delete_ResultsTab $raisedPage }]
    pack $bFrame -side bottom -anchor center -fill x -padx 4 -pady 1
    pack $bClose -side bottom -anchor center -fill x -padx 1 -pady 1
       
    # Placing action buttons
    pack $newButton $updateButton -side top -pady 5 -anchor se 
    
    # Placing rule selection section widgets
    pack $teallow $neverallow $auallow $audeny $audont -anchor w 
    pack $ttrans $tmember $tchange $clone -anchor w 
    pack $tefm $ttfm -side left -anchor nw 
    pack $enabled_fm -side top -pady 6 -anchor nw -fill both 
    pack $cb_fm -side bottom -anchor nw
    pack $cb_RegExp -side top -anchor nw 
    pack $cb_show_enabled_rules -side top -anchor nw
    pack $optsfm -side top -fill x -expand yes -anchor nw
    
    # Placing the search options notebook frame within the search options section    
    $notebook_searchOpts compute_size
    pack $notebook_searchOpts -fill both -expand yes -padx 4
    set raisedPage [$notebook_searchOpts raise [$notebook_searchOpts page 0]]
    Apol_TE::set_Indicator $raisedPage
    Apol_TE::create_empty_resultsTab
           
    # Placing the results notebook frame within the results section    
    pack $notebook_results -fill both -expand yes -padx 4
       
    return $frame	
}
