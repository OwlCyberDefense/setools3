#############################################################
#  dirflow_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com, mayerf@tresys.com, kcarr@tresys>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Information
# Flow analysis.
##############################################################
# ::Apol_Analysis_dirflow module namespace
##############################################################

namespace eval Apol_Analysis_dirflow {
        
    # widget  variables
     	variable combo_attribute
        variable combo_start
        variable list_objs
    	variable info_button_text "\n\nThis analysis generates the results of a Direct Information Flow \
    				  analysis beginning from the starting type selected.  The results of \
    				  the analysis are presented in tree form with the root of the tree being \
    				  the start point for the analysis.\n\nEach child node in the tree represents \
    				  a type in the current policy for which there is a direct information flow \
    				  to or from its parent node.  If 'in' was selected then the information flow \
    				  is from the child to the parent.  If 'out' was selected then information \
    				  flows from the parent to the child.\n\nThe results of the analysis may be \
    				  optionally filtered by object class selection or an end type regular \
    				  expression.\n\nNOTE: For any given generation, if the parent and the child \
    				  are the same, you cannot open the child.  This avoids cyclic analyses.\n\nFor \
    				  additional help on this topic select \"Information Flow Analysis\" from the \
    				  help menu."
        variable root_text  "\n\nThis tab provides the results of a Direct Information Flow analysis beginning \
        		    from the starting type selected above.  The results of the analysis are presented \
        		    in tree form with the root of the tree (this node) being the start point for the \
        		    analysis.\n\nEach child node in the tree represents a type in the current policy \
        		    for which there is a direct information flow to or from (depending on your selection \
        		    above) its parent node.\n\nNOTE: For any given generation, if the parent and the child \
        		    are the same, you cannot open the child.  This avoids cyclic analyses.\n\n"
        		    
        variable in_button
        variable out_button
        variable either_button
        variable both_button
        variable entry_end 
        variable cb_attrib
        variable sw_objs

    # button variables
        variable endtype_sel        0
        variable objects_sel        0
        variable in_button_sel      0
        variable out_button_sel     0
        variable either_button_sel  0
        variable both_button_sel    0
	variable display_attrib_sel 0

    # tree variables
        variable dirflow_tree       ""
        variable dirflow_info_text  ""

    # display variables
        variable start_type         ""
        variable end_type           ""
        variable display_attribute  ""
        variable flow_direction     ""

    # defined tag names for output 
	variable title_tag		TITLE
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	variable rules_tag		RULES
	variable counters_tag		COUNTERS
	variable types_tag		TYPE
	variable disabled_rule_tag     	DISABLE_RULE
	
## Within the namespace command for the module, you must call Apol_Analysis::register_analysis_modules,
## the first argument is the namespace name of the module, and the second is the
## descriptive display name you want to be displayed in the GUI selection box.
    	Apol_Analysis::register_analysis_modules "Apol_Analysis_dirflow" "Direct Information Flow"
}



## Apol_Analysis_dirflow::initialize is called when the tool first starts up.  The
## analysis has the opportunity to do any additional initialization it must  do
## that wasn't done in the initial namespace eval command.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::initialize { } {    
        Apol_Analysis_dirflow::reset_variables
     	if {[ApolTop::is_policy_open]} {
	     	# Have the attributes checkbutton OFF by default
		set Apol_Analysis_dirflow::display_attrib_sel 0
		Apol_Analysis_dirflow::config_attrib_comboBox_state
	     	Apol_Analysis_dirflow::change_types_list
	        # By default have the in button pressed
	        set Apol_Analysis_dirflow::in_button_sel 1
	        $Apol_Analysis_dirflow::in_button select
	        Apol_Analysis_dirflow::in_button_press
	        set Apol_Analysis_dirflow::objects_sel 0
	        Apol_Analysis_dirflow::config_objects_list_state
	        $Apol_Analysis_dirflow::list_objs selection clear 0 end
	        set Apol_Analysis_dirflow::endtype_sel 0
	        Apol_Analysis_dirflow::config_endtype_state
	}     	
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::get_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::get_analysis_info {} {
     	return $Apol_Analysis_dirflow::info_button_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::get_results_raised_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::get_results_raised_tab {} {
     	return $Apol_Analysis_dirflow::dirflow_info_text
} 

## Command Apol_Analysis_dirflow::do_analysis is the principal interface command.
## The GUI will call this when the module is to perform it's analysis.  The
## module should know how to get its own option information (the options
## are displayed via ::display_mod_options
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::do_analysis { results_frame } {  
	variable start_type
        variable end_type
        variable endtype_sel
	variable dirflow_tree
	variable dirflow_info_text
        variable flow_direction
        variable list_objs
        variable objects_sel
	
        set selected_objects [Apol_Analysis_dirflow::get_selected_objects]
        
        # if a permap is not loaded then load the default permap
        # if an error occurs on open, then skip analysis
        set rt [catch {set map_loaded [Apol_Perms_Map::is_pmap_loaded]} err ]
        if { $rt != 0 } {
	    tk_messageBox -icon error -type ok -title "Error" -message "$err"
	    return -code error
	}
	if { !$map_loaded } {
	    set rt [catch {Apol_Perms_Map::load_default_perm_map} err]
	    if { $rt != 0 } {
		if {$rt == $Apol_Perms_Map::warning_return_val} {
			tk_messageBox -icon warning -type ok -title "Warning" -message "$err"
		} else {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -code error
		}
	    }
	}
	
     	set rt [catch {set results [apol_DirectInformationFlowAnalysis \
		$Apol_Analysis_dirflow::start_type \
		$Apol_Analysis_dirflow::flow_direction \
		$Apol_Analysis_dirflow::objects_sel \
		$selected_objects \
		$Apol_Analysis_dirflow::endtype_sel \
		$Apol_Analysis_dirflow::end_type] } err]

     	if {$rt != 0} {
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	}

	set query_args [list \
		$Apol_Analysis_dirflow::start_type \
		$Apol_Analysis_dirflow::flow_direction \
		$Apol_Analysis_dirflow::objects_sel \
		$selected_objects \
		$Apol_Analysis_dirflow::endtype_sel \
		$Apol_Analysis_dirflow::end_type]

	set dirflow_tree [Apol_Analysis_dirflow::create_resultsDisplay $results_frame]
	set rt [catch {Apol_Analysis_dirflow::create_result_tree_structure \
		$dirflow_tree \
		$results \
		$query_args} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	}
     	return 0
} 

## Apol_Analysis_dirflow::close must exist; it is called when a policy is closed.
## Typically you should reset any context or option variables you have.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::close { } { 
        variable list_objs

	Apol_Analysis_dirflow::reset_variables
	$Apol_Analysis_dirflow::combo_attribute configure -state disabled -entrybg $ApolTop::default_bg_color
     	$Apol_Analysis_dirflow::combo_attribute configure -values ""
#        set Apol_Analysis_dirflow::objects_sel 0
        ApolTop::enable_tkListbox $list_objs
        $Apol_Analysis_dirflow::list_objs delete 0 end
        ApolTop::disable_tkListbox $list_objs
        Apol_Analysis_dirflow::config_objects_list_state
        set Apol_Analysis_dirflow::endtype_sel 0
        Apol_Analysis_dirflow::config_endtype_state
     	return 0
} 

## Apol_Analysis_dirflow::open must exist; it is called when a policy is opened.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::open { } {   	
        variable in_button
        variable cb_attrib
        variable list_objs
        ApolTop::enable_tkListbox $list_objs
        Apol_Analysis_dirflow::populate_ta_list
        ApolTop::disable_tkListbox $list_objs
        set in_button_sel 1
        $in_button select
        Apol_Analysis_dirflow::in_button_press
        Apol_Analysis_dirflow::config_attrib_comboBox_state
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::load_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::load_query_options { file_channel parentDlg } {
	
	set query_options ""
	set query_options_tmp ""
        while {[eof $file_channel] != 1} {
		gets $file_channel line
		set tline [string trim $line]
		# Skip empty lines and comments
		if {$tline == "" || [string compare -length 1 $tline "#"] == 0} {
			continue
		}
		set query_options_tmp [lappend query_options_tmp $tline]
	}
	if {$query_options_tmp == ""} {
		return -code error "No query parameters were found."
	}
	# Re-format the query options list into a string where all elements are seperated
	# by a single space. Then split this string into a list using space and colon characters
	# as the delimeters.	
	set query_options_tmp [split [join $query_options_tmp " "] " :"]
	set query_options [ApolTop::strip_list_of_empty_items $query_options_tmp]
	if {$query_options == ""} {
		return -code error "No query parameters were found."
	}
		
        Apol_Analysis_dirflow::clear_all_button_press
        # Query option variables
        set Apol_Analysis_dirflow::endtype_sel [lindex $query_options 0]
        set Apol_Analysis_dirflow::objects_sel [lindex $query_options 1]       
        set Apol_Analysis_dirflow::in_button_sel [lindex $query_options 2]    
        set Apol_Analysis_dirflow::out_button_sel [lindex $query_options 3] 
        set Apol_Analysis_dirflow::either_button_sel [lindex $query_options 4]
        set Apol_Analysis_dirflow::both_button_sel [lindex $query_options 5]   
	# Ignore empty list elements
	if {[lindex $query_options 8] != "\{\}"} {
		set Apol_Analysis_dirflow::end_type [string trim [lindex $query_options 8] "\{\}"]
	}
	if {[lindex $query_options 9] != "\{\}"} {
		set tmp [string trim [lindex $query_options 9] "\{\}"]
		if {[lsearch -exact $Apol_Types::attriblist $tmp] != -1} {
	        	set Apol_Analysis_dirflow::display_attribute $tmp
	        	set Apol_Analysis_dirflow::display_attrib_sel [lindex $query_options 6]   
	        } else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified attribute $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
		}
	}
        set Apol_Analysis_dirflow::flow_direction [lindex $query_options 10]
	set active_objs ""
       	if {[lindex $query_options 11] != "\{\}"} {
	        # we have to pretend to parse a list here since this is a string and not a TCL list.
	        set split_list [split [lindex $query_options 11] "\{"]
	        # If this is not a list of elements, then just get the single element
	        if {[llength $split_list] == 1} {
	        	set active_objs [lappend active_objs [lindex $query_options 11]]
	        } else {
		        # An empty list element will be generated because the first character of string 
		        # is in splitChars, so we ignore the first element of the split list.
		        set active_objs [lappend active_objs [lindex $split_list 1]]
		        set i 12
		        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
		        	set active_objs [lappend active_objs [lindex $query_options $i]]
		        	incr i
		        }
		        # This is the end of the list, so grab the first element of the split list, since the last 
		        # element of split list is an empty list element. See Previous comment.
			set end_element [lindex [split [lindex $query_options $i] "\}"] 0]
			set active_objs [lappend active_objs $end_element]
		}
	}
     	Apol_Analysis_dirflow::config_objects_list_state
     	set invalid_objs ""
        foreach obj $active_objs {
        	# Search to see if it exists in the current listbox elements. Another policy may be loaded.
        	set idx [lsearch -exact [$Apol_Analysis_dirflow::list_objs get 0 end] $obj]
        	if {$idx != -1} {
            		$Apol_Analysis_dirflow::list_objs selection set $idx
            	} else {
     			set invalid_objs [lappend invalid_objs $obj]
     		}  
            	# If it doesn't exist, then simply ignore.
        }
	# Display a popup with a list of invalid objects
	if {$invalid_objs != ""} {
		puts "The following objects do not exist in the currently \
			loaded policy and were ignored:\n\n"
		foreach obj $invalid_objs {
			puts "$obj\n"
		}
	}
		        
	Apol_Analysis_dirflow::config_endtype_state
	Apol_Analysis_dirflow::config_attrib_comboBox_state
	
	# We set the start type parameter here because Apol_Analysis_dirflow::config_attrib_comboBox_state
	# clears the start type before changing the start types list.
	if {[lindex $query_options 7] != "\{\}"} {
		set tmp [string trim [lindex $query_options 7] "\{\}"]
		# Validate that the type exists in the loaded policy.
     		if {[lsearch -exact $Apol_Types::typelist $tmp] != -1} {
			set Apol_Analysis_dirflow::start_type $tmp
		} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified type starting source domain type $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
     		}     
	}
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::save_query_options {module_name file_channel file_name} {
        # option variables
        variable endtype_sel        
        variable objects_sel        
        variable in_button_sel      
        variable out_button_sel     
        variable either_button_sel  
        variable both_button_sel    
	variable display_attrib_sel
        variable start_type         
        variable end_type           
        variable display_attribute  
        variable flow_direction     
        variable list_objs

	set sel_obj_names ""	
        foreach obj_idx [$list_objs curselection]  {
        	set sel_obj_names [lappend sel_obj_names [$list_objs get $obj_idx]]
        } 	
     	set options [list \
		$endtype_sel \
		$objects_sel \
		$in_button_sel \
		$out_button_sel \
		$either_button_sel \
		$both_button_sel \
		$display_attrib_sel \
		$start_type \
		$end_type \
		$display_attribute \
		$flow_direction \
		$sel_obj_names]
	
	puts $file_channel "$module_name"	
	puts $file_channel "$options"
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::get_current_results_state { } {
	# widget variables
        variable dirflow_tree       
        variable dirflow_info_text
        # option variables
        variable endtype_sel        
        variable objects_sel        
        variable in_button_sel      
        variable out_button_sel     
        variable either_button_sel  
        variable both_button_sel    
	variable display_attrib_sel
        variable start_type         
        variable end_type           
        variable display_attribute  
        variable flow_direction     
        variable list_objs

        set selected_objs [$list_objs curselection] 	
     	set options [list \
     		$dirflow_tree \
     		$dirflow_info_text \
		$endtype_sel \
		$objects_sel \
		$in_button_sel \
		$out_button_sel \
		$either_button_sel \
		$both_button_sel \
		$display_attrib_sel \
		$start_type \
		$end_type \
		$display_attribute \
		$flow_direction \
		$selected_objs]
     	return $options
} 

## Apol_Analysis_dirflow::set_display_to_results_state is called to reset the options
## or any other context that analysis needs when the GUI switches back to an
## existing analysis.  options is a list that we created in a previous 
## get_current_results_state() call.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::set_display_to_results_state { query_options } { 
        variable dirflow_tree       
        variable dirflow_info_text  
        variable endtype_sel        
        variable objects_sel        
        variable in_button_sel      
        variable out_button_sel     
        variable either_button_sel  
        variable both_button_sel    
	variable display_attrib_sel
        variable start_type         
        variable end_type           
        variable display_attribute  
        variable flow_direction 
        variable list_objs
        
        Apol_Analysis_dirflow::clear_all_button_press
        # widget variables
        set dirflow_tree [lindex $query_options 0]
        set dirflow_info_text [lindex $query_options 1]
        # Query option variables
        set endtype_sel [lindex $query_options 2]
        set objects_sel [lindex $query_options 3]       
        set in_button_sel [lindex $query_options 4]    
        set out_button_sel [lindex $query_options 5] 
        set either_button_sel [lindex $query_options 6]
        set both_button_sel [lindex $query_options 7]   
	set display_attrib_sel [lindex $query_options 8] 
	# Set start type below, so skip this index (9) for now.  
	set end_type [lindex $query_options 10]
        set display_attribute [lindex $query_options 11] 
        set flow_direction [lindex $query_options 12]
        set active_objs [lindex $query_options 13]
        foreach i $active_objs {
            $list_objs selection set $i
        }

        Apol_Analysis_dirflow::config_objects_list_state
	Apol_Analysis_dirflow::config_endtype_state
	Apol_Analysis_dirflow::config_attrib_comboBox_state
	# We set the start type parameter here because Apol_Analysis_dirflow::config_attrib_comboBox_state
	# clears the start type before changing the start types list.
	set start_type [lindex $query_options 9]
     	return 0
} 

## Apol_Analysis_dirflow::free_results_data is called to destroy subwidgets 
#  under a results frame as well as free any data associated with them.
#  query_options is a list that we created in a previous get_current_results_state() call,
#  from which we extract the subwidget pathnames for the results frame.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::free_results_data
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::free_results_data {query_options} {  
	set dirflow_tree [lindex $query_options 12]
        set dirflow_info_text [lindex $query_options 13]

	if {[winfo exists $dirflow_tree]} {
		$dirflow_tree delete [$dirflow_tree nodes root]
		if {[$dirflow_tree nodes root] != ""} {
			return -1			
		}
		destroy $dirflow_tree
	}
	if {[winfo exists $dirflow_info_text]} {
		$dirflow_info_text delete 0.0 end
		destroy $dirflow_info_text
	}
	return 0
}

#################################################################################
#################################################################################
##
## The rest of these procs are not interface procedures, but rather internal
## functions to this analysis.
##
#################################################################################
#################################################################################
proc Apol_Analysis_dirflow::treeSelect {dirflow_tree dirflow_info_text node} {
	# Set the tree selection to the current node.
	$dirflow_tree selection set $node
        if {$node ==  [$dirflow_tree nodes root]} {
		Apol_Analysis_dirflow::display_root_type_info $node \
			$dirflow_info_text $dirflow_tree
	} else {
		Apol_Analysis_dirflow::render_target_type_data \
			[$dirflow_tree itemcget $node -data] \
			$dirflow_info_text $dirflow_tree $node
	}
	Apol_Analysis_dirflow::formatInfoText $dirflow_info_text
	ApolTop::makeTextBoxReadOnly $dirflow_info_text
	
	return 0

}
###########################################################################
# ::display_root_type_info
#
proc Apol_Analysis_dirflow::display_root_type_info { source_type dirflow_info_text dirflow_tree } {

    $dirflow_info_text configure -state normal
    $dirflow_info_text delete 0.0 end
    set startIdx [$dirflow_info_text index insert]
    $dirflow_info_text insert end "Direct Information Flow Analysis: Starting type: "
    set endIdx [$dirflow_info_text index insert]
    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
    set startIdx $endIdx
    $dirflow_info_text insert end $source_type
    set endIdx [$dirflow_info_text index insert]
    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
    set startIdx $endIdx
    # now add the standard text
    $dirflow_info_text configure -wrap word
    set start_idx [$dirflow_info_text index insert]
    $dirflow_info_text insert end $Apol_Analysis_dirflow::root_text
    $dirflow_info_text tag add ROOT_TEXT $start_idx end
    $dirflow_info_text tag configure ROOT_TEXT -font $ApolTop::text_font 

    return 0
}

proc Apol_Analysis_dirflow::render_target_type_data {data dirflow_info_text dirflow_tree node} {
	$dirflow_info_text configure -state normal        
	$dirflow_info_text delete 0.0 end
        $dirflow_info_text configure -wrap none

	if { $data == "" } {
		return ""
	}
        set cur_end_type [lindex $data 0]
        set flow_dir [lindex $data 1]
        set num_objs [lindex $data 2]
	set curIdx 3
        set startIdx [$dirflow_info_text index insert]
	set start_type [$dirflow_tree itemcget [$dirflow_tree parent $node] -text]

        if {$flow_dir == "both"} {
# Print the output title
	    $dirflow_info_text insert end "Information flows both into and out of "
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
	    set startIdx [$dirflow_info_text index insert]
	    $dirflow_info_text insert end $start_type
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
	    set startIdx [$dirflow_info_text index insert]
	    $dirflow_info_text insert end " - \[from/to\] "
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
	    set startIdx [$dirflow_info_text index insert]
	    $dirflow_info_text insert end $cur_end_type
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
	    set startIdx $endIdx
# Print label for in flows 
	    $dirflow_info_text insert end "\n\nObject classes for "
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $dirflow_info_text insert end "\[IN/OUT\]"
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx	 
	    set startIdx $endIdx
	    $dirflow_info_text insert end " flows:"
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx
# Then process inflows   
 	    for {set i 0} {$i<$num_objs} {incr i} {
		if {[lindex $data $curIdx] == "1"} {
		    incr curIdx
		    $dirflow_info_text insert end "\n\t"
		    # This should be the object name
		    $dirflow_info_text insert end [lindex $data $curIdx]
		    set endIdx [$dirflow_info_text index insert]
		    $dirflow_info_text tag add $Apol_Analysis_dirflow::subtitle_tag $startIdx $endIdx
		    incr curIdx
		    set num_rules [lindex $data $curIdx]
		    for {set j 0} {$j<$num_rules} {incr j} {
		    	$dirflow_info_text insert end "\n\t"
		    	set startIdx [$dirflow_info_text index insert]
			incr curIdx
			set rule [lindex $data $curIdx]
			# Get the line number only
			set end_link_idx [string first "\]" [string trim $rule] 0]
			set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
			set lineno [string trim $lineno]
	
			set rule [string range $rule [expr $end_link_idx + 1] end]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dirflow_info_text insert end "\[$lineno\]"
				Apol_PolicyConf::insertHyperLink $dirflow_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
			}
			set startIdx [$dirflow_info_text index insert]
			$dirflow_info_text insert end " $rule"
			set endIdx [$dirflow_info_text index insert]
			$dirflow_info_text tag add $Apol_Analysis_dirflow::rules_tag $startIdx $endIdx
			
			incr curIdx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $curIdx] == 0} {
				$dirflow_info_text insert end "   "
				set startIdx [$dirflow_info_text index insert]
				$dirflow_info_text insert end "\[Disabled\]"
				set endIdx [$dirflow_info_text index insert]
				$dirflow_info_text tag add $Apol_Analysis_dirflow::disabled_rule_tag $startIdx $endIdx
			} 
			set startIdx [$dirflow_info_text index insert]
		    }
		} 
		incr curIdx
	    }
        } else {
	    # If it is not both then print only the out flows, or only the inflows
	    if { $flow_dir == "in" } {
		# Print the output title
		$dirflow_info_text insert end "Information flows into "
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
		set startIdx [$dirflow_info_text index insert]
		$dirflow_info_text insert end $start_type
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
		set startIdx [$dirflow_info_text index insert]
		$dirflow_info_text insert end " - from "
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
		set startIdx [$dirflow_info_text index insert]
		$dirflow_info_text insert end $cur_end_type
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
		set startIdx $endIdx		
	    } elseif { $flow_dir == "out" } {
		# Print the output title
		$dirflow_info_text insert end "Information flows out of "
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
		set startIdx [$dirflow_info_text index insert]
		$dirflow_info_text insert end $start_type
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
		set startIdx [$dirflow_info_text index insert]
		$dirflow_info_text insert end " - to "
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_tag $startIdx $endIdx
		set startIdx [$dirflow_info_text index insert]
		$dirflow_info_text insert end $cur_end_type
		set endIdx [$dirflow_info_text index insert]
		$dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx
		set startIdx $endIdx			
	    }

	    $dirflow_info_text insert end "\n\nObject classes for "
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx
	    set flow_dir [string toupper $flow_dir]
	    $dirflow_info_text insert end $flow_dir
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::title_type_tag $startIdx $endIdx	 
	    set startIdx $endIdx
	    $dirflow_info_text insert end " flows:"
	    set endIdx [$dirflow_info_text index insert]
	    $dirflow_info_text tag add $Apol_Analysis_dirflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx

	    for {set i 0} {$i<$num_objs} {incr i} {
		if { [lindex $data $curIdx] == "1" } {
		    incr curIdx
		    $dirflow_info_text insert end "\n\t"
		    # This should be the object name
		    $dirflow_info_text insert end [lindex $data $curIdx]
		    set endIdx [$dirflow_info_text index insert]
		    $dirflow_info_text tag add $Apol_Analysis_dirflow::subtitle_tag $startIdx $endIdx
		    incr curIdx
		    set num_rules [lindex $data $curIdx]
		    for {set j 0} {$j<$num_rules} {incr j} {
		    	$dirflow_info_text insert end "\n\t"
		    	set startIdx [$dirflow_info_text index insert]
			incr curIdx
			set rule [lindex $data $curIdx]
			# Get the line number only
			set end_link_idx [string first "\]" [string trim $rule] 0]
			set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
			set lineno [string trim $lineno]
	
			set rule [string range $rule [expr $end_link_idx + 1] end]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dirflow_info_text insert end "\[$lineno\]"
				Apol_PolicyConf::insertHyperLink $dirflow_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
			}
			set startIdx [$dirflow_info_text index insert]
			$dirflow_info_text insert end " $rule"
			set endIdx [$dirflow_info_text index insert]
			$dirflow_info_text tag add $Apol_Analysis_dirflow::rules_tag $startIdx $endIdx
			
			incr curIdx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $curIdx] == 0} {
				$dirflow_info_text insert end "   "
				set startIdx [$dirflow_info_text index insert]
				$dirflow_info_text insert end "\[Disabled\]"
				set endIdx [$dirflow_info_text index insert]
				$dirflow_info_text tag add $Apol_Analysis_dirflow::disabled_rule_tag $startIdx $endIdx
			}
			set startIdx [$dirflow_info_text index insert]
		    }
		} 
		incr curIdx
	    }
	}
	return
}

###########################################################################
# ::formatInfoText
#
proc Apol_Analysis_dirflow::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_dirflow::title_tag -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_dirflow::title_type_tag -foreground blue -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_dirflow::subtitle_tag -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_dirflow::rules_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_dirflow::counters_tag -foreground blue -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_dirflow::types_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_dirflow::disabled_rule_tag -foreground red
	
	# Configure hyperlinking to policy.conf file
	Apol_PolicyConf::configure_HyperLinks $tb
}

proc Apol_Analysis_dirflow::insert_src_type_node { dirflow_tree query_args} {
        variable start_type

       	$dirflow_tree insert end root $start_type \
		-text $start_type \
		-open 1	\
        	-drawcross auto \
		-data "$query_args"

        return [$dirflow_tree nodes root]
}

proc Apol_Analysis_dirflow::create_target_type_nodes { parent dirflow_tree results_list } {
        if { [file tail [$dirflow_tree parent $parent]] == [file tail $parent] } {
		return 0
	}

	if { [$dirflow_tree nodes $parent] == "" } {
		# Get # of target types (if none, then just draw the tree without child nodes)
		# We skip index 0 b/c index 1 is the starting type, which we already have.
		set num_target_types [lindex $results_list 1]
		#  if there are any target types, index 2 will be the first target node from the results list.
		set curentIdx 2
		
		# If there are any target types then create and insert children nodes for the source_type node				
		for { set x 0 } { $x < $num_target_types } { incr x } { 
			set target_name [lindex $results_list $curentIdx]		        	
			set nextIdx [Apol_Analysis_dirflow::parseList_get_index_next_node $curentIdx $results_list]
			if {$nextIdx == -1} {
				return -code error "Error parsing results"
			}

			set target_node "${parent}/${target_name}/"
			$dirflow_tree insert end $parent $target_node \
				-text $target_name \
				-open 0	\
		        	-drawcross allways \
		        	-data [lrange $results_list $curentIdx [expr $nextIdx-1]]
			set curentIdx $nextIdx
		}
		set nodes [lsort [$dirflow_tree nodes $parent]]
		$dirflow_tree reorder $parent $nodes 
	        $dirflow_tree configure -redraw 1
	}
        return 0
}

proc Apol_Analysis_dirflow::parseList_get_index_next_node { currentIdx results_list } {
	# Increment the index to get the flow direction
        incr currentIdx
        set direction [lindex $results_list $currentIdx]
        # Increment the index to get the number of object classes
        incr currentIdx
        set num_classes [lindex $results_list $currentIdx]
        # Increment the index to get the next item in the list, which  
        # should be a flag indicating whether to use this object
        incr currentIdx

        if {$direction == "both"} {
		# First read past all the in flows
		for {set i 0} {$i < $num_classes} {incr i} {
			# Check if we care about this particular object
			if { [lindex $results_list $currentIdx] == "1" } {
				# Skip the object class name in the list and go to the number of rules list item
				incr currentIdx 2
				set num_rules [lindex $results_list $currentIdx]
				# We multiply the number of rules by 2 because each rule consists of:
				# 	1. rule string (includes line number)
				#	2. enabled flag
				incr currentIdx [expr $num_rules * 2]
			} 
			# Move to the next item in the results list
			incr currentIdx
		}
        } elseif {$direction == "in" || $direction == "out"} {
		for {set i 0} {$i < $num_classes} {incr i} {
			# Check if this particular object was included in our query
			if { [lindex $results_list $currentIdx] == "1" } {
				incr currentIdx 2
				set num_rules [lindex $results_list $currentIdx]
				# We multiply the number of rules by 2 because each rule consists of:
				# 	1. rule string (includes line number)
				#	2. enabled flag
				incr currentIdx [expr $num_rules * 2]
			} 
			# Move to the next item in the results list
			incr currentIdx
		}
        } else {
        	puts "Invalid flow direction ($direction) encountered while parsing results."
        	return -1
        }

	return $currentIdx
}

proc Apol_Analysis_dirflow::create_result_tree_structure { dirflow_tree results_list query_args} {
        set home_node [Apol_Analysis_dirflow::insert_src_type_node $dirflow_tree \
        	$query_args]
	set rt [catch {Apol_Analysis_dirflow::create_target_type_nodes $home_node \
		$dirflow_tree $results_list} err]
	if {$rt != 0} {
		return -code error $err
	}
	Apol_Analysis_dirflow::treeSelect \
		$Apol_Analysis_dirflow::dirflow_tree \
		$Apol_Analysis_dirflow::dirflow_info_text \
		$home_node
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::do_child_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::do_child_analysis { dirflow_tree selected_node } {
    # The last query arguments were stored in the data for the root node
        ApolTop::setBusyCursor
        if { [$dirflow_tree nodes $selected_node] == "" } {
		set query_args [$dirflow_tree itemcget [$dirflow_tree nodes root] -data]
	        set start_t [file tail $selected_node]
	     	set rt [catch {set results [apol_DirectInformationFlowAnalysis \
			$start_t \
			[lindex $query_args 1] \
			[lindex $query_args 2] \
			[lindex $query_args 3] \
			[lindex $query_args 4] \
			[lindex $query_args 5]] } err]
	
	     	if {$rt != 0} {	
			return -code error $err
		}
		Apol_Analysis_dirflow::create_target_type_nodes $selected_node $dirflow_tree $results
	}
        ApolTop::resetBusyCursor
	return 0
}

proc Apol_Analysis_dirflow::create_resultsDisplay { results_frame } {
        variable dirflow_tree
        variable dirflow_info_text

        # set up paned window
	set pw   [PanedWindow $results_frame.pw -side top]
	set pw_tree [$pw add]
	set pw_info [$pw add -weight 5]
	
	# title frames
	set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Direct Information Flow Tree"]
	set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Direct Information Flow Data"]		
	set sw_tree [ScrolledWindow [$frm_tree getframe].sw_tree -auto none]		 
	set sw_info [ScrolledWindow [$frm_info getframe].sw_info -auto none]		 

	# tree window
	set dirflow_tree  [Tree [$sw_tree getframe].dirflow_tree \
	           -relief flat -borderwidth 0 -highlightthickness 0 \
		   -redraw 0 -bg white -showlines 1 -padx 0 \
		   -opencmd  {Apol_Analysis_dirflow::do_child_analysis $Apol_Analysis_dirflow::dirflow_tree}]
	$sw_tree setwidget $dirflow_tree 
		
	# info window
	set dirflow_info_text [text [$sw_info getframe].dirflow_info_text \
		-wrap none \
		-bg white \
		-font $ApolTop::text_font]
	$sw_info setwidget $dirflow_info_text
	bind $dirflow_info_text <Enter> {focus %W}
	
	pack $pw -fill both -expand yes -anchor nw 
	pack $frm_tree -fill both -expand yes -anchor nw
	pack $frm_info -fill both -expand yes
	pack $sw_tree -fill both -expand yes
	pack $sw_info -fill both -expand yes 
	
	$dirflow_tree bindText  <ButtonPress-1> {
		Apol_Analysis_dirflow::treeSelect \
		$Apol_Analysis_dirflow::dirflow_tree \
		$Apol_Analysis_dirflow::dirflow_info_text}

    	$dirflow_tree bindText  <Double-ButtonPress-1> {
    		Apol_Analysis_dirflow::treeSelect \
		$Apol_Analysis_dirflow::dirflow_tree \
		$Apol_Analysis_dirflow::dirflow_info_text}
    
	return $dirflow_tree
}

proc Apol_Analysis_dirflow::get_selected_objects { } {
        variable list_objs
        variable objects_sel

        set selected_objects ""
        set len [$list_objs size]
        
        if {$objects_sel} {
            for {set i 0} {$i < $len} {incr i} {
	        if { [$list_objs selection includes $i] } {
		    set selected_objects [lappend selected_objects [$list_objs get $i]]
	        }
            }
        }
        return $selected_objects
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::reset_variables { } { 

	set Apol_Analysis_dirflow::start_type     	"" 
        set Apol_Analysis_dirflow::end_type             ""
        set Apol_Analysis_dirflow::flow_direction       ""
	set Apol_Analysis_dirflow::dirflow_tree		""	
	set Apol_Analysis_dirflow::dirflow_info_text	""
        set Apol_Analysis_dirflow::in_button_sel        0
        set Apol_Analysis_dirflow::out_button_sel       0
        set Apol_Analysis_dirflow::either_button_sel    0
        set Apol_Analysis_dirflow::both_button_sel      0
        set Apol_Analysis_dirflow::endtype_sel          0
        set Apol_Analysis_dirflow::objects_sel          0
        set Apol_Analysis_dirflow::display_attrib_sel   0
        set Apol_Analysis_dirflow::display_attribute    ""

     	return 0
} 
 
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::update_display_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::update_display_variables {  } {
	variable start_type
	set start_type $Apol_Analysis_dirflow::start_type
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::config_attrib_comboBox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::config_attrib_comboBox_state { } {    
     	variable combo_attribute
	variable display_attrib_sel 	
        variable combo_start

	if { $display_attrib_sel } {
		$combo_attribute configure -state normal -entrybg white
		# Clear the starting type value
		set Apol_Analysis_dirflow::start_type ""
		Apol_Analysis_dirflow::change_types_list
	} else {
		$combo_attribute configure -state disabled -entrybg  $ApolTop::default_bg_color
		set attrib_typesList $Apol_Types::typelist
        	set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_start configure -values $attrib_typesList
	}
	
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::config_endtype_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::config_endtype_state { } {
        variable entry_end
        variable endtype_sel
        variable end_type

        if { $endtype_sel } {
	        $entry_end configure -state normal -background white
	} else {
	        $entry_end configure -state disabled -background $ApolTop::default_bg_color
	}
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::config_objects_list_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::config_objects_list_state { } {
        variable list_objs
        variable objects_sel
        variable sw_objs

        if { $objects_sel } {
	        ApolTop::enable_tkListbox $list_objs
	        $list_objs configure -selectmode multiple
	        $list_objs configure -background white
		$sw_objs configure -scrollbar vertical
	} else {
	        $list_objs configure -background $ApolTop::default_bg_color
	        $sw_objs configure -scrollbar none
	        ApolTop::disable_tkListbox $list_objs
	}
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::in_button_press
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::in_button_press { } {
        variable out_button
        variable in_button
        variable either_button
        variable both_button
        variable flow_direction

        set flow_direction "in"
        $out_button deselect
        $either_button deselect
        $both_button deselect
        $in_button select
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::out_button_press
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::out_button_press { } {
        variable in_button
        variable either_button
        variable both_button
        variable out_button
        variable flow_direction
        
        set flow_direction "out"
        $in_button deselect 
        $either_button deselect
        $both_button deselect
        $out_button select
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::either_button_press
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::either_button_press { } {
        variable in_button
        variable out_button
        variable both_button
        variable either_button
        variable flow_direction

        set flow_direction "either"
        $out_button deselect
        $in_button deselect
        $both_button deselect
        $either_button select
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::both_button_press
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::both_button_press { } {
        variable in_button
        variable out_button
        variable either_button
        variable flow_direction
        variable both_button

        set flow_direction "both"
        $out_button deselect
        $either_button deselect
        $in_button deselect
        $both_button select
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::select_all_button_press
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::select_all_button_press { } {
        variable list_objs

        $list_objs selection set 0 end
        return 0
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::clear_all_button_press
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::clear_all_button_press { } {
        variable list_objs

        $list_objs selection clear 0 end
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::change_types_list { } { 

        variable combo_start
	variable display_attribute
	
	if { $display_attribute != "" } {
		$combo_start configure -text ""		   
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $display_attribute]} err]	
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -code error
		} 
		set attrib_typesList [lsort $attrib_typesList]
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
		$combo_start configure -values $attrib_typesList
        } else {
        	set attrib_typesList $Apol_Types::typelist
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_start configure -values $attrib_typesList
        }
     	return 0
}

## Apol_Analysis_dirflow::display_mod_options is called by the GUI to display the
## analysis options interface the analysis needs.  Each module must know how
## to display their own options, as well bind appropriate commands and variables
## with the options GUI.  opts_frame is the name of a frame in which the options
## GUI interface is to be packed.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::display_mod_options { opts_frame } {    
	Apol_Analysis_dirflow::reset_variables 	
     	Apol_Analysis_dirflow::create_options $opts_frame
        Apol_Analysis_dirflow::populate_ta_list
 	
     	if {[ApolTop::is_policy_open]} {
	     	# Have the attributes checkbutton OFF by default
		set Apol_Analysis_dirflow::display_attrib_sel 0
		Apol_Analysis_dirflow::config_attrib_comboBox_state
	     	Apol_Analysis_dirflow::change_types_list
	        # By default have the in button pressed
	        set Apol_Analysis_dirflow::in_button_sel 1
	        $Apol_Analysis_dirflow::in_button select
	        Apol_Analysis_dirflow::in_button_press
	} else {
	        Apol_Analysis_dirflow::config_attrib_comboBox_state
	}
	Apol_Analysis_dirflow::config_endtype_state
	Apol_Analysis_dirflow::config_objects_list_state
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::populate_ta_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::populate_ta_list { } {
        variable combo_start
        variable combo_attribute
        variable list_objs

	set attrib_typesList $Apol_Types::typelist
	set idx [lsearch -exact $attrib_typesList "self"]
	if {$idx != -1} {
		set attrib_typesList [lreplace $attrib_typesList $idx $idx]
	}
	$combo_start configure -values $attrib_typesList
     	$combo_attribute configure -values $Apol_Types::attriblist
        set len [llength $Apol_Class_Perms::class_list]
        for {set i 0} {$i < $len } {incr i} {
	        set temp [lindex $Apol_Class_Perms::class_list $i]
	        $list_objs insert end $temp
        }
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dirflow::create_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dirflow::create_options { options_frame } {
     	variable combo_attribute
        variable combo_start
	variable display_attrib_sel 
        variable display_attribute
        variable descriptive_text
        variable start_type
        variable end_type
        variable endtype_sel
        variable entry_end
        variable list_objs
        variable objects_sel
        variable in_button_sel
        variable out_button_sel
        variable either_button_sel
        variable both_button_sel
        variable in_button
        variable out_button
        variable either_button
        variable both_button
        variable cb_attrib
        variable sw_objs
	
	set entry_frame [frame $options_frame.entry_frame]
        set left_frame 	[TitleFrame $entry_frame.left_frame -text "Required parameters"]
        set right_frame [TitleFrame $entry_frame.right_frame -text "Optional result filters"]
        set left  [$left_frame getframe]
        set right [$right_frame getframe]

        set start_attrib_frame [frame $left.start_attrib_frame]
        set start_frame [frame $start_attrib_frame.start_frame]
        set attrib_frame [frame $start_attrib_frame.attrib_frame]
        set object_opt_frame [frame $right.object_opt_frame]
        set objcl_frame [frame $object_opt_frame.objcl_frame]
        set bttns_frame [frame $object_opt_frame.bttns_frame]
        set flowtype_frame [frame $left.flowtype_frame]
        set ckbttn_frame [frame $flowtype_frame.ckbttn_frame]
        set endtype_frame [frame $right.endtype_frame]

	# Information Flow Entry frames
	set lbl_start_type [Label $start_frame.lbl_start_type \
		-text "Starting type:"]
    	set combo_start [ComboBox $start_frame.combo_start \
    		-helptext "You must choose a starting type for information flow" \
		-editable 1 \
    		-textvariable Apol_Analysis_dirflow::start_type \
		-entrybg white \
		-exportselection 0]  

        set lbl_flowtype [Label $flowtype_frame.lbl_flowtype \
        	-text "Flow direction:"]

        set in_button [checkbutton $ckbttn_frame.in_button \
        	-text "In" \
		-variable Apol_Analysis_dirflow::in_button_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dirflow::in_button_press }]

        set out_button [checkbutton $ckbttn_frame.out_button \
        	-text "Out" \
		-variable Apol_Analysis_dirflow::out_button_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dirflow::out_button_press }]

        set either_button [checkbutton $ckbttn_frame.either_button \
        	-text "Either" \
		-variable Apol_Analysis_dirflow::either_button_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dirflow::either_button_press }]

        set both_button [checkbutton $ckbttn_frame.both_button \
        	-text "Both" \
		-variable Apol_Analysis_dirflow::both_button_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dirflow::both_button_press }]

        set cb_attrib [checkbutton $attrib_frame.cb_attrib \
        	-text "Select starting type using attrib:" \
		-variable Apol_Analysis_dirflow::display_attrib_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dirflow::config_attrib_comboBox_state }]

    	set combo_attribute [ComboBox $attrib_frame.combo_attribute  \
    		-textvariable Apol_Analysis_dirflow::display_attribute \
    		-modifycmd { Apol_Analysis_dirflow::change_types_list} \
		-exportselection 0] 

        set clear_all_bttn [button $bttns_frame.clear_all_bttn \
        	-text "Clear All" \
		-command {Apol_Analysis_dirflow::clear_all_button_press} ]
        set select_all_bttn [button $bttns_frame.select_all_bttn \
        	-text "Select All" \
		-command {Apol_Analysis_dirflow::select_all_button_press} ]

        set cb_endtype [checkbutton $endtype_frame.cb_endtype \
        	-text "Find end types using regular expression:" \
		-variable Apol_Analysis_dirflow::endtype_sel \
		-offvalue 0 -onvalue 1 -justify left -wraplength 150 \
		-command { Apol_Analysis_dirflow::config_endtype_state }]

        set entry_end [Entry $endtype_frame.entry_end \
		-helptext "You may choose an optional result type" \
		-editable 1 \
		-textvariable Apol_Analysis_dirflow::end_type \
		-exportselection 0] 

        set cb_objects [checkbutton $objcl_frame.cb_objects \
        	-text "Exclude rules with selected object classes:" \
		-variable Apol_Analysis_dirflow::objects_sel \
		-offvalue 0 -onvalue 1 \
		-justify left \
		-command {Apol_Analysis_dirflow::config_objects_list_state }]

        set sw_objs [ScrolledWindow $objcl_frame.sw_objs -auto both]
        set list_objs [listbox [$sw_objs getframe].list_objs -height 7 \
        	-highlightthickness 0 \
		-selectmode multiple \
		-exportselection 0] 
        $sw_objs setwidget $list_objs

        # pack all the widgets
	pack $entry_frame -side left -anchor nw -fill both -padx 5 -expand yes
        pack $left_frame $right_frame -side left -anchor nw -fill both -padx 5 -expand yes
        pack $left $right -fill both -expand yes
        pack $start_attrib_frame $flowtype_frame -side top -anchor nw -fill both -expand yes -pady 5 
        pack $start_frame $attrib_frame -side top -anchor nw -fill both -expand yes
        pack $lbl_flowtype -side top -anchor nw
        pack $ckbttn_frame -side left -anchor nw -fill both -expand yes
        pack $object_opt_frame $endtype_frame -side left -padx 10 -fill both -expand yes
        pack $bttns_frame -side bottom -fill both -expand yes
        pack $objcl_frame -side top -expand yes -fill both
      	
	pack $select_all_bttn -side left -anchor nw -fill x -expand yes -pady 2
        pack $clear_all_bttn -side right -anchor nw -fill x -expand yes -pady 2
        pack $cb_objects -side top -anchor nw
        pack $sw_objs -fill both -anchor nw -expand yes -fill both

	pack $lbl_start_type -side top -anchor nw
        pack $combo_start -side left -anchor nw -expand yes -fill x
        pack $cb_attrib -side top -anchor nw
        pack $combo_attribute -side top -anchor nw -padx 15 -expand yes -fill x

        pack $in_button $out_button $either_button $both_button -side left -anchor nw -expand yes -fill x

        pack $cb_endtype -side top -anchor nw 
        pack $entry_end -side left -anchor nw -fill x -expand yes
            	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list. 

        bindtags $combo_start.e [linsert [bindtags $combo_start.e] 3 start_list_Tag]
        bind start_list_Tag <KeyPress> {ApolTop::_create_popup $Apol_Analysis_dirflow::combo_start %W %K}

	bindtags $combo_attribute.e [linsert [bindtags $combo_attribute.e] 3 attribs_list_Tag]
	bind attribs_list_Tag <KeyPress> { ApolTop::_create_popup $Apol_Analysis_dirflow::combo_attribute %W %K }

	bindtags $list_objs [linsert [bindtags $list_objs] 3 list_objs_Tag]
	return 0	
}
