#############################################################
#  dta_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com, mayerf@tresys.com>
# -----------------------------------------------------------
#
# This module implements the domain transition analysis interface.

##############################################################
# ::Apol_Analysis_dta module namespace
##############################################################
namespace eval Apol_Analysis_dta {
	# Options widgets 
	variable combo_domain
	variable combo_attribute
	variable cb_attrib
	variable lbl_domain
		
    	# Options Display Variables
	variable display_type			""
	variable display_attribute		""
	variable display_attrib_sel		0
	variable display_direction		"forward"
	
	# Options State Variables
	variable type_state			""
	variable attribute_state		""
	variable attrib_selected_state 		0
	variable direction_state		"forward"
	
	# Current results display
	variable dta_tree		""	
	variable dta_info_text		""
	    	
    	# Defined Tag Names
	variable title_tag		TITLE
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	variable rules_tag		RULES
	variable counters_tag		COUNTERS
	variable types_tag		TYPE
	
    	# Register ourselves
    	Apol_Analysis::register_analysis_modules "Apol_Analysis_dta" "Domain Transition"
    	
    	variable descriptive_text	"\n\nA forward domain transition analysis will determine all (target) \
    		domains to which a given (source) domain may transition.  For a forward domain \
    		transition to be allowed, three forms of access must be granted:\n\n\ \
    		\t(1) source domain must have process transition permission for target domain,\n\
    		\t(2) source domain must have file execute permission for some entrypoint type, and\n\
    		\t(3) target domain must have file entrypoint permission for the same entrypoint type.\n\nA \
    		reverse domain transition analysis will determine all (source) domains that can transition to \
    		a given (target) domain.  For a reverse domain transition to be allowed, three forms of access must be granted:\n\n\
    		\t(1) target domain must have process transition permission from the source domain,\n\
    		\t(2) target domain must have file entrypoint permission to some entrypoint type, and\n\
    		\t(3) source domain must have file execute permission to the same entrypoint type.\n\n\The \
    		results are presented in tree form.  You can open target children domains to \
    		perform another domain transition analysis on that domain.\n\nFor additional \
    		help on this topic select \"Domain Transition Analysis\" from the help menu."
	
    	
	
	# root text for forward dta results
	variable dta_root_text_f 	"\n\nThis tab provides the results of a forward domain transition analysis\
		starting from the source domain type above.  The results of this analysis are presented in tree form with the root\
		of the tree (this node) being the start point for the analysis.\n\nEach child node in the tree represents\
		a TARGET DOMAIN TYPE.  A target domain type is a domain to which the source domain may transition.  You can\
		follow the domain transition tree by opening each subsequent generation of children in the tree.\n\nNOTE: For any\
		given generation, if the parent and the child are the same, you cannot open the child. This avoids cyclic analyses.\n\nThe\
		criteria that defines an allowed domain transition are:\n\n1) There must be at least one rule that allows TRANSITION\
		access for PROCESS objects between the SOURCE and TARGET domain types.\n\n2) There must be at least one FILE TYPE that\
		allows the TARGET type ENTRYPOINT access for FILE objects.\n\n3) There must be at least one FILE TYPE that meets\
		criterion 2) above and allows the SOURCE type EXECUTE access for FILE objects.\n\nThe information window shows\
		all the rules and file types that meet these criteria for each target domain type.\n\nFUTURE NOTE: In the future\
		we also plan to show the type_transition rules that provide for a default domain transitions.  While such rules\
		cause a domain transition to occur by default, they do not allow it.  Thus, associated type_transition rules\
		are not truly part of the definition of allowed domain transitions."
	
	# root text for reverse dta results
	variable dta_root_text_r 	"\n\nThis tab provides the results of a reverse domain transition analysis\
		given the target domain type above.  The results of this analysis are presented in tree form with the root\
		of the tree (this node) being the target point of the analysis.\n\nEach child node in the tree represents\
		a source DOMAIN TYPE.  A source domain type is a domain that can transition to the target domain.  You can\
		follow the domain transition tree by opening each subsequent generation of children in the tree.\n\nNOTE: For any\
		given generation, if the parent and the child are the same, you cannot open the child. This avoids cyclic analyses.\n\nThe\
		criteria that defines an allowed domain transition are:\n\n1) There must be at least one rule that allows TRANSITION\
		access for PROCESS objects between the SOURCE and TARGET domain types.\n\n2) There must be at least one FILE TYPE that\
		allows the TARGET type ENTRYPOINT access for FILE objects.\n\n3) There must be at least one FILE TYPE that meets\
		criterion 2) above and allows the SOURCE type EXECUTE access for FILE objects.\n\nThe information window shows\
		all the rules and file types that meet these criteria for each source domain type.\n\nFUTURE NOTE: In the future\
		we also plan to show the type_transition rules that provide for a default domain transitions.  While such rules\
		cause a domain transition to occur by default, they do not allow it.  Thus, associated type_transition rules\
		are not truly part of the definition of allowed domain transitions."
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::close { } {   
	Apol_Analysis_dta::reset_variables
     	$Apol_Analysis_dta::combo_attribute configure -values ""
	$Apol_Analysis_dta::combo_attribute configure -state disabled -entrybg $ApolTop::default_bg_color
	Apol_Analysis_dta::config_domain_label
        Apol_Analysis_dta::config_attrib_comboBox_state
	$Apol_Analysis_dta::combo_domain configure -values ""
	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::open { } {  
	variable display_attrib_sel
	
	Apol_Analysis_dta::populate_ta_list	
	# Have the attributes checkbutton OFF by default
	set display_attrib_sel	0
	Apol_Analysis_dta::config_domain_label
	Apol_Analysis_dta::config_attrib_comboBox_state
	Apol_Analysis_dta::change_types_list	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::initialize { } { 	
	Apol_Analysis_dta::reset_variables
	if {[ApolTop::is_policy_open]} {
	     	# Have the attributes checkbutton OFF by default
		set Apol_Analysis_dta::display_attrib_sel	0
		Apol_Analysis_dta::config_domain_label
		Apol_Analysis_dta::config_attrib_comboBox_state
		Apol_Analysis_dta::change_types_list	
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_analysis_info { } {   
	return $Apol_Analysis_dta::descriptive_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::display_mod_options { opts_frame } {
	Apol_Analysis_dta::reset_variables	  	
     	Apol_Analysis_dta::create_options $opts_frame
     	Apol_Analysis_dta::config_domain_label
     	Apol_Analysis_dta::populate_ta_list
     	
     	if {[ApolTop::is_policy_open]} {
	     	# Have the attributes checkbutton OFF by default
		set Apol_Analysis_dta::display_attrib_sel	0
		Apol_Analysis_dta::config_attrib_comboBox_state
		Apol_Analysis_dta::change_types_list	
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::load_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::load_query_options { file_channel parentDlg } {         
        variable type_state		
	variable attribute_state		
	variable attrib_selected_state 
	variable direction_state
	
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

     	if {[lindex $query_options 0] != "\{\}"} {
     		set tmp [string trim [lindex $query_options 0] "\{\}"]
     		# Validate that the type exists in the loaded policy.
     		if {[lsearch -exact $Apol_Types::typelist $tmp] != -1} {
     			set type_state $tmp
     		} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified type starting source domain type $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
     		}     		
     	}
     	if {[lindex $query_options 1] != "\{\}"} {
     		set tmp [string trim [lindex $query_options 1] "\{\}"]
     		if {[lsearch -exact $Apol_Types::attriblist $tmp] != -1} {
     			set attribute_state $tmp
     		} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified attribute $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
		}
     	}
	set attrib_selected_state [lindex $query_options 2]
	
	if {[lindex $query_options 3] != "\{\}"} {
     		set tmp [string trim [lindex $query_options 3] "\{\}"]
     		set direction_state $tmp
     	}
	
	# After updating any display variables, must configure widgets accordingly
	Apol_Analysis_dta::update_display_variables 
	Apol_Analysis_dta::config_domain_label
	Apol_Analysis_dta::config_attrib_comboBox_state	
	if { $attribute_state != "" } {
		# Need to change the types list to reflect the currently selected attrib and then reset the 
		# currently selected type in the types combo box. 
		Apol_Analysis_dta::change_types_list  	
		set Apol_Analysis_dta::display_type $type_state
	}
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::save_query_options {module_name file_channel file_name} {
	variable display_type			
	variable display_attribute		
	variable display_attrib_sel
	variable display_direction
			     	
     	set options [list $display_type $display_attribute $display_attrib_sel $display_direction]
     	
     	puts $file_channel "$module_name"
	puts $file_channel "$options"
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_current_results_state { } {
	variable display_type			
	variable display_attribute		
	variable display_attrib_sel
	variable display_direction
	variable dta_tree
	variable dta_info_text
		     	
     	set options [list $dta_tree $dta_info_text $display_type $display_attribute $display_attrib_sel $display_direction]
     	return $options
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::set_display_to_results_state { query_options } {     	
     	variable type_state		
	variable attribute_state		
	variable attrib_selected_state 
	variable direction_state
	variable dta_tree
	variable dta_info_text
		    
	# widget variables
	set dta_tree [lindex $query_options 0]
     	set dta_info_text [lindex $query_options 1]
     	# query options variables
     	set type_state [lindex $query_options 2]
     	set attribute_state  [lindex $query_options 3]
     	set attrib_selected_state [lindex $query_options 4]
     	set direction_state [lindex $query_options 5]
     	
	# After updating any display variables, must configure widgets accordingly
	Apol_Analysis_dta::update_display_variables 
	Apol_Analysis_dta::config_domain_label
	Apol_Analysis_dta::config_attrib_comboBox_state	
	if { $attribute_state != "" } {
		# Need to change the types list to reflect the currently selected attrib and then reset the 
		# currently selected type in the types combo box. 
		Apol_Analysis_dta::change_types_list  	
		set Apol_Analysis_dta::display_type $type_state
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::free_results_data
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::free_results_data {query_options} {  
	set dta_tree [lindex $query_options 0]
     	set dta_info_text [lindex $query_options 1]

	if {[winfo exists $dta_tree]} {
		$dta_tree delete [$dta_tree nodes root]
		if {[$dta_tree nodes root] != ""} {
			return -1			
		}
		destroy $dta_tree
	} 
	if {[winfo exists $dta_info_text]} {
		$dta_info_text delete 0.0 end
		destroy $dta_info_text
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::do_analysis { results_frame } {     
	variable display_type		
	variable display_attribute		
	variable display_attrib_sel 
	variable dta_tree
	variable dta_info_text

        if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -code error
        } 		
      	if {$Apol_Analysis_dta::display_direction == "forward"} {
		set reverse 0
	} else {
		set reverse 1
	}
	
     	set rt [catch {set results [apol_DomainTransitionAnalysis $reverse $display_type]} err]
     	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 
	set dta_tree [Apol_Analysis_dta::create_resultsDisplay $results_frame $reverse]
	Apol_Analysis_dta::create_result_tree_structure $dta_tree $results $reverse
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

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::reset_variables { } {  
	# Reset display vars  
    	set Apol_Analysis_dta::display_type		""
	set Apol_Analysis_dta::display_attribute	""
	set Apol_Analysis_dta::display_attrib_sel 	0
	set Apol_Analysis_dta::display_direction	"forward"
	
	# Reset state vars
	set Apol_Analysis_dta::type_state		""
	set Apol_Analysis_dta::attribute_state		""
	set Apol_Analysis_dta::attrib_selected_state 	0
	set Apol_Analysis_dta::direction_state		"forward"
	
	# Reset results display variables
	set Apol_Analysis_dta::dta_tree		""	
	set Apol_Analysis_dta::dta_info_text	""
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::update_display_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::update_display_variables {  } {
	variable display_type			
	variable display_attribute		
	variable display_attrib_sel	
	variable display_direction
	
	set display_type $Apol_Analysis_dta::type_state	
	set display_attribute $Apol_Analysis_dta::attribute_state
	set display_attrib_sel $Apol_Analysis_dta::attrib_selected_state
	set display_direction $Apol_Analysis_dta::direction_state
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::populate_ta_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::populate_ta_list { } { 
	variable combo_domain
	variable combo_attribute
	   
	set attrib_typesList $Apol_Types::typelist
	set idx [lsearch -exact $attrib_typesList "self"]
	if {$idx != -1} {
		set attrib_typesList [lreplace $attrib_typesList $idx $idx]
	}
	$combo_domain configure -values $attrib_typesList
     	$combo_attribute configure -values $Apol_Types::attriblist
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::change_types_list { } { 
	variable combo_domain
	variable display_attribute
	
	if { $display_attribute != "" } {
		$combo_domain configure -text ""	  
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

		$combo_domain configure -values $attrib_typesList
        } else {
        	set attrib_typesList $Apol_Types::typelist
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_domain configure -values $attrib_typesList
        }
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::config_domain_label
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::config_domain_label { } {    
     	variable lbl_domain 	
	
	if {$Apol_Analysis_dta::display_direction == "forward"} {
		$lbl_domain configure -text "Starting source domain:"
	} else {
		$lbl_domain configure -text "Starting target domain:"
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::config_attrib_comboBox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::config_attrib_comboBox_state { } {    
     	variable combo_attribute
     	variable combo_domain
	variable display_attrib_sel 	
	
	if { $display_attrib_sel } {
		$combo_attribute configure -state normal -entrybg white
		# Clear the starting domain value
		set Apol_Analysis_dta::display_type ""
		Apol_Analysis_dta::change_types_list
	} else {
		$combo_attribute configure -state disabled -entrybg  $ApolTop::default_bg_color
		set attrib_typesList $Apol_Types::typelist
        	set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_domain configure -values $attrib_typesList
	}
	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_result_tree_structure
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_result_tree_structure { dta_tree results_list reverse } {
	# Get the source type name and insert into the tree structure as the root node.
	set source_type [lindex $results_list 0]
	set home_node [Apol_Analysis_dta::insert_src_type_node $source_type $dta_tree $reverse]
	# Create target type children nodes.
	Apol_Analysis_dta::create_target_type_nodes $home_node $dta_tree $results_list
	Apol_Analysis_dta::treeSelect $Apol_Analysis_dta::dta_tree $Apol_Analysis_dta::dta_info_text $home_node
	
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_target_type_nodes
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_target_type_nodes { parent dta_tree results_list } {
	if { [file tail [$dta_tree parent $parent]] == [file tail $parent] } {
		return 
	}
	if { [file tail [$dta_tree parent $parent]] == [file tail $parent] } {
		return 
	}
	if { [$dta_tree nodes $parent] == "" } {
		# Get # of target domain types (if none, then just draw the tree without child nodes)
		set num_target_domains [lindex $results_list 1]
		# If there are any target types then create and insert children nodes for the source_type node 
		set start_idx 2
		for { set x 0 } { $x < $num_target_domains } { incr x } { 
			set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $start_idx]
			if {$end_idx == -1} {
				# TODO: DO SOMETHING ERROR
				# ERROR MSG: "Error parsing results"
			}
			set target_name [lindex $results_list $start_idx]
			set target_node "${parent}/${target_name}/"
			$dta_tree insert end $parent $target_node -text $target_name \
				-open 0	\
		        	-drawcross allways \
		        	-data [lrange $results_list [expr $start_idx +1] $end_idx]
		        set start_idx [expr $end_idx + 1]
		}
		set nodes [lsort [$dta_tree nodes $parent]]
		$dta_tree reorder $parent $nodes 
	        $dta_tree configure -redraw 1
	}
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::do_child_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::do_child_analysis { dta_tree selected_node } {
	if { [$dta_tree nodes $selected_node] == "" } {
		set reverse [$dta_tree itemcget [$dta_tree nodes root] -data]
		set source_type [file tail $selected_node]
		set rt [catch {set results [apol_DomainTransitionAnalysis $reverse $source_type]} err]
	     	if {$rt != 0} {	
			return -code error $err
		} 
		Apol_Analysis_dta::create_target_type_nodes $selected_node $dta_tree $results
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_target_type_data_end_idx
#
#  This worker function takes a list and extracts from it the idx of the 
#  last data item for the current target.  This proc assumes that the idx is the index
#  of the first element of the current child target type.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_target_type_data_end_idx { results_list idx } {
	
	# First see if this is the end of the list
	if {$idx >= [llength $results_list]} {
		# return an empty string indicating no more items in list
		return -code error
	}
	
	# Determine length of sublist containing type's data
	# 
	# type (name) and (# of pt rules)
	set len 1
	# account for the (pt rules)
	set num_pt [lindex $results_list [expr $idx + $len]]
	incr len [expr $num_pt * 2 ]
	# (# of file types)
	incr len
	set num_types [lindex $results_list [expr $idx + $len]]
	for {set i 0} { $i < $num_types } { incr i } {
		# (file type) and (# ep rules)
		incr len 2
		# account for (ep rules)
		set num_ep [lindex $results_list [expr $idx + $len]]
		incr len [expr $num_ep * 2]
		# (# ex rules)
		incr len
		# account for (ex rules)
		set num_ex [lindex $results_list [expr $idx + $len]]
		incr len [expr $num_ex * 2]
	}
	return [expr $len + $idx]
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::render_target_type_data
#
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::render_target_type_data { data dta_info_text dta_tree node} {

	$dta_info_text configure -state normal
        $dta_info_text delete 0.0 end
	$dta_info_text configure -wrap none

	# First see if this is the end of the list
	if { $data == "" } {
	        $dta_info_text configure -state disabled
		return ""
	}
	set target [$dta_tree itemcget $node -text]
	set parent [$dta_tree itemcget [$dta_tree parent $node] -text]
	# Set the mark to 0.0
	$dta_info_text mark set insert 1.0
	set start_idx [$dta_info_text index insert]
	
	$dta_info_text insert end "Domain transition from "
	# The character at $end_idx isn't tagged, so must add 1 to $end_idx argument.
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_tag $start_idx $end_idx
	
	set start_idx [$dta_info_text index insert]
	if {[$dta_tree itemcget [$dta_tree nodes root] -data]} {
		$dta_info_text insert end $target
	} else {
		$dta_info_text insert end $parent
	}
	set end_idx [$dta_info_text index insert] 
	$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx
	
	set start_idx [$dta_info_text index insert]
	$dta_info_text insert end " to "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_tag $start_idx $end_idx
	
	set start_idx [$dta_info_text index insert]
	if {[$dta_tree itemcget [$dta_tree nodes root] -data]} {
		$dta_info_text insert end $parent
	} else {
		$dta_info_text insert end $target
	}
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx

	# (# of pt rules)
	$dta_info_text insert end "\n\n"
	set start_idx [$dta_info_text index insert]
	set idx 0
	set num_pt [lindex $data $idx]
	incr idx
	$dta_info_text insert end "Process Transition Rules:  "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
	set start_idx $end_idx
	$dta_info_text insert end "$num_pt\n"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx

	for {set i 0} { $i < $num_pt } { incr i } {
		set rule [lindex $data $idx]
		incr idx
		set lineno [lindex $data $idx] 
		incr idx
		$dta_info_text insert end "\t"
		set start_idx [$dta_info_text index insert]
		$dta_info_text insert end "($lineno) "
		set end_idx [$dta_info_text index insert]
		Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
		set start_idx $end_idx
		$dta_info_text insert end "$rule\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
	}
	# (# of file types)
	set num_types [lindex $data $idx ]
	set start_idx $end_idx
	$dta_info_text insert end "\nEntry Point File Types:  "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
	set start_idx $end_idx
	$dta_info_text insert end "$num_types\n"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
	
	incr idx
	for {set i 0} { $i < $num_types } { incr i } {
		# (file type) 
		set type [lindex $data $idx]
		incr idx
		set start_idx $end_idx
		$dta_info_text insert end "\t$type\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::types_tag $start_idx $end_idx
		set num_ep [lindex $data $idx]
		incr idx
		set start_idx $end_idx
		$dta_info_text insert end "\t\tFile Entrypoint Rules:  "
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$dta_info_text insert end "$num_ep\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
		
		for {set j 0 } { $j < $num_ep } { incr j }  {
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]
			incr idx
			$dta_info_text insert end "\t\t"
			set start_idx [$dta_info_text index insert]
			$dta_info_text insert end "($lineno) "
			set end_idx [$dta_info_text index insert]
			Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
			set start_idx $end_idx
			$dta_info_text insert end "$rule\n"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
		}
		set num_ex [lindex $data $idx]
		incr idx
		set start_idx $end_idx
		$dta_info_text insert end "\n\t\tFile Execute Rules:  "
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$dta_info_text insert end "$num_ex\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
		
		for {set j 0 } { $j < $num_ex } { incr j }  {
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]
			incr idx
			$dta_info_text insert end "\t\t"
			set start_idx [$dta_info_text index insert]
			$dta_info_text insert end "($lineno) "
			set end_idx [$dta_info_text index insert]
			Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
			set start_idx $end_idx
			$dta_info_text insert end "$rule\n"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
		}

		$dta_info_text insert end "\n"
	}
	$dta_info_text configure -state disabled
	return 0
}

###########################################################################
# ::formatInfoText
#
proc Apol_Analysis_dta::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_dta::title_tag -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_dta::title_type_tag -foreground blue -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_dta::subtitle_tag -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_dta::rules_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_dta::counters_tag -foreground blue -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_dta::types_tag -font $ApolTop::text_font
	
	# Configure hyperlinking to policy.conf file
	Apol_PolicyConf::configure_HyperLinks $tb
}

###########################################################################
# ::display_root_type_info
#
proc Apol_Analysis_dta::display_root_type_info { source_type dta_info_text dta_tree } {

        $dta_info_text configure -state normal
        $dta_info_text delete 0.0 end
        if {[$dta_tree itemcget $source_type -data]} {
	    $dta_info_text insert end "Reverse Domain Transition Analysis: Starting Type:  "
        } else {
	    $dta_info_text insert end "Forward Domain Transition Analysis: Starting Type:  "
        }

	$dta_info_text tag add ROOT_TITLE 0.0 end
	$dta_info_text tag configure ROOT_TITLE -font {Helvetica 14 bold}
	set start_idx [$dta_info_text index insert]
	$dta_info_text insert end "$source_type"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add ROOT_TYPE $start_idx $end_idx
	$dta_info_text tag configure ROOT_TYPE -font {Helvetica 14 bold} -foreground blue
	
	# now add the standard text
	$dta_info_text configure -wrap word
	set start_idx [$dta_info_text index insert]
	if {[$dta_tree itemcget $source_type -data]} {
		set root_text $Apol_Analysis_dta::dta_root_text_r
	} else {
		set root_text $Apol_Analysis_dta::dta_root_text_f
		
	}
	$dta_info_text insert end $root_text
	$dta_info_text tag add ROOT_TEXT $start_idx end
	$dta_info_text tag configure ROOT_TEXT -font $ApolTop::text_font
	$dta_info_text configure -state disabled
	return 0
}

###########################################################################
# ::treeSelect
#  	- Method is invoked when the user selects a node in the tree widget.
#
proc Apol_Analysis_dta::treeSelect { dta_tree dta_info_text node } {
	# Set the tree selection to the current node.
	$dta_tree selection set $node

	if {$node ==  [$dta_tree nodes root]} {
		Apol_Analysis_dta::display_root_type_info $node $dta_info_text $dta_tree
		return
	}
	Apol_Analysis_dta::render_target_type_data [$dta_tree itemcget $node -data] $dta_info_text $dta_tree $node
	Apol_Analysis_dta::formatInfoText $dta_info_text
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::insert_src_type_node
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::insert_src_type_node { source_type dta_tree reverse } {
	$dta_tree insert end root $source_type -text $source_type \
		-open 1	\
        	-drawcross auto \
        	-data "$reverse"
        return [$dta_tree nodes root]
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_options { options_frame } {
	variable combo_domain
	variable combo_attribute
	variable cb_attrib
	variable lbl_domain
	
	set entry_frame [frame $options_frame.entry_frame]
	set radio_frame [frame $options_frame.radio_frame]
	
	# Domain transition section
	set lbl_domain [Label $entry_frame.lbl_domain]
    	set combo_domain [ComboBox $entry_frame.combo_domain -width 20 \
    		-helptext "Starting Domain"  \
    		-editable 1 \
    		-entrybg white \
    		-textvariable Apol_Analysis_dta::display_type]  
    	set combo_attribute [ComboBox $entry_frame.combo_attribute  \
    		-textvariable Apol_Analysis_dta::display_attribute \
    		-modifycmd { Apol_Analysis_dta::change_types_list}]  
	set cb_attrib [checkbutton $entry_frame.trans -text "Select starting domain using attrib:" \
		-variable Apol_Analysis_dta::display_attrib_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dta::config_attrib_comboBox_state }]
	set lbl_direction [Label $radio_frame.lbl_direction -text "Select direction:"]
	set radio_forward [radiobutton $radio_frame.radio_forward -text "Forward" \
		-variable Apol_Analysis_dta::display_direction \
		-value forward \
		-command {Apol_Analysis_dta::config_domain_label}]
	set radio_reverse [radiobutton $radio_frame.radio_reverse -text "Reverse" \
		-variable Apol_Analysis_dta::display_direction \
		-value reverse \
		-command {Apol_Analysis_dta::config_domain_label}]
	
	pack $radio_frame -side top -anchor nw -pady 5
	pack $entry_frame -side top -padx 10 -anchor nw
	
	pack $lbl_domain -side top -anchor nw
	pack $combo_domain -side top -anchor nw -fill x
    	pack $cb_attrib -padx 15 -side top -anchor nw
    	pack $combo_attribute -side top -anchor nw -fill x -padx 15
	pack $lbl_direction -side left -anchor nw 
	pack $radio_forward $radio_reverse -side left -anchor nw -padx 5
	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list. 
	bindtags $combo_attribute.e [linsert [bindtags $combo_attribute.e] 3 attribs_list_Tag]
	bind attribs_list_Tag <KeyPress> { ApolTop::_create_popup $Apol_Analysis_dta::combo_attribute %W %K }
	bindtags $combo_domain.e [linsert [bindtags $combo_domain.e] 3 domains_list_Tag]
	bind domains_list_Tag <KeyPress> { ApolTop::_create_popup $Apol_Analysis_dta::combo_domain %W %K }

	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_resultsDisplay
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_resultsDisplay {results_frame reverse} {
	variable dta_tree
	variable dta_info_text

	# set up paned window
	set pw   [PanedWindow $results_frame.pw -side top]
	set pw_tree [$pw add]
	set pw_info [$pw add -weight 5]
	
	# title frames
        if { $reverse } {
	    set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Reverse Domain Transition Tree"]
	    set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Reverse Domain Transition Information"]	
	} else {
	    set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Forward Domain Transition Tree"]
	    set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Forward Domain Transition Information"]
	}
	set sw_tree [ScrolledWindow [$frm_tree getframe].sw_tree -auto none]		 
	set sw_info [ScrolledWindow [$frm_info getframe].sw_info -auto none]		 

	# tree window
	set dta_tree  [Tree [$sw_tree getframe].dta_tree \
	           -relief flat -borderwidth 0 -width 15 -highlightthickness 0 \
		   -redraw 0 -bg white -showlines 1 -padx 0 \
		   -opencmd  {Apol_Analysis_dta::do_child_analysis $Apol_Analysis_dta::dta_tree}]
	$sw_tree setwidget $dta_tree 

	# info window
	set dta_info_text [text [$sw_info getframe].dta_info_text -wrap none -bg white -font $ApolTop::text_font]
	$sw_info setwidget $dta_info_text
	
	pack $pw -fill both -expand yes -anchor nw 
	pack $frm_tree -fill both -expand yes -anchor nw
	pack $frm_info -fill both -expand yes
	pack $sw_tree -fill both -expand yes
	pack $sw_info -fill both -expand yes 
	
	$dta_tree bindText  <ButtonPress-1>        {Apol_Analysis_dta::treeSelect $Apol_Analysis_dta::dta_tree $Apol_Analysis_dta::dta_info_text}
    	$dta_tree bindText  <Double-ButtonPress-1> {Apol_Analysis_dta::treeSelect $Apol_Analysis_dta::dta_tree $Apol_Analysis_dta::dta_info_text}
    
	return $dta_tree
}
