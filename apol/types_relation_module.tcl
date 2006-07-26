#############################################################
#  types_relation_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2004-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com> 8-11-2004
# -----------------------------------------------------------
#
# This module implements the two types relationship analysis interface.

namespace eval Apol_Analysis_tra {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_tra" "Types Relationship Summary"
}

proc Apol_Analysis_tra::open {} {
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(typeA)
    Apol_Widget::resetTypeComboboxToPolicy $widgets(typeB)
}

proc Apol_Analysis_tra::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(typeA)
    Apol_Widget::clearTypeCombobox $widgets(typeB)
}

proc Apol_Analysis_tra::getInfo {} {
    return "The types relationship summary analysis in Apol is a convenience
mechanism to allow a user to quickly do several queries and analyses
already in present in Apol to understand the relationship between two
types.  This is meant to quickly display the relationship between two
types and therefore doesn't include all of the options present in the
standard queries and analyses.

\nFor additional help on this topic select \"Types Relationship Summary
Analysis\" from the help menu."
}

proc Apol_Analysis_tra::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set fA [frame [$req_tf getframe].fA]
    pack $fA -side left -anchor nw -padx 2
    set lA [label $fA.l -text "Type A"]
    pack $lA -anchor w
    set widgets(typeA) [Apol_Widget::makeTypeCombobox $fA.t]
    pack $widgets(typeA)
    set fB [frame [$req_tf getframe].fB]
    pack $fB -side left -anchor nw -padx 2
    set lB [label $fB.l -text "Type B"]
    pack $lB -anchor w
    set widgets(typeB) [Apol_Widget::makeTypeCombobox $fB.t]
    pack $widgets(typeB)

}

proc Apol_Analysis_tra::newAnalysis {} {
    if {[set rt [checkParams]] != {}} {
        return $rt
    }
    if {[catch {analyze} results]} {
        return $results
    }
    set f [createResultsDisplay]
    if {[catch {renderResults $f $results} rt]} {
        Apol_Analysis::deleteCurrentResults
        return $rt
    }
    return {}
}


proc Apol_Analysis_tra::updateAnalysis {f} {
    if {[set rt [checkParams]] != {}} {
        return $rt
    }
    if {[catch {analyze} results]} {
        return $results
    }
    clearResultsDisplay $f
    if {[catch {renderResults $f $results} rt]} {
        return $rt
    }
    return {}
}

proc Apol_Analysis_tra::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_tra::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    reinitializeWidgets
}

proc Apol_Analysis_tra::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        puts $channel "$key $value"
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeA)]
    puts $channel "typeA [lindex $type 0]"
    puts $channel "typeA:attrib [lindex $type 1]"
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeB)]
    puts $channel "typeB [lindex $type 0]"
    puts $channel "typeB:attrib [lindex $type 1]"
}

proc Apol_Analysis_tra::loadQuery {channel} {
    variable vals

    set classes_exc {}
    set subjects_exc {}
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        set key {}
        set value {}
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        set vals($key) $value
    }
    reinitializeWidgets
}

proc Apol_Analysis_tra::gotoLine {tab line_num} {
}

proc Apol_Analysis_tra::search {tab str case_Insensitive regExpr srch_Direction } {
}


#################### private functions below ####################

proc Apol_Analysis_tra::reinitializeVals {} {
    variable vals

    array set vals {
        typeA {}  typeA:attrib {}
        typeB {}  typeB:attrib {}

        opts:attribs 1
        opts:roles 1
        opts:users 1
        opts:accesses 0
        opts:dissimilars 0
        opts:allows 0
        opts:trans 0
    }
}

proc Apol_Analysis_tra::reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(typeA:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(typeA) [list $vals(typeA) $vals(typeA:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(typeA) $vals(typeA)
    }
    if {$vals(typeB:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(typeB) [list $vals(typeB) $vals(typeB:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(typeB) $vals(typeB)
    }
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::do_analysis {results_frame} {  
	variable tra_listbox
	variable typeA		
    	variable typeB
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel		
	variable dta_BA_sel
	variable trans_flow_AB_sel		
	variable trans_flow_BA_sel	
	variable dir_flow_sel		
	variable te_rules_sel	
	variable tt_rule_sel		
	variable excluded_dirflow_objs
	variable forward_options_Dlg
	
	if {![ApolTop::is_policy_open]} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "No current policy file is opened!"
		return -code error
        } 
   
       	if {$typeA == ""} {
       		tk_messageBox -icon error -type ok -title "Error" \
       			-message "Type A cannot be empty!"
	    	return -code error
       	}
       	if {$typeB == ""} {
       		tk_messageBox -icon error -type ok -title "Error" \
       			-message "Type B cannot be empty!"
	    	return -code error
       	}
       	
       	if {!$comm_attribs_sel && !$comm_roles_sel && !$comm_users_sel && !$comm_access_sel && \
       	    !$unique_access_sel && !$dta_AB_sel && !$dta_BA_sel && !$trans_flow_AB_sel && \
       	    !$trans_flow_BA_sel && !$dir_flow_sel && !$te_rules_sel && !$tt_rule_sel} {
       		tk_messageBox -icon error -type ok -title "Error" \
       			-message "You did not select any search items."
	    	return -code error
       	}
       	
	# if a permap is not loaded then load the default permap
        # if an error occurs on open, then skip analysis
        set rt [catch {set map_loaded [Apol_Perms_Map::is_pmap_loaded]} err]
        if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return -code error
	}
	set do_trans [expr ($trans_flow_AB_sel || $trans_flow_BA_sel)]
	if {[expr (!$map_loaded && ($do_trans || $dir_flow_sel))]} {
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
	Apol_Analysis_tra::display_progressDlg	
	set dta_object(x) "" 
	if {$dta_AB_sel || $dta_BA_sel} {
		Apol_Analysis_dta::forward_options_copy_object $forward_options_Dlg dta_object
	}

	# Initialize dta variables - These options are here for setting advanced options for DTA analysis.
        set dta_reverse 0
	set dta_num_object_classes 0
	set dta_perm_options ""
        set dta_filter_types 0
        set dta_types ""
	set dta_objects_sel 0
	
	if {$dta_AB_sel || $dta_BA_sel} {	        		
		foreach class $dta_object($forward_options_Dlg,class_list) {
			set perms ""
			# Make sure to strip out just the class name, as this may be an excluded class.
			set idx [string first $Apol_Analysis_dta::excluded_tag $class]
			if {$idx == -1} {
				set class_elements [array names dta_object "$forward_options_Dlg,perm_status_array,$class,*"]
				set class_added 0
				foreach element $class_elements {
					set perm [lindex [split $element ","] 3]
					if {[string equal $dta_object($element) "include"]} {
						if {$class_added == 0} {
							incr dta_num_object_classes 
							set dta_perm_options [lappend dta_perm_options $class]
							set class_added 1
						}	
						set perms [lappend perms $perm]
					}
				}
				if {$perms != ""} {
					set dta_perm_options [lappend dta_perm_options [llength $perms]]
					foreach perm $perms {
						set dta_perm_options [lappend dta_perm_options $perm]
					}
				}	
			}
		}
		set dta_types $Apol_Types::typelist 
		
		if {$dta_num_object_classes} {	
			set dta_objects_sel 1
		} 
		if {$dta_types != ""} {   
			set dta_filter_types 1
		} 
	}
	array unset dta_object
	# Initialize transitive flow variables - These options are here for setting advanced options for DTA analysis.
	set tif_num_object_classes 0
	set tif_perm_options ""
	set tif_types ""
	set tif_objects_sel 0
	set tif_filter_types 0
	
	# Initialize direct flow variables - These options are here for setting advanced options for DTA analysis.
	set filter_dirflow_objs 0
		
	set rt [catch {set results [apol_TypesRelationshipAnalysis \
		$typeA \
		$typeB \
     		$comm_attribs_sel \
     		$comm_roles_sel \
     		$comm_users_sel \
     		$comm_access_sel \
     		$unique_access_sel \
		[expr ($dta_AB_sel || $dta_BA_sel)] \
		[expr ($trans_flow_AB_sel || $trans_flow_BA_sel)] \
		$dir_flow_sel \
		$tt_rule_sel \
		$te_rules_sel \
		$tif_objects_sel \
		$tif_num_object_classes \
		$tif_perm_options \
		$tif_filter_types \
		$tif_types \
		$dta_objects_sel \
		$dta_num_object_classes \
		$dta_perm_options \
		$dta_filter_types \
		$dta_types \
		$filter_dirflow_objs \
		$excluded_dirflow_objs]} err]

	Apol_Analysis_tra::destroy_progressDlg	
     	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 

	set tra_listbox [Apol_Analysis_tra::create_resultsDisplay $results_frame]
	set rt [catch {Apol_Analysis_tra::create_results_list_structure $tra_listbox $results} err]
	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::listSelect
# ---------------------------------------------------------
proc Apol_Analysis_tra::listSelect {tra_listbox tra_info_text selected_item} { 
	variable typeA
	variable typeB
	
	$tra_info_text configure -state normal
        $tra_info_text delete 0.0 end
       	$tra_info_text mark set insert 1.0
       	
	switch -exact -- $selected_item {
		common_attribs {
			Apol_Analysis_tra::display_common_attribs \
				$tra_listbox \
				$tra_info_text \
				"Common Attributes" \
				[$tra_listbox itemcget $selected_item -data]
		}
		common_roles {
			Apol_Analysis_tra::display_common_attribs \
				$tra_listbox \
				$tra_info_text \
				"Common Roles" \
				[$tra_listbox itemcget $selected_item -data]
		}
		common_users {
			Apol_Analysis_tra::display_common_attribs \
				$tra_listbox \
				$tra_info_text \
				"Common Users" \
				[$tra_listbox itemcget $selected_item -data]
		}
		tt_rules {
			Apol_Analysis_tra::display_rules \
				$tra_listbox \
				$tra_info_text \
				"Type transition/change rules" \
				[$tra_listbox itemcget $selected_item -data]
		}
		te_rules {
			Apol_Analysis_tra::display_rules \
				$tra_listbox \
				$tra_info_text \
				"TE Allow Rules" \
				[$tra_listbox itemcget $selected_item -data]
		}
		common_objects {
			$tra_info_text configure -wrap word
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeA" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end " and "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeB" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end " access \
				[$tra_listbox itemcget $selected_item -data] common type(s).\n\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
			
			if {[$tra_listbox itemcget $selected_item -data] > 0} {
				$tra_info_text insert end "Open the subtree for this item to see the list of \
					common types that can be accessed. You may then select a type from the \
					subtree to see the allow rules which provide the access."
			}
		}
		unique_objects {
			$tra_info_text configure -wrap word
			$tra_info_text insert end "Open the subtree for this item to access individual \
				subtrees of types which can be accessed by either "
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeA" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
				
			$tra_info_text insert end " or "
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeB" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			$tra_info_text insert end ".\nYou may then select a type from a subtree to see the \
				allow rules which provide the access."
		}
		unique_objects:typeA {
			$tra_info_text configure -wrap word
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeA" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end " accesses \
				[$tra_listbox itemcget $selected_item -data] type(s) to which "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeB" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end " does not have access.\n\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
			
			if {[$tra_listbox itemcget $selected_item -data] > 0} {
				$tra_info_text insert end "Open the subtree for this item to see the list of types. \
					You may then select a type from the subtree to see the allow rules which provide \
					the access."
			}
		}
		unique_objects:typeB {
			$tra_info_text configure -wrap word
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeB" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end " accesses \
				[$tra_listbox itemcget $selected_item -data] type(s) to which "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "$typeA" 
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
			
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end " does not have access.\n\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
			if {[$tra_listbox itemcget $selected_item -data] > 0} {
				$tra_info_text insert end "Open the subtree for this item to see the list of types. \
					You may then select a type from the subtree to see the allow rules which provide \
					the access."
			}
		}
		dir_flows {
			Apol_Analysis_tra::display_direct_flows \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
		}
		trans_flows_A {
			Apol_Analysis_tra::display_transitive_flows \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeA
		}
		trans_flows_B {
			Apol_Analysis_tra::display_transitive_flows \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeB
		}
		dta_analysis_A {
			Apol_Analysis_tra::display_dta_info \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeA
		}
		dta_analysis_B {
			Apol_Analysis_tra::display_dta_info \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeB
		}
		default {
			if {[$tra_listbox parent $selected_item] == "unique_objects:typeA" ||
			    [$tra_listbox parent $selected_item] == "unique_objects:typeB"} {
			    	set idx [string length "unique_objects:"]
			    	set node [string range $selected_item $idx [expr [string length $selected_item] - 1]]
				Apol_Analysis_tra::display_unique_object_info \
					$tra_listbox \
					$tra_info_text \
					$node \
					[$tra_listbox itemcget $selected_item -data]
			} elseif {[$tra_listbox parent $selected_item] == "common_objects"} {
				set idx [string length "common_objects:"]
			    	set node [string range $selected_item $idx [expr [string length $selected_item] - 1]]
				Apol_Analysis_tra::display_common_object_info \
					$tra_listbox \
					$tra_info_text \
					$node \
					[$tra_listbox itemcget $selected_item -data]
			} else {
				puts "Invalid listbox item element $selected_item"
				return -1
			}
		}
	}
	ApolTop::makeTextBoxReadOnly $tra_info_text
	$tra_listbox selection set $selected_item
	Apol_Analysis_tra::formatInfoText $Apol_Analysis_tra::tra_info_text
	return 0
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_common_attribs
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_common_attribs {tra_listbox tra_info_text header_txt data} {       	
       	if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	
        set num [lindex $data 0]
        set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$header_txt ($num):\n\n"   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	
	if {$num} {  
		set itemlist [lrange $data 1 end]
		
		foreach item $itemlist {
			$tra_info_text insert end "$item\n"
		}
	} 
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_rules
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_rules {tra_listbox tra_info_text header_txt data} {
       	if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set i 0
        set num [lindex $data $i]
        set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$header_txt ($num):\n\n"   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	set curr_idx [expr $i + 1]
	for {set x 0} {$x < $num} {incr x} {
		Apol_Analysis_tra::print_rule $tra_info_text $data $curr_idx 0
		incr curr_idx
	} 
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::print_rule
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::print_rule {tra_info_text data curr_idx indent} {	
	if {$indent} {
		$tra_info_text insert end "    "
	}
	set startIdx [$tra_info_text index insert]
	set rule [lindex $data $curr_idx]
	# Get the line number only
	set end_link_idx [string first "\]" [string trim $rule] 0]
	set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
	set lineno [string trim $lineno]

	set rule [string range $rule [expr $end_link_idx + 1] end]
	
	# Only display line number hyperlink if this is not a binary policy.
	if {![ApolTop::is_binary_policy]} {
		$tra_info_text insert end "\[$lineno\]"
		Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
	}
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end "$rule\n"
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
		
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_common_object_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_common_object_info {tra_listbox tra_info_text node data} {
	variable typeA
	variable typeB
	
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end "$typeA"   
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end " accesses " 
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end "$node" 
	set endIdx [$tra_info_text index insert] 
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end ":\n\n"
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
	
	set i 0
	set num_comm_rules_A [lindex $data $i]
	for { set p 0 } { $p < $num_comm_rules_A } { incr p } { 
		incr i
		Apol_Analysis_tra::print_rule $tra_info_text $data $i 0
	}
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end "\n$typeB"   
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end " accesses " 
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end "$node" 
	set endIdx [$tra_info_text index insert] 
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
	
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end ":\n\n"
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
	
	incr i
	set num_comm_rules_B [lindex $data $i]
	for { set p 0 } { $p < $num_comm_rules_B } { incr p } { 
		incr i
		Apol_Analysis_tra::print_rule $tra_info_text $data $i 0
	}

	return 0
}

					
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_unique_object_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_unique_object_info {tra_listbox tra_info_text node data} {
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set i 0
	set type [lindex $data $i]
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$type" 
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end " accesses " 
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$node" 
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end ":\n\n" 
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	
	incr i
	set num_rules_A [lindex $data $i]
	for { set p 0 } { $p < $num_rules_A } { incr p } { 
		incr i
		Apol_Analysis_tra::print_rule $tra_info_text $data $i 0
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_direct_flows
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_direct_flows {tra_listbox tra_info_text data} {
	variable typeA
    	variable typeB

        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set start_type $typeA
	set i 0
	
	# Get # of target types 
	set num_target_types [lindex $data $i]
	
	if {$num_target_types == 0} {
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "No direct information flows"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	} else {
		incr i
		set cur_end_type [lindex $data $i]
		incr i
		set flow_dir [lindex $data $i]
		incr i
		set num_objs [lindex $data $i]
		incr i
		set curIdx $i
		set startIdx [$tra_info_text index insert]
			
		$tra_info_text insert end "Information flows both into and out of "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $start_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end " - \[from/to\] "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $cur_end_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx $endIdx
	    
		# If there are any target types then format and display the data				
		for { set x 0 } { $x < $num_target_types } { incr x } { 			
			if {$flow_dir == "both"} {
				# Print label for in flows 
				$tra_info_text insert end "\n\nObject classes for "
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				$tra_info_text insert end "\[IN/OUT\]"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx	 
				set startIdx $endIdx
				$tra_info_text insert end " flows:"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				# Then te inflows   
				for {set i 0} {$i<$num_objs} {incr i} {
					if {[lindex $data $curIdx] == "1"} {
					    incr curIdx
					    $tra_info_text insert end "\n\t"
					    # This should be the object name
					    $tra_info_text insert end [lindex $data $curIdx]
					    set endIdx [$tra_info_text index insert]
					    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
					    incr curIdx
					    set num_rules [lindex $data $curIdx]
					    for {set j 0} {$j<$num_rules} {incr j} {
					    	$tra_info_text insert end "\n\t"
					    	set startIdx [$tra_info_text index insert]
						incr curIdx
						set rule [lindex $data $curIdx]
						# Get the line number only
						set end_link_idx [string first "\]" [string trim $rule] 0]
						set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
						set lineno [string trim $lineno]
					
						set rule [string range $rule [expr $end_link_idx + 1] end]
						
						# Only display line number hyperlink if this is not a binary policy.
						if {![ApolTop::is_binary_policy]} {
							$tra_info_text insert end "\[$lineno\]"
							Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
						}
						set startIdx [$tra_info_text index insert]
						$tra_info_text insert end " $rule"
						set endIdx [$tra_info_text index insert]
						$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
						
						incr curIdx
						# The next element should be the enabled boolean flag.
						if {[lindex $data $curIdx] == 0} {
							$tra_info_text insert end "   "
							set startIdx [$tra_info_text index insert]
							$tra_info_text insert end "\[Disabled\]"
							set endIdx [$tra_info_text index insert]
							$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $startIdx $endIdx
						} 
						set startIdx [$tra_info_text index insert]
					    }
					    
					} 
					incr curIdx
				}
			} else {
				$tra_info_text insert end "\n\nObject classes for "
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				set flow_dir [string toupper $flow_dir]
				$tra_info_text insert end $flow_dir
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx	 
				set startIdx $endIdx
				$tra_info_text insert end " flows:"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				
				for {set i 0} {$i<$num_objs} {incr i} {
					if { [lindex $data $curIdx] == "1" } {
					    incr curIdx
					    $tra_info_text insert end "\n\t"
					    # This should be the object name
					    $tra_info_text insert end [lindex $data $curIdx]
					    set endIdx [$tra_info_text index insert]
					    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
					    incr curIdx
					    set num_rules [lindex $data $curIdx]
					    for {set j 0} {$j<$num_rules} {incr j} {
					    	$tra_info_text insert end "\n\t"
					    	set startIdx [$tra_info_text index insert]
						incr curIdx
						set rule [lindex $data $curIdx]
						# Get the line number only
						set end_link_idx [string first "\]" [string trim $rule] 0]
						set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
						set lineno [string trim $lineno]
					
						set rule [string range $rule [expr $end_link_idx + 1] end]
						
						# Only display line number hyperlink if this is not a binary policy.
						if {![ApolTop::is_binary_policy]} {
							$tra_info_text insert end "\[$lineno\]"
							Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
						}
						set startIdx [$tra_info_text index insert]
						$tra_info_text insert end " $rule"
						set endIdx [$tra_info_text index insert]
						$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
						
						incr curIdx
						# The next element should be the enabled boolean flag.
						if {[lindex $data $curIdx] == 0} {
							$tra_info_text insert end "   "
							set startIdx [$tra_info_text index insert]
							$tra_info_text insert end "\[Disabled\]"
							set endIdx [$tra_info_text index insert]
							$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $startIdx $endIdx
						}
						set startIdx [$tra_info_text index insert]
					    }
					} 
					incr curIdx
				}
			}
		}
	}

	return 0
}
						
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_transitive_flows
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_transitive_flows {tra_listbox tra_info_text data start_type} { 
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set i 0
	
	# Get # of target types 
	set num_target_types [lindex $data $i]
	if {$num_target_types} {
		incr i
		set end_type [lindex $data $i]
			
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end "Information flows from "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $start_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end " to "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $end_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx $endIdx 
	} else {
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "No transitive information flows from $start_type"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	}
	         	    
	# If there are any target types then format and display the data				
	for { set x 0 } { $x < $num_target_types } { incr x } { 
		# the number of paths 
		incr i
	        set currentIdx $i
	        set num_paths [lindex $data $currentIdx]
		
		$tra_info_text insert end "\n\nApol found the following number of information flows: "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
	        set startIdx $endIdx
		$tra_info_text insert end $num_paths
	        set endIdx [$tra_info_text index insert]
	        $tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
                		
		for {set j 0} {$j < $num_paths} {incr j} {
		    set startIdx [$tra_info_text index insert]
		    $tra_info_text insert end "\n\nFlow"
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
		    set startIdx $endIdx
		    $tra_info_text insert end " [expr $j+1] "
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
		    set startIdx $endIdx
		    $tra_info_text insert end "requires " 
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
		    set startIdx $endIdx 
		    # Increment to the number of flows 
		    incr currentIdx
		    set num_flows [lindex $data $currentIdx]
		    $tra_info_text insert end $num_flows
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
		    set startIdx $endIdx
		    $tra_info_text insert end " step(s)."
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
		    for {set k 0} {$k < $num_flows} {incr k} {
			# First print the flow number
			$tra_info_text insert end "\n\n\tStep "
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			set startIdx $endIdx
			$tra_info_text insert end [expr $k + 1]
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
			set startIdx $endIdx
			$tra_info_text insert end ": "
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			set startIdx $endIdx
			$tra_info_text insert end "from "
			# increment to the start type for the flow
			incr currentIdx
			$tra_info_text insert end [lindex $data $currentIdx]
			$tra_info_text insert end " to "
			# Increment to the end type for the flow
			incr currentIdx
			$tra_info_text insert end [lindex $data $currentIdx]
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			set startIdx $endIdx
			# Increment to the # of object classes
			incr currentIdx
			set num_classes [lindex $data $currentIdx]
			for {set l 0} {$l < $num_classes} {incr l} {
			    # Increment to the first object class
		    	    incr currentIdx
			    $tra_info_text insert end "\n\t[lindex $data $currentIdx]"
			    set endIdx [$tra_info_text index insert]
			    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			    set startIdx $endIdx
			    # Increment to the # of object class rules
			    incr currentIdx
			    set num_rules [lindex $data $currentIdx]
			    for {set m 0} {$m < $num_rules} {incr m} {
			    	# Increment to the next rule for the object
				incr currentIdx
				set rule [lindex $data $currentIdx]
				$tra_info_text insert end "\n\t"
				set startIdx [$tra_info_text index insert]
				# Get the line number only
				set end_link_idx [string first "\]" [string trim $rule] 0]
				set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
				set lineno [string trim $lineno]
				set rule [string range $rule [expr $end_link_idx + 1] end]
				
				# Only display line number hyperlink if this is not a binary policy.
				if {![ApolTop::is_binary_policy]} {
					$tra_info_text insert end "\[$lineno\]"
					Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
				}
				set startIdx [$tra_info_text index insert]
				$tra_info_text insert end " $rule"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
				
				incr currentIdx
				# The next element should be the enabled boolean flag.
				if {[lindex $data $currentIdx] == 0} {
					$tra_info_text insert end "   "
					set startIdx [$tra_info_text index insert]
					$tra_info_text insert end "\[Disabled\]"
					set endIdx [$tra_info_text index insert]
					$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $startIdx $endIdx
				} 
				set startIdx [$tra_info_text index insert]
			    } 
			}
		    }
		}
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_dta_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_dta_info {tra_listbox tra_info_text data start_type} {   
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set idx 0

	# Get # of target types 
	set num_target_types [lindex $data $idx]
	if {![string is integer $num_target_types]} {
		puts "Number of target types is not an integer: $num_target_types"
		return
	}
			
	if {$num_target_types} {
		incr idx
		set end_type [lindex $data $idx]
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "Domain transition from "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end $start_type
		set end_idx [$tra_info_text index insert] 
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end " to "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end $end_type
		set end_idx [$tra_info_text index insert] 
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	} else {
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "No domain transitions"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	}

	#  are any target types then format and display the data				
	for { set x 0 } { $x < $num_target_types } { incr x } { 
		incr idx
		# (# of pt rules)
		$tra_info_text insert end "\n\n"
		set start_idx [$tra_info_text index insert]
		set num_pt [lindex $data $idx]
		if {![string is integer $num_pt]} {
			puts "Number of allow rules is not an integer: $num_pt"
			return
		}
			
		$tra_info_text insert end "TE Allow Rules:  "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$tra_info_text insert end "$num_pt\n"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx

		for { set i 0 } { $i < $num_pt } { incr i } {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx] 
			
			$tra_info_text insert end "\t"
			set start_idx [$tra_info_text index insert]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$tra_info_text insert end "($lineno) "
				set end_idx [$tra_info_text index insert]
				Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$tra_info_text insert end "$rule"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
			
			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$tra_info_text insert end "   "
				set startIdx [$tra_info_text index insert]
				$tra_info_text insert end "\[Disabled\]\n"
				set end_idx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
			} else {
				$tra_info_text insert end "\n"
			}
		}
		incr idx
		# (# of file types)
		set num_types [lindex $data $idx]
		if {![string is integer $num_types]} {
			puts "Number of file types is not an integer: $num_types"
			return
		}
			
		set start_idx $end_idx
		$tra_info_text insert end "\nEntry Point File Types:  "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$tra_info_text insert end "$num_types\n"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx
		
		for {set i 0} { $i < $num_types } { incr i } {
			incr idx
			# (file type) 
			set type [lindex $data $idx]
			set start_idx $end_idx
			$tra_info_text insert end "\t$type\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::types_tag $start_idx $end_idx
			incr idx
			set num_ep [lindex $data $idx]
			if {![string is integer $num_ep]} {
				puts "Number of entrypoint access rules is not an integer: $num_ep"
				return
			}
			
			set start_idx $end_idx
			$tra_info_text insert end "\t\tFile Entrypoint Rules:  "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
			set start_idx $end_idx
			$tra_info_text insert end "$num_ep\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx
		
			for {set j 0} {$j < $num_ep} {incr j}  {
				incr idx
				set rule [lindex $data $idx]
				incr idx
				set lineno [lindex $data $idx]

				$tra_info_text insert end "\t\t"
				set start_idx [$tra_info_text index insert]
				
				# Only display line number hyperlink if this is not a binary policy.
				if {![ApolTop::is_binary_policy]} {
					$tra_info_text insert end "($lineno) "
					set end_idx [$tra_info_text index insert]
					Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
					set start_idx $end_idx
				}
				$tra_info_text insert end "$rule"
				set end_idx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
				
				incr idx
				# The next element should be the enabled boolean flag.
				if {[lindex $data $idx] == 0} {
					$tra_info_text insert end "   "
					set startIdx [$tra_info_text index insert]
					$tra_info_text insert end "\[Disabled\]\n"
					set end_idx [$tra_info_text index insert]
					$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
				} else {
					$tra_info_text insert end "\n"
				}
			}
			incr idx
			set num_ex [lindex $data $idx]
			if {![string is integer $num_ex]} {
				puts "Number of execute access rules is not an integer: $num_ex"
				return
			}
			
			set start_idx $end_idx
			$tra_info_text insert end "\n\t\tFile Execute Rules:  "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
			set start_idx $end_idx
			$tra_info_text insert end "$num_ex\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx
			
			for { set j 0 } { $j < $num_ex } { incr j }  {
				incr idx
				set rule [lindex $data $idx]
				incr idx
				set lineno [lindex $data $idx]
				
				$tra_info_text insert end "\t\t"
				set start_idx [$tra_info_text index insert]
				
				# Only display line number hyperlink if this is not a binary policy.
				if {![ApolTop::is_binary_policy]} {
					$tra_info_text insert end "($lineno) "
					set end_idx [$tra_info_text index insert]
					Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
					set start_idx $end_idx
				}
				$tra_info_text insert end "$rule"
				set end_idx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
				
				incr idx
				# The next element should be the enabled boolean flag.
				if {[lindex $data $idx] == 0} {
					$tra_info_text insert end "   "
					set startIdx [$tra_info_text index insert]
					$tra_info_text insert end "\[Disabled\]\n"
					set end_idx [$tra_info_text index insert]
					$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
				} else {
					$tra_info_text insert end "\n"
				}
			}
		}
	}
			
        $tra_info_text configure -state disabled
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::create_results_list_structure
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::create_results_list_structure {tra_listbox results_list} {
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel
	variable dta_BA_sel		
	variable trans_flow_AB_sel		
	variable trans_flow_BA_sel
	variable dir_flow_sel		
	variable te_rules_sel	
	variable tt_rule_sel		

	# Parse the list and add the list elements as we parse
	# get type strings
	set typeA [lindex $results_list 0]
	set typeB [lindex $results_list 1]
	set i 2
	set parent "root"
	# Get # of common attributes
	set num_common_attribs [lindex $results_list $i]
	set start_idx $i
	# If there are common attribs...
	for { set x 0 } { $x < $num_common_attribs } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$comm_attribs_sel} { 
		$tra_listbox insert end $parent common_attribs \
				-text "Common Attributes" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]
	}
	
	# Get # of common roles
	incr i
	set num_common_roles [lindex $results_list $i]
	set start_idx $i
	# If there are common roles... 
	for { set x 0 } { $x < $num_common_roles } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$comm_roles_sel} {
		$tra_listbox insert end $parent common_roles \
				-text "Common Roles" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]
	}
	
	# Get # of common users
	incr i
	set num_common_users [lindex $results_list $i]
	set start_idx $i
	# If there are common users... 
	for { set x 0 } { $x < $num_common_users } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$comm_users_sel} {
		$tra_listbox insert end $parent common_users \
				-text "Common Users" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i] 
	}
	# Get # of other type transition rules
	incr i
	set num_other_tt_rules [lindex $results_list $i]
	set start_idx $i
	# If there are type transition rules... 
	for { set x 0 } { $x < $num_other_tt_rules } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$tt_rule_sel} { 
		$tra_listbox insert end $parent tt_rules \
				-text "Type Transition/Change Rules" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i] 
	}
	
	# Get # of other te rules
	incr i
	set num_te_rules [lindex $results_list $i]
	set start_idx $i
	# If there are te rules... 
	for { set x 0 } { $x < $num_te_rules } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$te_rules_sel} {
		$tra_listbox insert end $parent te_rules \
				-text "TE Allow Rules" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i] 
	}
	
	# Get # common objects
	incr i
	set num_comm_objs [lindex $results_list $i]
	set start_idx $i
	# Insert item into listbox 
	if {$comm_access_sel} {
		$tra_listbox insert end $parent common_objects \
				-text "Common access to resources" \
				-open 0	\
		        	-drawcross auto \
		        	-data $num_comm_objs 
	}	
	for { set x 0 } { $x < $num_comm_objs } { incr x } { 
		# Get object type string
		incr i
		set type [lindex $results_list $i]
		incr i
		set start_idx $i
		# Next item should be number of rules for type A
		set num_rules_A [lindex $results_list $i]
		incr i $num_rules_A
		# Increment to number of rules for type B
		incr i 
		set num_rules_b [lindex $results_list $i]
		incr i $num_rules_b
		$tra_listbox insert end common_objects "common_objects:$type" \
				-text $type \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i] 
	}

	# Get # uniqe objects types for A
	incr i
	set num_uniqe_objs_A [lindex $results_list $i]	
	# Insert item into listbox
	if {$unique_access_sel} { 
		$tra_listbox insert end $parent unique_objects \
				-text "Dissimilar access to resources" \
				-open 0	\
		        	-drawcross auto
		$tra_listbox insert end unique_objects unique_objects:typeA \
				-text $typeA \
				-open 0	\
		        	-drawcross auto -data $num_uniqe_objs_A
	}
	
	for { set x 0 } { $x < $num_uniqe_objs_A } { incr x } { 
		# Get object type string
		incr i
		set type [lindex $results_list $i]
		incr i
		set start_idx $i
		# Next item should be number of rules 
		set num_rules_A [lindex $results_list $i]
		incr i $num_rules_A
		if {$unique_access_sel} { 
			set data [concat $typeA [lrange $results_list $start_idx $i]]
			$tra_listbox insert end "unique_objects:typeA" "unique_objects:$type" \
					-text $type \
					-open 0	\
			        	-drawcross auto \
			        	-data $data 
		}
	}
	
	# Get unique rules
	incr i
	set num_uniqe_objs_B [lindex $results_list $i]	
	if {$unique_access_sel} { 
		$tra_listbox insert end unique_objects unique_objects:typeB \
				-text $typeB \
				-open 0	\
		        	-drawcross auto -data $num_uniqe_objs_B
	}
	
	for { set x 0 } { $x < $num_uniqe_objs_B } { incr x } { 
		# Get object type string
		incr i
		set type [lindex $results_list $i]
		incr i
		set start_idx $i
		# Next item should be number of rules 
		set num_rules_B [lindex $results_list $i]
		incr i $num_rules_B
		if {$unique_access_sel} { 
			set data [concat $typeB [lrange $results_list $start_idx $i]]
			$tra_listbox insert end "unique_objects:typeB" "unique_objects:$type" \
					-text $type \
					-open 0	\
			        	-drawcross auto \
			        	-data $data
		}
	}	
	# Parse dirflow data 
	# Get # of target types
	incr i
	set start_idx $i
	set num_dirflow_target_types [lindex $results_list $i]
	# This should be the end type
	set currentIdx [expr $i + 1]			
	for { set x 0 } { $x < $num_dirflow_target_types } { incr x } { 
		set nextIdx [Apol_Analysis_dirflow::parseList_get_index_next_node $currentIdx $results_list]
		if {$nextIdx == -1} {
			return -code error "Error parsing results. See stdout for more information."
		}
		set currentIdx $nextIdx
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox 
	if {$dir_flow_sel} {
		$tra_listbox insert end $parent dir_flows \
				-text "Direct Flows Between A and B" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]  
	}
	set start_idx $i
	set num_transflow_types_A [lindex $results_list $i]
	set currentIdx [expr $i + 1]				
	for { set x 0 } { $x < $num_transflow_types_A } { incr x } { 		        	
		set nextIdx [Apol_Analysis_fulflow::parseList_get_index_next_node $currentIdx $results_list]
		if {$nextIdx == -1} {
			return -code error "Error parsing Transitive Flow results"
		}
		set currentIdx $nextIdx
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox 
	if {$trans_flow_AB_sel} {
		$tra_listbox insert end $parent trans_flows_A \
				-text "Transitive Flows A->B" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]   
	}
	set start_idx $i
	set num_transflow_types_B [lindex $results_list $i]
	set currentIdx [expr $i + 1]				
	for { set x 0 } { $x < $num_transflow_types_B } { incr x } { 		        	
		set nextIdx [Apol_Analysis_fulflow::parseList_get_index_next_node $currentIdx $results_list]
		if {$nextIdx == -1} {
			return -code error "Error parsing Transitive Flow results"
		}
		set currentIdx $nextIdx
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox
	if {$trans_flow_BA_sel} { 
		$tra_listbox insert end $parent trans_flows_B \
				-text "Transitive Flows B->A" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]  
	}
	
	set start_idx $i	
	set num_dta_types_A [lindex $results_list $i]
	set currentIdx [expr $i + 1]
	for { set x 0 } { $x < $num_dta_types_A } { incr x } { 
		set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $currentIdx]
		if {$end_idx == -1} {
			# Print error 
			return -code error "Error parsing results for type [lindex $results_list $currentIdx].\nSee stdout for more information."
		}
	        set currentIdx [expr $end_idx + 1]
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox
	if {$dta_AB_sel} { 
		$tra_listbox insert end $parent dta_analysis_A \
				-text "Domain Transitions A->B" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]  
	}
	
	set start_idx $i
	set num_dta_types_B [lindex $results_list $i]
	set currentIdx [expr $i + 1]
	for { set x 0 } { $x < $num_dta_types_B } { incr x } { 
		set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $currentIdx]
		if {$end_idx == -1} {
			# Print error 
			return -code error "Error parsing results for type [lindex $results_list $currentIdx].\nSee stdout for more information."
		}
	        set currentIdx [expr $end_idx + 1]
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox 
	if {$dta_BA_sel} { 
		$tra_listbox insert end $parent dta_analysis_B \
				-text "Domain Transitions B->A" \
				-open 0	\
		        	-drawcross auto \
		        	-data [lrange $results_list $start_idx $i]  
	}						
	
        $tra_listbox configure -redraw 1
	Apol_Analysis_tra::listSelect $Apol_Analysis_tra::tra_listbox \
				      $Apol_Analysis_tra::tra_info_text \
				      [$tra_listbox nodes $parent 0]
        return 0
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::create_resultsDisplay
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::create_resultsDisplay {results_frame} {
	variable tra_listbox
	variable tra_info_text

	# set up paned window
	set pw   [PanedWindow $results_frame.pw -side top]
	set pw_tree [$pw add]
	set pw_info [$pw add -weight 5]
	
	# title frames
	set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Types Relationship Results"]
	set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Types Relationship Information"]	

	set sw_lbox [ScrolledWindow [$frm_tree getframe].sw_lbox -auto none]		 
	set sw_info [ScrolledWindow [$frm_info getframe].sw_info -auto none]		 

	# tree window
	set tra_listbox [Tree [$sw_lbox getframe].tra_listbox \
	           -relief flat -borderwidth 0 -highlightthickness 0 \
		   -redraw 0 -bg white -showlines 1 -padx 0]
	$sw_lbox setwidget $tra_listbox 

	# info window
	set tra_info_text [text [$sw_info getframe].tra_info_text \
		-wrap none -bg white -font $ApolTop::text_font]
	$sw_info setwidget $tra_info_text
	bind $tra_info_text <Enter> {focus %W}
	
	pack $pw -fill both -expand yes -anchor nw 
	pack $frm_tree -fill both -expand yes -anchor nw
	pack $frm_info -fill both -expand yes
	pack $sw_lbox -fill both -expand yes
	pack $sw_info -fill both -expand yes 
	
	$tra_listbox bindText  <ButtonPress-1>        {Apol_Analysis_tra::listSelect \
							$Apol_Analysis_tra::tra_listbox \
							$Apol_Analysis_tra::tra_info_text}
    	$tra_listbox bindText  <Double-ButtonPress-1> {Apol_Analysis_tra::listSelect \
    							$Apol_Analysis_tra::tra_listbox \
    							$Apol_Analysis_tra::tra_info_text}
    
	return $tra_listbox
}
