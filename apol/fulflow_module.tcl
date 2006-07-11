#############################################################
#  fulflow_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com, mayerf@tresys.com, kcarr@tresys>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Transitivie
# Information Flow analysis.

namespace eval Apol_Analysis_fulflow {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_fulflow" "Transitive Information Flow"
}

proc Apol_Analysis_fulflow::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
}

proc Apol_Analysis_fulflow::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_fulflow::getInfo {} {
    return "This analysis generates the results of a Transitive Information Flow
analysis beginning from the starting type selected.  The results of
the analysis are presented in tree form with the root of the tree
being the start point for the analysis.

\nEach child node in the tree represents a type in the current policy
for which there is a transitive information flow to or from its parent
node.  If flow 'To' is selected the information flows from the child
to the parent.  If flow 'From' is selected then information flows from
the parent to the child.

\nThe results of the analysis may be optionally filtered by object
classes and/or permissions, intermediate types, or an end type regular
expression.

\nNOTE: For any given generation, if the parent and the child are the
same, you cannot open the child.  This avoids cyclic analyses.

\nFor additional help on this topic select \"Information Flow Analysis\"
from the help menu."
}

proc Apol_Analysis_fulflow::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set dir_tf [TitleFrame $options_frame.dir -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set dir_to [radiobutton [$dir_tf getframe].to -text "To" \
                    -variable Apol_Analysis_fulflow::vals(dir) -value to]
    set dir_from [radiobutton [$dir_tf getframe].from -text "From" \
                      -variable Apol_Analysis_fulflow::vals(dir) -value from]
    pack $dir_to $dir_from -anchor w

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -text "Starting type"]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set advanced_f [frame [$filter_tf getframe].advanced]
    pack $advanced_f -side left -anchor nw
    set widgets(advanced_enable) [checkbutton $advanced_f.enable -text "Use advanced filters" \
                                      -variable Apol_Analysis_fulflow::vals(advanced:enable)]
    pack $widgets(advanced_enable) -anchor w
    set widgets(advanced) [button $advanced_f.b -text "Advanced Filters" \
                               -command Apol_Analysis_fulflow::createAdvancedDialog \
                               -state disabled]
    pack $widgets(advanced) -anchor w -padx 4
    trace add variable Apol_Analysis_fulflow::vals(advanced:enable) write \
        Apol_Analysis_fulflow::toggleAdvancedSelected
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter end types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_fulflow::newAnalysis {} {
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

proc Apol_Analysis_fulflow::updateAnalysis {f} {
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

proc Apol_Analysis_fulflow::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_fulflow::switchTab {query_options} {
    variable vals
    array set vals $query_options
    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_fulflow::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        switch -- $key {
            default {
                puts $channel "$key $value"
            }
        }
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(type)]
    puts $channel "type [lindex $type 0]"
    puts $channel "type:attrib [lindex $type 1]"
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    puts $channel "regexp:enable $use_regexp"
    puts $channel "regexp $regexp"
}

proc Apol_Analysis_fulflow::loadQuery {channel} {
    variable vals
    set targets_inc {}
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        set key {}
        set value {}
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
    }
    reinitializeWidgets
}

proc Apol_Analysis_fulflow::gotoLine {tab line_num} {
}

proc Apol_Analysis_fulflow::search {tab str case_Insensitive regExpr srch_Direction } {
}

#################### private functions below ####################

proc Apol_Analysis_fulflow::reinitializeVals {} {
    variable vals

    array set vals {
        dir to

        type {}  type:attrib {}

        regexp:enable 0
        regexp {}

        access:enable 0
    }
}

proc Apol_Analysis_fulflow::reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_fulflow::toggleAdvancedSelected {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(advanced:enable)} {
        $widgets(advanced) configure -state normal
    } else {
        $widgets(advanced) configure -state disabled
    }
}


if {0} {    				   
        variable root_text "\n\nThis tab provides the results of a Transitive Information Flow analysis \
        		   beginning from the starting type selected above.  The results of the analysis \
        		   are presented in tree form with the root of the tree (this node) being the \
        		   start point for the analysis.\n\nEach child node in the tree represents a type \
        		   in the current policy for which there is a transitive information flow to or \
        		   from (depending on your selection above) its parent node.\n\nNOTE: For any \
        		   given generation, if the parent and the child are the same, you cannot open \
        		   the child.  This avoids cyclic analyses.\n\n"

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::verify_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::verify_options {} {
	variable start_type
        variable end_type
        variable endtype_sel
	variable fulflow_tree
	variable fulflow_info_text
        variable flow_direction
	variable advanced_filter_Dlg
	variable f_opts

	if {![info exists f_opts]} { return 0 }
	if {$f_opts($advanced_filter_Dlg,filtered_excl_types) != "" && $start_type != ""} {   
		if {[lsearch $f_opts($advanced_filter_Dlg,filtered_excl_types) $start_type] != -1} {
			set err "Advanced filter cannot exclude start type ($start_type) from analysis"
			tk_messageBox -icon error -type ok -title "Error" -message $err
			return -code error $err
		}
	} else { return 0 }
}

## Command Apol_Analysis_fulflow::do_analysis is the principal interface command.
## The GUI will call this when the module is to perform it's analysis.  The
## module should know how to get its own option information (the options
## are displayed via ::display_mod_options
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::do_analysis { results_frame } {  
	variable start_type
        variable end_type
        variable endtype_sel
	variable fulflow_tree
	variable fulflow_info_text
        variable flow_direction
	variable advanced_filter_Dlg
	variable f_opts
		        	
	# if a permap is not loaded then load the default permap
        # if an error occurs on open, then skip analysis
        set rt [catch {Apol_Analysis_fulflow::load_default_perm_map} err]
	if {$rt != 0} {	
		return -code error $err
	}
	
	# If the advanced options object doesn't exist, then create it.
	if {![array exists f_opts] || [array names f_opts "$advanced_filter_Dlg,name"] == ""} {
		Apol_Analysis_fulflow::advanced_filters_create_object $advanced_filter_Dlg
	} 
		
	# Initialize local variables
	set num_object_classes 0
	set perm_options ""
	set objects_sel "0"
	set filter_types "0"

	foreach class $f_opts($advanced_filter_Dlg,class_list) {
		set perms ""
		# Make sure to strip out just the class name, as this may be an  
		# excluded class, which has the " (Excluded)" tag appended to its' name.
		set idx [string first $Apol_Analysis_fulflow::excluded_tag $class]

		if {$idx == -1} {
			set class_elements [array names f_opts "$advanced_filter_Dlg,perm_status_array,$class,*"]
			set exclude_perm_added 0
			foreach element $class_elements {
				set perm [lindex [split $element ","] 3]
				# These are manually set to be included, so skip.
				if {![string equal $f_opts($element) "exclude"]} {
					continue
				} 
				# If we get to this point, then the permission was either manually excluded,
				# excluded because it's weight falls below the threshhold value, or both.
				if {$exclude_perm_added == 0} {
					incr num_object_classes 
					set perm_options [lappend perm_options $class]
					set exclude_perm_added 1
				}	
				set perms [lappend perms $perm]
			}
			if {$perms != ""} {
				set perm_options [lappend perm_options [llength $perms]]
				foreach perm $perms {
					set perm_options [lappend perm_options $perm]
				}
			}	
		} else {
			set class [string range $class 0 [expr $idx - 1]]
			set perm_options [lappend perm_options $class]	
			# Appending 0 for the number of permissions indicates to the  
			# lower-level code to exclude the entire object class from the 
			# results
			set perm_options [lappend perm_options 0]	
			incr num_object_classes 
		}
	}

	if {$num_object_classes} {	
		set objects_sel "1"
	} 
	if {$f_opts($advanced_filter_Dlg,filtered_excl_types) != ""} {   
		set filter_types "1"
	} 

	Apol_Analysis_fulflow::display_progressDlg
	set rt [catch {set results [apol_TransitiveFlowAnalysis \
		$start_type \
		$flow_direction \
		$objects_sel \
		$num_object_classes \
		$endtype_sel \
		$end_type \
		$perm_options \
		$filter_types \
		$f_opts($advanced_filter_Dlg,filtered_excl_types) \
		$f_opts($advanced_filter_Dlg,threshhold_cb_value) \
		$f_opts($advanced_filter_Dlg,threshhold_value)]} err]
	
	if {$rt != 0} {	
		Apol_Analysis_fulflow::destroy_progressDlg
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error $err
	}
	set query_args [list \
		$start_type \
		$flow_direction \
		$objects_sel \
		$num_object_classes \
		$endtype_sel \
		$end_type \
		$perm_options \
		$filter_types \
		$f_opts($advanced_filter_Dlg,filtered_excl_types) \
		$f_opts($advanced_filter_Dlg,threshhold_cb_value) \
		$f_opts($advanced_filter_Dlg,threshhold_value)]
			
	set fulflow_tree [Apol_Analysis_fulflow::create_resultsDisplay $results_frame]
	set rt [catch {Apol_Analysis_fulflow::create_result_tree_structure $fulflow_tree $results $query_args} err]
	if {$rt != 0} {
		Apol_Analysis_fulflow::destroy_progressDlg
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error $err
	}
	Apol_Analysis_fulflow::destroy_progressDlg
	set Apol_Analysis_fulflow::progress_indicator -1
     	return 0
} 

proc Apol_Analysis_fulflow::treeSelect {fulflow_tree fulflow_info_text node} {
	# Set the tree selection to the current node.
	$fulflow_tree selection set $node
	
        if {$node == [$fulflow_tree nodes root]} {
		Apol_Analysis_fulflow::display_root_type_info $node $fulflow_info_text $fulflow_tree
	        Apol_Analysis_fulflow::formatInfoText $fulflow_info_text
	} else {
		Apol_Analysis_fulflow::insert_transitive_flows_header $fulflow_info_text $fulflow_tree $node
		Apol_Analysis_fulflow::render_information_flows $fulflow_info_text $fulflow_tree $node
		Apol_Analysis_fulflow::formatInfoText $fulflow_info_text
	}
	ApolTop::makeTextBoxReadOnly $fulflow_info_text
	return 0
}

# Procedure to do elapsed time formatting
proc Apol_Analysis_fulflow::convert_seconds {sec} {
	set hours [expr {$sec / 3600}]
	set minutes [expr {$sec / 60 - $hours * 60}]
	set seconds [expr {$sec - $minutes * 60 - $hours * 3600}]
	return [format "%02s:%02s:%02s" $hours $minutes $seconds]
}


###########################################################################
# ::display_find_more_flows_Dlg
#
proc Apol_Analysis_fulflow::display_find_more_flows_Dlg {} {
	variable find_flows_Dlg
	variable fulflow_tree
	variable find_flows_start
	variable find_flows_results_Dlg
	
	if {$find_flows_start} {
    		tk_messageBox -icon error -type ok -title "Error" -message "You must first abort the current search."
    		raise $find_flows_results_Dlg
    		return -1
    	}
	if {[winfo exists $find_flows_Dlg]} {
    		destroy $find_flows_Dlg
    	}
	
	set src_node [$fulflow_tree parent [$fulflow_tree selection get]]
	set tgt_node [$fulflow_tree selection get] 
	set Apol_Analysis_fulflow::abort_trans_analysis 0
	
	# Create the top-level dialog and subordinate widgets
    	toplevel $find_flows_Dlg 
     	wm withdraw $find_flows_Dlg	
    	wm title $find_flows_Dlg "Find more flows"
    	wm protocol $find_flows_Dlg WM_DELETE_WINDOW " "
    		
	# Create frames
        set topf  [frame $find_flows_Dlg.topf]
        set nodes_f [frame $topf.nodes_f]
        set time_f [frame $topf.time_f]
        set path_limit_f [frame $topf.path_limit_f]
        set button_f [frame $topf.button_f]
        
        set src_lbl [label $nodes_f.src_lbl -text "Source: [$fulflow_tree itemcget $src_node -text]"]
        set tgt_lbl [label $nodes_f.tgt_lbl -text "Target: [$fulflow_tree itemcget $tgt_node -text]"]
        
        # Create time limit widgets
        set time_lbl [label $time_f.time_lbl -text "Time Limit:"]
        set hrs_lbl  [label $time_f.hrs_lbl -text "Hour(s)"]
        set min_lbl  [label $time_f.min_lbl -text "Minute(s)"]
        set sec_lbl  [label $time_f.sec_lbl -text "Second(s)"]
        set time_entry_hour [Entry $time_f.time_entry_hour -editable 1 -width 5 \
        	-textvariable Apol_Analysis_fulflow::time_limit_hr -bg white]
        set time_entry_min [Entry $time_f.time_entry_min -editable 1 -width 5 \
        	-textvariable Apol_Analysis_fulflow::time_limit_min -bg white]
        set time_entry_sec [Entry $time_f.time_entry_sec -editable 1 -width 5 \
        	-textvariable Apol_Analysis_fulflow::time_limit_sec -bg white]
		
	# Create path limit widgets
	set path_limit_lbl [label $path_limit_f.path_limit_lbl -text "Limit by these number of flows:"]
        set path_limit_entry [Entry $path_limit_f.path_limit_entry -editable 1 -width 5 \
        	-textvariable Apol_Analysis_fulflow::flow_limit_num -bg white]
		
	# Create button widgets
	set b_find [button $button_f.b_find -text "Find" -width 6 \
		-command "Apol_Analysis_fulflow::find_more_flows $src_node $tgt_node"]
	set b_cancel [button $button_f.b_cancel -text "Cancel" -width 6 \
		-command "destroy $find_flows_Dlg"] 
		
	# Place widgets 
	pack $topf -fill both -expand yes -padx 10 -pady 10
        pack $nodes_f $time_f $path_limit_f -side top -fill x -padx 2 -pady 2
        pack $button_f -side bottom -padx 2 -pady 2 -anchor center
        pack $src_lbl $tgt_lbl -side top -padx 2 -pady 2 -anchor nw
        pack $time_lbl $time_entry_hour $hrs_lbl $time_entry_min $min_lbl $time_entry_sec $sec_lbl -side left -padx 1 -anchor nw
        pack $path_limit_lbl $path_limit_entry -side left -padx 2 -anchor nw
        pack $b_find $b_cancel -side left -padx 4 -anchor center
	wm deiconify $find_flows_Dlg
	focus $find_flows_Dlg
	wm protocol $find_flows_Dlg WM_DELETE_WINDOW "destroy $find_flows_Dlg"
	return 0
}

###########################################################################
# ::display_find_flows_results_Dlg
#
proc Apol_Analysis_fulflow::display_find_flows_results_Dlg {time_limit_str flow_limit_num} {
	variable find_flows_results_Dlg
	variable time_exp_lbl
	variable num_found_lbl
	
	if {[winfo exists $find_flows_results_Dlg]} {
    		destroy $find_flows_results_Dlg
    	}
	
	# Create the top-level dialog and subordinate widgets
    	toplevel $find_flows_results_Dlg 
     	wm withdraw $find_flows_results_Dlg	
    	wm title $find_flows_results_Dlg "Flow results"
    	    		
	# Create frames
        set topf  [frame $find_flows_results_Dlg.topf]
        set time_f [frame $topf.time_f]
        set button_f [frame $topf.button_f]
        set num_flows_f [frame $topf.num_flows_f]
        set main_lbl [label $topf.time_lbl1 -text "Finding more flows:"]
        set time_lbl1 [label $time_f.time_lbl1 -text "Time: "]
        set time_exp_lbl [label $time_f.time_exp_lbl]
        set time_lbl2 [label $time_f.time_lbl2 -text " elapsed out of $time_limit_str"]
        set num_lbl1 [label $num_flows_f.num_lbl1 -text "Flows: found "]
        set num_found_lbl [label $num_flows_f.num_found_lbl]
        set num_lbl2 [label $num_flows_f.num_lbl2 -text " out of $flow_limit_num"]
        set b_abort_transitive [button $button_f.b_abort_transitive -text "Stop" -width 6 \
		-command "set Apol_Analysis_fulflow::abort_trans_analysis 1"] 
		
	pack $button_f -side bottom -padx 2 -pady 2 -anchor center
	pack $topf -fill both -expand yes -padx 10 -pady 10
	pack $main_lbl -side top -anchor nw -pady 2
        pack $time_f $num_flows_f -side top -padx 15 -pady 2 -anchor nw
      	pack $b_abort_transitive -side left -fill both -expand yes -anchor center
      	pack $time_lbl1 $time_exp_lbl $time_lbl2 -side left -expand yes -anchor nw
      	pack $num_lbl1 $num_found_lbl $num_lbl2 -side left -expand yes -anchor nw
	wm deiconify $find_flows_results_Dlg
	
	wm transient $find_flows_results_Dlg $ApolTop::mainframe
        catch {grab $find_flows_results_Dlg}
    	if {[winfo exists $find_flows_results_Dlg]} {
		focus $find_flows_results_Dlg
    	}
    	update
	return 0
}

###########################################################################
# ::find_more_flows_generate_virtual_events
#
proc Apol_Analysis_fulflow::find_more_flows_generate_virtual_events {} {
	variable find_flows_results_Dlg
	
	bind $find_flows_results_Dlg <<FindMoreFlowsStarted>> {
		set elapsed_time [Apol_Analysis_fulflow::convert_seconds \
			[expr [clock seconds] - $Apol_Analysis_fulflow::start_time]]
		$Apol_Analysis_fulflow::time_exp_lbl configure -text $elapsed_time
       	}
        # TODO: generate virtual events to place onto Tcl's event queue, to capture progress.
	#event generate $find_flows_results_Dlg <<FindMoreFlowsStarted>> -when head
	return 0
}

###########################################################################
# ::find_more_flows
#
proc Apol_Analysis_fulflow::find_more_flows {src_node tgt_node} {
	variable fulflow_tree
	variable time_limit_hr	
	variable time_limit_min	
	variable time_limit_sec 
	variable flow_limit_num
	variable progressBar
        variable fulflow_info_text
        variable time_exp_lbl
	variable num_found_lbl
	variable find_flows_Dlg
	variable find_flows_results_Dlg
	variable find_flows_start
	variable start_time
	
	set time_limit_str [format "%02s:%02s:%02s" $time_limit_hr $time_limit_min $time_limit_sec]
	if {$flow_limit_num == "" && $time_limit_str == "00:00:00"} {
		tk_messageBox -icon error -type ok -title "Error" -message "You must specify a time limit."
		raise $find_flows_Dlg
		focus $find_flows_Dlg
		return -1
	} elseif {$flow_limit_num < 1} {
		tk_messageBox -icon error -type ok -title "Error" -message "Number of flows cannot be less than 1."
		raise $find_flows_Dlg
		focus $find_flows_Dlg
		return -1
	}
	if {$time_limit_hr != "" && [expr ($time_limit_hr > 24 || $time_limit_hr < 0)]} {
		tk_messageBox -icon error -type ok -title "Error" -message "Invalid hours limit input. Must be between 0 and 24 inclusive."
		raise $find_flows_Dlg
		focus $find_flows_Dlg
		return -1
	}
	if {$time_limit_min != "" && [expr ($time_limit_min > 59 || $time_limit_min < 0)]} {
		tk_messageBox -icon error -type ok -title "Error" -message "Invalid minutes limit input. Must between 0-59 inclusive."
		raise $find_flows_Dlg
		focus $find_flows_Dlg
		return -1
	}	
	if {$time_limit_sec != "" && [expr ($time_limit_sec > 59 || $time_limit_sec < 0)]} {
		tk_messageBox -icon error -type ok -title "Error" -message "Invalid seconds limit input. Must be between 0-59 inclusive."
		raise $find_flows_Dlg
		focus $find_flows_Dlg
		return -1
	}
	if {[winfo exists $find_flows_Dlg]} {
    		destroy $find_flows_Dlg
    	}
 	set old_focus [focus]
        Apol_Analysis_fulflow::display_find_flows_results_Dlg $time_limit_str $flow_limit_num
	set Apol_Analysis_fulflow::abort_trans_analysis 0
        set src_data [$fulflow_tree itemcget [$fulflow_tree nodes root] -data]	
 	set src [$fulflow_tree itemcget $src_node -text]
	wm protocol $find_flows_results_Dlg WM_DELETE_WINDOW "raise $find_flows_results_Dlg; focus $find_flows_results_Dlg"

	set start_time [clock seconds]
	set curr_flows_num 0
	set find_flows_start 1
		
	# Current time - start time = elapsed time
	$time_exp_lbl configure -text [Apol_Analysis_fulflow::convert_seconds [expr [clock seconds] - $start_time]]
	#Apol_Analysis_fulflow::find_more_flows_generate_virtual_events
	$num_found_lbl configure -text $curr_flows_num
	update

	# The last query arguments were stored in the data for the root node
	set rt [catch {apol_TransitiveFindPathsStart \
		$src \
		[lindex $src_data 1] \
		[lindex $src_data 2] \
		[lindex $src_data 3] \
		1 \
		"^[$fulflow_tree itemcget $tgt_node -text]$" \
		[lindex $src_data 6] \
		[lindex $src_data 7] \
		[lindex $src_data 8] \
		[lindex $src_data 9] \
		[lindex $src_data 10]} err]
	
	if {$rt != 0} {
		if {[winfo exists $find_flows_results_Dlg]} {
			destroy $find_flows_results_Dlg
		}
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	
	while {1} {
		# TODO: generate virtual events to place onto Tcl's event queue, to capture progress.
		#event generate $find_flows_results_Dlg <<FindMoreFlowsStarted>> -when head
		# Current time - start time = elapsed time
		set elapsed_time [Apol_Analysis_fulflow::convert_seconds [expr [clock seconds] - $start_time]]
		$time_exp_lbl configure -text $elapsed_time
		if {$time_limit_str != "00:00:00" && [string equal $time_limit_str $elapsed_time]} {
			break
		}
		# apol_TransitiveFindPathsNext will always stay the same or return a value greater 
		# than the current curr_flows_num value
		set rt [catch {set curr_flows_num [apol_TransitiveFindPathsNext]} err]
		if {$rt == -1} {
			    tk_messageBox -icon error -type ok -title "Error" -message $err
			    return -1
		}
		$num_found_lbl configure -text $curr_flows_num
		if {$flow_limit_num != "" && $curr_flows_num >= $flow_limit_num} {
			break
		}
		update
		# Check to see if the user has pressed the abort button
		if {$Apol_Analysis_fulflow::abort_trans_analysis} {
			set find_flows_start 0
			# Destroy the dialog and release the grab
			if {[winfo exists $find_flows_results_Dlg]} {
				grab release $find_flows_results_Dlg
				destroy $find_flows_results_Dlg
				catch {focus $old_focus}
			}
			# If there were flows found, then break out of loop so we can display 
			if {$curr_flows_num > 0} {break}
			set rt [catch {apol_TransitiveFindPathsAbort} err]
			if {$rt != 0} {	
				tk_messageBox -icon info -type ok -title "Abort Error" -message $err
				return -1
			}
			return -1
		}
	} 		
	set rt [catch {set results [apol_TransitiveFindPathsGetResults]} err]
	if {$rt != 0} {	
		set find_flows_start 0
		if {[winfo exists $find_flows_results_Dlg]} {
			destroy $find_flows_results_Dlg
		}
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}

	# Get # of target types (if none, then just draw the tree without child nodes)
	# We skip index 0 b/c it is the starting type, which we already have.
	set num_target_types [lindex $results 0]	
	if {$num_target_types} {
		# Start form index 1. This should be the first target node if there were any target nodes returned.
		set nextIdx [Apol_Analysis_fulflow::parseList_get_index_next_node 1 $results]
		set data [lrange $results 1 [expr $nextIdx-1]]
		$fulflow_tree itemconfigure $tgt_node -data $data
		Apol_Analysis_fulflow::insert_more_flows_header $fulflow_info_text $fulflow_tree \
			$src_node $tgt_node \
			$time_limit_str $elapsed_time \
			$flow_limit_num $curr_flows_num
		Apol_Analysis_fulflow::render_information_flows $fulflow_info_text $fulflow_tree $tgt_node
		Apol_Analysis_fulflow::formatInfoText $fulflow_info_text 
	}
	set find_flows_start 0
	if {[winfo exists $find_flows_results_Dlg]} {
		grab release $find_flows_results_Dlg
    		destroy $find_flows_results_Dlg
    		catch {focus $old_focus}
    	}
	return 0
}

###########################################################################
# ::display_root_type_info
#
proc Apol_Analysis_fulflow::display_root_type_info { source_type fulflow_info_text fulflow_tree } {
	$fulflow_info_text configure -state normal
	$fulflow_info_text delete 0.0 end
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "Transitive Information Flow Analysis: Starting type: "
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	set startIdx $endIdx
	$fulflow_info_text insert end $source_type
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
	set startIdx $endIdx
	# now add the standard text
	$fulflow_info_text configure -wrap word
	set start_idx [$fulflow_info_text index insert]
	$fulflow_info_text insert end $Apol_Analysis_fulflow::root_text
	$fulflow_info_text tag add ROOT_TEXT $start_idx end
	$fulflow_info_text tag configure ROOT_TEXT -font $ApolTop::text_font 
	$fulflow_info_text see 1.0
	$fulflow_info_text configure -state disabled
	
	return 0
}

###########################################################################
# ::insert_more_flows_header
#	- Called to insert the header text when displaying results from 
#	  a find more flows search.
proc Apol_Analysis_fulflow::insert_more_flows_header {fulflow_info_text fulflow_tree src_node tgt_node time_limit_str elapsed_time flow_limit_num curr_flows_num} {  
	$fulflow_info_text configure -state normal	
	$fulflow_info_text delete 0.0 end
	$fulflow_info_text mark set insert 1.0
        $fulflow_info_text configure -wrap none
	
	set data [$fulflow_tree itemcget $tgt_node -data]
	if {$data == ""} {
	        $fulflow_info_text configure -state disabled
		return ""	
	}
	# The flow direction is embedded in the data store of the root node at index 1.
        set query_args [$fulflow_tree itemcget [$fulflow_tree nodes root] -data]
        set flow_direction [lindex $query_args 1]
	if {$flow_direction == "in"} {
		set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end "More Information Flows to "
		set endIdx [$fulflow_info_text index insert]
	    	$fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	    	set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end " [$fulflow_tree itemcget $src_node -text]"
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
		set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end " from "
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
		set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end "[$fulflow_tree itemcget $tgt_node -text]"
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
	} elseif {$flow_direction == "out"} { 
		set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end "More Information Flows from "
		set endIdx [$fulflow_info_text index insert]
	    	$fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	    	set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end "[$fulflow_tree itemcget $src_node -text]"
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
		set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end " to "
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
		set startIdx [$fulflow_info_text index insert]
		$fulflow_info_text insert end "[$fulflow_tree itemcget $tgt_node -text]"
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
	} else {
		puts "Invalid flow direction ($flow_direction) specified!"
		return 
	}
	# Insert find more flows link
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "  ("
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "Find more flows"
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::find_flows_tag $startIdx $endIdx
	$fulflow_info_text insert end ")"
	
	# Insert time/flows limit strings
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "\n\nTime: $elapsed_time out of $time_limit_str"
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
	
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "\n\nApol found the following number of information flows: "
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
        set startIdx $endIdx
        $fulflow_info_text insert end  "$curr_flows_num" 
        set endIdx [$fulflow_info_text index insert]
        $fulflow_info_text tag add $Apol_Analysis_fulflow::counters_tag $startIdx $endIdx
        set startIdx $endIdx
        $fulflow_info_text insert end " out of "
        set endIdx [$fulflow_info_text index insert]
        $fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
        set startIdx $endIdx
        $fulflow_info_text insert end "$flow_limit_num"
        set endIdx [$fulflow_info_text index insert]
        $fulflow_info_text tag add $Apol_Analysis_fulflow::counters_tag $startIdx $endIdx		
        $fulflow_info_text configure -state disabled
        
	return 0
}

###########################################################################
# ::insert_transitive_flows_header
#	- Called to insert the header text when displaying results from 
#	  a transitive flows search.
proc Apol_Analysis_fulflow::insert_transitive_flows_header {fulflow_info_text fulflow_tree node} {  
	$fulflow_info_text configure -state normal	
	$fulflow_info_text delete 0.0 end
	$fulflow_info_text mark set insert 1.0
        $fulflow_info_text configure -wrap none
	
	set data [$fulflow_tree itemcget $node -data]
	if {$data == ""} {
	        $fulflow_info_text configure -state disabled
		return 	
	}
	
	set start_type [$fulflow_tree itemcget [$fulflow_tree parent $node] -text]
        set startIdx [$fulflow_info_text index insert]
        # Index 0 will be the end type 
        set currentIdx 0 
        set end_type [lindex $data $currentIdx]
        # The flow direction is embedded in the data store of the root node at index 1.
        set query_args [$fulflow_tree itemcget [$fulflow_tree nodes root] -data]
        set flow_direction [lindex $query_args 1]

	if {$flow_direction == "in"} {
	    $fulflow_info_text insert end "Information flows to "
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end $start_type
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end " from "
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end $end_type
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
	    set startIdx $endIdx 
	} elseif {$flow_direction == "out"} {	
	    $fulflow_info_text insert end "Information flows from "
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end $start_type
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end " to "
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_tag $startIdx $endIdx
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end $end_type
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::title_type_tag $startIdx $endIdx
 	    set startIdx $endIdx 
	} else {
		puts "Invalid flow direction ($flow_direction) specified!"
		return 
	}
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "  ("
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "Find more flows"
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::find_flows_tag $startIdx $endIdx
	$fulflow_info_text insert end ")"
	
	# Index 1 will be the number of paths 
        set currentIdx 1 
	set startIdx [$fulflow_info_text index insert]
	$fulflow_info_text insert end "\n\nApol found the following number of information flows: "
	set endIdx [$fulflow_info_text index insert]
	$fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
        set startIdx $endIdx
	set num_paths [lindex $data $currentIdx]
	$fulflow_info_text insert end $num_paths
        set endIdx [$fulflow_info_text index insert]
        $fulflow_info_text tag add $Apol_Analysis_fulflow::counters_tag $startIdx $endIdx
        
	$fulflow_info_text configure -state disabled
	return 0
}

###########################################################################
# ::render_information_flows
#	- This proc will insert any information flows found into the textbox.
#	- NOTE: This procedure should be called after the header has been 
#	  inserted using one of the two procs above. If these header procs
# 	  are not called, the caller needs to  first delete and configure  
#	  the textbox.
proc Apol_Analysis_fulflow::render_information_flows {fulflow_info_text fulflow_tree node} {  
	$fulflow_info_text configure -state normal
	
	set data [$fulflow_tree itemcget $node -data] 
	if {$data == ""} {
	        $fulflow_info_text configure -state disabled
		return 	
	}
	
	# Index 1 will be the number of paths 
        set currentIdx 1
        set num_paths [lindex $data $currentIdx]		
	for {set i 0} {$i<$num_paths} {incr i} {
	    set startIdx [$fulflow_info_text index insert]
	    $fulflow_info_text insert end "\n\nFlow"
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $fulflow_info_text insert end " [expr $i+1] "
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::counters_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $fulflow_info_text insert end "requires " 
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx 
	    # Increment to the number of flows 
	    incr currentIdx
	    set num_flows [lindex $data $currentIdx]
	    $fulflow_info_text insert end $num_flows
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::counters_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $fulflow_info_text insert end " step(s)."
	    set endIdx [$fulflow_info_text index insert]
	    $fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
	    for {set j 0} {$j<$num_flows} {incr j} {
		# First print the flow number
		$fulflow_info_text insert end "\n\n\tStep "
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
		set startIdx $endIdx
		$fulflow_info_text insert end [expr $j + 1]
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::counters_tag $startIdx $endIdx
		set startIdx $endIdx
		$fulflow_info_text insert end ": "
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
		set startIdx $endIdx
		$fulflow_info_text insert end "from "
		# increment to the start type for the flow
		incr currentIdx
		$fulflow_info_text insert end [lindex $data $currentIdx]
		$fulflow_info_text insert end " to "
		# Increment to the end type for the flow
		incr currentIdx
		$fulflow_info_text insert end [lindex $data $currentIdx]
		set endIdx [$fulflow_info_text index insert]
		$fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
		set startIdx $endIdx
		# Increment to the # of object classes
		incr currentIdx
		set num_classes [lindex $data $currentIdx]
		for {set k 0} {$k<$num_classes} {incr k} {
		    # Increment to the first object class
	    	    incr currentIdx
		    $fulflow_info_text insert end "\n\t[lindex $data $currentIdx]"
		    set endIdx [$fulflow_info_text index insert]
		    $fulflow_info_text tag add $Apol_Analysis_fulflow::subtitle_tag $startIdx $endIdx
		    set startIdx $endIdx
		    # Increment to the # of object class rules
		    incr currentIdx
		    set num_rules [lindex $data $currentIdx]
		    for {set l 0} {$l<$num_rules} {incr l} {
		    	# Increment to the next rule for the object
			incr currentIdx
			set rule [lindex $data $currentIdx]
			$fulflow_info_text insert end "\n\t"
			set startIdx [$fulflow_info_text index insert]
			# Get the line number only
			set end_link_idx [string first "\]" [string trim $rule] 0]
			set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
			set lineno [string trim $lineno]
			set rule [string range $rule [expr $end_link_idx + 1] end]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$fulflow_info_text insert end "\[$lineno\]"
				Apol_PolicyConf::insertHyperLink $fulflow_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
			}
			set startIdx [$fulflow_info_text index insert]
			$fulflow_info_text insert end " $rule"
			set endIdx [$fulflow_info_text index insert]
			$fulflow_info_text tag add $Apol_Analysis_fulflow::rules_tag $startIdx $endIdx
			
			incr currentIdx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $currentIdx] == 0} {
				$fulflow_info_text insert end "   "
				set startIdx [$fulflow_info_text index insert]
				$fulflow_info_text insert end "\[Disabled\]"
				set endIdx [$fulflow_info_text index insert]
				$fulflow_info_text tag add $Apol_Analysis_fulflow::disabled_rule_tag $startIdx $endIdx
			} 
			set startIdx [$fulflow_info_text index insert]
		    } 
		}
	    }
	}
	$fulflow_info_text see 1.0 
	$fulflow_info_text configure -state disabled
	
	return 0
}

###########################################################################
# ::formatInfoText
#
proc Apol_Analysis_fulflow::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_fulflow::title_tag -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_fulflow::title_type_tag -foreground blue -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_fulflow::subtitle_tag -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_fulflow::rules_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_fulflow::counters_tag -foreground blue -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_fulflow::types_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_fulflow::find_flows_tag -font {Helvetica 14 bold} -foreground blue -underline 1
	$tb tag configure $Apol_Analysis_fulflow::disabled_rule_tag -foreground red 
	
	$tb tag bind $Apol_Analysis_fulflow::find_flows_tag <Button-1> "Apol_Analysis_fulflow::display_find_more_flows_Dlg"
	$tb tag bind $Apol_Analysis_fulflow::find_flows_tag <Enter> { set Apol_Analysis_fulflow::orig_cursor [%W cget -cursor]; %W configure -cursor hand2 }
	$tb tag bind $Apol_Analysis_fulflow::find_flows_tag <Leave> { %W configure -cursor $Apol_Analysis_fulflow::orig_cursor }
	
	# Configure hyperlinking to policy.conf file
	Apol_PolicyConf::configure_HyperLinks $tb
}

proc Apol_Analysis_fulflow::insert_src_type_node { fulflow_tree query_args} {
        variable start_type

       	$fulflow_tree insert end root $start_type \
		-text $start_type \
		-open 1	\
        	-drawcross auto \
		-data $query_args

        return [$fulflow_tree nodes root]
}

proc Apol_Analysis_fulflow::create_target_type_nodes { parent fulflow_tree results_list } {
        if { [file tail [$fulflow_tree parent $parent]] == [file tail $parent] } {
		return 
	}

	if { [$fulflow_tree nodes $parent] == "" } {
		# Get # of target types (if none, then just draw the tree without child nodes)
		# We skip index 0 b/c it is the starting type, which we already have.
		set num_target_types [lindex $results_list 1]	
		# Set the index to 2. This should be the first target node if there were any target nodes returned.
		set curentIdx 2
		
		for { set x 0 } {$x < $num_target_types} { incr x } { 
			#  if there are any target types, the next list element will be the first target node from the results list.
			set target_name [lindex $results_list $curentIdx]
			
			set nextIdx [Apol_Analysis_fulflow::parseList_get_index_next_node $curentIdx $results_list]
			if {$nextIdx == -1} {
				return -code error "Error parsing results. See stdout for more information."
			}
			
			set target_node "${parent}/${target_name}/"
			$fulflow_tree insert end $parent $target_node \
				-text $target_name \
				-open 0	\
		        	-drawcross allways \
		        	-data [lrange $results_list $curentIdx [expr $nextIdx-1]]
			set curentIdx $nextIdx
		}
		set nodes [lsort [$fulflow_tree nodes $parent]]
		$fulflow_tree reorder $parent $nodes 
	        $fulflow_tree configure -redraw 1
	}
        return 0
}

proc Apol_Analysis_fulflow::parseList_get_index_next_node { currentIdx results_list } {
	# Increment to # paths
	incr currentIdx
	set num_paths [lindex $results_list $currentIdx]
	if {![string is integer $num_paths]} {
		return -1;
	}
	# for each flow in each path parse by all the types, objects, and rules
	for {set i 0} {$i < $num_paths} {incr i} {
		incr currentIdx
		set num_flows [lindex $results_list $currentIdx]
		if {![string is integer $num_flows]} {
			return -1;
		}	    
		for {set j 0} {$j < $num_flows} {incr j} {
			incr currentIdx 3
			set num_objs [lindex $results_list $currentIdx]
			if {![string is integer $num_objs]} {
				return -1;
			}
			for {set k 0} {$k < $num_objs} {incr k} {
				incr currentIdx 2
				set num_rules [lindex $results_list $currentIdx]
				if {![string is integer $num_rules]} {
					return -1;
				}
				# We multiply the number of rules by 2 because each rule consists of:
				# 	1. rule string (includes line number)
				#	2. enabled flag
				incr currentIdx [expr $num_rules * 2]
			}
		}
	}
	incr currentIdx
	return $currentIdx
}

proc Apol_Analysis_fulflow::create_result_tree_structure { fulflow_tree results_list query_args} {
        set home_node [Apol_Analysis_fulflow::insert_src_type_node $fulflow_tree $query_args]
	set rt [catch {Apol_Analysis_fulflow::create_target_type_nodes $home_node $fulflow_tree $results_list} err]
	if {$rt != 0} {
		return -code error $err
	}
	
	Apol_Analysis_fulflow::treeSelect \
		$Apol_Analysis_fulflow::fulflow_tree $Apol_Analysis_fulflow::fulflow_info_text $home_node
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::do_child_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::do_child_analysis { fulflow_tree selected_node } {    
	ApolTop::setBusyCursor
	Apol_Analysis_fulflow::display_progressDlg	
	if { [$fulflow_tree nodes $selected_node] == "" } {	
	    	# The last query arguments were stored in the data for the root node
		set query_args [$fulflow_tree itemcget [$fulflow_tree nodes root] -data]
	        set start_t [file tail $selected_node]
		set rt [catch {set results [apol_TransitiveFlowAnalysis \
			$start_t \
			[lindex $query_args 1] \
			[lindex $query_args 2] \
			[lindex $query_args 3] \
			[lindex $query_args 4] \
			[lindex $query_args 5] \
			[lindex $query_args 6] \
			[lindex $query_args 7] \
			[lindex $query_args 8] \
			[lindex $query_args 9] \
			[lindex $query_args 10]]} err]
			
		if {$rt != 0} {	
			Apol_Analysis_fulflow::destroy_progressDlg
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
	    		return -code error
		}
		Apol_Analysis_fulflow::create_target_type_nodes $selected_node $fulflow_tree $results
	}
	Apol_Analysis_fulflow::destroy_progressDlg
	ApolTop::resetBusyCursor
	return 0
}

proc Apol_Analysis_fulflow::create_resultsDisplay { results_frame } {
        variable fulflow_tree
        variable fulflow_info_text

        # set up paned window
	set pw   [PanedWindow $results_frame.pw -side top]
	set pw_tree [$pw add]
	set pw_info [$pw add -weight 5]
	
	# title frames
	set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Transitive Information Flow Tree"]
	set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Transitive Information Flow Data"]		
	set sw_tree [ScrolledWindow [$frm_tree getframe].sw_tree -auto none]		 
	set sw_info [ScrolledWindow [$frm_info getframe].sw_info -auto none]		 

	# tree window
	set fulflow_tree  [Tree [$sw_tree getframe].fulflow_tree \
	           -relief flat -borderwidth 0 -highlightthickness 0 \
		   -redraw 0 -bg white -showlines 1 -padx 0 \
		   -opencmd  {Apol_Analysis_fulflow::do_child_analysis $Apol_Analysis_fulflow::fulflow_tree}]
	$sw_tree setwidget $fulflow_tree 

	# info window
	set fulflow_info_text [text [$sw_info getframe].fulflow_info_text -wrap none -bg white -font $ApolTop::text_font]
	$sw_info setwidget $fulflow_info_text
	bind $fulflow_info_text <Enter> {focus %W}
	
	pack $pw -fill both -expand yes -anchor nw 
	pack $frm_tree -fill both -expand yes -anchor nw
	pack $frm_info -fill both -expand yes
	pack $sw_tree -fill both -expand yes
	pack $sw_info -fill both -expand yes 
	
	$fulflow_tree bindText  <ButtonPress-1> {Apol_Analysis_fulflow::treeSelect \
		$Apol_Analysis_fulflow::fulflow_tree $Apol_Analysis_fulflow::fulflow_info_text}

    	$fulflow_tree bindText  <Double-ButtonPress-1> {Apol_Analysis_fulflow::treeSelect \
		$Apol_Analysis_fulflow::fulflow_tree $Apol_Analysis_fulflow::fulflow_info_text}
    
	return $fulflow_tree
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::load_default_perm_map
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::load_default_perm_map {} {
	# if a permap is not loaded then load the default permap
        set rt [catch {set map_loaded [Apol_Perms_Map::is_pmap_loaded]} err]
        if { $rt != 0 } {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	}
	if {!$map_loaded} {
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
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_refresh_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_refresh_dialog {path_name} {  
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != ""} { 
		Apol_Analysis_fulflow::advanced_filters_destroy_object $path_name	
		Apol_Analysis_fulflow::advanced_filters_create_object $path_name	
		Apol_Analysis_fulflow::advanced_filters_update_dialog $path_name
	}
	
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_update_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_update_dialog {path_name} {
	variable f_opts
			
	# If the advanced filters dialog is displayed, then we need to update its' state.
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != "" &&
	    [winfo exists $f_opts($path_name,name)]} {
		set rt [catch {Apol_Analysis_fulflow::advanced_filters_set_widgets_to_default_state \
			$path_name} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
		raise $f_opts($path_name,name)
		focus -force $f_opts($path_name,name)
		
		# Reset the selection in the listbox
		if {$f_opts($path_name,class_selected_idx) != "-1"} {
			$f_opts($path_name,class_listbox) selection set \
				[$f_opts($path_name,class_listbox) index \
				$f_opts($path_name,class_selected_idx)]
			Apol_Analysis_fulflow::advanced_filters_display_permissions $path_name
		}
	} 

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_include_types
#	- remove_list - the list displayed inside the listbox from which the 
#			type is being removed.
#	- add_list - the list displayed inside the listbox to which the type 
#		     being added. 
#	- remove_lbox - listbox widget from which the type is being removed.
#	- add_lbox - listbox widget to which the type is being added.
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_include_types {remove_list_1 \
							    add_list_1 \
							    remove_lbox \
							    add_lbox \
							    master_incl_types_list_1 \
							    master_excl_types_list_1} {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	upvar #0 $master_incl_types_list_1 master_incl_types_list
	upvar #0 $master_excl_types_list_1 master_excl_types_list
	
	set type_indices [$remove_lbox curselection]		
	if {$type_indices != ""} {
		set tmp_list ""
		foreach idx $type_indices {
			set tmp_list [lappend tmp_list [$remove_lbox get $idx]]	
		}
		foreach type $tmp_list {
			set idx  [lsearch -exact $remove_list $type]
			if {$idx != -1} {
				set remove_list [lreplace $remove_list $idx $idx]
				# put in add list
				set add_list [lappend add_list $type]
				set add_list [lsort $add_list]
			}
			# Update the non-filtered list variables (i.e. types not filtered by attribute)
			set master_incl_types_list [lappend master_incl_types_list $type]
			set idx  [lsearch -exact $master_excl_types_list $type]
			if {$idx != -1} {
				set master_excl_types_list [lreplace $master_excl_types_list $idx $idx]
			}
		    }
		$remove_lbox selection clear 0 end
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_exclude_types
#	- remove_list - the list displayed inside the listbox from which the 
#			type is being removed.
#	- add_list - the list displayed inside the listbox to which the type 
#		     being added. 
#	- remove_lbox - listbox widget from which the type is being removed.
#	- add_lbox - listbox widget to which the type is being added.
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_exclude_types {remove_list_1 \
							    add_list_1 \
							    remove_lbox \
							    add_lbox \
							    master_incl_types_list_1 \
							    master_excl_types_list_1} {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	upvar #0 $master_incl_types_list_1 master_incl_types_list
	upvar #0 $master_excl_types_list_1 master_excl_types_list
		
	set type_indices [$remove_lbox curselection]		
	if {$type_indices != ""} {
		set tmp_list ""
		foreach idx $type_indices {
			set tmp_list [lappend tmp_list [$remove_lbox get $idx]]	
		}
		foreach type $tmp_list {
			set idx  [lsearch -exact $remove_list $type]
			if {$idx != -1} {
				set remove_list [lreplace $remove_list $idx $idx]
				# put in add list
				set add_list [lappend add_list $type]
				set add_list [lsort $add_list]
			}
			# Update the non-filtered list variables (i.e. types not filtered by attribute)
			set master_excl_types_list [lappend master_excl_types_list $type]
			set idx  [lsearch -exact $master_incl_types_list $type]
			if {$idx != -1} {
				set master_incl_types_list [lreplace $master_incl_types_list $idx $idx]
			}
		    }
		$remove_lbox selection clear 0 end
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state {cb_selected_1 \
									combo_box \
									lbox \
									which_list \
									path_name} {
	variable f_opts
	
	upvar #0 $cb_selected_1 cb_selected
	if {$cb_selected} {
		$combo_box configure -state normal -entrybg white
		if {$which_list == "incl"} {
			Apol_Analysis_fulflow::advanced_filters_filter_types_using_attrib \
				Apol_Analysis_fulflow::f_opts($path_name,incl_attrib_combo_value) \
				$lbox \
				Apol_Analysis_fulflow::f_opts($path_name,master_incl_types_list)
		} else {
			Apol_Analysis_fulflow::advanced_filters_filter_types_using_attrib \
				Apol_Analysis_fulflow::f_opts($path_name,excl_attrib_combo_value) \
				$lbox \
				Apol_Analysis_fulflow::f_opts($path_name,master_excl_types_list)
		}
	} else {
		$combo_box configure -state disabled -entrybg $ApolTop::default_bg_color
		if {$which_list == "incl"} {
			set [$lbox cget -listvar] \
				[lsort $f_opts($path_name,master_incl_types_list)]
		} elseif {$which_list == "excl"} {
			set [$lbox cget -listvar] \
				[lsort $f_opts($path_name,master_excl_types_list)]
		} else {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "Invalid paremeter ($which_list) to \
				Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state. \
				Must be either 'incl' or 'excl'"
	    		return -1
		}
	}
		
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_filter_types_using_attrib
#	- attribute - the specified attribute
#	- lbox - the listbox in which to perform the selection
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_filter_types_using_attrib {attribute_1 lbox non_filtered_types_1} {	
	upvar #0 $attribute_1 attribute
	upvar #0 $non_filtered_types_1 non_filtered_types
	
	if {$attribute != ""} {
		$lbox delete 0 end
		# Get a list of types for the specified attribute
            set attrib_types [lindex [apol_GetAttribs $attribute] 0 1]
		if {$non_filtered_types != ""} {
			set len [llength $non_filtered_types]
			for {set i 0} {$i < $len} {incr i} { 
				# Check if this is a filtered type
				set idx [lsearch -exact $attrib_types [lindex $non_filtered_types $i]]
				if {$idx != -1} {
					$lbox insert end [lindex $non_filtered_types $i]
				}
			}
		}
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_include_exclude_permissions
#	- perms_box - the specified attribute
#	- which - include or exclude
#
#	- This proc will change a list item in the class listbox. When all perms 
#	  are excluded, the object class is grayed out in the listbox and the 
# 	  class label is changed to "object_class (Exluded)". This is a visual 
# 	  representation to the user that the object class itself is being  
# 	  implicitly excluded from the query as a result of all of its' 
#	  permissions being excluded. When any or all permissions are included, 
#	  the class label is reset to the class name itself and is then un-grayed.
#	  Any other functions that then take a selected listbox element as an 
#	  argument MUST first search the class string for the sequence " (Excluded)"
# 	  before processing the class name.
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_include_exclude_permissions {which path_name} {	
	variable f_opts
	
	if {[ApolTop::is_policy_open]} {
		if {[string equal $which "include"] == 0 && [string equal $which "exclude"] == 0} {
			puts "Tcl error: wrong 'which' argument sent to Apol_Analysis_fulflow::advanced_filters_include_exclude_permissions. Must be either 'include' or 'exclude'."	
			return -1
		}
		set objs [$f_opts($path_name,class_listbox) curselection]
 		foreach object_class_idx $objs {
 			set object_class [$f_opts($path_name,class_listbox) get $object_class_idx]
 			set idx [string first $Apol_Analysis_fulflow::excluded_tag $object_class]
 			if {$idx != -1} {
 				set object_class [string range $object_class 0 [expr $idx - 1]]
 			}
 			set rt [catch {set perms_list [apol_GetPermsByClass $object_class 1]} err]
 			if {$rt != 0} {
 				tk_messageBox -icon error -type ok -title "Error" -message "$err"
 				return -1
 			}
 			foreach perm $perms_list {
 				set f_opts($path_name,perm_status_array,$object_class,$perm) $which
 			}
 			if {$object_class_idx != ""} {
 				set items [$f_opts($path_name,class_listbox) get 0 end]
				if {[string equal $which "exclude"]} {
					$f_opts($path_name,class_listbox) itemconfigure $object_class_idx \
						-foreground gray
					set [$f_opts($path_name,class_listbox) cget -listvar] \
						[lreplace $items $object_class_idx $object_class_idx \
						"$object_class$Apol_Analysis_fulflow::excluded_tag"]
				} else {
					$f_opts($path_name,class_listbox) itemconfigure $object_class_idx \
						-foreground $f_opts($path_name,select_fg_orig)
					set [$f_opts($path_name,class_listbox) cget -listvar] \
						[lreplace $items $object_class_idx $object_class_idx \
						"$object_class"]
				}
  			}
  			if {$f_opts($path_name,class_selected_idx) == $object_class_idx} {
  				$f_opts($path_name,permissions_title_frame) configure \
  					-text "Permissions for [$f_opts($path_name,class_listbox) get \
  						$object_class_idx]:"
  			}
  		}
	}
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_change_obj_state_on_perm_select
#`	-  This proc also searches a class string for the sequence " (Excluded)"
# 	   in order to process the class name only. 
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_change_obj_state_on_perm_select {path_name} {
	variable f_opts 
	
	set num_excluded 0	
	# There may be multiple selected items, but we need the object class that is 
	# currently displayed in the text box. We have this index stored in our global 
	# class_selected_idx variable.
	if {$f_opts($path_name,class_selected_idx) != "-1"} {
		set class_sel [$f_opts($path_name,class_listbox) get \
			$f_opts($path_name,class_selected_idx)]
		set idx [string first $Apol_Analysis_fulflow::excluded_tag $class_sel]
		if {$idx != -1} {
			set class_sel [string range $class_sel 0 [expr $idx - 1]]
		}
		set class_elements [array get f_opts "$path_name,perm_status_array,$class_sel,*"]
		if {$class_elements != ""} {
			set num_perms_for_class [expr {[llength $class_elements] / 2}]
			set len [llength $class_elements]
			for {set i 0} {$i < $len} {incr i} {
				incr i
				if {[string equal [lindex $class_elements $i] "exclude"]} {
					incr num_excluded	
				}
			}
			set items [$f_opts($path_name,class_listbox) get 0 end]
			# If the total all permissions for the object have been 
			# excluded then inform the user. 
			if {$num_excluded == $num_perms_for_class} {
				$f_opts($path_name,class_listbox) itemconfigure \
					$f_opts($path_name,class_selected_idx) \
					-foreground gray
				set [$f_opts($path_name,class_listbox) cget -listvar] \
					[lreplace $items $f_opts($path_name,class_selected_idx) \
					$f_opts($path_name,class_selected_idx) \
					"$class_sel$Apol_Analysis_fulflow::excluded_tag"]
			} else {
				$f_opts($path_name,class_listbox) itemconfigure \
					$f_opts($path_name,class_selected_idx) \
					-foreground $f_opts($path_name,select_fg_orig)
				set [$f_opts($path_name,class_listbox) cget -listvar] \
					[lreplace $items $f_opts($path_name,class_selected_idx) \
					$f_opts($path_name,class_selected_idx) \
					"$class_sel"]
			}
  			$f_opts($path_name,permissions_title_frame) configure \
  				-text "Permissions for [$f_opts($path_name,class_listbox) get \
  					$f_opts($path_name,class_selected_idx)]:"
		}
	}
	
	return 0	
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_fulflow::advanced_filters_embed_perm_buttons 
#	- Embeds include/exclude radiobuttons in the permissions textbox next to
#	  each permission label.
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_embed_perm_buttons {list_b class perm path_name} {
	variable f_opts
	
 	# Frames
	set frame [frame $list_b.f:$class:$perm -bd 0 -bg white]
	set lbl_frame [frame $frame.lbl_frame:$class:$perm -width 20 -bd 1 -bg white]
	set cb_frame [frame $frame.cb_frame:$class:$perm -width 10 -bd 0 -bg white]
	
	# Label
	set lbl1 [label $lbl_frame.lbl1:$class:$perm -bg white -justify left -width 20  \
			-anchor nw -text $perm] 
	set lbl2 [label $lbl_frame.lbl2:$class:$perm -bg white -justify left -width 5 -text "--->"]
	
	# Radiobuttons. Here we are embedding selinux and mls permissions into the pathname 
	# in order to make them unique radiobuttons.
	set cb_include [radiobutton $cb_frame.cb_include:$class:$perm -bg white \
		-value include -text "Include" \
		-highlightthickness 0 \
		-variable Apol_Analysis_fulflow::f_opts($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_fulflow::advanced_filters_change_obj_state_on_perm_select \
			$path_name"]	
	set cb_exclude [radiobutton $cb_frame.cb_exclude:$class:$perm -bg white \
		-value exclude -text "Exclude" \
		-highlightthickness 0 \
		-variable Apol_Analysis_fulflow::f_opts($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_fulflow::advanced_filters_change_obj_state_on_perm_select \
			$path_name"]
	set lbl_weight [Label $cb_frame.lbl_weight:$class:$perm -bg white \
		-text "Perm map weight: [Apol_Perms_Map::get_weight_for_class_perm $class $perm]" \
		-padx 10]
	
	# Placing widgets
	pack $frame -side left -anchor nw -expand yes -pady 10
	pack $lbl_frame $cb_frame -side left -anchor nw -expand yes
	pack $lbl1 $lbl2 -side left -anchor nw
	pack $cb_include $cb_exclude $lbl_weight -side left -anchor nw
	
	# Return the pathname of the frame to embed.
 	return $frame
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_fulflow::advanced_filters_clear_perms_text 
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_clear_perms_text {path_name} {
	variable f_opts
	
	# Enable the text widget. 
	$f_opts($path_name,perms_box) configure -state normal
	# Clear the text widget and any embedded windows
	set names [$f_opts($path_name,perms_box) window names]
	foreach emb_win $names {
		if { [winfo exists $emb_win] } {
			set rt [catch {destroy $emb_win} err]
			if {$rt != 0} {
				tk_messageBox \
					-icon error \
					-type ok \
					-title "Error" \
					-message "$err"
				return -1
			}
		}
	}
	$f_opts($path_name,perms_box) delete 1.0 end
	$f_opts($path_name,perms_box) configure -state disabled
}

proc Apol_Analysis_fulflow::render_permissions {path_name} {
	variable f_opts
	
	set class_idx [$f_opts($path_name,class_listbox) curselection]
	if {$class_idx == ""} {
		# Something was simply deselected.
		return 0
	} 
	focus -force $f_opts($path_name,class_listbox)
	set class_name [$f_opts($path_name,class_listbox) get $class_idx]
	$f_opts($path_name,permissions_title_frame) configure -text "Permissions for $class_name:"
	Apol_Analysis_fulflow::advanced_filters_clear_perms_text $path_name
	update 
	# Make sure to strip out just the class name, as this may be an excluded class.
	set idx [string first $Apol_Analysis_fulflow::excluded_tag $class_name]
	if {$idx != -1} {
		set class_name [string range $class_name 0 [expr $idx - 1]]
	}
	# Get all valid permissions for the selected class from the policy database.
	set rt [catch {set perms_list [apol_GetPermsByClass $class_name 1]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return -1
	}
	set perms_list [lsort $perms_list]
	$f_opts($path_name,perms_box) configure -state normal
	foreach perm $perms_list { 
		# If this permission does not exist in our perm status array, this means
		# that a saved query was loaded and the permission defined in the policy
		# is not defined in the saved query. So we default this to be included.
		if {[array names f_opts "$path_name,perm_status_array,$class_name,$perm"] == ""} {
			set f_opts($path_name,perm_status_array,$class_name,$perm) include
		}
		$f_opts($path_name,perms_box) window create end -window \
			[Apol_Analysis_fulflow::advanced_filters_embed_perm_buttons \
			$f_opts($path_name,perms_box) $class_name $perm $path_name] 
		$f_opts($path_name,perms_box) insert end "\n"
	}
	# Disable the text widget. 
	$f_opts($path_name,perms_box) configure -state disabled
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_fulflow::advanced_filters_display_permissions 
# 	- Displays permissions for the selected object class in the permissions 
#	  text box.
#	- Takes the selected object class index as the only argument. 
#	  This proc also searches the class string for the sequence " (Excluded)"
# 	  in order to process the class name only. This is because a Tk listbox
# 	  is being used and does not provide a -text option for items in the 
# 	  listbox.
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_display_permissions {path_name} {
	variable f_opts
	
	if {[$f_opts($path_name,class_listbox) get 0 end] == "" || \
		[llength [$f_opts($path_name,class_listbox) curselection]] > 1} {
		# Nothing in the listbox; return
		return 0
	}
	set bind_tag_id [string trim $path_name "."]
	bind ${bind_tag_id}_fulflow_object_list_Tag <<ListboxSelect>> ""
	set f_opts($path_name,class_selected_idx) [$f_opts($path_name,class_listbox) curselection]
	Apol_Analysis_fulflow::render_permissions $path_name
	update idletasks
	bind ${bind_tag_id}_fulflow_object_list_Tag <<ListboxSelect>> \
		"Apol_Analysis_fulflow::advanced_filters_display_permissions $path_name"
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_initialize_objs_and_perm_filters
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_initialize_objs_and_perm_filters {path_name} {
	variable f_opts
	
	set f_opts($path_name,class_list) $Apol_Class_Perms::class_list
	# Initialization for object classes section
	foreach class $f_opts($path_name,class_list) {
		set rt [catch {set perms_list [apol_GetPermsByClass $class 1]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
		foreach perm $perms_list {
			set f_opts($path_name,perm_status_array,$class,$perm) include
		}
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_initialize_vars
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_initialize_vars {path_name} {
	variable f_opts

	if {$f_opts($path_name,filter_vars_init) == 0} {
		# Initialize all object classes/permissions and related information to default values
		Apol_Analysis_fulflow::advanced_filters_initialize_objs_and_perm_filters $path_name
		
  		# Initialize included/excluded intermediate types section to default values
 		set f_opts($path_name,master_incl_types_list) $Apol_Types::typelist 
 		set idx [lsearch -exact $f_opts($path_name,master_incl_types_list) "self"]
  		if {$idx != -1} {
 			set f_opts($path_name,master_incl_types_list) \
 				 [lreplace $f_opts($path_name,master_incl_types_list) \
 				  $idx $idx]
  		}   
 	        set f_opts($path_name,master_excl_types_list) $f_opts($path_name,filtered_excl_types)
 	        set f_opts($path_name,filtered_incl_types) $f_opts($path_name,master_incl_types_list)
 	        set f_opts($path_name,filtered_excl_types) $f_opts($path_name,master_excl_types_list)
  	        set f_opts($path_name,filter_vars_init) 1
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_set_widgets_to_default_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_set_widgets_to_default_state {path_name} {
	variable f_opts
	
	$f_opts($path_name,combo_incl) configure -values $Apol_Types::attriblist
     	$f_opts($path_name,combo_excl) configure -values $Apol_Types::attriblist
     	$f_opts($path_name,combo_excl) configure -text $f_opts($path_name,excl_attrib_combo_value)
	$f_opts($path_name,combo_incl) configure -text $f_opts($path_name,incl_attrib_combo_value)	
	
	set f_opts($path_name,select_fg_orig) [$f_opts($path_name,class_listbox) cget -foreground]
	
	# Configure the class listbox items to indicate excluded/included object classes.
        set class_lbox_idx 0
        foreach class $f_opts($path_name,class_list) {
        	# Make sure to strip out just the class name, as this may be an excluded class.
		set idx [string first $Apol_Analysis_fulflow::excluded_tag $class]
		if {$idx != -1} {
			set class [string range $class 0 [expr $idx - 1]]
		}	
		set num_excluded 0
		set class_perms [array names f_opts "$path_name,perm_status_array,$class,*"]
		foreach element $class_perms {
			if {[string equal $f_opts($element) "exclude"]} {
				incr num_excluded
			}
		}
		if {$num_excluded == [llength $class_perms]} {
			set [$f_opts($path_name,class_listbox) cget -listvar] \
				[lreplace $f_opts($path_name,class_list) $class_lbox_idx \
				$class_lbox_idx "$class$Apol_Analysis_fulflow::excluded_tag"]
			$f_opts($path_name,class_listbox) itemconfigure $class_lbox_idx \
				-foreground gray
		} else {
			set [$f_opts($path_name,class_listbox) cget -listvar] \
				[lreplace $f_opts($path_name,class_list) $class_lbox_idx \
				$class_lbox_idx "$class"]
			$f_opts($path_name,class_listbox) itemconfigure $class_lbox_idx \
				-foreground $f_opts($path_name,select_fg_orig)
		}
		incr class_lbox_idx
	}

	Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state \
		Apol_Analysis_fulflow::f_opts($path_name,incl_attrib_cb_sel) \
		$f_opts($path_name,combo_incl) \
		$f_opts($path_name,lbox_incl) \
		incl \
		$path_name

	Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state \
		Apol_Analysis_fulflow::f_opts($path_name,excl_attrib_cb_sel) \
		$f_opts($path_name,combo_excl) \
		$f_opts($path_name,lbox_excl) \
		excl \
		$path_name
	
	set val [expr $f_opts($path_name,threshhold_value) - 1]
	$f_opts($path_name,spinbox_threshhold) setvalue @$val
	Apol_Analysis_fulflow::advanced_filters_change_spinbox_state \
		$path_name
	# Select the top most item by default
	$f_opts($path_name,class_listbox) selection set 0
	Apol_Analysis_fulflow::advanced_filters_display_permissions $path_name
}



# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_copy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_copy_object {path_name new_object} {
	variable f_opts
	upvar 1 $new_object object 
	
	if {![array exists f_opts] || [array names f_opts "$path_name,name"] == ""} {
		Apol_Analysis_fulflow::advanced_filters_create_object $path_name
	}
	array set object [array get f_opts "$path_name,*"]
	
	return 0
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_change_spinbox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_change_spinbox_state {path_name} {
	variable f_opts

	if {$f_opts($path_name,threshhold_cb_value)} {
		$f_opts($path_name,spinbox_threshhold) configure -state normal -entrybg white
	} else {
		$f_opts($path_name,spinbox_threshhold) configure -state disabled -entrybg $ApolTop::default_bg_color
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_change_threshhold_value
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_change_threshhold_value {path_name} {
	variable f_opts

	set f_opts($path_name,threshhold_value) \
		[expr [$f_opts($path_name,spinbox_threshhold) getvalue] + 1]
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_fulflow::advanced_filters_create_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_fulflow::advanced_filters_create_dialog {path_name title_txt} {
	variable f_opts 

	if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -1
        } 
       
   	set rt [catch {Apol_Analysis_fulflow::load_default_perm_map} err]
	if {$rt != 0} {		
		return -1
	}
	
	# Check to see if object already exists.
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != ""} {
	    	# Check to see if the dialog already exists.
	    	if {[winfo exists $f_opts($path_name,name)]} {
		    	raise $f_opts($path_name,name)
		    	focus $f_opts($path_name,name)
	    		return 0
	    	} 
	    	# else we need to display the dialog with the correct object settings
    	} else {
	    	# Create a new options dialog object
    		Apol_Analysis_fulflow::advanced_filters_create_object $path_name
    	}	
   	
    	# Create the top-level dialog and subordinate widgets
    	toplevel $f_opts($path_name,name) 
     	wm withdraw $f_opts($path_name,name) 	
    	wm title $f_opts($path_name,name) $title_txt 
	wm protocol $f_opts($path_name,name) WM_DELETE_WINDOW  " "
		    	   	
   	set close_frame [frame $f_opts($path_name,name).close_frame -relief sunken -bd 1]
   	set topf  [frame $f_opts($path_name,name).topf]
        set pw1 [PanedWindow $topf.pw1 -side left -weights available]
        $pw1 add -weight 2 -minsize 225
        $pw1 add -weight 2 -minsize 225
        pack $close_frame -side bottom -anchor center -pady 2
        pack $pw1 -fill both -expand yes	
        pack $topf -fill both -expand yes -padx 10 -pady 10
        
   	# Main Titleframes
   	set objs_frame  [TitleFrame [$pw1 getframe 0].objs_frame -text "Filter by object class permissions:"]
        set types_frame [TitleFrame [$pw1 getframe 1].types_frame -text "Filter by intermediate types:"]
        
        # Widgets for object classes frame
        set pw1   [PanedWindow [$objs_frame getframe].pw -side top -weights available]
        set pane  [$pw1 add]
        set search_pane [$pw1 add]
        set pw2   [PanedWindow $pane.pw -side left -weights available]
        set class_pane 	[$pw2 add]
        set f_opts($path_name,classes_box) [TitleFrame $class_pane.tbox -text "Object Classes:" -bd 0]
        set f_opts($path_name,permissions_title_frame) [TitleFrame $search_pane.rbox \
        	-text "Permissions:" -bd 0]
          
        set sw_class [ScrolledWindow [$f_opts($path_name,classes_box) getframe].sw -auto none]
        set f_opts($path_name,class_listbox) [listbox [$sw_class getframe].lb \
        	-height 10 -highlightthickness 0 \
        	-bg white -selectmode extended \
        	-listvar Apol_Analysis_fulflow::f_opts($path_name,class_list) \
        	-exportselection 0]
        $sw_class setwidget $f_opts($path_name,class_listbox)  
      	     	
	set sw_list [ScrolledWindow [$f_opts($path_name,permissions_title_frame) getframe].sw_c -auto none]
	set f_opts($path_name,perms_box) [text [$f_opts($path_name,permissions_title_frame) getframe].perms_box \
		-cursor $ApolTop::prevCursor \
		-bg white -font $ApolTop::text_font]
	$sw_list setwidget $f_opts($path_name,perms_box)
	
	set threshhold_frame [frame [$f_opts($path_name,permissions_title_frame) getframe].threshhold_frame]
	set f_opts($path_name,spinbox_threshhold) [SpinBox $threshhold_frame.spinbox_threshhold \
		-bg white \
		-range [list 1 10 1] \
  		-editable 0 -entrybg white -width 6 \
  		-helptext "Specify a weight threshhold" \
  		-modifycmd "Apol_Analysis_fulflow::advanced_filters_change_threshhold_value $path_name"]
  	set cbutton_threshhold [checkbutton $threshhold_frame.cbutton_threshhold \
		-text "Exclude permissions that have weights below this threshold:" \
		-variable Apol_Analysis_fulflow::f_opts($path_name,threshhold_cb_value) \
		-offvalue 0 -onvalue 1 \
		-command "Apol_Analysis_fulflow::advanced_filters_change_spinbox_state \
			$path_name"]

	set bframe [frame [$f_opts($path_name,permissions_title_frame) getframe].bframe]
	set b_incl_all_perms [Button $bframe.b_incl_all_perms -text "Include All Perms" \
		-helptext "Select this to include all permissions for the selected object in the query." \
		-command "Apol_Analysis_fulflow::advanced_filters_include_exclude_permissions \
			include $path_name"]
	set b_excl_all_perms [Button $bframe.b_excl_all_perms -text "Exclude All Perms" \
		-helptext "Select this to exclude all permissions for the selected object from the query." \
		-command "Apol_Analysis_fulflow::advanced_filters_include_exclude_permissions \
			exclude $path_name"]
		
	# Bindings
	set bind_tag_id [string trim $path_name "."]
	bindtags $f_opts($path_name,class_listbox) \
		[linsert [bindtags $f_opts($path_name,class_listbox)] 3 \
		${bind_tag_id}_fulflow_object_list_Tag]  
        bind ${bind_tag_id}_fulflow_object_list_Tag \
        	<<ListboxSelect>> "Apol_Analysis_fulflow::advanced_filters_display_permissions $path_name"
        
        pack $cbutton_threshhold $f_opts($path_name,spinbox_threshhold) -side left -anchor nw -padx 2
        pack $threshhold_frame -fill x -anchor nw -side bottom -pady 2
        pack $b_excl_all_perms -side right -anchor nw -pady 2 -expand yes -fill x -ipadx 1
        pack $b_incl_all_perms -side left -anchor nw -pady 2 -expand yes -fill x -ipadx 2
        pack $bframe -side bottom -fill both -anchor sw -pady 2
        pack $f_opts($path_name,permissions_title_frame) -pady 2 -padx 2 -fill both -expand yes
	pack $f_opts($path_name,classes_box) -padx 2 -side left -fill both -expand yes	   
        pack $sw_class -fill both -expand yes -side top
	pack $sw_list -fill both -expand yes -side top
	pack $pw2 -fill both -expand yes
        pack $pw1 -fill both -expand yes
                	
        # Widgets for types frame
        set include_f [TitleFrame [$types_frame getframe].include_f \
        	-text "Include these types:" -bd 0]
        set middle_f  [frame [$types_frame getframe].middle_f]
        set exclude_f [TitleFrame [$types_frame getframe].exclude_f \
        	-text "Exclude these types:" -bd 0]
        set b_incl_f  [frame [$include_f getframe].b_incl_f]
        set b_excl_f  [frame [$exclude_f getframe].b_excl_f]
        set buttons_incl_f [frame $b_incl_f.buttons_incl_f]
        set buttons_excl_f [frame $b_excl_f.buttons_excl_f]
        
        set sw_incl [ScrolledWindow [$include_f getframe].sw_incl]
  	set sw_excl [ScrolledWindow [$exclude_f getframe].sw_excl]	
	set f_opts($path_name,lbox_incl) [listbox [$sw_incl getframe].lbox_incl \
		-height 6 \
		-highlightthickness 0 \
		-listvar Apol_Analysis_fulflow::f_opts($path_name,filtered_incl_types) \
		-selectmode extended -bg white -exportselection 0]
	set f_opts($path_name,lbox_excl) [listbox [$sw_excl getframe].lbox_excl \
		-height 6 \
		-highlightthickness 0 \
		-listvar Apol_Analysis_fulflow::f_opts($path_name,filtered_excl_types) \
		-selectmode extended -bg white -exportselection 0]
	$sw_incl setwidget $f_opts($path_name,lbox_incl)
	$sw_excl setwidget $f_opts($path_name,lbox_excl)
	
	bindtags $f_opts($path_name,lbox_incl) \
		[linsert [bindtags $Apol_Analysis_fulflow::f_opts($path_name,lbox_incl)] 3 \
		${bind_tag_id}_lbox_incl_Tag]
	bindtags $f_opts($path_name,lbox_excl) \
		[linsert [bindtags $Apol_Analysis_fulflow::f_opts($path_name,lbox_excl)] 3 \
		${bind_tag_id}_lbox_excl_Tag]
	
	bind ${bind_tag_id}_lbox_incl_Tag <<ListboxSelect>> "focus -force $f_opts($path_name,lbox_incl)"
	bind ${bind_tag_id}_lbox_excl_Tag <<ListboxSelect>> "focus -force $f_opts($path_name,lbox_excl)"
	
	bind ${bind_tag_id}_lbox_incl_Tag <KeyPress> "ApolTop::tklistbox_select_on_key_callback \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl) \
			Apol_Analysis_fulflow::f_opts($path_name,filtered_incl_types) \
			%K"
	bind ${bind_tag_id}_lbox_excl_Tag <KeyPress> "ApolTop::tklistbox_select_on_key_callback \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl) \
			Apol_Analysis_fulflow::f_opts($path_name,filtered_excl_types) \
			%K"
			
        set include_bttn [Button $middle_f.include_bttn -text "<--" \
		-command "Apol_Analysis_fulflow::advanced_filters_include_types \
			Apol_Analysis_fulflow::f_opts($path_name,filtered_excl_types) \
			Apol_Analysis_fulflow::f_opts($path_name,filtered_incl_types) \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl) \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl) \
			Apol_Analysis_fulflow::f_opts($path_name,master_incl_types_list) \
			Apol_Analysis_fulflow::f_opts($path_name,master_excl_types_list)" \
		-helptext "Include this type in the query" -width 8]
	set exclude_bttn [Button $middle_f.exclude_bttn -text "-->" \
		-command "Apol_Analysis_fulflow::advanced_filters_exclude_types \
			Apol_Analysis_fulflow::f_opts($path_name,filtered_incl_types) \
			Apol_Analysis_fulflow::f_opts($path_name,filtered_excl_types) \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl) \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl) \
			Apol_Analysis_fulflow::f_opts($path_name,master_incl_types_list) \
			Apol_Analysis_fulflow::f_opts($path_name,master_excl_types_list)" \
		-helptext "Exclude this type from the query" -width 8]
	set b_incl_all_sel [Button $buttons_incl_f.b_incl_all_sel -text "Select All" \
		-command "Apol_Analysis_fulflow::select_all_lbox_items \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl)"]
	set b_incl_all_clear [Button $buttons_incl_f.b_incl_all_clear -text "Unselect" \
		-command "Apol_Analysis_fulflow::clear_all_lbox_items \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl)"]
	set b_excl_all_sel [Button $buttons_excl_f.b_excl_all_sel -text "Select All" \
		-command "Apol_Analysis_fulflow::select_all_lbox_items \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl)"]
	set b_excl_all_clear [Button $buttons_excl_f.b_excl_all_clear -text "Unselect" \
		-command "Apol_Analysis_fulflow::clear_all_lbox_items \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl)"]
	
	set f_opts($path_name,combo_incl) [ComboBox $b_incl_f.combo_incl \
		-editable 0 -autopost 1 \
    		-textvariable Apol_Analysis_fulflow::f_opts($path_name,incl_attrib_combo_value) \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd "Apol_Analysis_fulflow::advanced_filters_filter_types_using_attrib \
  				Apol_Analysis_fulflow::f_opts($path_name,incl_attrib_combo_value) \
  				$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl) \
 				Apol_Analysis_fulflow::f_opts($path_name,master_incl_types_list)"] 
  	
  	set f_opts($path_name,combo_excl) [ComboBox [$exclude_f getframe].combo_excl \
		-editable 0 -autopost 1 \
    		-textvariable Apol_Analysis_fulflow::f_opts($path_name,excl_attrib_combo_value) \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd "Apol_Analysis_fulflow::advanced_filters_filter_types_using_attrib \
				Apol_Analysis_fulflow::f_opts($path_name,excl_attrib_combo_value) \
				$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl) \
				Apol_Analysis_fulflow::f_opts($path_name,master_excl_types_list)"] 
				
	set cb_incl_attrib [checkbutton $b_incl_f.cb_incl_attrib \
		-text "Filter included type(s) by attribute:" \
		-variable Apol_Analysis_fulflow::f_opts($path_name,incl_attrib_cb_sel) \
		-offvalue 0 -onvalue 1 \
		-command "Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state \
			Apol_Analysis_fulflow::f_opts($path_name,incl_attrib_cb_sel) \
			$Apol_Analysis_fulflow::f_opts($path_name,combo_incl) \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_incl) \
			incl \
			$path_name"]
	set cb_excl_attrib [checkbutton [$exclude_f getframe].cb_excl_attrib \
		-text "Filter excluded type(s) by attribute:" \
		-variable Apol_Analysis_fulflow::f_opts($path_name,excl_attrib_cb_sel) \
		-offvalue 0 -onvalue 1 \
		-command "Apol_Analysis_fulflow::advanced_filters_configure_adv_combo_state \
			Apol_Analysis_fulflow::f_opts($path_name,excl_attrib_cb_sel) \
			$Apol_Analysis_fulflow::f_opts($path_name,combo_excl) \
			$Apol_Analysis_fulflow::f_opts($path_name,lbox_excl) \
			excl \
			$path_name"]
								    
	# Create and pack close button for the dialog
  	set close_bttn [Button $close_frame.close_bttn -text "Close" -width 8 \
		-command "Apol_Analysis_fulflow::advanced_filters_destroy_dialog $path_name"]
	pack $close_bttn -side left -anchor center
					  	
	# pack all subframes and widgets for the types frame
	pack $b_excl_f -side bottom -anchor center -pady 2 
	pack $b_incl_f -side bottom -anchor center -pady 2 
	pack $buttons_excl_f -side bottom -anchor center -pady 2
	pack $buttons_incl_f -side bottom -anchor center -pady 2
	pack $b_excl_all_sel $b_excl_all_clear -side left -anchor center -expand yes -pady 2
	pack $sw_excl -side top -anchor nw -fill both -expand yes -pady 2 -padx 6
	pack $cb_excl_attrib -side top -anchor center -padx 6
	pack $f_opts($path_name,combo_excl) -side top -anchor center -pady 2 -padx 15 

	pack $b_incl_all_sel $b_incl_all_clear -side left -anchor center -expand yes -pady 2
	pack $sw_incl -side top -anchor nw -fill both -expand yes -pady 2 -padx 6
	pack $cb_incl_attrib -side top -anchor center -padx 6
	pack $f_opts($path_name,combo_incl) -side top -anchor center -pady 2 -padx 15 
	
	pack $include_bttn $exclude_bttn -side top -pady 2 -anchor center
	pack $include_f $exclude_f -side left -anchor nw -fill both -expand yes
	pack $middle_f -side left -anchor center -after $include_f -padx 5 -expand yes
	pack $types_frame $objs_frame -side top -anchor nw -padx 5 -pady 2 -expand yes -fill both
	
        # Configure top-level dialog specifications
        set width 780
	set height 750
	wm geom $f_opts($path_name,name) ${width}x${height}
	wm deiconify $f_opts($path_name,name)
	focus $f_opts($path_name,name)
	
	Apol_Analysis_fulflow::advanced_filters_set_widgets_to_default_state $path_name
	wm protocol $f_opts($path_name,name) WM_DELETE_WINDOW \
		"Apol_Analysis_fulflow::advanced_filters_destroy_dialog $path_name"
    	
	return 0
}
