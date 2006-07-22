#############################################################
#  transflow_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com, mayerf@tresys.com, kcarr@tresys>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Transitive
# Information Flow analysis.

namespace eval Apol_Analysis_transflow {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_transflow" "Transitive Information Flow"
}

proc Apol_Analysis_transflow::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
}

proc Apol_Analysis_transflow::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_transflow::getInfo {} {
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

proc Apol_Analysis_transflow::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set dir_tf [TitleFrame $options_frame.dir -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set dir_to [radiobutton [$dir_tf getframe].to -text "To" \
                    -variable Apol_Analysis_transflow::vals(dir) -value to]
    set dir_from [radiobutton [$dir_tf getframe].from -text "From" \
                      -variable Apol_Analysis_transflow::vals(dir) -value from]
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
                                      -variable Apol_Analysis_transflow::vals(advanced:enable)]
    pack $widgets(advanced_enable) -anchor w
    set widgets(advanced) [button $advanced_f.b -text "Advanced Filters" \
                               -command Apol_Analysis_transflow::createAdvancedDialog \
                               -state disabled]
    pack $widgets(advanced) -anchor w -padx 4
    trace add variable Apol_Analysis_transflow::vals(advanced:enable) write \
        Apol_Analysis_transflow::toggleAdvancedSelected
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter end types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_transflow::newAnalysis {} {
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

proc Apol_Analysis_transflow::updateAnalysis {f} {
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

proc Apol_Analysis_transflow::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_transflow::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    reinitializeWidgets
}

proc Apol_Analysis_transflow::saveQuery {channel} {
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

proc Apol_Analysis_transflow::loadQuery {channel} {
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

    # fill in only classes found within the current policy
    open

    reinitializeWidgets
}

proc Apol_Analysis_transflow::gotoLine {tab line_num} {
}

proc Apol_Analysis_transflow::search {tab str case_Insensitive regExpr srch_Direction } {
}

#################### private functions below ####################

proc Apol_Analysis_transflow::reinitializeVals {} {
    variable vals

    array set vals {
        dir to

        type {}  type:attrib {}

        regexp:enable 0
        regexp {}

        access:enable 0
    }
}

proc Apol_Analysis_transflow::reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_transflow::toggleAdvancedSelected {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(advanced:enable)} {
        $widgets(advanced) configure -state normal
    } else {
        $widgets(advanced) configure -state disabled
    }
}

#################### functions that do analyses ####################

proc Apol_Analysis_transflow::checkParams {} {
    variable vals
    variable widgets
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened!"
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(type)]
    if {[lindex $type 0] == {}} {
        return "No type was selected."
    }
    set vals(type) [lindex $type 0]
    set vals(type:attrib) [lindex $type 1]
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    if {$use_regexp && $regexp == {}} {
            return "No regular expression provided."
    }
    set vals(regexp:enable) $use_regexp
    set vals(regexp) $regexp

    # if a permap is not loaded then load the default permap
    if {![Apol_Perms_Map::is_pmap_loaded]} {
        if {![Apol_Perms_Map::loadDefaultPermMap]} {
            return "This analysis requires that a permission map is loaded."
	}
    }

    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_transflow::analyze {} {
    variable vals
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }
    apol_TransInformationFlowAnalysis $vals(dir) $vals(type) $regexp
}

proc Apol_Analysis_transflow::analyzeMore {tree node} {
    # disallow more analysis if this node is the same as its parent
    set new_start [$tree itemcget $node -text]
    if {[$tree itemcget [$tree parent $node] -text] == $new_start} {
        return {}
    }
    set g [lindex [$tree itemcget top -data] 0]
    apol_TransInformationFlowMore $g $new_start
}

################# functions that control analysis output #################

proc Apol_Analysis_transflow::createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Trans Flow" [array get vals]]

    set tree_tf [TitleFrame $f.left -text "Transitive Information Flow Tree"]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto both]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg white]
    $sw setwidget $tree
    pack $sw -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Transitive Information Flow Results"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure subtitle -font {Helvetica 10 bold}
    $res.tb tag configure num -foreground blue -font {Helvetica 10 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_transflow::treeSelect $res]
    $tree configure -opencmd [list Apol_Analysis_transflow::treeOpen $tree]
    bind $tree <Destroy> [list Apol_Analysis_transflow::treeDestroy $tree]
    return $f
}

proc Apol_Analysis_transflow::treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "x"} {
            renderResultsTransFlow $res $tree $node [lindex $data 1]
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end [lindex $data 1]
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_transflow::treeOpen {tree node} {
    puts "FIX ME!"
    if {0} {
    foreach {is_expanded results} [$tree itemcget $node -data] {break}
    if {[string index $node 0] == "x" && !$is_expanded} {
        ApolTop::setBusyCursor
        update idletasks
        set retval [catch {analyzeMore $tree $node} new_results]
        ApolTop::resetBusyCursor
        if {$retval} {
            tk_messageBox -icon error -type ok -title "Direct Information Flow" -message "Could not perform additional analysis:\n\n$new_results"
        } else {
            # mark this node as having been expanded
            $tree itemconfigure $node -data [list 1 $results]
            createResultsNodes $tree $node $new_results
        }
    }
    }
}

proc Apol_Analysis_transflow::treeDestroy {tree} {
    set graph_handler [lindex [$tree itemcget top -data] 0]
    apol_InformationFlowDestroy $graph_handler
}

proc Apol_Analysis_transflow::clearResultsDisplay {f} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    set graph_handler [lindex [$tree itemcget top -data] 0]
    apol_InformationFlowDestroy $graph_handler
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}


proc Apol_Analysis_transflow::renderResults {f results} {
    variable vals

    set graph_handler [lindex $results 0]
    set results_list [lrange $results 1 end]

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    set top_text [renderTopText]
    $tree itemconfigure top -data [list $graph_handler $top_text]

    createResultsNodes $tree top $results_list
    $tree selection set top
    $tree opentree top 0
    update idletasks
    $tree see top
}

proc Apol_Analysis_transflow::renderTopText {} {
    variable vals

    set top_text [list "Transitive Information Flow Analysis: Starting type: " title]
    lappend top_text $vals(type) title_type \
        "\n\n" title \
        "This tab provides the results of a Transitive Information Flow
analysis beginning from the starting type selected above.  The results
of the analysis are presented in tree form with the root of the tree
(this node) being the start point for the analysis.

\nEach child node in the tree represents a type in the current policy
for which there is a transitive information flow to or from (depending
on your selection above) its parent node.

\nNOTE: For any given generation, if the parent and the child are the
same, you cannot open the child.  This avoids cyclic analyses." {}
}

proc Apol_Analysis_transflow::createResultsNodes {tree parent_node results} {
    set all_targets {}
    puts "fix me!"
}


# Procedure to do elapsed time formatting
proc Apol_Analysis_transflow::convert_seconds {sec} {
	set hours [expr {$sec / 3600}]
	set minutes [expr {$sec / 60 - $hours * 60}]
	set seconds [expr {$sec - $minutes * 60 - $hours * 3600}]
	return [format "%02s:%02s:%02s" $hours $minutes $seconds]
}


###########################################################################
# ::display_find_more_flows_Dlg
#
proc Apol_Analysis_transflow::display_find_more_flows_Dlg {} {
	variable find_flows_Dlg
	variable transflow_tree
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

	set src_node [$transflow_tree parent [$transflow_tree selection get]]
	set tgt_node [$transflow_tree selection get]
	set Apol_Analysis_transflow::abort_trans_analysis 0

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

        set src_lbl [label $nodes_f.src_lbl -text "Source: [$transflow_tree itemcget $src_node -text]"]
        set tgt_lbl [label $nodes_f.tgt_lbl -text "Target: [$transflow_tree itemcget $tgt_node -text]"]

        # Create time limit widgets
        set time_lbl [label $time_f.time_lbl -text "Time Limit:"]
        set hrs_lbl  [label $time_f.hrs_lbl -text "Hour(s)"]
        set min_lbl  [label $time_f.min_lbl -text "Minute(s)"]
        set sec_lbl  [label $time_f.sec_lbl -text "Second(s)"]
        set time_entry_hour [Entry $time_f.time_entry_hour -editable 1 -width 5 \
	-textvariable Apol_Analysis_transflow::time_limit_hr -bg white]
        set time_entry_min [Entry $time_f.time_entry_min -editable 1 -width 5 \
	-textvariable Apol_Analysis_transflow::time_limit_min -bg white]
        set time_entry_sec [Entry $time_f.time_entry_sec -editable 1 -width 5 \
	-textvariable Apol_Analysis_transflow::time_limit_sec -bg white]

	# Create path limit widgets
	set path_limit_lbl [label $path_limit_f.path_limit_lbl -text "Limit by these number of flows:"]
        set path_limit_entry [Entry $path_limit_f.path_limit_entry -editable 1 -width 5 \
	-textvariable Apol_Analysis_transflow::flow_limit_num -bg white]

	# Create button widgets
	set b_find [button $button_f.b_find -text "Find" -width 6 \
		-command "Apol_Analysis_transflow::find_more_flows $src_node $tgt_node"]
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
proc Apol_Analysis_transflow::display_find_flows_results_Dlg {time_limit_str flow_limit_num} {
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
		-command "set Apol_Analysis_transflow::abort_trans_analysis 1"]

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
# ::find_more_flows
#
proc Apol_Analysis_transflow::find_more_flows {src_node tgt_node} {
	variable transflow_tree
	variable time_limit_hr
	variable time_limit_min
	variable time_limit_sec
	variable flow_limit_num
	variable progressBar
        variable transflow_info_text
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
        Apol_Analysis_transflow::display_find_flows_results_Dlg $time_limit_str $flow_limit_num
	set Apol_Analysis_transflow::abort_trans_analysis 0
        set src_data [$transflow_tree itemcget [$transflow_tree nodes root] -data]
	set src [$transflow_tree itemcget $src_node -text]
	wm protocol $find_flows_results_Dlg WM_DELETE_WINDOW "raise $find_flows_results_Dlg; focus $find_flows_results_Dlg"

	set start_time [clock seconds]
	set curr_flows_num 0
	set find_flows_start 1

	# Current time - start time = elapsed time
	$time_exp_lbl configure -text [Apol_Analysis_transflow::convert_seconds [expr [clock seconds] - $start_time]]
	#Apol_Analysis_transflow::find_more_flows_generate_virtual_events
	$num_found_lbl configure -text $curr_flows_num
	update

	# The last query arguments were stored in the data for the root node
	set rt [catch {apol_TransitiveFindPathsStart \
		$src \
		[lindex $src_data 1] \
		[lindex $src_data 2] \
		[lindex $src_data 3] \
		1 \
		"^[$transflow_tree itemcget $tgt_node -text]$" \
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
		set elapsed_time [Apol_Analysis_transflow::convert_seconds [expr [clock seconds] - $start_time]]
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
		if {$Apol_Analysis_transflow::abort_trans_analysis} {
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
		set nextIdx [Apol_Analysis_transflow::parseList_get_index_next_node 1 $results]
		set data [lrange $results 1 [expr $nextIdx-1]]
		$transflow_tree itemconfigure $tgt_node -data $data
		Apol_Analysis_transflow::insert_more_flows_header $transflow_info_text $transflow_tree \
			$src_node $tgt_node \
			$time_limit_str $elapsed_time \
			$flow_limit_num $curr_flows_num
		Apol_Analysis_transflow::render_information_flows $transflow_info_text $transflow_tree $tgt_node
		Apol_Analysis_transflow::formatInfoText $transflow_info_text
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
# ::insert_more_flows_header
#	- Called to insert the header text when displaying results from
#	  a find more flows search.
proc Apol_Analysis_transflow::insert_more_flows_header {transflow_info_text transflow_tree src_node tgt_node time_limit_str elapsed_time flow_limit_num curr_flows_num} {
	$transflow_info_text configure -state normal
	$transflow_info_text delete 0.0 end
	$transflow_info_text mark set insert 1.0
        $transflow_info_text configure -wrap none

	set data [$transflow_tree itemcget $tgt_node -data]
	if {$data == ""} {
	        $transflow_info_text configure -state disabled
		return ""
	}
	# The flow direction is embedded in the data store of the root node at index 1.
        set query_args [$transflow_tree itemcget [$transflow_tree nodes root] -data]
        set flow_direction [lindex $query_args 1]
	if {$flow_direction == "in"} {
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end "More Information Flows to "
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end " [$transflow_tree itemcget $src_node -text]"
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end " from "
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end "[$transflow_tree itemcget $tgt_node -text]"
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
	} elseif {$flow_direction == "out"} {
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end "More Information Flows from "
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end "[$transflow_tree itemcget $src_node -text]"
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end " to "
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
		set startIdx [$transflow_info_text index insert]
		$transflow_info_text insert end "[$transflow_tree itemcget $tgt_node -text]"
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
	} else {
		puts "Invalid flow direction ($flow_direction) specified!"
		return
	}
	# Insert find more flows link
	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "  ("
	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "Find more flows"
	set endIdx [$transflow_info_text index insert]
	$transflow_info_text tag add $Apol_Analysis_transflow::find_flows_tag $startIdx $endIdx
	$transflow_info_text insert end ")"

	# Insert time/flows limit strings
	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "\n\nTime: $elapsed_time out of $time_limit_str"
	set endIdx [$transflow_info_text index insert]
	$transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx

	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "\n\nApol found the following number of information flows: "
	set endIdx [$transflow_info_text index insert]
	$transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
        set startIdx $endIdx
        $transflow_info_text insert end  "$curr_flows_num"
        set endIdx [$transflow_info_text index insert]
        $transflow_info_text tag add $Apol_Analysis_transflow::counters_tag $startIdx $endIdx
        set startIdx $endIdx
        $transflow_info_text insert end " out of "
        set endIdx [$transflow_info_text index insert]
        $transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
        set startIdx $endIdx
        $transflow_info_text insert end "$flow_limit_num"
        set endIdx [$transflow_info_text index insert]
        $transflow_info_text tag add $Apol_Analysis_transflow::counters_tag $startIdx $endIdx
        $transflow_info_text configure -state disabled

	return 0
}

###########################################################################
# ::insert_transitive_flows_header
#	- Called to insert the header text when displaying results from
#	  a transitive flows search.
proc Apol_Analysis_transflow::insert_transitive_flows_header {transflow_info_text transflow_tree node} {
	$transflow_info_text configure -state normal
	$transflow_info_text delete 0.0 end
	$transflow_info_text mark set insert 1.0
        $transflow_info_text configure -wrap none

	set data [$transflow_tree itemcget $node -data]
	if {$data == ""} {
	        $transflow_info_text configure -state disabled
		return
	}

	set start_type [$transflow_tree itemcget [$transflow_tree parent $node] -text]
        set startIdx [$transflow_info_text index insert]
        # Index 0 will be the end type
        set currentIdx 0
        set end_type [lindex $data $currentIdx]
        # The flow direction is embedded in the data store of the root node at index 1.
        set query_args [$transflow_tree itemcget [$transflow_tree nodes root] -data]
        set flow_direction [lindex $query_args 1]

	if {$flow_direction == "in"} {
	    $transflow_info_text insert end "Information flows to "
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end $start_type
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end " from "
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end $end_type
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
	    set startIdx $endIdx
	} elseif {$flow_direction == "out"} {
	    $transflow_info_text insert end "Information flows from "
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end $start_type
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end " to "
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_tag $startIdx $endIdx
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end $end_type
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::title_type_tag $startIdx $endIdx
	    set startIdx $endIdx
	} else {
		puts "Invalid flow direction ($flow_direction) specified!"
		return
	}
	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "  ("
	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "Find more flows"
	set endIdx [$transflow_info_text index insert]
	$transflow_info_text tag add $Apol_Analysis_transflow::find_flows_tag $startIdx $endIdx
	$transflow_info_text insert end ")"

	# Index 1 will be the number of paths
        set currentIdx 1
	set startIdx [$transflow_info_text index insert]
	$transflow_info_text insert end "\n\nApol found the following number of information flows: "
	set endIdx [$transflow_info_text index insert]
	$transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
        set startIdx $endIdx
	set num_paths [lindex $data $currentIdx]
	$transflow_info_text insert end $num_paths
        set endIdx [$transflow_info_text index insert]
        $transflow_info_text tag add $Apol_Analysis_transflow::counters_tag $startIdx $endIdx

	$transflow_info_text configure -state disabled
	return 0
}

###########################################################################
# ::render_information_flows
#	- This proc will insert any information flows found into the textbox.
#	- NOTE: This procedure should be called after the header has been
#	  inserted using one of the two procs above. If these header procs
#	  are not called, the caller needs to  first delete and configure
#	  the textbox.
proc Apol_Analysis_transflow::render_information_flows {transflow_info_text transflow_tree node} {
	$transflow_info_text configure -state normal

	set data [$transflow_tree itemcget $node -data]
	if {$data == ""} {
	        $transflow_info_text configure -state disabled
		return
	}

	# Index 1 will be the number of paths
        set currentIdx 1
        set num_paths [lindex $data $currentIdx]
	for {set i 0} {$i<$num_paths} {incr i} {
	    set startIdx [$transflow_info_text index insert]
	    $transflow_info_text insert end "\n\nFlow"
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $transflow_info_text insert end " [expr $i+1] "
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::counters_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $transflow_info_text insert end "requires "
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
	    set startIdx $endIdx
	    # Increment to the number of flows
	    incr currentIdx
	    set num_flows [lindex $data $currentIdx]
	    $transflow_info_text insert end $num_flows
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::counters_tag $startIdx $endIdx
	    set startIdx $endIdx
	    $transflow_info_text insert end " step(s)."
	    set endIdx [$transflow_info_text index insert]
	    $transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
	    for {set j 0} {$j<$num_flows} {incr j} {
		# First print the flow number
		$transflow_info_text insert end "\n\n\tStep "
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
		set startIdx $endIdx
		$transflow_info_text insert end [expr $j + 1]
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::counters_tag $startIdx $endIdx
		set startIdx $endIdx
		$transflow_info_text insert end ": "
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
		set startIdx $endIdx
		$transflow_info_text insert end "from "
		# increment to the start type for the flow
		incr currentIdx
		$transflow_info_text insert end [lindex $data $currentIdx]
		$transflow_info_text insert end " to "
		# Increment to the end type for the flow
		incr currentIdx
		$transflow_info_text insert end [lindex $data $currentIdx]
		set endIdx [$transflow_info_text index insert]
		$transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
		set startIdx $endIdx
		# Increment to the # of object classes
		incr currentIdx
		set num_classes [lindex $data $currentIdx]
		for {set k 0} {$k<$num_classes} {incr k} {
		    # Increment to the first object class
		    incr currentIdx
		    $transflow_info_text insert end "\n\t[lindex $data $currentIdx]"
		    set endIdx [$transflow_info_text index insert]
		    $transflow_info_text tag add $Apol_Analysis_transflow::subtitle_tag $startIdx $endIdx
		    set startIdx $endIdx
		    # Increment to the # of object class rules
		    incr currentIdx
		    set num_rules [lindex $data $currentIdx]
		    for {set l 0} {$l<$num_rules} {incr l} {
			# Increment to the next rule for the object
			incr currentIdx
			set rule [lindex $data $currentIdx]
			$transflow_info_text insert end "\n\t"
			set startIdx [$transflow_info_text index insert]
			# Get the line number only
			set end_link_idx [string first "\]" [string trim $rule] 0]
			set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
			set lineno [string trim $lineno]
			set rule [string range $rule [expr $end_link_idx + 1] end]

			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$transflow_info_text insert end "\[$lineno\]"
				Apol_PolicyConf::insertHyperLink $transflow_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
			}
			set startIdx [$transflow_info_text index insert]
			$transflow_info_text insert end " $rule"
			set endIdx [$transflow_info_text index insert]
			$transflow_info_text tag add $Apol_Analysis_transflow::rules_tag $startIdx $endIdx

			incr currentIdx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $currentIdx] == 0} {
				$transflow_info_text insert end "   "
				set startIdx [$transflow_info_text index insert]
				$transflow_info_text insert end "\[Disabled\]"
				set endIdx [$transflow_info_text index insert]
				$transflow_info_text tag add $Apol_Analysis_transflow::disabled_rule_tag $startIdx $endIdx
			}
			set startIdx [$transflow_info_text index insert]
		    }
		}
	    }
	}
	$transflow_info_text see 1.0
	$transflow_info_text configure -state disabled

	return 0
}
