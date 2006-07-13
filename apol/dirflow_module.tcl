#############################################################
#  dirflow_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com, mayerf@tresys.com, kcarr@tresys>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Information
# Flow analysis.

namespace eval Apol_Analysis_dirflow {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_dirflow" "Direct Information Flow"
}

proc Apol_Analysis_dirflow::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
    set vals(classes:selected) $Apol_Class_Perms::class_list
    Apol_Widget::setScrolledListboxState $widgets(classes) normal
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    $classes_lb selection set 0 end
    toggleClasses {} {} {}
}

proc Apol_Analysis_dirflow::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_dirflow::getInfo {} {
    return "This analysis generates the results of a Direct Information Flow
analysis beginning from the starting type selected.  The results of
the analysis are presented in tree form with the root of the tree
being the start point for the analysis.

\nEach child node in the tree represents a type in the current policy
for which there is a direct information flow to or from its parent
node.  If 'in' was selected then the information flow is from the
child to the parent.  If 'out' was selected then information flows
from the parent to the child.

\nThe results of the analysis may be optionally filtered by object class
selection or an end type regular expression.

\nNOTE: For any given generation, if the parent and the child are the
same, you cannot open the child.  This avoids cyclic analyses.

\nFor additional help on this topic select \"Information Flow Analysis\"
from the help menu."
}

proc Apol_Analysis_dirflow::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set dir_tf [TitleFrame $options_frame.mode -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set dir_in [radiobutton [$dir_tf getframe].in -text In -value in \
                    -variable Apol_Analysis_dirflow::vals(dir)]
    set dir_out [radiobutton [$dir_tf getframe].out -text Out -value out \
                     -variable Apol_Analysis_dirflow::vals(dir)]
    set dir_either [radiobutton [$dir_tf getframe].either -text Either -value either \
                        -variable Apol_Analysis_dirflow::vals(dir)]
    set dir_both [radiobutton [$dir_tf getframe].both -text Both -value both \
                         -variable Apol_Analysis_dirflow::vals(dir)]
    pack $dir_in $dir_out $dir_either $dir_both -anchor w

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -text "Starting type"]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set class_f [frame [$filter_tf getframe].class]
    pack $class_f -side left -anchor nw
    set class_enable [checkbutton $class_f.enable -text "Filter by object class" \
                          -variable Apol_Analysis_dirflow::vals(classes:enable)]
    pack $class_enable -anchor w
    set widgets(classes) [Apol_Widget::makeScrolledListbox $class_f.classes \
                              -height 6 -width 24 \
                              -listvar Apol_Class_Perms::class_list \
                              -selectmode extended -exportselection 0]
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    bind $classes_lb <<ListboxSelect>> \
        [list Apol_Analysis_dirflow::selectClassesListbox $classes_lb]
    pack $widgets(classes) -padx 4 -expand 0 -fill both
    trace add variable Apol_Analysis_dirflow::vals(classes:enable) write \
        Apol_Analysis_dirflow::toggleClasses
    Apol_Widget::setScrolledListboxState $widgets(classes) disabled
    set classes_bb [ButtonBox $class_f.bb -homogeneous 1 -spacing 4]
    $classes_bb add -text "Include All" \
        -command [list Apol_Analysis_dirflow::includeAll $classes_lb]
    $classes_bb add -text "Exclude All"  \
        -command [list Apol_Analysis_dirflow::excludeAll $classes_lb]
    pack $classes_bb -pady 4
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter end types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_dirflow::newAnalysis {} {
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

proc Apol_Analysis_dirflow::updateAnalysis {f} {
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

proc Apol_Analysis_dirflow::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_dirflow::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    reinitializeWidgets
}

proc Apol_Analysis_dirflow::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        puts $channel "$key $value"
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(type)]
    puts $channel "type [lindex $type 0]"
    puts $channel "type:attrib [lindex $type 1]"
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    puts $channel "regexp:enable $use_regexp"
    puts $channel "regexp $regexp"
}

proc Apol_Analysis_dirflow::loadQuery {channel} {
    variable vals

    set classes {}
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        set key {}
        set value {}
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        switch -- $key {
            classes:selected {
                set classes_exc $value
            }
            default {
                set vals($key) $value
            }
        }
    }

    # fill in only classes found within the current policy
    open

    set vals(classes:selected) {}
    foreach c $classes {
        set i [lsearch $Apol_Class_Perms::class_list $c]
        if {$i >= 0} {
            lappend vals(classes:selected) $c
        }
    }
    set vals(classes:selected) [lsort $vals(classes:selected)]
    reinitializeWidgets
}

proc Apol_Analysis_dirflow::gotoLine {tab line_num} {
}

proc Apol_Analysis_dirflow::search {tab str case_Insensitive regExpr srch_Direction } {
}

#################### private functions below ####################

proc Apol_Analysis_dirflow::reinitializeVals {} {
    variable vals
    array set vals {
        dir in
        type {}  type:attrib {}

        classes:enable 0
        classes:selected {}

        regexp:enable 0
        regexp {}
    }
}

proc Apol_Analysis_dirflow::reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)

    Apol_Widget::setScrolledListboxState $widgets(classes) enabled
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    $classes_lb selection clear 0 end
    foreach c $vals(classes:selected) {
        set i [lsearch $vals(classes:list) $c]
        $classes_lb selection set $i $i
    }
    toggleClasses {} {} {}
}

proc Apol_Analysis_dirflow::toggleClasses {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(classes:enable)} {
        Apol_Widget::setScrolledListboxState $widgets(classes) enabled
    } else {
        Apol_Widget::setScrolledListboxState $widgets(classes) disabled
    }
}

proc Apol_Analysis_dirflow::selectClassesListbox {lb} {
    variable vals
    for {set i 0} {$i < [$lb index end]} {incr i} {
        set t [$lb get $i]
        if {[$lb selection includes $i]} {
            lappend vals(classes:selected) $t
        } else {
            if {[set j [lsearch $vals(classes:selected) $t]] >= 0} {
                set vals(classes:selected) [lreplace $vals(classes:selected) $j $j]
            }
        }
    }
    set vals(classes:selected) [lsort -uniq $vals(classes:selected)]
    focus $lb
}

proc Apol_Analysis_dirflow::includeAll {lb} {
    variable vals
    $lb selection set 0 end
    set vals(classes:selected) $Apol_Class_Perms::class_list
}

proc Apol_Analysis_dirflow::excludeAll {lb} {
    variable vals
    $lb selection clear 0 end
    set vals(classes:selected) {}
}

#################### functions that do analyses ####################

proc Apol_Analysis_dirflow::checkParams {} {
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
    if {$vals(classes:enable) && $vals(classes:selected)} {
        return "At least one object class must be included."
    }

    # if a permap is not loaded then load the default permap
    if {![Apol_Perms_Map::is_pmap_loaded]} {
        if {![Apol_Perms_Map::loadDefaultPermMap]} {
            return "This analysis requires that a permission map is loaded."
	}
    }

    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_dirflow::analyze {} {
    variable vals
    if {$vals(classes:enable)} {
        set classes $vals(classes:selected)
    } else {
        set classes {}
    }
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }
    apol_DirectInformationFlowAnalysis $vals(dir) $vals(type) $classes $regexp
}

################# functions that control analysis output #################

proc Apol_Analysis_dirflow::createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Direct Flow" [array get vals]]

    set tree_tf [TitleFrame $f.left -text "Direct Information Flow Tree"]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto both]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg white]
    $sw setwidget $tree
    pack $sw -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Direct Information Flow Results"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure num -font {Helvetica 12 bold}
    $res.tb tag configure type_tag -foreground blue -font {Helvetica 12 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_dirflow::treeSelect $res]
    return $f
}

proc Apol_Analysis_dirflow::treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "x"} {
            renderResultsRuleObject $res $tree $node $data
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end $data
        }
        $res.tb configure -state disabled
    }
}

if {0} {

    This tab provides the results of a Direct Information Flow analysis beginning 
    from the starting type selected above.  The results of the analysis are presented
    in tree form with the root of the tree (this node) being the start point for the 
    analysis.

    Each child node in the tree represents a type in the current policy
    for which there is a direct information flow to or from (depending on your selection
                                                             above) its parent node.

    NOTE: For any given generation, if the parent and the child 
    are the same, you cannot open the child.  This avoids cyclic analyses.
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
				return -code error "Error parsing results. See stdout for more information."
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
				#	1. rule string (includes line number)
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
				#	1. rule string (includes line number)
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
