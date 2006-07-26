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
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
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
        if {![string match "find_more:*" $key]} {
            puts $channel "$key $value"
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

        find_more:hours 0   find_more:minutes 0   find_more:seconds 30
        find_more:limit 20
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
    $res.tb tag configure find_more -underline 1
    $res.tb tag configure subtitle -font {Helvetica 10 bold}
    $res.tb tag configure num -foreground blue -font {Helvetica 10 bold}
    $res.tb tag bind find_more <Button-1> [list Apol_Analysis_transflow::findMore $res $tree]
    $res.tb tag bind find_more <Enter> [list $res.tb configure -cursor hand2]
    $res.tb tag bind find_more <Leave> [list $res.tb configure -cursor {}]
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
    foreach {is_expanded results} [$tree itemcget $node -data] {break}
    if {[string index $node 0] == "x" && !$is_expanded} {
        ApolTop::setBusyCursor
        update idletasks
        set retval [catch {analyzeMore $tree $node} new_results]
        ApolTop::resetBusyCursor
        if {$retval} {
            tk_messageBox -icon error -type ok -title "Transitive Information Flow" -message "Could not perform additional analysis:\n\n$new_results"
        } else {
            # mark this node as having been expanded
            $tree itemconfigure $node -data [list 1 $results]
            createResultsNodes $tree $node $new_results
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
    variable vals
    set all_targets {}
    foreach r $results {
        foreach {flow_dir source target length steps} $r {break}
        foreach t [apol_ExpandType $target] {
            lappend all_targets $t
            lappend paths($t) [list $length $steps]
        }
    }
    set i 0
    foreach t [lsort -uniq $all_targets] {
        set flow_dir $vals(dir)
        set sorted_paths {}
        foreach path [lsort -uniq [lsort -index 0 -integer $paths($t)]] {
            if {$flow_dir == "to"} {
                # flip the steps around
                set p {}
                foreach step [lindex $path 1] {
                    set p [concat [list $step] $p]
                }
                lappend sorted_paths $p
            } else {
                lappend sorted_paths [lindex $path 1]
            }
        }
        set data [list $flow_dir $sorted_paths]
        $tree insert end $parent_node x\#auto -text $t -drawcross allways \
            -data [list 0 $data]
    }
}

proc Apol_Analysis_transflow::renderResultsTransFlow {res tree node data} {
    set parent_name [$tree itemcget [$tree parent $node] -text]
    set name [$tree itemcget $node -text]
    foreach {flow_dir paths} $data {break}
    switch -- $flow_dir {
        to {
            $res.tb insert end "Information flows to " title \
                $parent_name title_type \
                " from " title \
                $name title_type
        }
        from {
            $res.tb insert end "Information flows from " title \
                $parent_name title_type \
                " to " title \
                $name title_type
        }
    }
    $res.tb insert end "  (" title \
        "Find more flows" {title_type find_more} \
        ")\n\n" title \
        "Apol found the following number of information flows: " subtitle \
        [llength $paths] num \
        "\n" subtitle
    set path_num 1
    foreach path $paths {
        $res.tb insert end "\n" {}
        renderPath $res $path_num $path
        incr path_num
    }
}

proc Apol_Analysis_transflow::renderPath {res path_num path} {
    $res.tb insert end "Flow " subtitle \
        $path_num num \
        " requires " subtitle \
        [llength $path] num \
        " steps(s).\n" subtitle \
        "    " {}
    $res.tb insert end [lindex $path 0 0] subtitle \
        " -> " {} \
        [lindex $path 0 1] subtitle
    foreach step [lrange $path 1 end] {
        $res.tb insert end " -> " {} \
            [lindex $step 1] subtitle
    }
    $res.tb insert end \n {}
    foreach steps $path {
        Apol_Widget::appendSearchResultAVRule $res 6 [lindex $steps 3 0]
        foreach step [lrange [lindex $steps 3] 1 end] {
            Apol_Widget::appendSearchResultAVRule $res 10 $step
        }
    }
}

#################### procedures to find further flows ####################

proc Apol_Analysis_transflow::findMore {res tree} {
    set node [$tree selection get]
    set start [$tree itemcget [$tree parent $node] -text]
    set end [$tree itemcget $node -text]

    set d [Dialog .trans_more -cancel 1 -default 0 -modal local -parent . \
               -separator 1 -title "Find More Flows"]
    $d add -text Find -command [list Apol_Analysis_transflow::verifyFindMore $d]
    $d add -text Cancel

    set f [$d getframe]
    set l1 [label $f.l1 -text "Source: $start"]
    set l2 [label $f.l2 -text "Target: $end"]
    set time_f [frame $f.time]
    set path_f [frame $f.path]
    pack $l1 $l2 $time_f $path_f -anchor w -padx 8 -pady 4

    set t1 [label $time_f.t1 -text "Time limit: "]
    set e1 [entry $time_f.e1 -textvariable Apol_Analysis_transflow::vals(find_more:hours) -width 5 -justify right -bg white]
    set t2 [label $time_f.t2 -text "Hour(s)  "]
    set e2 [entry $time_f.e2 -textvariable Apol_Analysis_transflow::vals(find_more:minutes) -width 5 -justify right -bg white]
    set t3 [label $time_f.t3 -text "Minute(s)  "]
    set e3 [entry $time_f.e3 -textvariable Apol_Analysis_transflow::vals(find_more:seconds) -width 5 -justify right -bg white]
    set t4 [label $time_f.t4 -text "Second(s)  "]
    pack $t1 $e1 $t2 $e2 $t3 $e3 $t4 -side left

    set t1 [label $path_f.t1 -text "Limit by these number of flows: "]
    set e1 [entry $path_f.e1 -textvariable Apol_Analysis_transflow::vals(find_more:limit) -width 5 -justify right -bg white]
    pack $t1 $e1 -side left

    set retval [$d draw]
    destroy .trans_more
    if {$retval == 0} {
        set graph_handler [lindex [$tree itemcget top -data] 0]
        if {[catch {apol_TransInformationFurtherPrepare $graph_handler $start $end} err]} {
            tk_messageBox -icon error -type ok -title "Find More Flows" -message "Could not prepare infoflow graph:\n$err"
        } else {
            doFindMore $res $tree $node
        }
    }
}

proc Apol_Analysis_transflow::verifyFindMore {d} {
    variable vals
    set message {}
    if {[set hours [string trim $vals(find_more:hours)]] == {}} {
        set hours 0
    }
    if {[set minutes [string trim $vals(find_more:minutes)]] == {}} {
        set minutes 0
    }
    if {[set seconds [string trim $vals(find_more:seconds)]] == {}} {
        set seconds 0
    }
    set path_limit [string trim $vals(find_more:limit)]
    if {![string is integer $hours] || $hours > 24 || $hours < 0} {
        set message "Invalid hours limit input.  Must be between 0-24 inclusive."
    } elseif {![string is integer $minutes] || $minutes > 59 || $minutes < 0} {
        set message "Invalid minutes limit input.  Must be between 0-59 inclusive."
    } elseif {![string is integer $seconds] || $seconds > 59 || $seconds < 0} {
        set message "Invalid seconds limit input.  Must be between 0-59 inclusive."
    } elseif {$path_limit == {} && $hours == 0 && $minutes == 0 && $seconds == 0} {
        set message "You must specify a time limit."
    } elseif {$path_limit != {} && (![string is integer $path_limit] || $path_limit < 0)} {
        set message "Number of flows cannot be less than 1."
    }
    if {$message != {}} {
        tk_messageBox -icon error -type ok -title "Find More Flows" -message $message
    } else {
        $d enddialog 0
    }
}

proc Apol_Analysis_transflow::doFindMore {res tree node} {
    variable vals
    if {[set hours [string trim $vals(find_more:hours)]] == {}} {
        set hours 0
    }
    if {[set minutes [string trim $vals(find_more:minutes)]] == {}} {
        set minutes 0
    }
    if {[set seconds [string trim $vals(find_more:seconds)]] == {}} {
        set seconds 0
    }
    set path_limit [string trim $vals(find_more:limit)]
    if {$hours != 0 || $minutes != 0 || $seconds != 0} {
        set time_limit [expr {$hours * 3600 + $minutes * 60 + $seconds}]
        set time_limit_str [format " elapsed out of %02d:%02d:%02d" $hours $minutes $seconds]
    } else {
        set time_limit {}
        set time_limit_str {}
    }
    if {$path_limit != {}} {
        set path_limit_str " out of $path_limit"
    } else {
        set path_limit 0
        set path_limit_str {}
    }
    set vals(find_more:abort) 0
    set vals(find_more:searches_text) {}
    set vals(find_more:searches_done) -1
    
    set d [ProgressDlg .trans_domore -parent . -title "Find Results" \
               -width 40 -height 5 \
               -textvariable Apol_Analysis_transflow::vals(find_more:searches_text) \
               -variable Apol_Analysis_transflow::vals(find_more:searches_done) \
               -stop Stop \
               -command [list set Apol_Analysis_transflow::vals(find_more:abort) 1]]
    set graph_handler [lindex [$tree itemcget top -data] 0]
    set start_time [clock seconds]
    set elapsed_time 0
    set results {}
    set path_found 0
    
    while {1} {
        set elapsed_time [expr {[clock seconds] - $start_time}]
        set vals(find_more:searches_text) "Finding more flows:\n\n"
        append vals(find_more:searches_text) "    Time: [clock format $elapsed_time -format "%H:%M:%S" -gmt 1]$time_limit_str\n\n"
        append vals(find_more:searches_text) "    Flows: found $path_found$path_limit_str"
        update
        if {[catch {apol_TransInformationFurtherNext $graph_handler} r]} {
            tk_messageBox -icon error -type ok -title "Find More Flows" -message "Could not find more flows:\n$results"
            break
        }
        set results [lsort -unique [concat $results $r]]
        set path_found [llength $results]
        if {($time_limit != {} && $elapsed_time >= $time_limit) || \
                ($path_limit != 0 && $path_found > $path_limit) || \
                $vals(find_more:abort)} {
            break
        }
    }
    set vals(find_more:searches_text) "Rendering $path_found flow(s)."
    update idletasks

    $res.tb configure -state normal
    $res.tb delete 0.0 end
    set parent_name [$tree itemcget [$tree parent $node] -text]
    set name [$tree itemcget $node -text]
    set flow_dir [lindex [$tree itemcget $node -data] 1 0]
    switch -- $flow_dir {
        to {
            $res.tb insert end "More information flows to " title \
                $parent_name title_type \
                " from " title \
                $name title_type
        }
        from {
            $res.tb insert end "More information flows from " title \
                $parent_name title_type \
                " to " title \
                $name title_type
        }
    }
    $res.tb insert end "  (" title \
        "Find more flows" {title_type find_more} \
        ")\n\n" title \
        "Time: " subtitle \
        [clock format $elapsed_time -format "%H:%M:%S" -gmt 1] subtitle \
        [format " out of %02d:%02d:%02d" $hours $minutes $seconds] subtitle \
        "\n\nApol found the following number of information flows: " subtitle \
        $path_found num \
        " out of " subtitle \
        $path_limit num \
        "\n" subtitle
    set path_num 1
    foreach r [lrange [lsort -index 3 -integer $results] 1 end] {
        set path [lindex $r 4]
        if {$flow_dir == "to"} {
            # flip the steps around
            set p {}
            foreach step $path {
                set p [concat [list $step] $p]
            }
            set sorted_path $p
        } else {
            set sorted_path $path
        }
        $res.tb insert end "\n" {}
        renderPath $res $path_num $sorted_path
        incr path_num
    }
    $res.tb configure -state disabled
    destroy $d
}
