#  Copyright (C) 2003-2007 Tresys Technology, LLC
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

namespace eval Apol_Analysis_directflow {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_directflow" "Direct Information Flow"
}

proc Apol_Analysis_directflow::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
    set vals(classes:selected) $Apol_Class_Perms::class_list
    Apol_Widget::setScrolledListboxState $widgets(classes) normal
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    $classes_lb selection set 0 end
    toggleClasses {} {} {}
}

proc Apol_Analysis_directflow::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_directflow::getInfo {} {
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
same, the child cannot be opened.  This avoids cyclic analyses.

\nFor additional help on this topic select \"Information Flow Analysis\"
from the help menu."
}

proc Apol_Analysis_directflow::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set dir_tf [TitleFrame $options_frame.mode -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set dir_in [radiobutton [$dir_tf getframe].in -text In -value in \
                    -variable Apol_Analysis_directflow::vals(dir)]
    set dir_out [radiobutton [$dir_tf getframe].out -text Out -value out \
                     -variable Apol_Analysis_directflow::vals(dir)]
    set dir_either [radiobutton [$dir_tf getframe].either -text Either -value either \
                        -variable Apol_Analysis_directflow::vals(dir)]
    set dir_both [radiobutton [$dir_tf getframe].both -text Both -value both \
                         -variable Apol_Analysis_directflow::vals(dir)]
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
                          -variable Apol_Analysis_directflow::vals(classes:enable)]
    pack $class_enable -anchor w
    set widgets(classes) [Apol_Widget::makeScrolledListbox $class_f.classes \
                              -height 6 -width 24 \
                              -listvar Apol_Class_Perms::class_list \
                              -selectmode multiple -exportselection 0]
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    bind $classes_lb <<ListboxSelect>> \
        [list Apol_Analysis_directflow::selectClassesListbox $classes_lb]
    pack $widgets(classes) -padx 4 -expand 0 -fill both
    trace add variable Apol_Analysis_directflow::vals(classes:enable) write \
        Apol_Analysis_directflow::toggleClasses
    Apol_Widget::setScrolledListboxState $widgets(classes) disabled
    set classes_bb [ButtonBox $class_f.bb -homogeneous 1 -spacing 4]
    $classes_bb add -text "Include All" \
        -command [list Apol_Analysis_directflow::includeAll $classes_lb]
    $classes_bb add -text "Exclude All"  \
        -command [list Apol_Analysis_directflow::excludeAll $classes_lb]
    pack $classes_bb -pady 4
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_directflow::newAnalysis {} {
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

proc Apol_Analysis_directflow::updateAnalysis {f} {
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

proc Apol_Analysis_directflow::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_directflow::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    reinitializeWidgets
}

proc Apol_Analysis_directflow::saveQuery {channel} {
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

proc Apol_Analysis_directflow::loadQuery {channel} {
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
                set classes $value
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

proc Apol_Analysis_directflow::getTextWidget {tab} {
    return [$tab.right getframe].res
}

#################### private functions below ####################

proc Apol_Analysis_directflow::reinitializeVals {} {
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

proc Apol_Analysis_directflow::reinitializeWidgets {} {
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
        set i [lsearch $Apol_Class_Perms::class_list $c]
        $classes_lb selection set $i $i
    }
    toggleClasses {} {} {}
}

proc Apol_Analysis_directflow::toggleClasses {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(classes:enable)} {
        Apol_Widget::setScrolledListboxState $widgets(classes) enabled
    } else {
        Apol_Widget::setScrolledListboxState $widgets(classes) disabled
    }
}

proc Apol_Analysis_directflow::selectClassesListbox {lb} {
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

proc Apol_Analysis_directflow::includeAll {lb} {
    variable vals
    $lb selection set 0 end
    set vals(classes:selected) $Apol_Class_Perms::class_list
}

proc Apol_Analysis_directflow::excludeAll {lb} {
    variable vals
    $lb selection clear 0 end
    set vals(classes:selected) {}
}

#################### functions that do analyses ####################

proc Apol_Analysis_directflow::checkParams {} {
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
    if {$vals(classes:enable) && $vals(classes:selected) == {}} {
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

proc Apol_Analysis_directflow::analyze {} {
    variable vals
    set classes {}
    if {$vals(classes:enable)} {
        foreach c $vals(classes:selected) {
            foreach p [Apol_Analysis::getAllPermsForClass $c] {
                lappend classes [list $c $p]
            }
        }
    }
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }
    apol_DirectInformationFlowAnalysis $vals(dir) $vals(type) $classes $regexp
}

proc Apol_Analysis_directflow::analyzeMore {tree node} {
    # disallow more analysis if this node is the same as its parent
    set new_start [$tree itemcget $node -text]
    if {[$tree itemcget [$tree parent $node] -text] == $new_start} {
        return {}
    }
    set g [lindex [$tree itemcget top -data] 0]
    apol_DirectInformationFlowMore $g $new_start
}

################# functions that control analysis output #################

proc Apol_Analysis_directflow::createResultsDisplay {} {
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
    $res.tb tag configure subtitle -font {Helvetica 10 bold}
    $res.tb tag configure subtitle_dir -foreground blue -font {Helvetica 10 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_directflow::treeSelect $res]
    $tree configure -opencmd [list Apol_Analysis_directflow::treeOpen $tree]
    bind $tree <Destroy> [list Apol_Analysis_directflow::treeDestroy $tree]
    return $f
}

proc Apol_Analysis_directflow::treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "x"} {
            renderResultsDirectFlow $res $tree $node [lindex $data 1]
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end [lindex $data 1]
        }
        $res.tb configure -state disabled
    }
}

# perform additional direct infoflows if this node has not been
# analyzed yet
proc Apol_Analysis_directflow::treeOpen {tree node} {
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
            createResultsNodes $tree $node $new_results 1
        }
    }
}

proc Apol_Analysis_directflow::treeDestroy {tree} {
    set graph_handler [lindex [$tree itemcget top -data] 0]
    apol_InformationFlowDestroy $graph_handler
}

proc Apol_Analysis_directflow::clearResultsDisplay {f} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    set graph_handler [lindex [$tree itemcget top -data] 0]
    apol_InformationFlowDestroy $graph_handler
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_directflow::renderResults {f results} {
    variable vals

    set graph_handler [lindex $results 0]
    set results_list [lrange $results 1 end]

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    set top_text [renderTopText]
    $tree itemconfigure top -data [list $graph_handler $top_text]

    createResultsNodes $tree top $results_list 1
    $tree selection set top
    $tree opentree top 0
    update idletasks
    $tree see top
}

proc Apol_Analysis_directflow::renderTopText {} {
    variable vals

    set top_text [list "Direct Information Flow Analysis: Starting type: " title]
    lappend top_text $vals(type) title_type \
        "\n\n" title \
        "This tab provides the results of a Direct Information Flow analysis
beginning from the starting type selected above.  The results of the
analysis are presented in tree form with the root of the tree (this
node) being the start point for the analysis.

\nEach child node in the tree represents a type in the current policy
for which there is a direct information flow to or from (depending on
your selection above) its parent node.

\nNOTE: For any given generation, if the parent and the child are the
same, you cannot open the child.  This avoids cyclic analyses."
}

# create results to the given tree.  if do_expand is non-zero then
# allow subbranches to be made.
proc Apol_Analysis_directflow::createResultsNodes {tree parent_node results do_expand} {
    set all_targets {}
    foreach r $results {
        foreach {flow_dir source target rules} $r {break}
        if {!$do_expand} {
            set target [lindex $results 0 2]
        }
        lappend all_targets $target
        foreach r $rules {
            set class [apol_RenderAVRuleClass $r]
            lappend classes($target) $class
            lappend classes($target:$class) $r
        }
        set dir($target:$flow_dir) 1
    }
    foreach t [lsort -uniq $all_targets] {
        if {[info exists dir($t:both)] ||
            ([info exists dir($t:in)] && [info exists dir($t:out)])} {
            set flow_dir "both"
        } elseif {[info exists dir($t:in)]} {
            set flow_dir "in"
        } else {
            set flow_dir "out"
        }
        set rules {}
        foreach c [lsort -uniq $classes($t)] {
            lappend rules [list $c [lsort -uniq $classes($t:$c)]]
        }
        set data [list $flow_dir $rules]
        $tree insert end $parent_node x\#auto -text $t -drawcross allways \
            -data [list 0 $data]
    }
}

proc Apol_Analysis_directflow::renderResultsDirectFlow {res tree node data} {
    set parent_name [$tree itemcget [$tree parent $node] -text]
    set name [$tree itemcget $node -text]
    foreach {flow_dir classes} $data {break}
    switch -- $flow_dir {
        both {
            $res.tb insert end "Information flows both into and out of " title \
                $parent_name title_type \
                " from/to " title \
                $name title_type
        }
        in {
            $res.tb insert end "Information flows into " title \
                $parent_name title_type \
                " from " title \
                $name title_type
        }
        out {
            $res.tb insert end "Information flows out of " title \
                $parent_name title_type \
                " to " title \
                $name title_type
        }
    }
    $res.tb insert end "\n\n" title_type \
        "Objects classes for " subtitle \
        [string toupper $flow_dir] subtitle_dir \
        " flows:\n" subtitle
    foreach c $classes {
        foreach {class_name rules} $c {break}
        $res.tb insert end "      " {} \
            $class_name\n subtitle
        Apol_Widget::appendSearchResultAVRules $res 12 $rules
    }
}
