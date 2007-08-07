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

proc Apol_Analysis_directflow::create {options_frame} {
    variable vals
    variable widgets

    _reinitializeVals

    set dir_tf [TitleFrame $options_frame.mode -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set dir_in [radiobutton [$dir_tf getframe].in -text In \
                    -value $::APOL_INFOFLOW_IN \
                    -variable Apol_Analysis_directflow::vals(dir)]
    set dir_out [radiobutton [$dir_tf getframe].out -text Out \
                     -value $::APOL_INFOFLOW_OUT \
                     -variable Apol_Analysis_directflow::vals(dir)]
    set dir_either [radiobutton [$dir_tf getframe].either -text Either \
                        -value $::APOL_INFOFLOW_EITHER \
                        -variable Apol_Analysis_directflow::vals(dir)]
    set dir_both [radiobutton [$dir_tf getframe].both -text Both \
                      -value $::APOL_INFOFLOW_BOTH \
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
                              -listvar Apol_Analysis_directflow::vals(classes:all_classes) \
                              -selectmode multiple -exportselection 0]
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    bind $classes_lb <<ListboxSelect>> \
        [list Apol_Analysis_directflow::_selectClassesListbox $classes_lb]
    pack $widgets(classes) -padx 4 -expand 0 -fill both
    trace add variable Apol_Analysis_directflow::vals(classes:enable) write \
        Apol_Analysis_directflow::_toggleClasses
    Apol_Widget::setScrolledListboxState $widgets(classes) disabled
    set classes_bb [ButtonBox $class_f.bb -homogeneous 1 -spacing 4]
    $classes_bb add -text "Include All" \
        -command [list Apol_Analysis_directflow::_includeAll $classes_lb]
    $classes_bb add -text "Exclude All"  \
        -command [list Apol_Analysis_directflow::_excludeAll $classes_lb]
    pack $classes_bb -pady 4
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_directflow::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
    set vals(classes:all_classes) [Apol_Class_Perms::getClasses]
    set vals(classes:selected) $vals(classes:all_classes)
    Apol_Widget::setScrolledListboxState $widgets(classes) normal
    set classes_lb [Apol_Widget::getScrolledListbox $widgets(classes)]
    $classes_lb selection set 0 end
    _toggleClasses {} {} {}
}

proc Apol_Analysis_directflow::close {} {
    variable widgets
    _reinitializeVals
    _reinitializeWidgets
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

proc Apol_Analysis_directflow::newAnalysis {} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    set f [_createResultsDisplay]
    _renderResults $f $results
    $results -acquire
    $results -delete
    return {}
}

proc Apol_Analysis_directflow::updateAnalysis {f} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    _clearResultsDisplay $f
    _renderResults $f $results
    $results -acquire
    $results -delete
    return {}
}

proc Apol_Analysis_directflow::reset {} {
    _reinitializeVals
    _reinitializeWidgets
}

proc Apol_Analysis_directflow::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    _reinitializeWidgets
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
        set i [lsearch [Apol_Class_Perms::getClasses] $c]
        if {$i >= 0} {
            lappend vals(classes:selected) $c
        }
    }
    set vals(classes:selected) [lsort $vals(classes:selected)]
    _reinitializeWidgets
}

proc Apol_Analysis_directflow::getTextWidget {tab} {
    return [$tab.right getframe].res
}

proc Apol_Analysis_directflow::appendResultsNodes {tree parent_node results} {
    _createResultsNodes $tree $parent_node $results 0
}

#################### private functions below ####################

proc Apol_Analysis_directflow::_reinitializeVals {} {
    variable vals
    set vals(dir) $::APOL_INFOFLOW_IN
    array set vals {
        type {}  type:attrib {}

        classes:enable 0
        classes:selected {}

        regexp:enable 0
        regexp {}
    }
    set vals(classes:all_classes) [Apol_Class_Perms::getClasses]
}

proc Apol_Analysis_directflow::_reinitializeWidgets {} {
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
        set i [lsearch $vals(classes:all_classes) $c]
        $classes_lb selection set $i $i
    }
    _toggleClasses {} {} {}
}

proc Apol_Analysis_directflow::_toggleClasses {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(classes:enable)} {
        Apol_Widget::setScrolledListboxState $widgets(classes) enabled
    } else {
        Apol_Widget::setScrolledListboxState $widgets(classes) disabled
    }
}

proc Apol_Analysis_directflow::_selectClassesListbox {lb} {
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

proc Apol_Analysis_directflow::_includeAll {lb} {
    variable vals
    $lb selection set 0 end
    set vals(classes:selected) $vals(classes:all_classes)
}

proc Apol_Analysis_directflow::_excludeAll {lb} {
    variable vals
    $lb selection clear 0 end
    set vals(classes:selected) {}
}

#################### functions that do analyses ####################

proc Apol_Analysis_directflow::_checkParams {} {
    variable vals
    variable widgets
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened."
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(type)]
    if {[lindex $type 0] == {}} {
        return "No type was selected."
    }
    if {![Apol_Types::isTypeInPolicy [lindex $type 0]]} {
        return "[lindex $type 0] is not a type within the policy."
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
        if {![ApolTop::openDefaultPermMap]} {
            return "This analysis requires that a permission map is loaded."
	}
        apol_tcl_clear_info_string
    }

    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_directflow::_analyze {} {
    variable vals
    set classes {}
    if {$vals(classes:enable)} {
        foreach c $vals(classes:selected) {
            foreach p [Apol_Class_Perms::getPermsForClass $c] {
                lappend classes $c $p
            }
        }
    }
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }

    set q [new_apol_infoflow_analysis_t]
    $q set_mode $::ApolTop::policy $::APOL_INFOFLOW_MODE_DIRECT
    $q set_dir $::ApolTop::policy $vals(dir)
    $q set_type $::ApolTop::policy $vals(type)
    foreach {c p} $classes {
        $q append_class_perm $::ApolTop::policy $c $p
    }
    $q set_result_regex $::ApolTop::policy $regexp
    set results [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    return $results
}

proc Apol_Analysis_directflow::_analyzeMore {tree node} {
    # disallow more analysis if this node is the same as its parent
    set new_start [$tree itemcget $node -text]
    if {[$tree itemcget [$tree parent $node] -text] == $new_start} {
        return {}
    }
    set g [lindex [$tree itemcget top -data] 0]
    $g do_more $::ApolTop::policy $new_start
}

################# functions that control analysis output #################

proc Apol_Analysis_directflow::_createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Direct Flow" [array get vals]]

    set tree_tf [TitleFrame $f.left -text "Direct Information Flow Tree"]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto both]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg [Apol_Prefs::getPref active_bg]]
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

    $tree configure -selectcommand [list Apol_Analysis_directflow::_treeSelect $res]
    $tree configure -opencmd [list Apol_Analysis_directflow::_treeOpen $tree]
    return $f
}

proc Apol_Analysis_directflow::_treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "x"} {
            _renderResultsDirectFlow $res $tree $node [lindex $data 1]
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end [lindex $data 1]
        }
        $res.tb configure -state disabled
    }
}

# perform additional direct infoflows if this node has not been
# analyzed yet
proc Apol_Analysis_directflow::_treeOpen {tree node} {
    foreach {is_expanded results} [$tree itemcget $node -data] {break}
    if {[string index $node 0] == "x" && !$is_expanded} {
        Apol_Progress_Dialog::wait "Direct Information Flow Analysis" \
            "Performing Direct Information Flow Analysis..." \
            {
                set new_results [_analyzeMore $tree $node]
                # mark this node as having been expanded
                $tree itemconfigure $node -data [list 1 $results]
                if {$new_results != {}} {
                    _createResultsNodes $tree $node $new_results 1
                    $new_results -acquire
                    $new_results -delete
                }
            }
    }
}

proc Apol_Analysis_directflow::_clearResultsDisplay {f} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_directflow::_renderResults {f results} {
    variable vals

    set graph_handler [$results extract_graph]
    $graph_handler -acquire  ;# let Tcl's GC destroy graph when this tab closes
    set results_list [$results extract_result_vector]

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    set top_text [_renderTopText]
    $tree itemconfigure top -data [list $graph_handler $top_text]

    _createResultsNodes $tree top $results_list 1
    $tree selection set top
    $tree opentree top 0
    $tree see top

    $results_list -acquire
    $results_list -delete
}

proc Apol_Analysis_directflow::_renderTopText {} {
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

# If do_expand is zero, then generate result nodes for only the first
# target type of $results.  This is needed by two types relationship
# analysis.
proc Apol_Analysis_directflow::_createResultsNodes {tree parent_node results do_expand} {
    set all_targets {}
    set info_list [infoflow_result_vector_to_list $results]
    set results_processed 0
    foreach r $info_list {
        apol_tcl_set_info_string $::ApolTop::policy "Processing result $results_processed of [llength $info_list]"

        if {$do_expand} {
            set target [[$r get_end_type] get_name $::ApolTop::qpolicy]
        } else {
            set target [[[lindex $info_list 0] get_end_type] get_name $::ApolTop::qpolicy]
        }
        set flow_dir [$r get_dir]
        set step0 [apol_infoflow_step_from_void [[$r get_steps] get_element 0]]
        set rules [$step0 get_rules]

        lappend all_targets $target
        foreach r [avrule_vector_to_list $rules] {
            set class [[$r get_object_class $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
            lappend classes($target) $class
            lappend classes($target:$class) $r
        }
        set dir($target:$flow_dir) 1
        incr results_processed
    }

    set all_targets [lsort -uniq $all_targets]
    apol_tcl_set_info_string $::ApolTop::policy "Displaying [llength $all_targets] result(s)"
    update idle

    foreach t $all_targets {
        if {[info exists dir(${t}:${::APOL_INFOFLOW_BOTH})] ||
            ([info exists dir(${t}:${::APOL_INFOFLOW_IN})] &&
             [info exists dir(${t}:${::APOL_INFOFLOW_OUT})])} {
            set flow_dir "both"
        } elseif {[info exists dir(${t}:${::APOL_INFOFLOW_IN})]} {
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

proc Apol_Analysis_directflow::_renderResultsDirectFlow {res tree node data} {
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
        set v [new_apol_vector_t]
        foreach r $rules {
            $v append $r
        }
        apol_tcl_avrule_sort $::ApolTop::policy $v
        Apol_Widget::appendSearchResultRules $res 12 $v qpol_avrule_from_void
        $v -acquire
        $v -delete
    }
}
