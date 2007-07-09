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

namespace eval Apol_Analysis_relabel {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_relabel" "Direct Relabel"
}

proc Apol_Analysis_relabel::create {options_frame} {
    variable vals
    variable widgets

    _reinitializeVals

    set mode_tf [TitleFrame $options_frame.mode -text "Mode"]
    pack $mode_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set object_mode [radiobutton [$mode_tf getframe].object \
                         -text "Object" -value "object" \
                         -variable Apol_Analysis_relabel::vals(mode)]
    pack $object_mode -anchor w
    set widgets(mode:to) [checkbutton [$mode_tf getframe].to \
                              -text "To" \
                              -variable Apol_Analysis_relabel::vals(mode:to)]
    $widgets(mode:to) configure -command \
        [list Apol_Analysis_relabel::_toggleToFromPushed $widgets(mode:to)]
    set widgets(mode:from) [checkbutton [$mode_tf getframe].from \
                                -text "From" \
                                -variable Apol_Analysis_relabel::vals(mode:from)]
    $widgets(mode:from) configure -command \
        [list Apol_Analysis_relabel::_toggleToFromPushed $widgets(mode:from)]
    pack $widgets(mode:to) $widgets(mode:from) -anchor w -padx 8
    set subject_mode [radiobutton [$mode_tf getframe].subject \
                          -text "Subject" -value "subject" \
                          -variable Apol_Analysis_relabel::vals(mode)]
    pack $subject_mode -anchor w -pady 4
    trace add variable Apol_Analysis_relabel::vals(mode) write \
        Apol_Analysis_relabel::_toggleModeSelected

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -textvariable Apol_Analysis_relabel::vals(type:label)]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set advanced_f [frame [$filter_tf getframe].advanced]
    pack $advanced_f -side left -anchor nw
    set access_enable [checkbutton $advanced_f.enable -text "Use advanced filters" \
                           -variable Apol_Analysis_relabel::vals(advanced_enable)]
    pack $access_enable -anchor w
    set widgets(advanced) [button $advanced_f.adv -text "Advanced Filters" \
                               -command Apol_Analysis_relabel::_createAdvancedDialog \
                               -state disabled]
    pack $widgets(advanced) -anchor w -padx 4
    trace add variable Apol_Analysis_relabel::vals(advanced_enable) write \
        Apol_Analysis_relabel::_toggleAdvancedSelected
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_relabel::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
    set vals(classes:inc) {}
    foreach class [Apol_Class_Perms::getClasses] {
        set perms [Apol_Class_Perms::getPermsForClass $class]
        if {[lsearch $perms "relabelto"] >= 0 && [lsearch $perms "relabelfrom"] >= 0} {
            lappend vals(classes:inc) $class
        }
    }
    set vals(subjects:inc) [Apol_Types::getTypes]
    set vals(subjects:inc_all) $vals(subjects:inc)
}

proc Apol_Analysis_relabel::close {} {
    variable widgets
    _reinitializeVals
    _reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_relabel::getInfo {} {
    return "Direct relabel analysis is designed to facilitate querying a policy
for both potential changes to object labels and relabel privileges
granted to a subject. These two modes are respectively called Object
Mode and Subject Mode.

\nOBJECT MODE
In object mode the user specifies a starting or ending type and either
To, From, or Both. When To is selected all types to which the starting
type can be relabeled will be displayed. When From is selected all
types from which the ending type can be relabeled will be
displayed. Both will, obviously, do both analyses.

\nSUBJECT MODE
In subject mode the user specifies only a subject type. Two lists of
types will be displayed corresponding to all of the types To which the
subject can relabel and From which the subject can relabel.

\nOPTIONAL RESULT FILTERS
Results may be filtered in several ways. The end types resulting from
a query may be filtered by regular expression. The Advanced Filters
provide the option of selecting which object classes to include in the
analysis and which types to include as subjects of relabeling
operations. Note, excluded subjects are ignored in subject mode
because only the selected subject type is used as a subject."
}

proc Apol_Analysis_relabel::newAnalysis {} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    set f [_createResultsDisplay]
    _renderResults $f $results
    $results -delete
    return {}
}

proc Apol_Analysis_relabel::updateAnalysis {f} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    _clearResultsDisplay $f
    _renderResults $f $results
    $results -delete
    return {}
}

proc Apol_Analysis_relabel::reset {} {
    _reinitializeVals
    _reinitializeWidgets
    open
}

proc Apol_Analysis_relabel::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    _reinitializeWidgets
}

proc Apol_Analysis_relabel::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        if {$key != "classes:inc" && \
                $key != "subjects:inc_all" && $key != "subjects:inc" && \
                $key != "subjects:exc"} {
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

proc Apol_Analysis_relabel::loadQuery {channel} {
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
        switch -- $key {
            classes:exc {
                set classes_exc $value
            }
            subjects:exc_all {
                set subjects_exc $value
            }
            default {
                set vals($key) $value
            }
        }
    }

    # fill in the exclusion lists using only classes/types found
    # within the current policy
    open

    set vals(classes:exc) {}
    foreach c $classes_exc {
        set i [lsearch $vals(classes:inc) $c]
        if {$i >= 0} {
            lappend vals(classes:exc) $c
            set vals(classes:inc) [lreplace $vals(classes:inc) $i $i]
        }
    }
    set vals(classes:exc) [lsort $vals(classes:exc)]

    set vals(subjects:exc_all) {}
    set vals(subjects:exc) {}
    foreach s $subjects_exc {
        set i [lsearch $vals(subjects:inc_all) $s]
        if {$i >= 0} {
            lappend vals(subjects:exc_all) $s
            lappend vals(subjects:exc) $s
            set vals(subjects:inc_all) [lreplace $vals(subjects:inc_all) $i $i]
            set i [lsearch $vals(subjects:inc) $s]
            set vals(subjects:inc) [lreplace $vals(subjects:inc) $i $i]
        }
    }
    set vals(subjects:exc_all) [lsort $vals(subjects:exc_all)]
    set vals(subjects:exc) [lsort $vals(subjects:exc)]
    _reinitializeWidgets
}

proc Apol_Analysis_relabel::getTextWidget {tab} {
    return [$tab.right getframe].res
}

#################### private functions below ####################

proc Apol_Analysis_relabel::_reinitializeVals {} {
    variable vals

    array set vals {
        mode object
        mode:to 1
        mode:from 0

        type:label "Starting type"
        type {}  type:attrib {}

        regexp:enable 0
        regexp {}

        advanced_enable 0
        classes:inc {}  classes:exc {}
        subjects:inc {}  subjects:inc_all {}
        subjects:exc {}  subjects:exc_all {}
        subjects:attribenable 0 subjects:attrib {}
    }
}

proc Apol_Analysis_relabel::_reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
    _updateTypeLabel
}

proc Apol_Analysis_relabel::_toggleModeSelected {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(mode) == "object"} {
        $widgets(mode:to) configure -state normal
        $widgets(mode:from) configure -state normal
    } else {
        $widgets(mode:to) configure -state disabled
        $widgets(mode:from) configure -state disabled
    }
    _updateTypeLabel
}

# disallow both to and from to be deselected
proc Apol_Analysis_relabel::_toggleToFromPushed {cb} {
    variable vals
    if {!$vals(mode:to) && !$vals(mode:from)} {
        $cb select
    }
    _updateTypeLabel
}

proc Apol_Analysis_relabel::_updateTypeLabel {} {
    variable vals
    if {$vals(mode) == "subject"} {
        set vals(type:label) "Subject"
    } elseif {$vals(mode:to) && $vals(mode:from)} {
        set vals(type:label) "Starting/ending type"
    } elseif {$vals(mode:from)} {
        set vals(type:label) "Ending type"
    } else {
        set vals(type:label) "Starting type"
    }
}

proc Apol_Analysis_relabel::_toggleAdvancedSelected {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(advanced_enable)} {
        $widgets(advanced) configure -state normal
    } else {
        $widgets(advanced) configure -state disabled
    }
}

################# functions that do advanced filters #################

proc Apol_Analysis_relabel::_createAdvancedDialog {} {
    destroy .relabel_analysis_adv
    variable vals

    set d [Dialog .relabel_analysis_adv -modal local -separator 1 -title "Direct Relabel Advanced Filters" -parent .]
    $d add -text "Close"

    set tf [TitleFrame [$d getframe].objs -text "Filter By Object Classes"]
    pack $tf -side top -expand 1 -fill both -padx 2 -pady 4
    _createAdvancedFilter [$tf getframe] "Object Classes" classes 0
    set l [label [$tf getframe].l -text "Only showing object classes that have both 'relabelto' and 'relabelfrom' permissions."]
    grid $l - - -padx 4 -pady 2

    set tf [TitleFrame [$d getframe].types -text "Filter By Subject Types"]
    pack $tf -side top -expand 1 -fill both -padx 2 -pady 4
    if {$vals(mode) == "object"} {
        _createAdvancedFilter [$tf getframe] "Subject Types" subjects 0
    } else {
        _createAdvancedFilter [$tf getframe] "Subject Types" subjects 1
    }
    set inc [$tf getframe].inc
    set exc [$tf getframe].exc

    set attrib [frame [$tf getframe].a]
    grid $attrib - -
    set attrib_enable [checkbutton $attrib.ae -anchor w \
                           -text "Filter by attribute" \
                           -variable Apol_Analysis_relabel::vals(subjects:attribenable)]
    set attrib_box [ComboBox $attrib.ab -autopost 1 -entrybg white -width 16 \
                        -values $Apol_Types::attriblist \
                        -textvariable Apol_Analysis_relabel::vals(subjects:attrib)]
    $attrib_enable configure -command \
        [list Apol_Analysis_relabel::_attribEnabled $attrib_box]
    # remove any old traces on the attribute
    trace remove variable Apol_Analysis_relabel::vals(subjects:attrib) write \
        [list Apol_Analysis_relabel::_attribChanged]
    trace add variable Apol_Analysis_relabel::vals(subjects:attrib) write \
        [list Apol_Analysis_relabel::_attribChanged]
    pack $attrib_enable -side top -expand 0 -fill x -anchor sw -padx 5 -pady 2
    pack $attrib_box -side top -expand 1 -fill x -padx 10
    _attribEnabled $attrib_box
    if {$vals(mode) == "subject"} {
        $attrib_enable configure -state disabled
        $attrib_box configure -state disabled
    }

    $d draw
}

proc Apol_Analysis_relabel::_createAdvancedFilter {f title varname disabled} {
    set l1 [label $f.l1 -text "Included $title"]
    set l2 [label $f.l2 -text "Excluded $title"]
    grid $l1 x $l2 -sticky w

    set inc [Apol_Widget::makeScrolledListbox $f.inc -height 10 -width 24 \
                 -listvar Apol_Analysis_relabel::vals($varname:inc) \
                 -selectmode extended -exportselection 0]
    set exc [Apol_Widget::makeScrolledListbox $f.exc -height 10 -width 24 \
                 -listvar Apol_Analysis_relabel::vals($varname:exc) \
                 -selectmode extended -exportselection 0]
    set inc_lb [Apol_Widget::getScrolledListbox $inc]
    set exc_lb [Apol_Widget::getScrolledListbox $exc]
    set bb [ButtonBox $f.bb -homogeneous 1 -orient vertical -spacing 4]
    $bb add -text "-->" -width 10 -command [list Apol_Analysis_relabel::_moveToExclude $varname $inc_lb $exc_lb]
    $bb add -text "<--" -width 10 -command [list Apol_Analysis_relabel::_moveToInclude $varname $inc_lb $exc_lb]
    grid $inc $bb $exc -sticky nsew

    set inc_bb [ButtonBox $f.inc_bb -homogeneous 1 -spacing 4]
    $inc_bb add -text "Select All" -command [list $inc_lb selection set 0 end]
    $inc_bb add -text "Unselect" -command [list $inc_lb selection clear 0 end]
    set exc_bb [ButtonBox $f.exc_bb -homogeneous 1 -spacing 4]
    $exc_bb add -text "Select All" -command [list $exc_lb selection set 0 end]
    $exc_bb add -text "Unselect" -command [list $exc_lb selection clear 0 end]
    grid $inc_bb x $exc_bb -pady 4

    grid columnconfigure $f 0 -weight 1 -uniform 0 -pad 2
    grid columnconfigure $f 1 -weight 0 -pad 8
    grid columnconfigure $f 2 -weight 1 -uniform 0 -pad 2

    if {$disabled} {
        foreach w [list $l1 $l2 $bb $inc_bb $exc_bb] {
            $w configure -state disabled
        }
        Apol_Widget::setScrolledListboxState $inc disabled
        Apol_Widget::setScrolledListboxState $exc disabled
    }
}

proc Apol_Analysis_relabel::_moveToExclude {varname inc exc} {
    variable vals
    if {[set selection [$inc curselection]] == {}} {
        return
    }
    foreach i $selection {
        lappend perms [$inc get $i]
    }
    set vals($varname:exc) [lsort [concat $vals($varname:exc) $perms]]
    if {$varname == "subjects"} {
        set vals(subjects:exc_all) [lsort [concat $vals(subjects:exc_all) $perms]]
    }
    foreach p $perms {
        set i [lsearch $vals($varname:inc) $p]
        set vals($varname:inc) [lreplace $vals($varname:inc) $i $i]
        if {$varname == "subjects"} {
            set i [lsearch $vals(subjects:inc_all) $p]
            set vals(subjects:inc_all) [lreplace $vals(subjects:inc_all) $i $i]
        }
    }
    $inc selection clear 0 end
    $exc selection clear 0 end
}

proc Apol_Analysis_relabel::_moveToInclude {varname inc exc} {
    variable vals
    if {[set selection [$exc curselection]] == {}} {
        return
    }
    foreach i $selection {
        lappend perms [$exc get $i]
    }
    set vals($varname:inc) [lsort [concat $vals($varname:inc) $perms]]
    if {$varname == "subjects"} {
        set vals(subjects:inc_all) [lsort [concat $vals(subjects:inc_all) $perms]]
    }
    foreach p $perms {
        set i [lsearch $vals($varname:exc) $p]
        set vals($varname:exc) [lreplace $vals($varname:exc) $i $i]
        if {$varname == "subjects"} {
            set i [lsearch $vals(subjects:exc_all) $p]
            set vals(subjects:exc_all) [lreplace $vals(subjects:exc_all) $i $i]
        }
    }
    $inc selection clear 0 end
    $exc selection clear 0 end
}

proc Apol_Analysis_relabel::_attribEnabled {cb} {
    variable vals
    if {$vals(subjects:attribenable)} {
        $cb configure -state normal
        _filterTypeLists $vals(subjects:attrib)
    } else {
        $cb configure -state disabled
        _filterTypeLists ""
    }
}

proc Apol_Analysis_relabel::_attribChanged {name1 name2 op} {
    variable vals
    if {$vals(subjects:attribenable)} {
        _filterTypeLists $vals(subjects:attrib)
    }
}

proc Apol_Analysis_relabel::_filterTypeLists {attrib} {
    variable vals
    if {$attrib != {}} {
        set typesList {}
        if {[Apol_Types::isAttributeInPolicy $attrib]} {
            set qpol_type_datum [qpol_type_from_void $::ApolTop::qpolicy $attrib]
            set i [$qpol_type_datum get_type_iter $::ApolTop::qpolicy]
            foreach t [iter_to_list $i] {
                set t [qpol_type_from_void $t]
                lappend typesList [$t get_name $::ApolTop::qpolicy]
            }
            $i -delete
        }
        if {$typesList == {}} {
            # unknown attribute, so don't change listboxes
            return
        }
        set vals(subjects:inc) {}
        set vals(subjects:exc) {}
        foreach t $typesList {
            if {[lsearch $vals(subjects:inc_all) $t] >= 0} {
                lappend vals(subjects:inc) $t
            }
            if {[lsearch $vals(subjects:exc_all) $t] >= 0} {
                lappend vals(subjects:exc) $t
            }
        }
        set vals(subjects:inc) [lsort $vals(subjects:inc)]
        set vals(subjects:exc) [lsort $vals(subjects:exc)]
    } else {
        set vals(subjects:inc) $vals(subjects:inc_all)
        set vals(subjects:exc) $vals(subjects:exc_all)
    }
}

#################### functions that do analyses ####################

proc Apol_Analysis_relabel::_checkParams {} {
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
    if {$vals(advanced_enable)} {
        if {$vals(classes:inc) == {}} {
            return "At least one object class must be included."
        }
        if {$vals(mode) == "object" && $vals(subjects:inc_all) == {}} {
            return "At least one subject type must be included."
        }
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_relabel::_analyze {} {
    variable vals
    if {$vals(mode) == "object"} {
        if {$vals(mode:to) && $vals(mode:from)} {
            set mode $::APOL_RELABEL_DIR_BOTH
        } elseif {$vals(mode:to)} {
            set mode $::APOL_RELABEL_DIR_TO
        } else {
            set mode $::APOL_RELABEL_DIR_FROM
        }
    } else {
        set mode $::APOL_RELABEL_DIR_SUBJECT
    }
    if {$vals(advanced_enable) && $vals(classes:exc) != {}} {
        set classes $vals(classes:inc)
    } else {
        set classes {}
    }
    if {$vals(advanced_enable) && $vals(subjects:exc) != {}} {
        set subjects $vals(subjects:inc)
    } else {
        set subjects {}
    }
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }

    set q [new_apol_relabel_analysis_t]
    $q set_dir $::ApolTop::policy $mode
    $q set_type $::ApolTop::policy $vals(type)
    foreach c $classes {
        $q append_class $::ApolTop::policy $c
    }
    foreach s $subjects {
        $q append_subject $::ApolTop::policy $s
    }
    $q set_result_regex $::ApolTop::policy $regexp
    set results [$q run $::ApolTop::policy]
    $q -delete
    return $results
}

################# functions that control analysis output #################

proc Apol_Analysis_relabel::_createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Relabel" [array get vals]]

    if {$vals(mode) == "object"} {
        if {$vals(mode:to) && $vals(mode:from)} {
            set tree_title "Type $vals(type) relabels to/from"
        } elseif {$vals(mode:to)} {
            set tree_title "Type $vals(type) relabels to"
        } else {
            set tree_title "Type $vals(type) relabels from"
        }
    } else {
        set tree_title "Subject $vals(type) relabels"
    }
    set tree_tf [TitleFrame $f.left -text $tree_title]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto both]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg white]
    $sw setwidget $tree
    pack $sw -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Relabeling Results"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure num -font {Helvetica 12 bold}
    $res.tb tag configure type_tag -foreground blue -font {Helvetica 12 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_relabel::_treeSelect $res]
    return $f
}

proc Apol_Analysis_relabel::_treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "o"} {
            _renderResultsRuleObject $res $tree $node $data
        } elseif {[string index $node 0] == "s"} {
            _renderResultsRuleSubject $res $tree $node $data
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end $data
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_relabel::_clearResultsDisplay {f} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_relabel::_renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    if {$vals(mode) == "object"} {
        set top_text [_renderResultsObject $results $tree]
    } else {  ;# subject mode
        set top_text [_renderResultsSubject $results $tree]
    }
    $tree itemconfigure top -data $top_text
    $tree selection set top
    $tree opentree top
    $tree see top
}

proc Apol_Analysis_relabel::_result_type_sort {a b} {
    set t1 [[$a get_result_type] get_name $::ApolTop::qpolicy]
    set t2 [[$b get_result_type] get_name $::ApolTop::qpolicy]
    string compare $t1 $t2
}

proc Apol_Analysis_relabel::_renderResultsObject {results tree} {
    variable vals
    if {$vals(mode:from) && $vals(mode:to)} {
        set dir both
    } elseif {$vals(mode:to)} {
        set dir to
    } else {
        set dir from
    }

    foreach r [lsort -command _result_type_sort [relabel_result_vector_to_list $results]] {
        set type [[$r get_result_type] get_name $::ApolTop::qpolicy]
        set to [relabel_result_pair_vector_to_list [$r get_to]]
        set from [relabel_result_pair_vector_to_list [$r get_from]]
        set both [relabel_result_pair_vector_to_list [$r get_both]]
        set pairs {}
        foreach pair [concat $to $from $both] {
            set intermed [[$pair get_intermediate_type] get_name $::ApolTop::qpolicy]
            lappend pairs [list [$pair get_ruleA] [$pair get_ruleB] $intermed]
        }
        set pairs [lsort -unique $pairs]
        $tree insert end top o:$dir:\#auto -text $type -data $pairs
    }

    set top_text [list "Direct Relabel Analysis: " title]
    switch -- $dir {
        both { lappend top_text "Starting/Ending Type: " title }
        to   { lappend top_text "Ending Type: " title }
        from { lappend top_text "Starting Type: " title }
    }
    lappend top_text $vals(type) title_type \
        "\n\n" title \
        $vals(type) type_tag
    if {[$results get_size]} {
        switch -- $dir {
            both { lappend top_text " can be relabeled to and from " {} }
            to   { lappend top_text " can be relabeled to " {} }
            from { lappend top_text " can be relabeled from " {} }
        }
        lappend top_text [$results get_size] num \
            " type(s).\n\n" {} \
            "This tab provides the results of a Direct Relabel Analysis beginning\n" {}
        switch -- $dir {
            both { lappend top_text "with the starting/ending" {} }
            to   { lappend top_text "with the starting" {} }
            from { lappend top_text "with the ending" {} }
        }
        lappend top_text " type above. The results of the analysis are\n" {} \
            "presented in tree form with the root of the tree (this node) being the\n" {} \
            "starting point for the analysis.\n\n" {} \
            "Each child node in the tree represents a type in the current policy\n" {} \
            "to/from which relabeling is allowed (depending on you selection\n" {} \
            "above)." {}
    } else {
        switch -- $dir {
            both { lappend top_text " cannot be relabeled to/from any type." {} }
            to   { lappend top_text " cannot be relabeled to any type." {} }
            from { lappend top_text " cannot be relabeled from any type." {} }
        }
    }
}

proc Apol_Analysis_relabel::_renderResultsRuleObject {res tree node data} {
    set header [list [$tree itemcget top -text] title_type]
    lappend header " can be relabeled:\n" {}
    eval $res.tb insert end $header

    set dir [lindex [split $node :] 1]
    set target_type [$tree itemcget $node -text]
    foreach rule_pairs $data {
        set class [[[lindex $rule_pairs 0] get_object_class $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
        lappend classes($class) $rule_pairs
    }

    foreach key [lsort [array names classes]] {
        $res.tb configure -state normal
        $res.tb insert end "\n$key:\n" title
        foreach rule_pairs [lsort -index 2 $classes($key)] {
            foreach {a_rule b_rule intermed} $rule_pairs {break}

            # determine direction of relabelling
            if {$dir == "to" || $dir == "from"} {
                set dir_string $dir
            } else {
                set i [$a_rule get_perm_iter $::ApolTop::qpolicy]
                set a_perms [iter_to_str_list $i]
                $i -delete
                set i [$b_rule get_perm_iter $::ApolTop::qpolicy]
                set b_perms [iter_to_str_list $i]
                $i -delete

                if {[lsearch $a_perms "relabelto"] >= 0 && \
                        [lsearch $a_perms "relabelfrom"] >= 0 && \
                        [lsearch $b_perms "relabelto"] >= 0 && \
                        [lsearch $b_perms "relabelfrom"] >= 0} {
                    set dir_string "to and from"
                } elseif {[lsearch $a_perms "relabelto"] >= 0 &&
                          [lsearch $b_perms "relabelfrom"] >= 0} {
                    set dir_string "to"
                } else {
                    set dir_string "from"
                }
            }

            $res.tb configure -state normal
            $res.tb insert end "\n  $dir_string " num \
                $target_type type_tag \
                " by " {} \
                $intermed type_tag \
                "\n" {}

            set v [new_apol_vector_t]
            $v append $a_rule
            Apol_Widget::appendSearchResultRules $res 6 $v qpol_avrule_from_void
            $v -delete
            if {$a_rule != $b_rule} {
                set v [new_apol_vector_t]
                $v append $b_rule
                Apol_Widget::appendSearchResultRules $res 6 $v qpol_avrule_from_void
                $v -delete
            }
        }
    }
}

proc Apol_Analysis_relabel::_renderResultsSubject {results tree} {
    variable vals
    set to_count 0
    set from_count 0

    foreach r [relabel_result_vector_to_list $results] {
        set type [[$r get_result_type] get_name $::ApolTop::qpolicy]
        set to [relabel_result_pair_vector_to_list [$r get_to]]
        set from [relabel_result_pair_vector_to_list [$r get_from]]
        set both [relabel_result_pair_vector_to_list [$r get_both]]

        foreach pair [concat $to $both] {
            lappend to_types($type) [$pair get_ruleA]
        }
        foreach pair [concat $from $both] {
            lappend from_types($type) [$pair get_ruleA]
        }

    }

    set to_count [llength [array names to_types]]
    if {$to_count} {
        set to_text [list $vals(type) title_type " can relabel to " {} ]
        lappend to_text $to_count num \
            " type(s). Open the subtree of this item to view the list of types." {}
        $tree insert end top to -text "To" -data $to_text -drawcross auto
        foreach type [lsort [array names to_types]] {
            set rules [lsort -unique $to_types($type)]
            $tree insert end to s\#auto -text $type -data [list to $rules]
        }
    }
    set from_count [llength [array names from_types]]
    if {$from_count} {
        set from_text [list $vals(type) title_type " can relabel from " {} ]
        lappend from_text $from_count num \
            " type(s). Open the subtree of this item to view the list of types." {}
        $tree insert end top from -text "From" -data $from_text -drawcross auto
        foreach type [lsort [array names from_types]] {
            set rules [lsort -unique $from_types($type)]
            $tree insert end from s\#auto -text $type -data [list from $rules]
        }
    }

    set top_text [list "Direct Relabel Analysis: Subject: " title]
    lappend top_text $vals(type) title_type \
        "\n\n" title \
        $vals(type) type_tag
    if {$to_count + $from_count} {
        lappend top_text " can relabel to " {} \
            $to_count num \
            " type(s) and relabel from " {} \
            $from_count num \
            " type(s).\n\n" {} \
            "This tab provides the results of a Direct Relabel Analysis for the\n" {} \
            "subject above. The results of the analysis are presented in tree form\n" {} \
            "with the root of the tree (this node) being the starting point for the\n" {} \
            "analysis.\n\n" {} \
            "Each child node in the To and From subtrees represents a type in the\n" {} \
            "current policy which the chosen subject can relabel." {}
    } else {
        lappend top_text " does not relabel to or from any type as a subject." {}
    }
}

proc Apol_Analysis_relabel::_renderResultsRuleSubject {res tree node data} {
    foreach {dir rules} $data {break}
    set header [list [$tree itemcget top -text] title_type]
    lappend header " can relabel $dir " {} \
        [$tree itemcget $node -text] title_type \
        "\n\n" {}
    eval $res.tb insert end $header
    set v [new_apol_vector_t]
    foreach r $rules {
        $v append $r
    }
    Apol_Widget::appendSearchResultRules $res 0 $v qpol_avrule_from_void
    $v -delete
}
