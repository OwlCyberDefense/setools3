#############################################################
#  relabel_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <jtang@tresys.com>
# -----------------------------------------------------------
#
# This is the implementation of the interface for
# Relabeling Analysis

namespace eval Apol_Analysis_relabel {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_relabel" "Direct Relabel"
}

proc Apol_Analysis_relabel::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
    foreach class $Apol_Class_Perms::class_list {
        set perms [apol_GetAllPermsForClass $class]
        if {[lsearch $perms "relabelto"] >= 0 && [lsearch $perms "relabelfrom"] >= 0} {
            lappend vals(classes:inc) $class
        }
    }
    set vals(subjects:inc) $Apol_Types::typelist
    set vals(subjects:inc_all) $Apol_Types::typelist
}

proc Apol_Analysis_relabel::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
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

proc Apol_Analysis_relabel::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set mode_tf [TitleFrame $options_frame.mode -text "Mode"]
    pack $mode_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set object_mode [radiobutton [$mode_tf getframe].object \
                         -text "Object mode" -value "object" \
                         -variable Apol_Analysis_relabel::vals(mode)]
    pack $object_mode -anchor w
    set widgets(mode:to) [checkbutton [$mode_tf getframe].to \
                                -text "To" \
                                -variable Apol_Analysis_relabel::vals(mode:to)]
    $widgets(mode:to) configure -command \
        [list Apol_Analysis_relabel::toggleToFromPushed $widgets(mode:to)]
    set widgets(mode:from) [checkbutton [$mode_tf getframe].from \
                                -text "From" \
                                -variable Apol_Analysis_relabel::vals(mode:from)]
    $widgets(mode:from) configure -command \
        [list Apol_Analysis_relabel::toggleToFromPushed $widgets(mode:from)]
    pack $widgets(mode:to) $widgets(mode:from) -anchor w -padx 8
    set subject_mode [radiobutton [$mode_tf getframe].subject \
                          -text "Subject Mode" -value "subject" \
                          -variable Apol_Analysis_relabel::vals(mode)]
    pack $subject_mode -anchor w -pady 4
    trace add variable Apol_Analysis_relabel::vals(mode) write \
        Apol_Analysis_relabel::toggleModeSelected

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -textvariable Apol_Analysis_relabel::vals(type:label)]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters:"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -anchor nw
    set advanced [button [$filter_tf getframe].adv -text "Advanced Filters" \
                     -command Apol_Analysis_relabel::createAdvancedDialog]
    pack $advanced -pady 4 -anchor w
}

proc Apol_Analysis_relabel::newAnalysis {} {
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

proc Apol_Analysis_relabel::updateAnalysis {f} {
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

proc Apol_Analysis_relabel::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_relabel::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_relabel::saveQuery {channel} {
    variable vals
    foreach {key value} [array get vals] {
        puts $channel "$key $value"
    }
}

proc Apol_Analysis_relabel::loadQuery {channel} {
    variable vals
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        set vals($key) $value
    }
}

proc Apol_Analysis_relabel::gotoLine {tab line_num} {
}

proc Apol_Analysis_relabel::search {tab str case_Insensitive regExpr srch_Direction } {
}


#################### private functions below ####################

proc Apol_Analysis_relabel::reinitializeVals {} {
    variable vals

    array set vals {
        mode object
        mode:to 1
        mode:from 0

        type:label "Starting type"
        type {}  type:attrib {}

        regexp:enable 0
        regexp {}

        classes:inc {}  classes:exc {}
        subjects:inc {}  subjects:inc_all {}
        subjects:exc {}  subjects:exc_all {}
        subjects:attribenable 0 subjects:attrib {}
    }
}

proc Apol_Analysis_relabel::reinitializeWidgets {} {
    variable vals
    variable widgets

    Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
    updateTypeLabel
}

proc Apol_Analysis_relabel::toggleModeSelected {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(mode) == "object"} {
        $widgets(mode:to) configure -state normal
        $widgets(mode:from) configure -state normal
    } else {
        $widgets(mode:to) configure -state disabled
        $widgets(mode:from) configure -state disabled
    }
    updateTypeLabel
}

# disallow both to and from to be deselected
proc Apol_Analysis_relabel::toggleToFromPushed {cb} {
    variable vals
    if {!$vals(mode:to) && !$vals(mode:from)} {
        $cb select
    }
    updateTypeLabel
}

proc Apol_Analysis_relabel::updateTypeLabel {} {
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

################# functions that do advanced filters #################

proc Apol_Analysis_relabel::createAdvancedDialog {} {
    destroy .relabel_analysis_adv
    variable vals

    set d [Dialog .relabel_analysis_adv -modal local -separator 1 -title "Direct Relabel Advanced Filters" -parent .]
    $d add -text "Close"

    set tf [TitleFrame [$d getframe].objs -text "Filter By Object Classes"]
    pack $tf -side top -expand 1 -fill both -padx 2 -pady 4
    createAdvancedFilter [$tf getframe] "Object Classes" classes 0
    set l [label [$tf getframe].l -text "Only showing object classes that have both 'relabelto' and 'relabelfrom' permissions."]
    grid $l - - -padx 4 -pady 2

    set tf [TitleFrame [$d getframe].types -text "Filter By Subject Types"]
    pack $tf -side top -expand 1 -fill both -padx 2 -pady 4
    if {$vals(mode) == "object"} {
        createAdvancedFilter [$tf getframe] "Subject Types" subjects 0
    } else {
        createAdvancedFilter [$tf getframe] "Subject Types" subjects 1
    }
    set inc [$tf getframe].inc
    set exc [$tf getframe].exc

    set attrib [frame [$tf getframe].a]
    grid $attrib - -
    set attrib_enable [checkbutton $attrib.ae \
                           -text "Filter by attribute:" \
                           -variable Apol_Analysis_relabel::vals(subjects:attribenable)]
    set attrib_box [ComboBox $attrib.ab -autopost 1 -entrybg white -width 16 \
                        -values $Apol_Types::attriblist \
                        -textvariable Apol_Analysis_relabel::vals(subjects:attrib)]
    $attrib_enable configure -command \
        [list Apol_Analysis_relabel::attribEnabled $attrib_box $inc $exc]
    trace remove variable Apol_Analysis_relabel::vals(subjects:attrib) write \
        [list Apol_Analysis_relabel::attribChanged $inc $exc]
    trace add variable Apol_Analysis_relabel::vals(subjects:attrib) write \
        [list Apol_Analysis_relabel::attribChanged $.inc $exc]
    pack $attrib_enable -side top -expand 0 -fill x -anchor s -padx 5 -pady 2
    pack $attrib_box -side top -expand 1 -fill x -padx 10
    attribEnabled $attrib_box $inc $exc
    if {$vals(mode) == "subject"} {
        $attrib_enable configure -state disabled
        $attrib_box configure -state disabled
    }

    $d draw
}

proc Apol_Analysis_relabel::createAdvancedFilter {f title varname disabled} {
    set l1 [label $f.l1 -text "Included $title:"]
    set l2 [label $f.l2 -text "Excluded $title:"]
    grid $l1 x $l2 -sticky w

    set inc [Apol_Widget::makeScrolledListbox $f.inc -height 10 -width 24 \
                 -listvar Apol_Analysis_relabel::vals($varname:inc) \
                 -selectmode extended -exportselection 0]
    set exc [Apol_Widget::makeScrolledListbox $f.exc -height 10 -width 24 \
                 -listvar Apol_Analysis_relabel::vals($varname:exc) \
                 -selectmode extended -exportselection 0]
    set bb [ButtonBox $f.bb -homogeneous 1 -orient vertical -spacing 4]
    $bb add -text "-->" -width 10 -command [list Apol_Analysis_relabel::moveToExclude $varname $inc $exc]
    $bb add -text "<--" -width 10 -command [list Apol_Analysis_relabel::moveToInclude $varname $inc $exc]
    grid $inc $bb $exc -sticky nsew

    set inc_bb [ButtonBox $f.inc_bb -homogeneous 1 -spacing 4]
    $inc_bb add -text "Select All" -command [list $inc.lb selection set 0 end]
    $inc_bb add -text "Unselect" -command [list $inc.lb selection clear 0 end]
    set exc_bb [ButtonBox $f.exc_bb -homogeneous 1 -spacing 4]
    $exc_bb add -text "Select All" -command [list $exc.lb selection set 0 end]
    $exc_bb add -text "Unselect" -command [list $exc.lb selection clear 0 end]
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

proc Apol_Analysis_relabel::moveToExclude {varname inc exc} {
    variable vals
    if {[set selection [$inc.lb curselection]] == {}} {
        return
    }
    foreach i $selection {
        lappend perms [$inc.lb get $i]
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
    $inc.lb selection clear 0 end
    $exc.lb selection clear 0 end
}

proc Apol_Analysis_relabel::moveToInclude {varname inc exc} {
    variable vals
    if {[set selection [$exc.lb curselection]] == {}} {
        return
    }
    foreach i $selection {
        lappend perms [$exc.lb get $i]
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
    $inc.lb selection clear 0 end
    $exc.lb selection clear 0 end
}

proc Apol_Analysis_relabel::attribEnabled {cb inc exc} {
    variable vals
    if {$vals(subjects:attribenable)} {
        $cb configure -state normal
        filterTypeLists $vals(subjects:attrib) $inc $exc
    } else {
        $cb configure -state disabled
        filterTypeLists "" $inc $exc
    }
}

proc Apol_Analysis_relabel::attribChanged {inc exc name1 name2 op} {
    variable vals
    if {$vals(subjects:attribenable)} {
        filterTypeLists $vals(subjects:attrib) $inc $exc
    }
}

proc Apol_Analysis_relabel::filterTypeLists {attrib inc exc} {
    variable vals
    if {$attrib != ""} {
        set typesList [lindex [apol_GetAttribs $attrib] 0 1]
        if {$typesList == {}} {
            # unknown attribute, so don't change type combobox
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

proc Apol_Analysis_relabel::checkParams {} {
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
    if {$vals(classes:inc) == {}} {
        return "At least one object class must be included."
    }
    if {$vals(mode) == "object" && $vals(subjects:inc_all) == {}} {
        return "At least one subject type must be included."
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_relabel::analyze {} {
    variable vals
    if {$vals(mode) == "object"} {
        if {$vals(mode:to) && $vals(mode:from)} {
            set mode "both"
        } elseif {$vals(mode:to)} {
            set mode "to"
        } else {
            set mode "from"
        }
    } else {
        set mode "subject"
    }
    if {$vals(classes:exc) != {}} {
        set classes $vals(classes:inc)
    } else {
        set classes {}
    }
    if {$vals(subjects:exc) != {}} {
        set subjects $vals(subjects:inc)
    } else {
        set subjects {}
    }
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }
    apol_RelabelAnalysis $mode $vals(type) $classes $subjects $regexp
}

################# functions that control analysis output #################

proc Apol_Analysis_relabel::createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Relabel" [array get vals]]

    if {$vals(mode) == "object"} {
        if {$vals(mode:to) && $vals(mode:from)} {
            set tree_title "Type $vals(type) relabels to/from:"
        } elseif {$vals(mode:to)} {
            set tree_title "Type $vals(type) relabels to:"
        } else {
            set tree_title "Type $vals(type) relabels from:"
        }
    } else {
        set tree_title "Subject $vals(type) relabels:"
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

    $tree configure -selectcommand [list Apol_Analysis_relabel::treeSelect $res]
    return $f
}

proc Apol_Analysis_relabel::treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "o"} {
            renderResultsRuleObject $res $tree $node $data
        } elseif {[string index $node 0] == "s"} {
            renderResultsRuleSubject $res $tree $node $data
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end $data
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_relabel::clearResultsDisplay {f} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_relabel::renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    if {$vals(mode) == "object"} {
        set top_text [renderResultsObject $results $tree]
    } else {  ;# subject mode
        set top_text [renderResultsSubject $results $tree]
    }
    $tree itemconfigure top -data $top_text
    $tree selection set top
    $tree opentree top
    update idletasks
    $tree see top
}

proc Apol_Analysis_relabel::renderResultsObject {results tree} {
    variable vals
    if {$vals(mode:from) && $vals(mode:to)} {
        set dir both
    } elseif {$vals(mode:to)} {
        set dir to
    } else {
        set dir from
    }
    foreach r $results {
        foreach {to from both} $r {break}
        set expanded_type [expandTargetTypeSet [lindex $from 0]]
        if {$expanded_type == {}} {
            set expanded_type $target_type
        }
        foreach type $expanded_type {
            foreach a $to b $from {
                lappend types($type) [list $a $b]
            }
        }
    }
    foreach key [lsort [array names types]] {
        set types($key) [lsort -unique $types($key)]
        $tree insert end top o:$dir:\#auto -text $key -data $types($key)
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
    if {[llength [array names types]] > 0} {
        switch -- $dir {
            both { lappend top_text " can be relabeled to and from " {} }
            to   { lappend top_text " can be relabeled to " {} }
            from { lappend top_text " can be relabeled from " {} }
        }
        lappend top_text [llength [array names types]] num \
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

proc Apol_Analysis_relabel::renderResultsRuleObject {res tree node data} {
    set header [list [$tree itemcget top -text] title_type]
    lappend header " can be relabeled:\n" {}
    eval $res.tb insert end $header

    # the search direction is embedded within the node ID
    regexp -- {^[^:]+:([^:]+)} $node -> dir
    set target_type [$tree itemcget $node -text]
    foreach rule_pairs $data {
        set class [apol_RenderAVRuleClass [lindex $rule_pairs 0]]
        lappend classes($class) $rule_pairs
    }
    foreach key [lsort [array names classes]] {
        $res.tb configure -state normal
        $res.tb insert end "\n$key:\n" title
        foreach rule_pairs $classes($key) {
            foreach {a_rule b_rule} $rule_pairs {break}
            set source_type [apol_RenderAVRuleSource $a_rule]

            # determine direction of relabelling
            if {$dir == "to" || $dir == "from"} {
                set dir_string $dir
            } else {
                set a_perms [apol_RenderAVRulePerms $a_rule]
                set b_perms [apol_RenderAVRulePerms $b_rule]
                if {[lsearch $a_perms "relabelto"] >= 0 && \
                        [lsearch $a_perms "relabelfrom"] >= 0 && \
                        $a_rule == $b_rule} {
                    set dir_string "to and from"
                } elseif {[lsearch $a_perms "relabelfrom"] >= 0 &&
                          [lsearch $b_perms "relabelto"] >= 0} {
                    set dir_string "to"
                } else {
                    set dir_string "from"
                }
            }
            $res.tb configure -state normal
            $res.tb insert end "\n  $dir_string " num \
                $target_type type_tag \
                " by " {} \
                $source_type type_tag \
                "\n" {}
            foreach {rule_type source_set target_set class perm_default line_num cond_info} [apol_RenderAVRule $a_rule] {break}
            Apol_Widget::appendSearchResultLine $res 6 $line_num {} $rule_type  "\{ $source_set \}" "\{ $target_set \}" : $class "\{ $perm_default \}"
            if {$a_rule != $b_rule} {
                foreach {rule_type source_set target_set class perm_default line_num cond_info} [apol_RenderAVRule $b_rule] {break}
                Apol_Widget::appendSearchResultLine $res 6 $line_num {} $rule_type  "\{ $source_set \}" "\{ $target_set \}" : $class "\{ $perm_default \}"
            }
        }
    }
}

proc Apol_Analysis_relabel::renderResultsSubject {results tree} {
    variable vals
    foreach {to from both} [lindex $results 0] {}  ;# only first element used
    set to_count 0
    set from_count 0

    if {[llength $to] + [llength $both]} {
        $tree insert end top to -text "To" -drawcross auto
        foreach rule [concat $to $both] {
            foreach t [expandTargetTypeSet $rule] {
                lappend to_types($t) $rule
            }
        }
        set to_count [llength [array names to_types]]
        foreach type [lsort -index 0 [array names to_types]] {
            $tree insert end to s\#auto -text $type -data [list to $to_types($type)]
        }
        set to_text [list $vals(type) title_type " can relabel to " {} ]
        lappend to_text $to_count num \
            " type(s). Open the subtree of this item to view the list of types." {}
        $tree itemconfigure to -data $to_text
    }

    if {[llength $from] + [llength $both]} {
        $tree insert end top from -text "From" -drawcross auto
        foreach rule [concat $from $both] {
            foreach t [expandTargetTypeSet $rule] {
                lappend from_types($t) $rule
            }
        }
        set from_count [llength [array names from_types]]
        foreach type [lsort -index 0 [array names from_types]] {
            $tree insert end from s\#auto -text $type -data [list from $from_types($type)]
        }
        set from_text [list $vals(type) title_type " can relabel from " {} ]
        lappend from_text $from_count num \
            " type(s). Open the subtree of this item to view the list of types." {}
        $tree itemconfigure from -data $from_text
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

proc Apol_Analysis_relabel::renderResultsRuleSubject {res tree node data} {
    foreach {dir rules} $data {break}
    set header [list [$tree itemcget top -text] title_type]
    lappend header " can relabel $dir " {} \
        [$tree itemcget $node -text] type_tag \
        "\n\n" {}
    eval $res.tb insert end $header
    foreach rule $rules {
        foreach {rule_type source_set target_set class perm_default line_num cond_info} [apol_RenderAVRule $rule] {break}
        Apol_Widget::appendSearchResultLine $res 0 $line_num {} $rule_type  "\{ $source_set \}" "\{ $target_set \}" : $class "\{ $perm_default \}"
    }
}

proc Apol_Analysis_relabel::expandTargetTypeSet {rule_num} {
    set orig_type_set [apol_RenderAVRuleTarget $rule_num]
    set exp_type_set {}
    foreach t $orig_type_set {
        set exp_type_set [concat $exp_type_set [lindex [apol_GetAttribs $t] 0 1]]
    }
    if {$exp_type_set != {}} {
        return [lsort -unique $exp_type_set]
    } else {
        return $orig_type_set
    }
}
