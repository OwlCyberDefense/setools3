#############################################################
#  domaintrans_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com, mayerf@tresys.com>
# -----------------------------------------------------------
#
# This module implements the domain transition analysis interface.


namespace eval Apol_Analysis_domaintrans {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_domaintrans" "Domain Transition"
}

proc Apol_Analysis_domaintrans::open {} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
    set vals(targets:inc) $Apol_Types::typelist
    set vals(targets:inc_displayed) $Apol_Types::typelist
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c) [lsort [apol_GetAllPermsForClass $c]]
        set vals(classes:$c:enable) 1
    }
}

proc Apol_Analysis_domaintrans::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_domaintrans::getInfo {} {
    return "A forward domain transition analysis will determine all (target)
domains to which a given (source) domain may transition.  For a
forward domain transition to be allowed, three forms of access must be
granted:

\n    (1) source domain must have process transition permission for
        target domain,
    (2) source domain must have file execute permission for some
        entrypoint type, and
    (3) target domain must have file entrypoint permission for the
        same entrypoint type.

\nA reverse domain transition analysis will determine all (source)
domains that can transition to a given (target) domain.  For a reverse
domain transition to be allowed, three forms of access must be
granted:

\n    (1) target domain must have process transition permission from the
        source domain,
    (2) target domain must have file entrypoint permission to some
        entrypoint type, and
    (3) source domain must have file execute permission to the same
        entrypoint type.

\nThe results are presented in tree form.  You can open target children
domains to perform another domain transition analysis on that domain.

\nFor additional help on this topic select \"Domain Transition Analysis\"
from the help menu."
}

proc Apol_Analysis_domaintrans::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set dir_tf [TitleFrame $options_frame.dir -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set dir_forward [radiobutton [$dir_tf getframe].forward -text "Forward" \
                         -variable Apol_Analysis_domaintrans::vals(dir) -value forward]
    set dir_reverse [radiobutton [$dir_tf getframe].reverse -text "Reverse" \
                         -variable Apol_Analysis_domaintrans::vals(dir) -value reverse]
    pack $dir_forward $dir_reverse -anchor w
    trace add variable Apol_Analysis_domaintrans::vals(dir) write \
        Apol_Analysis_domaintrans::toggleDirection

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -textvariable Apol_Analysis_domaintrans::vals(type:label)]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set access_f [frame [$filter_tf getframe].access]
    pack $access_f -side left -anchor nw
    set widgets(access_enable) [checkbutton $access_f.enable -text "Use access filters" \
                                    -variable Apol_Analysis_domaintrans::vals(access:enable)]
    pack $widgets(access_enable) -anchor w
    set widgets(access) [button $access_f.b -text "Access Filters" \
                             -command Apol_Analysis_domaintrans::createAccessDialog \
                             -state disabled]
    pack $widgets(access) -anchor w -padx 4
    trace add variable Apol_Analysis_domaintrans::vals(access:enable) write \
        Apol_Analysis_domaintrans::toggleAccessSelected
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -side left -anchor nw -padx 8
}

proc Apol_Analysis_domaintrans::newAnalysis {} {
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

proc Apol_Analysis_domaintrans::updateAnalysis {f} {
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

proc Apol_Analysis_domaintrans::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_domaintrans::switchTab {query_options} {
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

proc Apol_Analysis_domaintrans::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        switch -- $key {
            targets:inc_displayed -
            classes:perms_displayed -
            search:regexp -
            search:object_types -
            search:classperm_perms {
                # don't save these variables
            }
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

proc Apol_Analysis_domaintrans::loadQuery {channel} {
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
        if {$key == "targets:inc"} {
            lappend targets_inc $value
        } elseif {[regexp -- {^classes:(.+)} $key -> class]} {
            set c($class) $value
        } else {
            set vals($key) $value
        }
    }

    # fill in the inclusion lists using only types/classes found
    # within the current policy
    open

    set vals(targets:inc) {}
    foreach s $targets_inc {
        set i [lsearch $Apol_Types::typelist $s]
        if {$i >= 0} {
            lappend vals(targets:inc) $s
        }
    }

    foreach class_key [array names c] {
        if {[regexp -- {^([^:]+):enable} $class_key -> class]} {
            if {[lsearch $Apol_Class_Perms::class_list $class] >= 0} {
                set vals(classes:$class:enable) $c($class_key)
            }
        } else {
            set class $class_key
            set old_p $vals(classes:$class)
            set new_p {}
            foreach p $c($class) {
                if {[lsearch $old_p $p] >= 0} {
                    lappend new_p $p
                }
            }
            set vals(classes:$class) [lsort -uniq $new_p]
        }
    }
    reinitializeWidgets
}

proc Apol_Analysis_domaintrans::gotoLine {tab line_num} {
}

proc Apol_Analysis_domaintrans::search {tab str case_Insensitive regExpr srch_Direction } {
}

#################### private functions below ####################

proc Apol_Analysis_domaintrans::reinitializeVals {} {
    variable vals

    array set vals {
        dir forward

        type:label "Source domain"
        type {}  type:attrib {}

        regexp:enable 0
        regexp {}

        access:enable 0
        targets:inc {}   targets:inc_displayed {}
        targets:attribenable 0  targets:attrb {}
    }
    array unset vals classes:*
    array unset vals search:*
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c) [lsort [apol_GetAllPermsForClass $c]]
        set vals(classes:$c:enable) 1
    }
}

proc Apol_Analysis_domaintrans::reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_domaintrans::toggleDirection {name1 name2 op} {
    variable vals
    if {$vals(dir) == "forward"} {
        set vals(type:label) "Source domain"
    } elseif {$vals(dir) == "reverse"} {
        set vals(type:label) "Target domain"
    }
    maybeEnableAccess
}

proc Apol_Analysis_domaintrans::toggleAccessSelected {name1 name2 op} {
    maybeEnableAccess
}

proc Apol_Analysis_domaintrans::maybeEnableAccess {} {
    variable vals
    variable widgets
    if {$vals(dir) == "forward"} {
        $widgets(access_enable) configure -state normal
        if {$vals(access:enable)} {
            $widgets(access) configure -state normal
        } else {
            $widgets(access) configure -state disabled
        }
    } else {
        $widgets(access_enable) configure -state disabled
        $widgets(access) configure -state disabled
    }
}

################# functions that do access filters #################

proc Apol_Analysis_domaintrans::createAccessDialog {} {
    destroy .domaintrans_adv
    set d [Dialog .domaintrans_adv -modal local -separator 1 -title "Domain Transition Access Filter" -parent .]
    $d add -text "Close"
    createAccessTargets [$d getframe]
    createAccessClasses [$d getframe]
    $d draw
}

proc Apol_Analysis_domaintrans::createAccessTargets {f} {
    variable vals

    set type_f [frame $f.targets]
    pack $type_f -side left -expand 0 -fill both -padx 4 -pady 4
    set l1 [label $type_f.l1 -text "Included Object Types"]
    pack $l1 -anchor w

    set targets [Apol_Widget::makeScrolledListbox $type_f.targets -height 10 -width 24 \
                 -listvar Apol_Analysis_domaintrans::vals(targets:inc_displayed) \
                 -selectmode extended -exportselection 0]
    set targets_lb [Apol_Widget::getScrolledListbox $targets]
    bind $targets_lb <<ListboxSelect>> \
        [list Apol_Analysis_domaintrans::selectTargetListbox $targets_lb]
    pack $targets -expand 0 -fill both

    set bb [ButtonBox $type_f.bb -homogeneous 1 -spacing 4]
    $bb add -text "Include All" \
        -command [list Apol_Analysis_domaintrans::includeAllItems $targets_lb targets]
    $bb add -text "Ignore All" \
        -command [list Apol_Analysis_domaintrans::ignoreAllItems $targets_lb targets]
    pack $bb -pady 4

    set attrib [frame $type_f.a]
    pack $attrib
    set attrib_enable [checkbutton $attrib.ae -anchor w \
                           -text "Filter by attribute" \
                           -variable Apol_Analysis_domaintrans::vals(targets:attribenable)]
    set attrib_box [ComboBox $attrib.ab -autopost 1 -entrybg white -width 16 \
                        -values $Apol_Types::attriblist \
                        -textvariable Apol_Analysis_domaintrans::vals(targets:attrib)]
    $attrib_enable configure -command \
        [list Apol_Analysis_domaintrans::attribEnabled $attrib_box $targets_lb]
    # remove any old traces on the attribute
    trace remove variable Apol_Analysis_domaintrans::vals(targets:attrib) write \
        [list Apol_Analysis_domaintrans::attribChanged $targets_lb]
    trace add variable Apol_Analysis_domaintrans::vals(targets:attrib) write \
        [list Apol_Analysis_domaintrans::attribChanged $targets_lb]
    pack $attrib_enable -side top -expand 0 -fill x -anchor sw -padx 5 -pady 2
    pack $attrib_box -side top -expand 1 -fill x -padx 10
    attribEnabled $attrib_box $targets_lb
    if {[set anchor [lindex [lsort [$targets_lb curselection]] 0]] != {}} {
        $targets_lb selection anchor $anchor
        $targets_lb see $anchor
    }
}

proc Apol_Analysis_domaintrans::selectTargetListbox {lb} {
    variable vals
    for {set i 0} {$i < [$lb index end]} {incr i} {
        set t [$lb get $i]
        if {[$lb selection includes $i]} {
            lappend vals(targets:inc) $t
        } else {
            if {[set j [lsearch $vals(targets:inc) $t]] >= 0} {
                set vals(targets:inc) [lreplace $vals(targets:inc) $j $j]
            }
        }
    }
    set vals(targets:inc) [lsort -uniq $vals(targets:inc)]
    focus $lb
}

proc Apol_Analysis_domaintrans::includeAllItems {lb varname} {
    variable vals
    $lb selection set 0 end
    set displayed [$lb get 0 end]
    set vals($varname:inc) [lsort -uniq [concat $vals($varname:inc) $displayed]]
}

proc Apol_Analysis_domaintrans::ignoreAllItems {lb varname} {
    variable vals
    $lb selection clear 0 end
    set displayed [$lb get 0 end]
    set inc {}
    foreach t $vals($varname:inc) {
        if {[lsearch $displayed $t] == -1} {
            lappend inc $t
        }
    }
    set vals($varname:inc) $inc
}

proc Apol_Analysis_domaintrans::attribEnabled {cb lb} {
    variable vals
    if {$vals(targets:attribenable)} {
        $cb configure -state normal
        filterTypeLists $vals(targets:attrib) $lb
    } else {
        $cb configure -state disabled
        filterTypeLists "" $lb
    }
}

proc Apol_Analysis_domaintrans::attribChanged {lb name1 name2 op} {
    variable vals
    if {$vals(targets:attribenable)} {
        filterTypeLists $vals(targets:attrib) $lb
    }
}

proc Apol_Analysis_domaintrans::filterTypeLists {attrib lb} {
    variable vals
    $lb selection clear 0 end
    if {$attrib != ""} {
        set vals(targets:inc_displayed) [lsort [lindex [apol_GetAttribs $attrib] 0 1]]
    } else {
        set vals(targets:inc_displayed) $Apol_Types::typelist
    }
    foreach t $vals(targets:inc) {
        if {[set i [lsearch $vals(targets:inc_displayed) $t]] >= 0} {
            $lb selection set $i $i
        }
    }
}

proc Apol_Analysis_domaintrans::createAccessClasses {f} {
    variable vals
    variable widgets

    set lf [frame $f.left]
    pack $lf -side left -expand 0 -fill both -padx 4 -pady 4
    set l1 [label $lf.l -text "Included Object Classes"]
    pack $l1 -anchor w
    set rf [frame $f.right]
    pack $rf -side left -expand 0 -fill both -padx 4 -pady 4
    set l2 [label $rf.l]
    pack $l2 -anchor w

    set classes [Apol_Widget::makeScrolledListbox $lf.classes -height 10 -width 24 \
                     -listvar Apol_Class_Perms::class_list \
                     -selectmode extended -exportselection 0]
    set classes_lb [Apol_Widget::getScrolledListbox $classes]
    pack $classes -expand 1 -fill both
    set cbb [ButtonBox $lf.cbb -homogeneous 1 -spacing 4]
    $cbb add -text "Include All" \
        -command [list Apol_Analysis_domaintrans::includeAllClasses $classes_lb]
    $cbb add -text "Ignore All" \
        -command [list Apol_Analysis_domaintrans::ignoreAllClasses $classes_lb]
    pack $cbb -pady 4 -expand 0

    set perms [Apol_Widget::makeScrolledListbox $rf.perms -height 10 -width 24 \
                     -listvar Apol_Analysis_domaintrans::vals(classes:perms_displayed) \
                     -selectmode extended -exportselection 0]
    set perms_lb [Apol_Widget::getScrolledListbox $perms]
    pack $perms -expand 1 -fill both
    set pbb [ButtonBox $rf.pbb -homogeneous 1 -spacing 4]
    $pbb add -text "Include All" \
        -command [list Apol_Analysis_domaintrans::includeAllPerms $classes_lb $perms_lb]
    $pbb add -text "Ignore All" \
        -command [list Apol_Analysis_domaintrans::ignoreAllPerms $classes_lb $perms_lb]
    pack $pbb -pady 4 -expand 0

    bind $classes_lb <<ListboxSelect>> \
        [list Apol_Analysis_domaintrans::selectClassListbox $l2 $classes_lb $perms_lb]
    bind $perms_lb <<ListboxSelect>> \
        [list Apol_Analysis_domaintrans::selectPermListbox $classes_lb $perms_lb]

    foreach class_key [array names vals classes:*:enable] {
        if {$vals($class_key)} {
            regexp -- {^classes:([^:]+):enable} $class_key -> class
            set i [lsearch $Apol_Class_Perms::class_list $class]
            $classes_lb selection set $i $i
        }
    }
    if {[set anchor [lindex [lsort [$classes_lb curselection]] 0]] != {}} {
        $classes_lb selection anchor $anchor
        $classes_lb see $anchor
    }
    set vals(classes:perms_displayed) {}
    selectClassListbox $l2 $classes_lb $perms_lb
}

proc Apol_Analysis_domaintrans::selectClassListbox {perm_label lb plb} {
    variable vals
    for {set i 0} {$i < [$lb index end]} {incr i} {
        set c [$lb get $i]
        set vals(classes:$c:enable) [$lb selection includes $i]
    }
    if {[set class [$lb get anchor]] == {}} {
        $perm_label configure -text "Permissions"
        return
    }

    $perm_label configure -text "Permissions for $class"
    set vals(classes:perms_displayed) [lsort [apol_GetAllPermsForClass $class]]
    $plb selection clear 0 end
    foreach p $vals(classes:$class) {
        set i [lsearch $vals(classes:perms_displayed) $p]
        $plb selection set $i
    }
    if {[set anchor [lindex [lsort [$plb curselection]] 0]] != {}} {
        $plb selection anchor $anchor
        $plb see $anchor
    }
    focus $lb
}

proc Apol_Analysis_domaintrans::includeAllClasses {lb} {
    variable vals
    $lb selection set 0 end
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c:enable) 1
    }
}

proc Apol_Analysis_domaintrans::ignoreAllClasses {lb} {
    variable vals
    $lb selection clear 0 end
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c:enable) 0
    }
}

proc Apol_Analysis_domaintrans::selectPermListbox {lb plb} {
    variable vals
    set class [$lb get anchor]
    set p {}
    foreach i [$plb curselection] {
        lappend p [$plb get $i]
    }
    set vals(classes:$class) $p
    focus $plb
}

proc Apol_Analysis_domaintrans::includeAllPerms {lb plb} {
    variable vals
    set class [$lb get anchor]
    $plb selection set 0 end
    set vals(classes:$class) $vals(classes:perms_displayed)
}

proc Apol_Analysis_domaintrans::ignoreAllPerms {lb plb} {
    variable vals
    set class [$lb get anchor]
    $plb selection clear 0 end
    set vals(classes:$class) {}
}

#################### functions that do analyses ####################

proc Apol_Analysis_domaintrans::checkParams {} {
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
    if {$vals(dir) == "forward" && $vals(access:enable)} {
        set vals(search:object_types) $vals(targets:inc)
        set vals(search:classperm_pairs) {}
        foreach class $Apol_Class_Perms::class_list {
            if {$vals(classes:$class:enable) == 0} {
                continue
            }
            foreach perm $vals(classes:$class) {
                lappend vals(search:classperm_pairs) [list $class $perm]
            }
        }
    } else {
        set vals(search:object_types) {}
        set vals(search:classperm_pairs) {}
    }
    if {$vals(regexp:enable)} {
        set vals(search:regexp) $vals(regexp)
    } else {
        set vals(search:regexp) {}
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_domaintrans::analyze {} {
    variable vals
    apol_DomainTransitionAnalysis $vals(dir) $vals(type) $vals(search:object_types) $vals(search:classperm_pairs) $vals(search:regexp)
}

proc Apol_Analysis_domaintrans::analyzeMore {tree node analysis_args} {
    foreach {dir orig_type object_types classperm_pairs regexp} $analysis_args {break}
    set new_start [$tree itemcget $node -text]
    apol_DomainTransitionAnalysis $dir $new_start $object_types $classperm_pairs $regexp
}

################# functions that control analysis output #################

proc Apol_Analysis_domaintrans::createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Domain Trans" [array get vals]]
    if {$vals(dir) == "forward"} {
        set tree_title "Forward Domain Transition"
    } else {
        set tree_title "Reverse Domain Transition"
    }
    set tree_tf [TitleFrame $f.left -text $tree_title]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto both]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg white]
    $sw setwidget $tree
    pack $sw -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Domain Transition Results"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure subtitle -font {Helvetica 10 bold}
    $res.tb tag configure num -foreground blue -font {Helvetica 10 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_domaintrans::treeSelect $res]
    $tree configure -opencmd [list Apol_Analysis_domaintrans::treeOpen $tree]
    return $f
}

proc Apol_Analysis_domaintrans::treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        if {[string index $node 0] == "f" || [string index $node 0] == "r"} {
            renderResultsDTA $res $tree $node [lindex $data 1]
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end $data
        }
        $res.tb configure -state disabled
    }
}

# perform additional domain transitions if this node has not been
# analyzed yet
proc Apol_Analysis_domaintrans::treeOpen {tree node} {
    foreach {search_crit results} [$tree itemcget $node -data] {break}
    if {([string index $node 0] == "f" || [string index $node 0] == "r") && $search_crit != {}} {
        ApolTop::setBusyCursor
        update idletasks
        set retval [catch {analyzeMore $tree $node $search_crit} new_results]
        ApolTop::resetBusyCursor
        if {$retval} {
            tk_messageBox -icon error -type ok -title "Domain Transition Analysis" -message "Could not perform additional analysis:\n\n$new_results"
        } else {
            # mark this node as having been expanded
            $tree itemconfigure $node -data [list {} $results]
            createResultsNodes $tree $node $new_results $search_crit
        }
    }
}

proc Apol_Analysis_domaintrans::clearResultsDisplay {f} {
    variable vals
    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_domaintrans::renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    set top_text [renderTopText]
    $tree itemconfigure top -data $top_text

    set search_crit [list $vals(dir) $vals(type) $vals(search:object_types) $vals(search:classperm_pairs) $vals(search:regexp)]
    createResultsNodes $tree top $results $search_crit
    $tree selection set top
    $tree opentree top 0
    update idletasks
    $tree see top
}

proc Apol_Analysis_domaintrans::renderTopText {} {
    variable vals

    if {$vals(dir) == "forward"} {
        set top_text [list "Forward Domain Transition Analysis: Starting Type: " title]
    } else {
        set top_text [list "Reverse Domain Transition Analysis: Starting Type: " title]
    }
    lappend top_text $vals(type) title_type \
        "\n\n" title
    if {$vals(dir) == "forward"} {
        lappend top_text \
"This tab provides the results of a forward domain transition analysis
starting from the source domain type above.  The results of this
analysis are presented in tree form with the root of the tree (this
node) being the start point for the analysis.

\nEach child node in the tree represents a TARGET DOMAIN TYPE.  A target
domain type is a domain to which the source domain may transition.
You can follow the domain transition tree by opening each subsequent
generation of children in the tree.\n" {}
    } else {
        lappend top_text \
"This tab provides the results of a reverse domain transition analysis
given the target domain type above.  The results of this analysis are
presented in tree form with the root of the tree (this node) being the
target point of the analysis.

\nEach child node in the tree represents a source DOMAIN TYPE.  A source
domain type is a domain that can transition to the target domain.  You
can follow the domain transition tree by opening each subsequent
generation of children in the tree.\n" {}
    }
    lappend top_text \
"\nNOTE: For any given generation, if the parent and the child are the
same, you cannot open the child. This avoids cyclic analyses.

\nThe criteria that defines an allowed domain transition are:

\n1) There must be at least one rule that allows TRANSITION access for
   PROCESS objects between the SOURCE and TARGET domain types.

\n2) There must be at least one FILE TYPE that allows the TARGET type
   ENTRYPOINT access for FILE objects.

\n3) There must be at least one FILE TYPE that meets criterion 2) above
   and allows the SOURCE type EXECUTE access for FILE objects.

\nThe information window shows all the rules and file types that meet
these criteria for each target domain type.

\nFUTURE NOTE: In the future we also plan to show the type_transition
rules that provide for a default domain transitions.  While such rules
cause a domain transition to occur by default, they do not allow it.
Thus, associated type_transition rules are not truly part of the
definition of allowed domain transition" {}
}

proc Apol_Analysis_domaintrans::createResultsNodes {tree parent_node results search_crit} {
    set dir [lindex $search_crit 0]
    foreach r $results {
        foreach {source target intermed execute proctrans entrypoint access_list} $r {break}
        if {$dir == "forward"} {
            set key $target
            set node f:\#auto
        } else {
            set key $source
            set node r:\#auto
        }
        lappend types($key) $proctrans
        lappend types($key:inter) $intermed
        lappend types($key:inter:$intermed:entry) $entrypoint
        lappend types($key:inter:$intermed:exec) $execute
        if {[info exists types($key:access)]} {
            set types($key:access) [concat $types($key:access) $access_list]
        } else {
            set types($key:access) $access_list
        }
    }
    foreach key [lsort [array names types]] {
        if {[string first : $key] != -1} {
            continue
        }
        set ep {}
        set proctrans [lsort -uniq $types($key)]
        foreach intermed [lsort -uniq $types($key:inter)] {
            lappend ep [list $intermed \
                            [lsort -uniq $types($key:inter:$intermed:entry)] \
                            [lsort -uniq $types($key:inter:$intermed:exec)]]
        }
        set access_list [lsort -uniq $types($key:access)]
        set data [list $proctrans $ep $access_list]
        $tree insert end $parent_node $node -text $key -drawcross allways \
            -data [list $search_crit $data]
    }
}

proc Apol_Analysis_domaintrans::renderResultsDTA {res tree node data} {
    set parent_name [$tree itemcget [$tree parent $node] -text]
    set name [$tree itemcget $node -text]
    foreach {proctrans ep access_list} $data {break}
    # direction of domain transition is encoded encoded in the node's
    # identifier
    if {[string index $node 0] == "f"} {
        set header [list "Domain transition from " title \
                        $parent_name title_type \
                        " to " title \
                        $name title_type]
    } else {
        set header [list "Domain transition from " title \
                        $name title_type \
                        " to " title \
                        $parent_name title_type]
    }
    eval $res.tb insert end $header
    $res.tb insert end "\n\n" title_type

    $res.tb insert end "Process Transition Rules: " subtitle \
        [llength $proctrans] num \
        "\n" subtitle
    foreach p $proctrans {
        Apol_Widget::appendSearchResultAVRule $res 6 $p
    }
    $res.tb insert end "\nEntry Point File Types: " subtitle \
        [llength $ep] num
    foreach e [lsort -index 0 $ep] {
        foreach {intermed entrypoint execute} $e {break}
        $res.tb insert end "\n      $intermed\n" {} \
            "            " {} \
            "File Entrypoint Rules: " subtitle \
            [llength $entrypoint] num \
            "\n" subtitle
        foreach e $entrypoint {
            Apol_Widget::appendSearchResultAVRule $res 12 $e
        }
        $res.tb insert end "\n" {} \
            "            " {} \
            "File Execute Rules: " subtitle \
            [llength $execute] num \
            "\n" subtitle
        foreach e $execute {
            Apol_Widget::appendSearchResultAVRule $res 12 $e
        }
    }
    if {[llength $access_list] > 0} {
        $res.tb insert end "\n" {} \
            "The access filters you specified returned the following rules: " subtitle \
            [llength $access_list] num \
            "\n" subtitle
        foreach a $access_list {
            Apol_Widget::appendSearchResultAVRule $res 6 $a
        }
    }
}
