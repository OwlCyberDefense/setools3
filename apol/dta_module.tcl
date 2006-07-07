#############################################################
#  dta_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com, mayerf@tresys.com>
# -----------------------------------------------------------
#
# This module implements the domain transition analysis interface.


namespace eval Apol_Analysis_dta {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_dta" "Domain Transition"
}

proc Apol_Analysis_dta::open {} {
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

proc Apol_Analysis_dta::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_dta::getInfo {} {
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

proc Apol_Analysis_dta::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set dir_tf [TitleFrame $options_frame.dir -text "Direction"]
    pack $dir_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set forward_dir [radiobutton [$dir_tf getframe].forward -text "Forward" \
                         -variable Apol_Analysis_dta::vals(dir) -value forward]
    set reverse_dir [radiobutton [$dir_tf getframe].reverse -text "Reverse" \
                         -variable Apol_Analysis_dta::vals(dir) -value reverse]
    pack $forward_dir $reverse_dir -anchor w
    trace add variable Apol_Analysis_dta::vals(dir) write \
        Apol_Analysis_dta::toggleDirection

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -textvariable Apol_Analysis_dta::vals(type:label)]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -anchor nw
    set access_f [frame [$filter_tf getframe].access]
    pack $access_f -anchor nw -pady 8
    set widgets(access_enable) [checkbutton $access_f.enable -text "Use access filters" \
                                    -variable Apol_Analysis_dta::vals(access:enable)]
    set widgets(access) [button $access_f.b -text "Access Filters" \
                             -command Apol_Analysis_dta::createAccessDialog \
                             -state disabled]
    pack $widgets(access_enable) -anchor w
    pack $widgets(access) -anchor w -padx 4
    trace add variable Apol_Analysis_dta::vals(access:enable) write \
        Apol_Analysis_dta::toggleAccessSelected
}

proc Apol_Analysis_dta::newAnalysis {} {
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

proc Apol_Analysis_dta::updateAnalysis {f} {
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

proc Apol_Analysis_dta::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_dta::switchTab {query_options} {
    variable vals
    array set vals $query_options
    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_dta::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        switch -- $key {
            targets:inc_displayed -
            classes:perms_displayed {
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

proc Apol_Analysis_dta::loadQuery {channel} {
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

proc Apol_Analysis_dta::gotoLine {tab line_num} {
}

proc Apol_Analysis_dta::search {tab str case_Insensitive regExpr srch_Direction } {
}

#################### private functions below ####################

proc Apol_Analysis_dta::reinitializeVals {} {
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
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c) [lsort [apol_GetAllPermsForClass $c]]
        set vals(classes:$c:enable) 1
    }
}

proc Apol_Analysis_dta::reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(type:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(type) [list $vals(type) $vals(type:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    }
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_dta::toggleDirection {name1 name2 op} {
    variable vals
    if {$vals(dir) == "forward"} {
        set vals(type:label) "Source domain"
    } elseif {$vals(dir) == "reverse"} {
        set vals(type:label) "Target domain"
    }
    maybeEnableAccess
}

proc Apol_Analysis_dta::toggleAccessSelected {name1 name2 op} {
    maybeEnableAccess
}

proc Apol_Analysis_dta::maybeEnableAccess {} {
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

proc Apol_Analysis_dta::createAccessDialog {} {
    destroy .dta_adv
    set d [Dialog .dta_adv -modal local -separator 1 -title "DTA Access Filter" -parent .]
    $d add -text "Close"
    createAccessTargets [$d getframe]
    createAccessClasses [$d getframe]
    $d draw
}

proc Apol_Analysis_dta::createAccessTargets {f} {
    variable vals

    set type_f [frame $f.targets]
    pack $type_f -side left -expand 0 -fill both -padx 4 -pady 4
    set l1 [label $type_f.l1 -text "Included Object Types:"]
    pack $l1 -anchor w

    set targets [Apol_Widget::makeScrolledListbox $type_f.targets -height 10 -width 24 \
                 -listvar Apol_Analysis_dta::vals(targets:inc_displayed) \
                 -selectmode extended -exportselection 0]
    bind $targets.lb <<ListboxSelect>> \
        [list Apol_Analysis_dta::selectTargetListbox $targets.lb]
    pack $targets -expand 0 -fill both

    set bb [ButtonBox $type_f.bb -homogeneous 1 -spacing 4]
    $bb add -text "Include All" \
        -command [list Apol_Analysis_dta::includeAllItems $targets.lb targets]
    $bb add -text "Ignore All" \
        -command [list Apol_Analysis_dta::ignoreAllItems $targets.lb targets]
    pack $bb -pady 4

    set attrib [frame $type_f.a]
    pack $attrib
    set attrib_enable [checkbutton $attrib.ae -anchor w \
                           -text "Filter by attribute:" \
                           -variable Apol_Analysis_dta::vals(targets:attribenable)]
    set attrib_box [ComboBox $attrib.ab -autopost 1 -entrybg white -width 16 \
                        -values $Apol_Types::attriblist \
                        -textvariable Apol_Analysis_dta::vals(targets:attrib)]
    $attrib_enable configure -command \
        [list Apol_Analysis_dta::attribEnabled $attrib_box $targets.lb]
    # remove any old traces on the attribute
    trace remove variable Apol_Analysis_dta::vals(targets:attrib) write \
        [list Apol_Analysis_dta::attribChanged $targets.lb]
    trace add variable Apol_Analysis_dta::vals(targets:attrib) write \
        [list Apol_Analysis_dta::attribChanged $targets.lb]
    pack $attrib_enable -side top -expand 0 -fill x -anchor sw -padx 5 -pady 2
    pack $attrib_box -side top -expand 1 -fill x -padx 10
    attribEnabled $attrib_box $targets.lb
}

proc Apol_Analysis_dta::selectTargetListbox {lb} {
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

proc Apol_Analysis_dta::includeAllItems {lb varname} {
    variable vals
    $lb selection set 0 end
    set displayed [$lb get 0 end]
    set vals($varname:inc) [lsort -uniq [concat $vals($varname:inc) $displayed]]
}

proc Apol_Analysis_dta::ignoreAllItems {lb varname} {
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

proc Apol_Analysis_dta::attribEnabled {cb lb} {
    variable vals
    if {$vals(targets:attribenable)} {
        $cb configure -state normal
        filterTypeLists $vals(targets:attrib) $lb
    } else {
        $cb configure -state disabled
        filterTypeLists "" $lb
    }
}

proc Apol_Analysis_dta::attribChanged {lb name1 name2 op} {
    variable vals
    if {$vals(targets:attribenable)} {
        filterTypeLists $vals(targets:attrib) $lb
    }
}

proc Apol_Analysis_dta::filterTypeLists {attrib lb} {
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

proc Apol_Analysis_dta::createAccessClasses {f} {
    variable vals
    variable widgets

    set lf [frame $f.left]
    pack $lf -side left -expand 0 -fill both -padx 4 -pady 4
    set l1 [label $lf.l -text "Included Object Classes:"]
    pack $l1 -anchor w
    set rf [frame $f.right]
    pack $rf -side left -expand 0 -fill both -padx 4 -pady 4
    set l2 [label $rf.l]
    pack $l2 -anchor w

    set classes [Apol_Widget::makeScrolledListbox $lf.classes -height 10 -width 24 \
                     -listvar Apol_Class_Perms::class_list \
                     -selectmode extended -exportselection 0]
    pack $classes -expand 1 -fill both
    set cbb [ButtonBox $lf.cbb -homogeneous 1 -spacing 4]
    $cbb add -text "Include All" \
        -command [list Apol_Analysis_dta::includeAllClasses $classes.lb]
    $cbb add -text "Ignore All" \
        -command [list Apol_Analysis_dta::ignoreAllClasses $classes.lb]
    pack $cbb -pady 4 -expand 0

    set perms [Apol_Widget::makeScrolledListbox $rf.perms -height 10 -width 24 \
                     -listvar Apol_Analysis_dta::vals(classes:perms_displayed) \
                     -selectmode extended -exportselection 0]
    pack $perms -expand 1 -fill both
    set pbb [ButtonBox $rf.pbb -homogeneous 1 -spacing 4]
    $pbb add -text "Include All" \
        -command [list Apol_Analysis_dta::includeAllPerms $classes.lb $perms.lb]
    $pbb add -text "Ignore All" \
        -command [list Apol_Analysis_dta::ignoreAllPerms $classes.lb $perms.lb]
    pack $pbb -pady 4 -expand 0

    bind $classes.lb <<ListboxSelect>> \
        [list Apol_Analysis_dta::selectClassListbox $l2 $classes.lb $perms.lb]
    bind $perms.lb <<ListboxSelect>> \
        [list Apol_Analysis_dta::selectPermListbox $classes.lb $perms.lb]

    set anchor [$classes.lb index end]
    foreach class_key [array names vals classes:*:enable] {
        if {$vals($class_key)} {
            regexp -- {^classes:([^:]+):enable} $class_key -> class
            set i [lsearch $Apol_Class_Perms::class_list $class]
            $classes.lb selection set $i $i
            if {$i < $anchor} {
                set anchor $i
            }
        }
    }
    if {$anchor != [$classes.lb index end]} {
        $classes.lb selection anchor $anchor
    }
    set vals(classes:perms_displayed) {}
    selectClassListbox $l2 $classes.lb $perms.lb
}

proc Apol_Analysis_dta::selectClassListbox {perm_label lb plb} {
    variable vals
    for {set i 0} {$i < [$lb index end]} {incr i} {
        set c [$lb get $i]
        set vals(classes:$c:enable) [$lb selection includes $i]
    }
    if {[set class [$lb get anchor]] == {}} {
        $perm_label configure -text "Permissions"
        return
    }

    $perm_label configure -text "Permissions for $class:"
    set vals(classes:perms_displayed) [lsort [apol_GetAllPermsForClass $class]]
    $plb selection clear 0 end
    foreach p $vals(classes:$class) {
        set i [lsearch $vals(classes:perms_displayed) $p]
        $plb selection set $i
    }
    focus $lb
}

proc Apol_Analysis_dta::includeAllClasses {lb} {
    variable vals
    $lb selection set 0 end
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c:enable) 1
    }
}

proc Apol_Analysis_dta::ignoreAllClasses {lb} {
    variable vals
    $lb selection clear 0 end
    foreach c $Apol_Class_Perms::class_list {
        set vals(classes:$c:enable) 0
    }
}

proc Apol_Analysis_dta::selectPermListbox {lb plb} {
    variable vals
    set class [$lb get anchor]
    set p {}
    foreach i [$plb curselection] {
        lappend p [$plb get $i]
    }
    set vals(classes:$class) $p
    focus $plb
}

proc Apol_Analysis_dta::includeAllPerms {lb plb} {
    variable vals
    set class [$lb get anchor]
    $plb selection set 0 end
    set vals(classes:$class) $vals(classes:perms_displayed)
}

proc Apol_Analysis_dta::ignoreAllPerms {lb plb} {
    variable vals
    set class [$lb get anchor]
    $plb selection clear 0 end
    set vals(classes:$class) {}
}

#################### functions that do analyses ####################

proc Apol_Analysis_dta::checkParams {} {
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
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_dta::analyze {} {
    return
}


################# functions that control analysis output #################

proc Apol_Analysis_dta::createResultsDisplay {} {
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
    $res.tb tag configure subtitle -font {Helvetica 12 bold}
    $res.tb tag configure num -foreground blue -font {Helvetica 12 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_dta::treeSelect $res]
    return $f
}

proc Apol_Analysis_dta::treeSelect {res tree node} {
}

proc Apol_Analysis_dta::clearResultsDisplay {f} {
    variable vals
    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_dta::renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    $tree itemconfigure top -data $top_text
    $tree selection set top
    $tree opentree top
    update idletasks
    $tree see top
}


#################### attic ####################

namespace eval Apol_Analysis_dta {
	# Options widgets
	variable combo_domain
	variable combo_attribute
	variable cb_attrib
	variable entry_frame
	# Forward transition advanced options search widgets
	variable forward_options_Dlg
	set forward_options_Dlg .forward_options_Dlg
	variable adv_frame
	variable b_forward_options
	variable cb_filters
	variable progressDlg
	set progressDlg .progress
	variable progressmsg		""
	variable progress_indicator	-1

	# Options Display Variables
	variable display_type			""
	variable display_attribute		""
	variable display_attrib_sel		0
	variable display_direction		"forward"
	variable endtype_sel			0
	variable end_type			""
	variable use_filters			0

	# Options State Variables
	variable type_state			""
	variable attribute_state		""
	variable attrib_selected_state		0
	variable direction_state		"forward"
	variable endtype_sel_state		0
	variable end_type_state			""
	variable use_filters_state		0

	# Current results display
	variable dta_tree		""
	variable dta_info_text		""

	# Array to hold multiple instances of the forward DTA advanced options dialog
	variable f_opts
	# Result type filters dialog widgets
	variable b_incl_all_perms
	variable b_excl_all_perms

	# Defined Tag Names
	variable title_tag		TITLE
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	variable rules_tag		RULES
	variable counters_tag		COUNTERS
	variable types_tag		TYPE
	variable disabled_rule_tag	DISABLE_RULE
	variable excluded_tag		" (Excluded)"

	# root text for forward dta results
	variable dta_root_text_f	"\n\nThis tab provides the results of a forward domain transition analysis\
		starting from the source domain type above.  The results of this analysis are presented in tree form with the root\
		of the tree (this node) being the start point for the analysis.\n\nEach child node in the tree represents\
		a TARGET DOMAIN TYPE.  A target domain type is a domain to which the source domain may transition.  You can\
		follow the domain transition tree by opening each subsequent generation of children in the tree.\n\nNOTE: For any\
		given generation, if the parent and the child are the same, you cannot open the child. This avoids cyclic analyses.\n\nThe\
		criteria that defines an allowed domain transition are:\n\n1) There must be at least one rule that allows TRANSITION\
		access for PROCESS objects between the SOURCE and TARGET domain types.\n\n2) There must be at least one FILE TYPE that\
		allows the TARGET type ENTRYPOINT access for FILE objects.\n\n3) There must be at least one FILE TYPE that meets\
		criterion 2) above and allows the SOURCE type EXECUTE access for FILE objects.\n\nThe information window shows\
		all the rules and file types that meet these criteria for each target domain type.\n\nFUTURE NOTE: In the future\
		we also plan to show the type_transition rules that provide for a default domain transitions.  While such rules\
		cause a domain transition to occur by default, they do not allow it.  Thus, associated type_transition rules\
		are not truly part of the definition of allowed domain transitions."

	# root text for reverse dta results
	variable dta_root_text_r	"\n\nThis tab provides the results of a reverse domain transition analysis\
		given the target domain type above.  The results of this analysis are presented in tree form with the root\
		of the tree (this node) being the target point of the analysis.\n\nEach child node in the tree represents\
		a source DOMAIN TYPE.  A source domain type is a domain that can transition to the target domain.  You can\
		follow the domain transition tree by opening each subsequent generation of children in the tree.\n\nNOTE: For any\
		given generation, if the parent and the child are the same, you cannot open the child. This avoids cyclic analyses.\n\nThe\
		criteria that defines an allowed domain transition are:\n\n1) There must be at least one rule that allows TRANSITION\
		access for PROCESS objects between the SOURCE and TARGET domain types.\n\n2) There must be at least one FILE TYPE that\
		allows the TARGET type ENTRYPOINT access for FILE objects.\n\n3) There must be at least one FILE TYPE that meets\
		criterion 2) above and allows the SOURCE type EXECUTE access for FILE objects.\n\nThe information window shows\
		all the rules and file types that meet these criteria for each source domain type.\n\nFUTURE NOTE: In the future\
		we also plan to show the type_transition rules that provide for a default domain transitions.  While such rules\
		cause a domain transition to occur by default, they do not allow it.  Thus, associated type_transition rules\
		are not truly part of the definition of allowed domain transitions."
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::do_analysis { results_frame } {
	variable display_type
	variable display_attribute
	variable display_attrib_sel
	variable endtype_sel
	variable end_type
	variable dta_tree
	variable dta_info_text
	# Advanced foward options DTA variables
	variable f_opts
	variable forward_options_Dlg

        if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -code error
        }
        Apol_Analysis_dta::display_progressDlg

        # Initialize local variables
        set reverse 0
	set num_object_classes 0
	set perm_options ""
        set types ""
	set use_filters 0

        # Only parse advanced options if this is a forward DTA analysis
	if {$Apol_Analysis_dta::display_direction == "forward"} {
		if {$Apol_Analysis_dta::use_filters} {
			set types $f_opts($forward_options_Dlg,filtered_incl_types)

			# At this point we need to handle the data used by the advanced foward DTA options dialog.
		        # If the advanced options object doesn't exist, then create it.
			if {![array exists f_opts] || [array names f_opts "$forward_options_Dlg,name"] == ""} {
				Apol_Analysis_dta::forward_options_create_object $forward_options_Dlg
			}

			foreach class $f_opts($forward_options_Dlg,class_list) {
				set perms ""
				# Make sure to strip out just the class name, as this may be an excluded class.
				set idx [string first $Apol_Analysis_dta::excluded_tag $class]
				if {$idx == -1} {
					set class_elements [array names f_opts "$forward_options_Dlg,perm_status_array,$class,*"]
					set class_added 0
					foreach element $class_elements {
						set perm [lindex [split $element ","] 3]
						if {[string equal $f_opts($element) "include"]} {
							if {$class_added == 0} {
								incr num_object_classes
								set perm_options [lappend perm_options $class]
								set class_added 1
							}
							set perms [lappend perms $perm]
						}
					}
					if {$perms != ""} {
						set perm_options [lappend perm_options [llength $perms]]
						foreach perm $perms {
							set perm_options [lappend perm_options $perm]
						}
					}
				}
			}
			set use_filters 1
		}
	} else {
		set reverse 1
	}

	set rt [catch {set results [apol_DomainTransitionAnalysis \
		$reverse \
		$display_type \
		$use_filters \
		$num_object_classes \
		$perm_options \
		$types \
		$endtype_sel \
		$end_type]} err]
	Apol_Analysis_dta::destroy_progressDlg
	if {$rt != 0} {
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	}

	set query_args [list \
		$reverse \
		$display_type \
		$use_filters \
		$num_object_classes \
		$perm_options \
		$types \
		$endtype_sel \
		$end_type]

	set dta_tree [Apol_Analysis_dta::create_resultsDisplay $results_frame $reverse]
	set rt [catch {Apol_Analysis_dta::create_result_tree_structure $dta_tree $results $query_args} err]
	if {$rt != 0} {
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_target_type_nodes
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_target_type_nodes { parent dta_tree results_list } {
	if { [file tail [$dta_tree parent $parent]] == [file tail $parent] } {
		return
	}
	if { [file tail [$dta_tree parent $parent]] == [file tail $parent] } {
		return
	}

	if { [$dta_tree nodes $parent] == "" } {
		# Get # of target domain types (if none, then just draw the tree without child nodes)
		set num_target_domains [lindex $results_list 1]
		# If there are any target types then create and insert children nodes for the source_type node
		set start_idx 2
		for { set x 0 } { $x < $num_target_domains } { incr x } {
			set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $start_idx]
			if {$end_idx == -1} {
				# Print error
				return -code error "Error parsing results for type [lindex $results_list $start_idx].\n"
			}
			set target_name [lindex $results_list $start_idx]
			set target_node "${parent}/${target_name}/"
			$dta_tree insert end $parent $target_node -text $target_name \
				-open 0	\
			-drawcross allways \
			-data [lrange $results_list [expr $start_idx +1] $end_idx]
		        set start_idx [expr $end_idx + 1]
		}
		set nodes [lsort [$dta_tree nodes $parent]]
		$dta_tree reorder $parent $nodes
	        $dta_tree configure -redraw 1
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::do_child_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::do_child_analysis { dta_tree selected_node } {
	ApolTop::setBusyCursor
	if { [$dta_tree nodes $selected_node] == "" } {
		set query_args [$dta_tree itemcget [$dta_tree nodes root] -data]
		set start_type [file tail $selected_node]
		set rt [catch {set results [apol_DomainTransitionAnalysis \
			[lindex $query_args 0] \
			$start_type \
			[lindex $query_args 2] \
			[lindex $query_args 3] \
			[lindex $query_args 4] \
			[lindex $query_args 5] \
			[lindex $query_args 6] \
			[lindex $query_args 7]]} err]

		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message $err
		}
		set rt [catch {Apol_Analysis_dta::create_target_type_nodes $selected_node $dta_tree $results} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message $err
		}
	}
	ApolTop::resetBusyCursor
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_target_type_data_end_idx
#
#  This worker function takes a list and extracts from it the idx of the
#  last data item for the current target.  This proc assumes that the idx is the index
#  of the first element of the current child target type.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_target_type_data_end_idx { results_list idx } {
	# First see if this is the end of the list
	if {$idx >= [llength $results_list]} {
		# return -1 as error code
		return -1
	}

	# Determine length of sublist containing type's data
	#
	# type (name) and (# of pt rules)
	set len 1
	# account for the (pt rules)
	set num_pt [lindex $results_list [expr $idx + $len]]
	# We multiply the number of pt rules by three because each pt rule consists of:
	#	1. rule
	#	2. line number
	#	3. enabled flag
	incr len [expr $num_pt * 3]
	# (# of file types)
	incr len
	set num_types [lindex $results_list [expr $idx + $len]]
	for {set i 0} { $i < $num_types } { incr i } {
		# (file type) and (# ep rules)
		incr len 2
		# account for (ep rules)
		set num_ep [lindex $results_list [expr $idx + $len]]
		# We multiply the number of ep rules by three because each pt rule consists of:
		#	1. rule
		#	2. line number
		#	3. enabled flag
		incr len [expr $num_ep * 3]
		# (# ex rules)
		incr len
		# account for (ex rules)
		set num_ex [lindex $results_list [expr $idx + $len]]

		# We multiply the number of ex rules by three because each pt rule consists of:
		#	1. rule
		#	2. line number
		#	3. enabled flag
		incr len [expr $num_ex * 3]
	}
	# (# addtional rules)
	incr len
	set num_additional [lindex $results_list [expr $idx + $len]]
	# We multiply the number of ex rules by three because each pt rule consists of:
	#	1. rule
	#	2. line number
	#	3. enabled flag
	incr len [expr $num_additional * 3]

	return [expr $len + $idx]
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::render_target_type_data
#
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::render_target_type_data { data dta_info_text dta_tree node} {
	$dta_info_text configure -state normal
        $dta_info_text delete 0.0 end
	$dta_info_text configure -wrap none

	# First see if this is the end of the list
	if { $data == "" } {
	        $dta_info_text configure -state disabled
		return ""
	}
	set target [$dta_tree itemcget $node -text]
	set parent [$dta_tree itemcget [$dta_tree parent $node] -text]
	# Set the mark to 0.0
	$dta_info_text mark set insert 1.0
	set start_idx [$dta_info_text index insert]

	$dta_info_text insert end "Domain transition from "
	# The character at $end_idx isn't tagged, so must add 1 to $end_idx argument.
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_tag $start_idx $end_idx

	set start_idx [$dta_info_text index insert]
	if {[lindex [$dta_tree itemcget [$dta_tree nodes root] -data] 0]} {
		$dta_info_text insert end $target
	} else {
		$dta_info_text insert end $parent
	}
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx

	set start_idx [$dta_info_text index insert]
	$dta_info_text insert end " to "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_tag $start_idx $end_idx

	set start_idx [$dta_info_text index insert]
	if {[lindex [$dta_tree itemcget [$dta_tree nodes root] -data] 0]} {
		$dta_info_text insert end $parent
	} else {
		$dta_info_text insert end $target
	}
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx

	# (# of pt rules)
	$dta_info_text insert end "\n\n"
	set start_idx [$dta_info_text index insert]
	set idx 0
	set num_pt [lindex $data $idx]

	$dta_info_text insert end "Process Transition Rules:  "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
	set start_idx $end_idx
	$dta_info_text insert end "$num_pt\n"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx

	for {set i 0} { $i < $num_pt } { incr i } {
		incr idx
		set rule [lindex $data $idx]
		incr idx
		set lineno [lindex $data $idx]

		$dta_info_text insert end "\t"
		set start_idx [$dta_info_text index insert]

		# Only display line number hyperlink if this is not a binary policy.
		if {![ApolTop::is_binary_policy]} {
			$dta_info_text insert end "($lineno) "
			set end_idx [$dta_info_text index insert]
			Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
			set start_idx $end_idx
		}
		$dta_info_text insert end "$rule"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx

		incr idx
		# The next element should be the enabled boolean flag.
		if {[lindex $data $idx] == 0} {
			$dta_info_text insert end "   "
			set startIdx [$dta_info_text index insert]
			$dta_info_text insert end "\[Disabled\]\n"
			set endIdx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
		} else {
			$dta_info_text insert end "\n"
		}
	}
	incr idx
	# (# of file types)
	set num_types [lindex $data $idx ]
	set start_idx $end_idx
	$dta_info_text insert end "\nEntry Point File Types:  "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
	set start_idx $end_idx
	$dta_info_text insert end "$num_types\n"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx

	for {set i 0} { $i < $num_types } { incr i } {
		incr idx
		# (file type)
		set type [lindex $data $idx]
		set start_idx $end_idx
		$dta_info_text insert end "\t$type\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::types_tag $start_idx $end_idx
		incr idx
		set num_ep [lindex $data $idx]

		set start_idx $end_idx
		$dta_info_text insert end "\t\tFile Entrypoint Rules:  "
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$dta_info_text insert end "$num_ep\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx

		for {set j 0 } { $j < $num_ep } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]

			$dta_info_text insert end "\t\t"
			set start_idx [$dta_info_text index insert]

			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dta_info_text insert end "($lineno) "
				set end_idx [$dta_info_text index insert]
				Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$dta_info_text insert end "$rule"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx

			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$dta_info_text insert end "   "
				set startIdx [$dta_info_text index insert]
				$dta_info_text insert end "\[Disabled\]\n"
				set endIdx [$dta_info_text index insert]
				$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
			} else {
				$dta_info_text insert end "\n"
			}
		}
		incr idx
		set num_ex [lindex $data $idx]

		set start_idx $end_idx
		$dta_info_text insert end "\n\t\tFile Execute Rules:  "
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$dta_info_text insert end "$num_ex\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx

		for { set j 0 } { $j < $num_ex } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]

			$dta_info_text insert end "\t\t"
			set start_idx [$dta_info_text index insert]

			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dta_info_text insert end "($lineno) "
				set end_idx [$dta_info_text index insert]
				Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$dta_info_text insert end "$rule"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx

			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$dta_info_text insert end "   "
				set startIdx [$dta_info_text index insert]
				$dta_info_text insert end "\[Disabled\]\n"
				set endIdx [$dta_info_text index insert]
				$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
			} else {
				$dta_info_text insert end "\n"
			}
		}
	}
	set reverse [lindex [$dta_tree itemcget [$dta_tree nodes root] -data] 0]
	if {!$reverse && $Apol_Analysis_dta::use_filters} {
		incr idx
		set num_additional [lindex $data $idx]

		$dta_info_text insert end "\n"
		set start_idx [$dta_info_text index insert]
		$dta_info_text insert end "The access filters you specified returned the following rules"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		#set start_idx [$dta_info_text index insert]
		#$dta_info_text insert end $target
		#set end_idx [$dta_info_text index insert]
		#$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx
		$dta_info_text insert end ": "
		set start_idx [$dta_info_text index insert]
		$dta_info_text insert end "$num_additional\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
		#$dta_info_text insert end " rules\n"
		for {set j 0 } { $j < $num_additional } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]

			$dta_info_text insert end "\t"
			set start_idx [$dta_info_text index insert]

			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dta_info_text insert end "($lineno) "
				set end_idx [$dta_info_text index insert]
				Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$dta_info_text insert end "$rule"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx

			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$dta_info_text insert end "   "
				set startIdx [$dta_info_text index insert]
				$dta_info_text insert end "\[Disabled\]\n"
				set endIdx [$dta_info_text index insert]
				$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
			} else {
				$dta_info_text insert end "\n"
			}
		}
	}

	$dta_info_text configure -state disabled
	return 0
}

###########################################################################
# ::display_root_type_info
#
proc Apol_Analysis_dta::display_root_type_info { source_type dta_info_text dta_tree } {

        $dta_info_text configure -state normal
        $dta_info_text delete 0.0 end
        if {[lindex [$dta_tree itemcget $source_type -data] 0]} {
	    $dta_info_text insert end "Reverse Domain Transition Analysis: Starting Type:  "
        } else {
	    $dta_info_text insert end "Forward Domain Transition Analysis: Starting Type:  "
        }

	$dta_info_text tag add ROOT_TITLE 0.0 end
	$dta_info_text tag configure ROOT_TITLE -font {Helvetica 14 bold}
	set start_idx [$dta_info_text index insert]
	$dta_info_text insert end "$source_type"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add ROOT_TYPE $start_idx $end_idx
	$dta_info_text tag configure ROOT_TYPE -font {Helvetica 14 bold} -foreground blue

	# now add the standard text
	$dta_info_text configure -wrap word
	set start_idx [$dta_info_text index insert]
	if {[lindex [$dta_tree itemcget $source_type -data] 0]} {
		set root_text $Apol_Analysis_dta::dta_root_text_r
	} else {
		set root_text $Apol_Analysis_dta::dta_root_text_f

	}
	$dta_info_text insert end $root_text
	$dta_info_text tag add ROOT_TEXT $start_idx end
	$dta_info_text tag configure ROOT_TEXT -font $ApolTop::text_font
	$dta_info_text configure -state disabled
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::insert_src_type_node
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::insert_src_type_node { dta_tree query_args } {
	$dta_tree insert end root [lindex $query_args 1] -text [lindex $query_args 1] \
		-open 1	\
	-drawcross auto \
	-data $query_args
        return [$dta_tree nodes root]
}
