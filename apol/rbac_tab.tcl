# Copyright (C) 2001-2007 Tresys Technology, LLC
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

namespace eval Apol_RBAC {
    variable vals
    variable widgets
}

proc Apol_RBAC::create {tab_name nb} {
    variable vals
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "RBAC Rules"]
    set topf [frame $frame.top]
    set bottomf [frame $frame.bottom]
    pack $topf -expand 0 -fill both -pady 2
    pack $bottomf -expand 1 -fill both -pady 2

    set rsbox [TitleFrame $topf.rs -text "Rule Selection"]
    set obox [TitleFrame $topf.opts -text "Search Options"]
    set dbox [TitleFrame $bottomf.results -text "RBAC Rules Display"]
    pack $rsbox -side left -expand 0 -fill both -padx 2
    pack $obox -side left -expand 1 -fill both -padx 2
    pack $dbox -expand 1 -fill both -padx 2

    # Rule selection subframe
    set rs [$rsbox getframe]
    radiobutton $rs.allow -text allow -value allow \
        -variable Apol_RBAC::vals(rule_selection)
    radiobutton $rs.trans -text role_transition -value trans \
        -variable Apol_RBAC::vals(rule_selection)
    radiobutton $rs.both -text "allow and role_transition" -value both \
        -variable Apol_RBAC::vals(rule_selection)
    trace add variable Apol_RBAC::vals(rule_selection) write \
        [list Apol_RBAC::_ruleChanged]
    pack $rs.allow $rs.trans $rs.both -side top -anchor w

    set widgets(options_pm) [PagesManager [$obox getframe].opts]

    _allowCreate [$widgets(options_pm) add allow]
    _transCreate [$widgets(options_pm) add trans]
    _bothCreate [$widgets(options_pm) add both]
    trace add variable Apol_RBAC::vals(source:which) write Apol_RBAC::_toggleRoleBox

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise allow

    set ok [button [$obox getframe].ok -text OK -width 6 -command Apol_RBAC::_searchRBACs]
    pack $ok -side right -padx 5 -pady 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_RBAC::open {ppath} {
    variable vals
    variable widgets
    $widgets(allow:source) configure -values $Apol_Roles::role_list
    $widgets(allow:target) configure -values $Apol_Roles::role_list
    $widgets(trans:source) configure -values $Apol_Roles::role_list
    $widgets(trans:default) configure -values $Apol_Roles::role_list
    $widgets(both:source) configure -values $Apol_Roles::role_list

    # force a refresh of the types box for transitions
    set vals(target_type:types) $vals(target_type:types)

    # force a flip to the allow page
    set vals(rule_selection) allow
}

proc Apol_RBAC::close {} {
    variable widgets

    _initializeVars
    $widgets(allow:source) configure -values {}
    $widgets(allow:target) configure -values {}
    $widgets(trans:source) configure -values {}
    $widgets(trans:target) configure -values {}
    $widgets(trans:default) configure -values {}
    $widgets(both:source) configure -values {}
}

proc Apol_RBAC::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

#### private functions below ####

proc Apol_RBAC::_initializeVars {} {
    variable vals
    array set vals {
        rule_selection allow

        source:use 0
        source:sym {}
        source:which source

        target_role:use 0
        target_role:sym {}
        target_type:use 0
        target_type:sym {}
        target_type:types 1
        target_type:attribs 0

        default:use 0
        default:sym {}
    }
}

proc Apol_RBAC::_allowCreate {a_f} {
    variable vals
    variable widgets

    set source [frame $a_f.source]
    set source_cb [checkbutton $source.enable -text "Source role" \
                       -variable Apol_RBAC::vals(source:use)]
    set widgets(allow:source) [ComboBox $source.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(source:sym) \
                                   -helptext "Type or select a role" -autopost 1]
    set which_fm [frame $source.which]
    set which_source [radiobutton $which_fm.source \
                          -text "As source" -state disabled \
                          -variable Apol_RBAC::vals(source:which) \
                          -value source]
    set which_any [radiobutton $which_fm.any \
                       -text "As source or target" -state disabled \
                       -variable Apol_RBAC::vals(source:which) \
                       -value either]
    trace add variable Apol_RBAC::vals(source:use) write \
        [list Apol_RBAC::_toggleCheckbutton $widgets(allow:source) [list $which_source $which_any]]
    pack $which_source $which_any -side top -anchor w
    pack $source_cb -side top -anchor w
    pack $widgets(allow:source) -side top -expand 0 -fill x -padx 4
    pack $which_fm -anchor w -padx 8
    pack $source -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set target [frame $a_f.target]
    set widgets(allow:target_cb) [checkbutton $target.enable -text "Target role" \
                                      -variable Apol_RBAC::vals(target_role:use)]
    set widgets(allow:target) [ComboBox $target.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(target_role:sym) \
                                   -helptext "Type or select a role" -autopost 1]
    trace add variable Apol_RBAC::vals(target_role:use) write \
        [list Apol_RBAC::_toggleCheckbutton $widgets(allow:target) {}]
    pack $widgets(allow:target_cb) -side top -anchor w
    pack $widgets(allow:target) -side top -expand 0 -fill x -padx 4
    pack $target -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_RBAC::_transCreate {t_f} {
    variable vals
    variable widgets

    set source [frame $t_f.source]
    set source_cb [checkbutton $source.enable -text "Source role" \
                       -variable Apol_RBAC::vals(source:use)]
    set widgets(trans:source) [ComboBox $source.cb -width 20 -state disabled \
                                        -entrybg $ApolTop::default_bg_color \
                                        -textvariable Apol_RBAC::vals(source:sym) \
                                        -helptext "Type or select a role" -autopost 1]
    set which_fm [frame $source.which]
    set which_source [radiobutton $which_fm.source \
                          -text "As source" -state disabled \
                          -variable Apol_RBAC::vals(source:which) \
                          -value source]
    set which_any [radiobutton $which_fm.any \
                       -text "As source or default" -state disabled \
                       -variable Apol_RBAC::vals(source:which) \
                       -value either]
    trace add variable Apol_RBAC::vals(source:use) write \
        [list Apol_RBAC::_toggleCheckbutton $widgets(trans:source) [list $which_source $which_any]]
    pack $which_source $which_any -side top -anchor w
    pack $source_cb -side top -anchor w
    pack $widgets(trans:source) -side top -expand 0 -fill x -padx 4
    pack $which_fm -anchor w -padx 8
    pack $source -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set target [frame $t_f.target]
    set target_cb [checkbutton $target.enable -text "Target type" \
                       -variable Apol_RBAC::vals(target_type:use)]
    set widgets(trans:target) [ComboBox $target.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(target_type:sym) \
                                   -helptext "Type or select a type/attribute" -autopost 1]
    set ta_frame [frame $target.ta]
    set types [checkbutton $ta_frame.types -text "Types" -state disabled \
                   -variable Apol_RBAC::vals(target_type:types)]
    set attribs [checkbutton $ta_frame.attribs -text "Attribs" -state disabled \
                   -variable Apol_RBAC::vals(target_type:attribs)]
    $types configure -command [list Apol_RBAC::_toggleTAPushed $types]
    $attribs configure -command [list Apol_RBAC::_toggleTAPushed $attribs]
    trace add variable Apol_RBAC::vals(target_type:types) write \
        [list Apol_RBAC::_toggleTASym]
    trace add variable Apol_RBAC::vals(target_type:attribs) write \
        [list Apol_RBAC::_toggleTASym]
    pack $types $attribs -side left -padx 2
    trace add variable Apol_RBAC::vals(target_type:use) write \
        [list Apol_RBAC::_toggleCheckbutton $widgets(trans:target) [list $types $attribs]]
    pack $target_cb -side top -anchor w
    pack $widgets(trans:target) -side top -expand 0 -fill x -padx 4
    pack $ta_frame -anchor center -pady 2
    pack $target -side left -padx 4 -pady 2 -expand 0 -fill y

    set default [frame $t_f.default]
    set widgets(trans:default_cb) [checkbutton $default.enable -text "Default role" \
                                       -variable Apol_RBAC::vals(default:use)]
    set widgets(trans:default) [ComboBox $default.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(default:sym) \
                                   -helptext "Type or select a role" -autopost 1]
    trace add variable Apol_RBAC::vals(default:use) write \
        [list Apol_RBAC::_toggleCheckbutton $widgets(trans:default) {}]
    pack $widgets(trans:default_cb) -side top -anchor w
    pack $widgets(trans:default) -side top -expand 0 -fill x -padx 4
    pack $default -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_RBAC::_bothCreate {b_f} {
    variable vals
    variable widgets

    set source [frame $b_f.source]
    set source_cb [checkbutton $source.enable -text "Source role" \
                       -variable Apol_RBAC::vals(source:use)]
    set widgets(both:source) [ComboBox $source.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(source:sym) \
                                   -helptext "Type or select a role" -autopost 1]
    set which_fm [frame $source.which]
    set which_source [radiobutton $which_fm.source \
                          -text "As source" -state disabled \
                          -variable Apol_RBAC::vals(source:which) \
                          -value source]
    set which_any [radiobutton $which_fm.any \
                       -text "Any field" -state disabled \
                       -variable Apol_RBAC::vals(source:which) \
                       -value either]
    trace add variable Apol_RBAC::vals(source:use) write \
        [list Apol_RBAC::_toggleCheckbutton $widgets(both:source) [list $which_source $which_any]]
    pack $which_source $which_any -side top -anchor w
    pack $source_cb -side top -anchor w
    pack $widgets(both:source) -side top -expand 0 -fill x -padx 4
    pack $which_fm -anchor w -padx 8
    pack $source -side left -padx 4 -pady 2 -expand 0 -anchor nw
}

proc Apol_RBAC::_toggleCheckbutton {cb w name1 name2 ops} {
    variable vals

    if {$vals($name2)} {
        $cb configure -state normal -entrybg white
        foreach x $w {
            $x configure -state normal
        }
    } else {
        $cb configure -state disabled -entrybg $ApolTop::default_bg_color
        foreach x $w {
            $x configure -state disabled
        }
    }

    _maybeEnableTargetRole
    _maybeEnableDefaultRole
}

# called whenever user selects 'as source'/'any' radio button
proc Apol_RBAC::_toggleRoleBox {name1 name2 ops} {
    _maybeEnableTargetRole
    _maybeEnableDefaultRole
}

proc Apol_RBAC::_maybeEnableTargetRole {} {
    variable vals
    variable widgets
    if {$vals(source:use) && $vals(source:which) == "either"} {
        $widgets(allow:target_cb) configure -state disabled
        $widgets(allow:target) configure -state disabled -entrybg $ApolTop::default_bg_color
    } else {
        $widgets(allow:target_cb) configure -state normal
        # reset subwidgets' state
        set vals(target_role:use) $vals(target_role:use)
    }
}

proc Apol_RBAC::_maybeEnableDefaultRole {} {
    variable vals
    variable widgets
    if {$vals(source:use) && $vals(source:which) == "either"} {
        $widgets(trans:default_cb) configure -state disabled
        $widgets(trans:default) configure -state disabled -entrybg $ApolTop::default_bg_color
    } else {
        $widgets(trans:default_cb) configure -state normal
        # reset subwidgets' state
        set vals(default:use) $vals(default:use)
    }
}

proc Apol_RBAC::_toggleTASym {name1 name2 ops} {
    variable vals
    variable widgets

    if {!$vals(target_type:types) && !$vals(target_type:attribs)} {
        # don't change combobox if both types and attribs are deselected
        return
    }
    if {$vals(target_type:types) && $vals(target_type:attribs)} {
        set items [lsort [concat [Apol_Types::getTypes] [Apol_Types::getAttributes]]]
    } elseif {$vals(target_type:types)} {
        set items [Apol_Types::getTypes]
    } else {
        set items [Apol_Types::getAttributes]
    }
    $widgets(trans:target) configure -values $items
}

# disallow both types and attribs to be deselected
proc Apol_RBAC::_toggleTAPushed {cb} {
    variable vals
    if {!$vals(target_type:types) && !$vals(target_type:attribs)} {
        $cb select
    }
}

# callback invoked when the user changes which RBAC rule to search
proc Apol_RBAC::_ruleChanged {name1 name2 ops} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    $widgets(options_pm) raise $vals(rule_selection)
}

proc Apol_RBAC::_searchRBACs {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }

    set raq {}
    set rtq {}

    if {$vals(rule_selection) == "allow" || $vals(rule_selection) == "both"} {
        set raq [new_apol_role_allow_query_t]
    }
    if {$vals(rule_selection) == "trans" || $vals(rule_selection) == "both"} {
        set rtq [new_apol_role_trans_query_t]
    }

    set source_sym {}
    set is_any 0
    if {$vals(source:use)} {
        if {$vals(source:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No source role selected."
            return
        }
        if {$vals(source:which) == "either"} {
            set is_any 1
        }
        set source_sym $vals(source:sym)
    }

    set target_role {}
    set target_type {}
    if {$vals(rule_selection) == "allow" && $vals(target_role:use) && \
            (!$vals(source:use) || $vals(source:which) != "either")} {
        if {$vals(target_role:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No target role selected."
            return
        }
        set target_role $vals(target_role:sym)
    }
    if {$vals(rule_selection) == "trans" && $vals(target_type:use)} {
        if {$vals(target_type:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No target type selected."
            return
        }
        set target_type $vals(target_type:sym)
    }
    
    set default_role {}
    if {$vals(rule_selection) == "trans" && $vals(default:use) && \
            (!$vals(source:use) || $vals(source:which) != "either")} {
        if {$vals(default:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No default role selected."
            return
        }
        set default_role $vals(default:sym)
    }

    set role_allows {}
    if {$raq != {}} {
        $raq set_source $::ApolTop::policy $source_sym
        $raq set_source_any $::ApolTop::policy $is_any
        $raq set_target $::ApolTop::policy $target_role
        set v [$raq run $::ApolTop::policy]
        $raq -acquire
        $raq -delete
        set role_allows [role_allow_vector_to_list $v]
        $v -acquire
        $v -delete
    }

    set role_trans {}
    if {$rtq != {}} {
        $rtq set_source $::ApolTop::policy $source_sym
        $rtq set_source_any $::ApolTop::policy $is_any
        $rtq set_target $::ApolTop::policy $target_type 0
        $rtq set_default $::ApolTop::policy $default_role
        set v [$rtq run $::ApolTop::policy]
        $rtq -acquire
        $rtq -delete
        set role_trans [role_trans_vector_to_list $v]
        $v -acquire
        $v -delete
    }

    set num_results [expr {[llength $role_allows] + [llength $role_trans]}]
    if {$num_results == 0} {
        set text "Search returned no results."
    } else {
        set text "$num_results rule"
        if {$num_results != 1} {
            append text s
        }
        append text " match the search criteria.\n\n"
    }

    foreach r [lsort -command _role_allow_sort $role_allows] {
        append text "[_render_role_allow $r]\n"
    }
    foreach r [lsort -command _role_trans_sort $role_trans] {
        append text "[_render_role_trans $r]\n"
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
}

proc Apol_RBAC::_render_role_allow {qpol_role_allow_datum} {
    apol_role_allow_render $::ApolTop::policy $qpol_role_allow_datum
}

proc Apol_RBAC::_render_role_trans {qpol_role_trans_datum} {
    apol_role_trans_render $::ApolTop::policy $qpol_role_trans_datum
}

proc Apol_RBAC::_role_allow_sort {a b} {
    set r1 [[$a get_source_role $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set r2 [[$b get_source_role $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    if {[set z [string compare $r1 $r2]] != 0} {
        return $z
    }

    set r1 [[$a get_target_role $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set r2 [[$b get_target_role $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    string compare $r1 $r2
}

proc Apol_RBAC::_role_trans_sort {a b} {
    set r1 [[$a get_source_role $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set r2 [[$b get_source_role $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    if {[set z [string compare $r1 $r2]] != 0} {
        return $z
    }

    set r1 [[$a get_target_type $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set r2 [[$b get_target_type $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    string compare $r1 $r2
}
