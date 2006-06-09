# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets


##############################################################
# ::Apol_RBAC
#
# The Access Control Rules page
##############################################################
namespace eval Apol_RBAC {
    variable vals
    variable widgets
}

proc Apol_RBAC::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results) $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_RBAC::set_Focus_to_Text {} {
    focus $Apol_RBAC::widgets(results)
}

proc Apol_RBAC::searchRBACs {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }

    switch -- $vals(rule_selection) {
        "allow" { set rule_selection allow}
        "trans" { set rule_selection role_transition}
        "both"  { set rule_selection [list allow role_transition] }
    }
    set other_opts {}
    set source_sym {}
    if {$vals(source:use)} {
        if {$vals(source:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No source role selected."
            return
        }
        if {$vals(source:which) == "either"} {
            lappend other_opts "source_any"
        }
        set source_sym $vals(source:sym)
    }
    set target_sym {}
    if {$rule_selection == "allow" && $vals(target_role:use) && \
            (!$vals(source:use) || $vals(source:which) != "either")} {
        if {$vals(target_role:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No target role selected."
            return
        }
        set target_sym $vals(target_role:sym)
    } elseif {$rule_selection == "role_transition" && $vals(target_type:use)} {
        if {$vals(target_type:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No target type selected."
            return
        }
        set target_sym $vals(target_type:sym)
    }
    set default_sym {}
    if {$rule_selection == "role_transition" && $vals(default:use) && \
            (!$vals(source:use) || $vals(source:which) != "either")} {
        if {$vals(default:sym) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No default role selected."
            return
        }
        set default_sym $vals(default:sym)
    }

    if {[catch {apol_SearchRBACRules $rule_selection $other_opts $source_sym $target_sym $default_sym} results]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error searching RBAC rules:\n$results"
        return
    }

    if {[llength $results] == 0} {
        set text "Search returned no results."
    } else {
        set text "[llength $results] rule"
        if {[llength $results] != 1} {
            append text s
        }
        append text " match the search criteria.\n\n"
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
    foreach r [lsort $results] {
        renderRBAC $r
    }
}

proc Apol_RBAC::renderRBAC {rule} {
    variable widgets
    foreach {rule_type source_set target_set default line_num} $rule {
        if {[llength $source_set] > 1} {
            set source_set "\{ $source_set \}"
        }
        if {[llength $target_set] > 1} {
            set target_set "\{ $target_set \}"
        }
        if {$default != {}} {
            Apol_Widget::appendSearchResultLine $widgets(results) $line_num \
                "$rule_type $source_set $target_set $default"
        } else {
            Apol_Widget::appendSearchResultLine $widgets(results) $line_num \
                "$rule_type $source_set $target_set"
        }
    }
}

proc Apol_RBAC::open { } {
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

proc Apol_RBAC::close { } {
    variable widgets

    initializeVars
    $widgets(allow:source) configure -values {}
    $widgets(allow:target) configure -values {}
    $widgets(trans:source) configure -values {}
    $widgets(trans:target) configure -values {}
    $widgets(trans:default) configure -values {}
    $widgets(both:source) configure -values {}
}

proc Apol_RBAC::free_call_back_procs { } {
}

proc Apol_RBAC::initializeVars {} {
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

proc Apol_RBAC::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

proc Apol_RBAC::create {nb} {
    variable vals
    variable widgets

    initializeVars

    # Layout frames
    set frame [$nb insert end $ApolTop::rbac_tab -text "RBAC Rules"]
    set topf [frame $frame.top]
    set bottomf [frame $frame.bottom]
    pack $topf -expand 0 -fill both -pady 2
    pack $bottomf -expand 1 -fill both -pady 2

    # Major subframes
    set rsbox [TitleFrame $topf.rs -text "Rule Selection"]
    set obox [TitleFrame $topf.opts -text "Search Criteria"]
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
        [list Apol_RBAC::ruleChanged]
    pack $rs.allow $rs.trans $rs.both -side top -anchor w

    # Search criteria subframe
    set widgets(options_pm) [PagesManager [$obox getframe].opts]

    allowCreate [$widgets(options_pm) add allow]
    transCreate [$widgets(options_pm) add trans]
    bothCreate [$widgets(options_pm) add both]
    trace add variable Apol_RBAC::vals(source:which) write Apol_RBAC::toggleRoleBox

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise allow

    set ok [button [$obox getframe].ok -text OK -width 6 -command Apol_RBAC::searchRBACs]
    pack $ok -side right -padx 5 -pady 5 -anchor ne

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_RBAC::ruleChanged {name1 name2 ops} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    $widgets(options_pm) raise $vals(rule_selection)
}

proc Apol_RBAC::allowCreate {a_f} {
    variable vals
    variable widgets

    set source [frame $a_f.source]
    set source_cb [checkbutton $source.enable -text "Source role" \
                       -variable Apol_RBAC::vals(source:use)]
    set widgets(allow:source) [ComboBox $source.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(source:sym) \
                                   -helptext "Type or select a role"]
    bind $widgets(allow:source).e <KeyPress> [list ApolTop::_create_popup $widgets(allow:source) %W %K]
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
        [list Apol_RBAC::toggleCheckbutton $widgets(allow:source) [list $which_source $which_any]]
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
                                   -helptext "Type or select a role"]
    bind $widgets(allow:target).e <KeyPress> [list ApolTop::_create_popup $widgets(allow:target) %W %K]
    trace add variable Apol_RBAC::vals(target_role:use) write \
        [list Apol_RBAC::toggleCheckbutton $widgets(allow:target) {}]
    pack $widgets(allow:target_cb) -side top -anchor w
    pack $widgets(allow:target) -side top -expand 0 -fill x -padx 4
    pack $target -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_RBAC::transCreate {t_f} {
    variable vals
    variable widgets

    set source [frame $t_f.source]
    set source_cb [checkbutton $source.enable -text "Source role" \
                       -variable Apol_RBAC::vals(source:use)]
    set widgets(trans:source) [ComboBox $source.cb -width 20 -state disabled \
                                        -entrybg $ApolTop::default_bg_color \
                                        -textvariable Apol_RBAC::vals(source:sym) \
                                        -helptext "Type or select a role"]
    bind $widgets(trans:source).e <KeyPress> [list ApolTop::_create_popup $widgets(allow:source) %W %K]
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
        [list Apol_RBAC::toggleCheckbutton $widgets(trans:source) [list $which_source $which_any]]
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
                                   -helptext "Type or select a type/attribute"]
    bind $widgets(trans:target).e <KeyPress> [list ApolTop::_create_popup $widgets(trans:target) %W %K]
    set ta_frame [frame $target.ta]
    set types [checkbutton $ta_frame.types -text "Types" -state disabled \
                   -variable Apol_RBAC::vals(target_type:types)]
    set attribs [checkbutton $ta_frame.attribs -text "Attribs" -state disabled \
                   -variable Apol_RBAC::vals(target_type:attribs)]
    $types configure -command [list Apol_RBAC::toggleTAPushed $types]
    $attribs configure -command [list Apol_RBAC::toggleTAPushed $attribs]
    trace add variable Apol_RBAC::vals(target_type:types) write \
        [list Apol_RBAC::toggleTASym]
    trace add variable Apol_RBAC::vals(target_type:attribs) write \
        [list Apol_RBAC::toggleTASym]
    pack $types $attribs -side left -padx 2
    trace add variable Apol_RBAC::vals(target_type:use) write \
        [list Apol_RBAC::toggleCheckbutton $widgets(trans:target) [list $types $attribs]]
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
                                   -helptext "Type or select a role"]
    bind $widgets(trans:default).e <KeyPress> [list ApolTop::_create_popup $widgets(trans:default) %W %K]
    trace add variable Apol_RBAC::vals(default:use) write \
        [list Apol_RBAC::toggleCheckbutton $widgets(trans:default) {}]
    pack $widgets(trans:default_cb) -side top -anchor w
    pack $widgets(trans:default) -side top -expand 0 -fill x -padx 4
    pack $default -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_RBAC::bothCreate {b_f} {
    variable vals
    variable widgets

    set source [frame $b_f.source]
    set source_cb [checkbutton $source.enable -text "Source role" \
                       -variable Apol_RBAC::vals(source:use)]
    set widgets(both:source) [ComboBox $source.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_RBAC::vals(source:sym) \
                                   -helptext "Type or select a role"]
    bind $widgets(both:source).e <KeyPress> [list ApolTop::_create_popup $widgets(both:source) %W %K]
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
        [list Apol_RBAC::toggleCheckbutton $widgets(both:source) [list $which_source $which_any]]
    pack $which_source $which_any -side top -anchor w
    pack $source_cb -side top -anchor w
    pack $widgets(both:source) -side top -expand 0 -fill x -padx 4
    pack $which_fm -anchor w -padx 8
    pack $source -side left -padx 4 -pady 2 -expand 0 -anchor nw
}

proc Apol_RBAC::toggleCheckbutton {cb w name1 name2 ops} {
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

    maybeEnableTargetRole
    maybeEnableDefaultRole
}

# called whenever user selects 'as source'/'any' radio button
proc Apol_RBAC::toggleRoleBox {name1 name2 ops} {
    maybeEnableTargetRole
    maybeEnableDefaultRole
}

proc Apol_RBAC::maybeEnableTargetRole {} {
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

proc Apol_RBAC::maybeEnableDefaultRole {} {
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

proc Apol_RBAC::toggleTASym {name1 name2 ops} {
    variable vals
    variable widgets

    if {!$vals(target_type:types) && !$vals(target_type:attribs)} {
        # don't change combobox if both types and attribs are deselected
        return
    }
    if {$vals(target_type:types) && $vals(target_type:attribs)} {
        set items [lsort [concat $Apol_Types::typelist $Apol_Types::attriblist]]
    } elseif {$vals(target_type:types)} {
        set items $Apol_Types::typelist
    } else {
        set items $Apol_Types::attriblist
    }
    $widgets(trans:target) configure -values $items
}

# disallow both types and attribs to be deselected
proc Apol_RBAC::toggleTAPushed {cb} {
    variable vals
    if {!$vals(target_type:types) && !$vals(target_type:attribs)} {
        $cb select
    }
}
