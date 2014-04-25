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

namespace eval Apol_Bounds {
    variable vals
    variable widgets
}

proc Apol_Bounds::create {tab_name nb} {
    variable vals
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "Bounds Rules"]
    set topf [frame $frame.top]
    set bottomf [frame $frame.bottom]
    pack $topf -expand 0 -fill both -pady 2
    pack $bottomf -expand 1 -fill both -pady 2

    set rsbox [TitleFrame $topf.rs -ipad 30 -text "Rule Selection"]
    set obox [TitleFrame $topf.opts -text "Search Options"]
    set dbox [TitleFrame $bottomf.results -text "Bounds Rules Display"]
    pack $rsbox -side left -expand 0 -fill both -padx 2
    pack $obox -side left -expand 1 -fill both -padx 2
    pack $dbox -expand 1 -fill both -padx 2

    # Rule selection subframe
    set rs [$rsbox getframe]
    radiobutton $rs.user -text user -value user \
        -variable Apol_Bounds::vals(rule_selection)
    radiobutton $rs.role -text role -value role \
        -variable Apol_Bounds::vals(rule_selection)
    radiobutton $rs.type -text type -value type \
        -variable Apol_Bounds::vals(rule_selection)
    trace add variable Apol_Bounds::vals(rule_selection) write \
        [list Apol_Bounds::_ruleChanged]
    pack $rs.user $rs.role $rs.type -side top -anchor w

    set widgets(options_pm) [PagesManager [$obox getframe].opts]

    _userCreate [$widgets(options_pm) add user]
    _roleCreate [$widgets(options_pm) add role]
    _typeCreate [$widgets(options_pm) add type]

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise type

    set ok [button [$obox getframe].ok -text OK -width 6 -command Apol_Bounds::_searchBounds]
    pack $ok -side right -padx 5 -pady 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Bounds::open {ppath} {
    variable vals
    variable widgets
    $widgets(user:user_parent) configure -values $Apol_Users::users_list
    $widgets(user:user_child) configure -values $Apol_Users::users_list
    $widgets(role:role_parent) configure -values $Apol_Roles::role_list
    $widgets(role:role_child) configure -values $Apol_Roles::role_list
    $widgets(type:type_parent) configure -values $Apol_Types::typelist
    $widgets(type:type_child) configure -values $Apol_Types::typelist

    set vals(rule_selection) type
}

proc Apol_Bounds::close {} {
    variable widgets

    _initializeVars
    $widgets(user:user_parent) configure -values {}
    $widgets(user:user_child) configure -values {}
    $widgets(role:role_parent) configure -values {}
    $widgets(role:role_child) configure -values {}
    $widgets(type:type_parent) configure -values {}
    $widgets(type:type_child) configure -values {}
}

proc Apol_Bounds::getTextWidget {} {
    variable widgets
#    return $widgets(results).tb
}

#### private functions below ####

proc Apol_Bounds::_initializeVars {} {
    variable vals
    array set vals {
        rule_selection type

        user_parent:use 0
        user_parent:sym {}
        user_child:sym {}
        user_child:use 0

        role_parent:use 0
        role_parent:sym {}
        role_child:sym {}
        role_child:use 0

        type_parent:use 0
        type_parent:sym {}
        type_child:sym {}
        type_child:use 0
    }
}

proc Apol_Bounds::_userCreate {a_f} {
    variable vals
    variable widgets

    set user_parent [frame $a_f.user_parent]
    set user_parent_cb [checkbutton $user_parent.enable -text "Parent user" \
                       -variable Apol_Bounds::vals(user_parent:use)]
    set widgets(user:user_parent) [ComboBox $user_parent.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_Bounds::vals(user_parent:sym) \
                                   -helptext "Select the bounding user" -autopost 1]

    trace add variable Apol_Bounds::vals(user_parent:use) write \
        [list Apol_Bounds::_toggleCheckbutton $widgets(user:user_parent) {}]
    pack $user_parent_cb -side top -anchor w
    pack $widgets(user:user_parent) -side top -expand 0 -fill x -padx 4

    pack $user_parent -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set user_child [frame $a_f.user_child]
    set widgets(user:user_child_cb) [checkbutton $user_child.enable -text "Child user" \
                                      -variable Apol_Bounds::vals(user_child:use)]
    set widgets(user:user_child) [ComboBox $user_child.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_Bounds::vals(user_child:sym) \
                                   -helptext "Select the bounded user" -autopost 1]
    trace add variable Apol_Bounds::vals(user_child:use) write \
        [list Apol_Bounds::_toggleCheckbutton $widgets(user:user_child) {}]
    pack $widgets(user:user_child_cb) -side top -anchor w
    pack $widgets(user:user_child) -side top -expand 0 -fill x -padx 4
    pack $user_child -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_Bounds::_roleCreate {t_f} {
    variable vals
    variable widgets

    set role_parent [frame $t_f.role_parent]
    set role_parent_cb [checkbutton $role_parent.enable -text "Parent role" \
                       -variable Apol_Bounds::vals(role_parent:use)]
    set widgets(role:role_parent) [ComboBox $role_parent.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_Bounds::vals(role_parent:sym) \
                                   -helptext "Select the bounding role" -autopost 1]

    trace add variable Apol_Bounds::vals(role_parent:use) write \
        [list Apol_Bounds::_toggleCheckbutton $widgets(role:role_parent) {}]
    pack $role_parent_cb -side top -anchor w
    pack $widgets(role:role_parent) -side top -expand 0 -fill x -padx 4

    pack $role_parent -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set role_child [frame $t_f.role_child]
    set widgets(role:role_child_cb) [checkbutton $role_child.enable -text "Child role" \
                                      -variable Apol_Bounds::vals(role_child:use)]
    set widgets(role:role_child) [ComboBox $role_child.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_Bounds::vals(role_child:sym) \
                                   -helptext "Select the bounded role" -autopost 1]
    trace add variable Apol_Bounds::vals(role_child:use) write \
        [list Apol_Bounds::_toggleCheckbutton $widgets(role:role_child) {}]
    pack $widgets(role:role_child_cb) -side top -anchor w
    pack $widgets(role:role_child) -side top -expand 0 -fill x -padx 4
    pack $role_child -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_Bounds::_typeCreate {b_t} {
    variable vals
    variable widgets

    set type_parent [frame $b_t.type_parent]
    set type_parent_cb [checkbutton $type_parent.enable -text "Parent type" \
                       -variable Apol_Bounds::vals(type_parent:use)]
    set widgets(type:type_parent) [ComboBox $type_parent.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_Bounds::vals(type_parent:sym) \
                                   -helptext "Select the bounding type" -autopost 1]

    trace add variable Apol_Bounds::vals(type_parent:use) write \
        [list Apol_Bounds::_toggleCheckbutton $widgets(type:type_parent) {}]
    pack $type_parent_cb -side top -anchor w
    pack $widgets(type:type_parent) -side top -expand 0 -fill x -padx 4

    pack $type_parent -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set type_child [frame $b_t.type_child]
    set widgets(type:type_child_cb) [checkbutton $type_child.enable -text "Child type" \
                                      -variable Apol_Bounds::vals(type_child:use)]
    set widgets(type:type_child) [ComboBox $type_child.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_Bounds::vals(type_child:sym) \
                                   -helptext "Select the bounded type" -autopost 1]
    trace add variable Apol_Bounds::vals(type_child:use) write \
        [list Apol_Bounds::_toggleCheckbutton $widgets(type:type_child) {}]
    pack $widgets(type:type_child_cb) -side top -anchor w
    pack $widgets(type:type_child) -side top -expand 0 -fill x -padx 4
    pack $type_child -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_Bounds::_toggleCheckbutton {cb w name1 name2 ops} {
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
}


# callback invoked when the user changes which Bounds rule to search
proc Apol_Bounds::_ruleChanged {name1 name2 ops} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    $widgets(options_pm) raise $vals(rule_selection)
}

proc Apol_Bounds::_searchBounds {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }


    if {$vals(rule_selection) == "user"} {
        Apol_Bounds::_searchUserBounds
        return
    }
    if {$vals(rule_selection) == "role"} {
        Apol_Bounds::_searchRoleBounds
        return
    }

    if {$vals(rule_selection) == "type" } {
        Apol_Bounds::_searchTypeBounds
        return
    }
}

proc Apol_Bounds::_searchUserBounds {} {
    variable vals
    variable widgets

    set results {}
    set bounds {}
    set counter 0
    set printit 0
    set parent_regexp 0
    set child_regexp 0

    if {$vals(user_parent:use) && $vals(user_parent:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No parent user selected."
    } elseif {$vals(user_parent:use)} {
        set parent_regexp 1
    }
    if {$vals(user_child:use) && $vals(user_child:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No child user selected."
    } elseif {$vals(user_child:use)} {
        set child_regexp 1
    }

    set q [new_apol_userbounds_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
            set q [qpol_userbounds_from_void [$v get_element $i]]
            set parent [$q get_parent_name $::ApolTop::qpolicy]
            set child [$q get_child_name $::ApolTop::qpolicy]
            if {$parent != ""} {
                if {$parent_regexp == 1 && $parent == $vals(user_parent:sym)} {
                    set printit 1
                } 
                if {$child_regexp == 1 && $child == $vals(user_child:sym)} {
                    set printit 1
                }
                if {$parent_regexp == 0 && $child_regexp == 0} {
                    set printit 1
                }
                if {$printit == 1} {
                    append bounds "userbounds $parent "
                    append bounds "$child;\n"
                    set counter [expr $counter + 1]
                }
            }
            set printit 0
        }
    }
    append results "$counter rules match search criteria.\n\n$bounds\n"
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Bounds::_searchRoleBounds {} {
    variable vals
    variable widgets

    set results {}
    set bounds {}
    set counter 0
    set printit 0
    set parent_regexp 0
    set child_regexp 0

    if {$vals(role_parent:use) && $vals(role_parent:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No parent role selected."
    } elseif {$vals(role_parent:use)} {
        set parent_regexp 1
    }
    if {$vals(role_child:use) && $vals(role_child:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No child role selected."
    } elseif {$vals(role_child:use)} {
        set child_regexp 1
    }

    set q [new_apol_rolebounds_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
            set q [qpol_rolebounds_from_void [$v get_element $i]]
            set parent [$q get_parent_name $::ApolTop::qpolicy]
            set child [$q get_child_name $::ApolTop::qpolicy]
            if {$parent != ""} {
                if {$parent_regexp == 1 && $parent == $vals(role_parent:sym)} {
                    set printit 1
                } 
                if {$child_regexp == 1 && $child == $vals(role_child:sym)} {
                    set printit 1
                }
                if {$parent_regexp == 0 && $child_regexp == 0} {
                    set printit 1
                }
                if {$printit == 1} {
                    append bounds "rolebounds $parent "
                    append bounds "$child;\n"
                    set counter [expr $counter + 1]
                }
            }
            set printit 0
        }
    }
    append results "$counter rules match search criteria.\n\n$bounds\n"
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Bounds::_searchTypeBounds {} {
    variable vals
    variable widgets

    set results {}
    set bounds {}
    set counter 0
    set printit 0
    set parent_regexp 0
    set child_regexp 0

    if {$vals(type_parent:use) && $vals(type_parent:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No parent type selected."
    } elseif {$vals(type_parent:use)} {
        set parent_regexp 1
    }
    if {$vals(type_child:use) && $vals(type_child:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No child type selected."
    } elseif {$vals(type_child:use)} {
        set child_regexp 1
    }

    set q [new_apol_typebounds_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
            set q [qpol_typebounds_from_void [$v get_element $i]]
            set parent [$q get_parent_name $::ApolTop::qpolicy]
            set child [$q get_child_name $::ApolTop::qpolicy]
            if {$parent != ""} {
                if {$parent_regexp == 1 && $parent == $vals(type_parent:sym)} {
                    set printit 1
                } 
                if {$child_regexp == 1 && $child == $vals(type_child:sym)} {
                    set printit 1
                }
                if {$parent_regexp == 0 && $child_regexp == 0} {
                    set printit 1
                }
                if {$printit == 1} {
                    append bounds "typebounds $parent "
                    append bounds "$child;\n"
                    set counter [expr $counter + 1]
                }
            }
            set printit 0
        }
    }
    append results "$counter rules match search criteria.\n\n$bounds\n"
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

