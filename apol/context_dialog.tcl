# Copyright (C) 2005-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets 1.7+

namespace eval Apol_Context_Dialog {
    variable dialog ""
    variable vars
}

# Create a dialog box to allow the user to select a single context
# (user + role + type + level [if MLS]).
proc Apol_Context_Dialog::getContext {{defaultContext {{} {} {} {{{} {}}}}} {parent .}} {
    variable dialog
    variable vars
    if {![winfo exists $dialog]} {
        _create_dialog $parent
    }

    # initialize widget states
    array set vars [list $dialog:low_enable 0  $dialog:high_enable 0]
    foreach {user role type range} $defaultContext {break}

    $vars($dialog:user_box) configure -values $Apol_Users::users_list
    set vars($dialog:user) $user
    if {$user == {}} {
        set vars($dialog:user_enable) 0
    } else {
        set vars($dialog:user_enable) 1
    }

    $vars($dialog:role_box) configure -values $Apol_Roles::role_list
    set vars($dialog:role) $role
    if {$role == {}} {
        set vars($dialog:role_enable) 0
    } else {
        set vars($dialog:role_enable) 1
    }
    
    Apol_Widget::resetTypeComboboxToPolicy $vars($dialog:type_box)
    Apol_Widget::setTypeComboboxValue $vars($dialog:type_box) $type
    if {$type == {}} {
        set vars($dialog:type_enable) 0
    } else {
        set vars($dialog:type_enable) 1
    }
    
    Apol_Widget::resetLevelSelectorToPolicy $vars($dialog:low_level)
    Apol_Widget::resetLevelSelectorToPolicy $vars($dialog:high_level)
    if {[ApolTop::is_mls_policy]} {
        if {[llength $range] == 1} {
            if {[lindex $range 0] == {{} {}}} {
                set vars($dialog:low_enable) 0
            } else {
                set vars($dialog:low_enable) 1
                Apol_Widget::setLevelSelectorLevel $vars($dialog:low_level) [lindex $range 0]
            }
            set vars($dialog:high_enable) 0
        } else {
            set vars($dialog:low_enable) 1
            Apol_Widget::setLevelSelectorLevel $vars($dialog:low_level) [lindex $range 0]
            set vars($dialog:high_enable) 1
            Apol_Widget::setLevelSelectorLevel $vars($dialog:high_level) [lindex $range 1]
        }
        $vars($dialog:low_cb) configure -state normal
    } else {
        set vars($dialog:low_enable) 0
        set vars($dialog:high_enable) 0
        $vars($dialog:low_cb) configure -state disabled
    }

    # force a recomputation of button sizes  (bug in ButtonBox)
    $dialog.bbox _redraw
    set retval [$dialog draw]
    if {$retval == -1 || $retval == 1} {
        return $defaultContext
    }
    _get_context $dialog
}


########## private functions below ##########

proc Apol_Context_Dialog::_create_dialog {parent} {
    variable dialog
    variable vars

    set dialog [Dialog .context_dialog -modal local -parent $parent \
                    -separator 1 -homogeneous 1 -title "Select Context"]
    array unset vars $dialog:*

    
    set f [$dialog getframe]
    set left_f [frame $f.left]

    set user_f [frame $left_f.user]
    set vars($dialog:user_cb) [checkbutton $user_f.enable -text "User" \
                                  -variable Apol_Context_Dialog::vars($dialog:user_enable)]
    set vars($dialog:user_box) [ComboBox $user_f.user -entrybg white -width 12 \
                                   -textvariable Apol_Context_Dialog::vars($dialog:user)]
    bind $vars($dialog:user_box).e <KeyPress> [list ApolTop::_create_popup $vars($dialog:user_box) %W %K]
    trace add variable Apol_Context_Dialog::vars($dialog:user_enable) write \
        [list Apol_Context_Dialog::_user_changed $dialog]
    pack $vars($dialog:user_cb) -anchor nw
    pack $vars($dialog:user_box) -anchor nw -padx 4 -expand 0 -fill x

    set role_f [frame $left_f.role]
    set vars($dialog:role_cb) [checkbutton $role_f.enable -text "Role" \
                                 -variable Apol_Context_Dialog::vars($dialog:role_enable)]
    set vars($dialog:role_box) [ComboBox $role_f.role -entrybg white -width 12 \
                                  -textvariable Apol_Context_Dialog::vars($dialog:role)]
    bind $vars($dialog:role_box).e <KeyPress> [list ApolTop::_create_popup $vars($dialog:role_box) %W %K]
    trace add variable Apol_Context_Dialog::vars($dialog:role_enable) write \
        [list Apol_Context_Dialog::_role_changed $dialog]
    pack $vars($dialog:role_cb) -anchor nw
    pack $vars($dialog:role_box) -anchor nw -padx 4 -expand 0 -fill x

    set type_f [frame $left_f.type]
    set vars($dialog:type_cb) [checkbutton $type_f.enable -text "Type" \
                                   -variable Apol_Context_Dialog::vars($dialog:type_enable)]
    set vars($dialog:type_box) [Apol_Widget::makeTypeCombobox $type_f.type]
    pack $vars($dialog:type_cb) -anchor nw
    pack $vars($dialog:type_box) -anchor nw -padx 4 -expand 0 -fill x
    trace add variable Apol_Context_Dialog::vars($dialog:type_enable) write \
        [list Apol_Context_Dialog::_type_changed $dialog]
    pack $user_f $role_f $type_f -side top -expand 1 -fill x

    set mlsbox [TitleFrame $f.mlsbox -text "MLS Range"]
    set mls_f [$mlsbox getframe]
    set vars($dialog:low_cb) [checkbutton $mls_f.low_cb -text "Single Level" \
                                  -variable Apol_Context_Dialog::vars($dialog:low_enable)]
    set vars($dialog:low_level) [Apol_Widget::makeLevelSelector $mls_f.low 8]
    trace add variable Apol_Context_Dialog::vars($dialog:low_enable) write \
        [list Apol_Context_Dialog::_low_changed $dialog]
    set vars($dialog:high_cb) [checkbutton $mls_f.high_cb \
                                   -text "High Level" \
                                   -variable Apol_Context_Dialog::vars($dialog:high_enable)]
    set vars($dialog:high_level) [Apol_Widget::makeLevelSelector $mls_f.high 8]
    trace add variable Apol_Context_Dialog::vars($dialog:high_enable) write \
        [list Apol_Context_Dialog::_high_changed $dialog]
    grid $vars($dialog:low_cb) $vars($dialog:high_cb) -sticky w
    grid $vars($dialog:low_level) $vars($dialog:high_level) -sticky nsew
    grid columnconfigure $mls_f 0 -weight 1 -uniform 1 -pad 2
    grid columnconfigure $mls_f 1 -weight 1 -uniform 1 -pad 2
    grid rowconfigure $mls_f 1 -weight 1

    pack $left_f $mlsbox -side left -expand 1 -fill both

    $dialog add -text "Ok" -command [list Apol_Context_Dialog::_okay $dialog]
    $dialog add -text "Cancel"
}

# For all options that have been enabled, ensure that the user also
# selected a value.  With those values, ensure that they are
# authorized (user has the role, etc).  For the MLS range, also check
# that the level is legal by constructing a 'range' with it (as both
# the low and high level).
proc Apol_Context_Dialog::_okay {dialog} {
    variable vars
    set type [Apol_Widget::getTypeComboboxValue $vars($dialog:type_box)]
    if {$vars($dialog:user_enable) && $vars($dialog:user) == {}} {
        tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
            -message "No user was selected."
        return
    }
    if {$vars($dialog:role_enable)} {
        if {$vars($dialog:role) == {}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No role was selected."
            return
        } elseif {$vars($dialog:role) != "object_r" && \
                      $vars($dialog:user_enable) && \
                      $vars($dialog:user) != "" && \
                      [ApolTop::is_policy_open]} {
            set users_list [apol_GetUsers $vars($dialog:user)]
            if {[lsearch -exact [lindex $users_list 0 1] $vars($dialog:role)] == -1} {
                tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                    -message "User $vars($dialog:user) does not have role $vars($dialog:role)."
                return
            }
        }
    }
    if {$vars($dialog:type_enable)} {
        if {$type == {}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No type was selected."
            return
        } elseif {$vars($dialog:role_enable) && \
                      $vars($dialog:role) != "" && \
                      $vars($dialog:role) != "object_r" && \
                      [ApolTop::is_policy_open]} {
            set role_info [apol_GetRoles $vars($dialog:role)]
            if {[lsearch -exact [lindex $role_info 0 1] $type] == -1} {
                tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                    -message "Role $vars($dialog:role) does not have type $type."
                return
            }
        }
    }

    if {$vars($dialog:low_enable)} {
        set range [_get_range $dialog]
        set low [lindex $range 0]
        if {$low == {{} {}}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No level was selected."
            return
        } elseif {[llength $range] == 1} {
            set high $low
        } else {
            set high [lindex $range 1]
        }
        if {[catch {apol_IsValidRange $low $high} val]} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "The selected range is not valid.  The selected level is not part of the current policy."
            return
        } elseif {$val == 0} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "The selected range is not valid.  The high level does not dominate the low level."
            return
        }
        if {$vars($dialog:user_enable) && $vars($dialog:user) != "" && [ApolTop::is_policy_open]} {
            set valid_range 0
            foreach user [apol_GetUsers {} {} 0] {
                if {[lindex $user 0] == $vars($dialog:user)} {
                    if {[apol_CompareRanges [lindex $user 3] [list $low $high] superset]} {
                        set valid_range 1
                    }
                    break
                }
            }
            if {!$valid_range} {
                tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                    -message "User $vars($dialog:user) is not authorized for the selected range."
                return
            }
        }
    }
    $dialog enddialog 0
}

proc Apol_Context_Dialog::_get_context {dialog} {
    variable vars
    set context {}
    if {$vars($dialog:user_enable)} {
        lappend context $vars($dialog:user)
    } else {
        lappend context {}
    }
    if {$vars($dialog:role_enable)} {
        lappend context $vars($dialog:role)
    } else {
        lappend context {}
    }
    if {$vars($dialog:type_enable)} {
        lappend context [Apol_Widget::getTypeComboboxValueAndAttrib $vars($dialog:type_box)]
    } else {
        lappend context {}
    }
    lappend context [_get_range $dialog]
}

proc Apol_Context_Dialog::_get_range {dialog} {
    variable vars
    if {!$vars($dialog:low_enable)} {
        return {{{} {}}}
    }
    set low [Apol_Widget::getLevelSelectorLevel $vars($dialog:low_level)]
    if {!$vars($dialog:high_enable)} {
        list $low
    } else {
        list $low [Apol_Widget::getLevelSelectorLevel $vars($dialog:high_level)]
    }
}

proc Apol_Context_Dialog::_user_changed {dialog name1 name2 op} {
    variable vars
    if {$vars($dialog:user_enable)} {
        $vars($dialog:user_box) configure -state normal
    } else {
        $vars($dialog:user_box) configure -state disabled
    }
}

proc Apol_Context_Dialog::_role_changed {dialog name1 name2 op} {
    variable vars
    if {$vars($dialog:role_enable)} {
        $vars($dialog:role_box) configure -state normal
    } else {
        $vars($dialog:role_box) configure -state disabled
    }
}

proc Apol_Context_Dialog::_type_changed {dialog name1 name2 op} {
    variable vars
    if {$vars($dialog:type_enable)} {
        Apol_Widget::setTypeComboboxState $vars($dialog:type_box) 1
    } else {
        Apol_Widget::setTypeComboboxState $vars($dialog:type_box) 0
    }
}

proc Apol_Context_Dialog::_low_changed {dialog name1 name2 op} {
    variable vars
    if {$vars($dialog:low_enable)} {
        $vars($dialog:high_cb) configure -state normal
        Apol_Widget::setLevelSelectorState $vars($dialog:low_level) 1
        if {$vars($dialog:high_enable)} {
            Apol_Widget::setLevelSelectorState $vars($dialog:high_level) 1
        }
    } else {
        $vars($dialog:high_cb) configure -state disabled
        Apol_Widget::setLevelSelectorState $vars($dialog:low_level) 0
        Apol_Widget::setLevelSelectorState $vars($dialog:high_level) 0
    }
}

proc Apol_Context_Dialog::_high_changed {dialog name1 name2 op} {
    variable vars
    if {$vars($dialog:high_enable)} {
        $vars($dialog:low_cb) configure -text "Low Level"
        Apol_Widget::setLevelSelectorState $vars($dialog:high_level) 1
    } else {
        $vars($dialog:low_cb) configure -text "Single Level"
        Apol_Widget::setLevelSelectorState $vars($dialog:high_level) 0
    }
}
