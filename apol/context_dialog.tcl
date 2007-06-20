# Copyright (C) 2005-2007 Tresys Technology, LLC
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

namespace eval Apol_Context_Dialog {
    variable dialog ""
    variable vars
}

# Create a dialog box to allow the user to select a single context
# (user + role + type + level [if MLS]).  This will return a 2-ple
# list.  The first is an apol_context_t; the caller must delete this
# afterwards.  Note that the context may be partially filled.  The
# second element is the attribute used to filter types; it may be an
# empty string to indicate no filtering.  If the dialog is cancelled
# then return an empty list.
proc Apol_Context_Dialog::getContext {{defaultContext {}} {defaultAttribute {}} {parent .}} {
    variable dialog
    variable vars
    if {![winfo exists $dialog]} {
        _create_dialog $parent
    }

    set user {}
    set role {}
    set type {}
    set low_level {}
    set high_level {}

    # initialize widget states
    array set vars [list $dialog:low_enable 0  $dialog:high_enable 0]
    if {$defaultContext != {}} {
        set user [$defaultContext get_user]
        set role [$defaultContext get_role]
        set type [$defaultContext get_type]
        if {$defaultAttribute != {}} {
            lappend type $defaultAttribute
        }
        set range [$defaultContext get_range]
        if {$range != "NULL"} {
            set low_level [$range get_low]
            set high_level [$range get_high]
        }
    }

    $vars($dialog:user_box) configure -values [Apol_Users::getUsers]
    set vars($dialog:user) $user
    if {$user == {}} {
        set vars($dialog:user_enable) 0
    } else {
        set vars($dialog:user_enable) 1
    }

    $vars($dialog:role_box) configure -values [Apol_Roles::getRoles]
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
    if {[ApolTop::is_policy_open] && [ApolTop::is_capable "mls"]} {
        if {$low_level != {}} {
            set vars($dialog:low_enable) 1
            Apol_Widget::setLevelSelectorLevel $vars($dialog:low_level) $low_level
        }
        if {$high_level != {} && $high_level != "NULL"} {
            set vars($dialog:low_enable) 1
            set vars($dialog:high_enable) 1
            Apol_Widget::setLevelSelectorLevel $vars($dialog:high_level) $high_level
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
        return {}
    }
    set context [_get_context $dialog]
    set attribute [lindex [Apol_Widget::getTypeComboboxValueAndAttrib $vars($dialog:type_box)] 1]
    list $context $attribute
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
                                   -textvariable Apol_Context_Dialog::vars($dialog:user) -autopost 1]
    trace add variable Apol_Context_Dialog::vars($dialog:user_enable) write \
        [list Apol_Context_Dialog::_user_changed $dialog]
    pack $vars($dialog:user_cb) -anchor nw
    pack $vars($dialog:user_box) -anchor nw -padx 4 -expand 0 -fill x

    set role_f [frame $left_f.role]
    set vars($dialog:role_cb) [checkbutton $role_f.enable -text "Role" \
                                 -variable Apol_Context_Dialog::vars($dialog:role_enable)]
    set vars($dialog:role_box) [ComboBox $role_f.role -entrybg white -width 12 \
                                  -textvariable Apol_Context_Dialog::vars($dialog:role) -autopost 1]
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

    $dialog add -text "OK" -command [list Apol_Context_Dialog::_okay $dialog]
    $dialog add -text "Cancel"
}

# For all options that have been enabled, ensure that the user also
# selected a value.  With those values, ensure that they are
# authorized (user has the role, etc).  For the MLS range, also check
# that the level is legal by constructing a 'range' with it (as both
# the low and high level).
proc Apol_Context_Dialog::_okay {dialog} {
    variable vars
    set context [new_apol_context_t]
    if {[ApolTop::is_policy_open]} {
        set p $::ApolTop::policy
    } else {
        set p NULL
    }

    if {$vars($dialog:user_enable)} {
        if {[set user $vars($dialog:user)] == {}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No user was selected."
            return
        }
        $context set_user $p $user
    }
    if {$vars($dialog:role_enable)} {
        if {[set role $vars($dialog:role)] == {}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No role was selected."
            return
        }
        $context set_role $p $role
    }
    if {$vars($dialog:type_enable)} {
        set type [lindex [Apol_Widget::getTypeComboboxValueAndAttrib $vars($dialog:type_box)] 0]
        if {$type == {}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No type was selected."
            return
        }
        $context set_type $p $type
    }
    if {$vars($dialog:low_enable)} {
        set range [_get_range $dialog]
        if {$range == {}} {
            tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
                -message "No level was selected."
            return
        }
        $context set_range $p $range
    }
    if {![ApolTop::is_policy_open] || [$context validate_partial $p] <= 0} {
        tk_messageBox -icon error -type ok -title "Could Not Validate Context" \
            -message "The selected context is not valid for the current policy."
        return
    } else {
        $dialog enddialog 0
    }
    $context -delete
}

proc Apol_Context_Dialog::_get_context {dialog} {
    variable vars
    set context [new_apol_context_t]
    if {[ApolTop::is_policy_open]} {
        set p $::ApolTop::policy
    } else {
        set p NULL
    }
    if {$vars($dialog:user_enable)} {
        $context set_user $p $vars($dialog:user)
    }
    if {$vars($dialog:role_enable)} {
        $context set_role $p $vars($dialog:role)
    }
    if {$vars($dialog:type_enable)} {
        set type [lindex [Apol_Widget::getTypeComboboxValueAndAttrib $vars($dialog:type_box)] 0]
        $context set_type $p $type
    }
    set range [_get_range $dialog]
    if {$range != {}} {
        $context set_range $p $range
    }
    return $context
}

proc Apol_Context_Dialog::_get_range {dialog} {
    variable vars
    if {!$vars($dialog:low_enable)} {
        return {}
    }
    if {[ApolTop::is_policy_open]} {
        set p $::ApolTop::policy
    } else {
        set p NULL
    }
    set range [new_apol_mls_range_t]
    $range set_low $p [Apol_Widget::getLevelSelectorLevel $vars($dialog:low_level)]

    if {$vars($dialog:high_enable)} {
        $range set_high $p [Apol_Widget::getLevelSelectorLevel $vars($dialog:high_level)]
    }
    return $range
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
