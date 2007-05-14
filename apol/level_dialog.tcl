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

namespace eval Apol_Level_Dialog {
    variable dialog ""
    variable vars
}

# Create a dialog box to allow the user to select a single MLS level.
# Return an instance of an apol_mls_level.  If no level is selected
# then return an empty list; otherwise return the level.  The caller
# must delete it afterwards.
proc Apol_Level_Dialog::getLevel {{defaultLevel {}} {parent .}} {
    variable dialog
    if {![winfo exists $dialog]} {
        _create_dialog $parent
    }
    set f [$dialog getframe]
    Apol_Widget::resetLevelSelectorToPolicy $f.level
    if {$defaultLevel != {}} {
        Apol_Widget::setLevelSelectorLevel $f.level $defaultLevel
    }
    # force a recomputation of button sizes  (bug in ButtonBox)
    $dialog.bbox _redraw
    set retval [$dialog draw]
    if {$retval == -1 || $retval == 1} {
        return {}
    }
    _get_level $dialog
}


########## private functions below ##########

proc Apol_Level_Dialog::_create_dialog {parent} {
    variable dialog
    variable vars

    set dialog [Dialog .level_dialog -modal local -parent $parent \
                    -separator 1 -homogeneous 1 -title "Select Level"]
    array unset vars $dialog:*

    set f [$dialog getframe]
    set label [label $f.ll -text "Level:"]
    set level [Apol_Widget::makeLevelSelector $f.level 12]

    pack $label -anchor w
    pack $level -expand 1 -fill both

    $dialog add -text "Ok" -command [list Apol_Level_Dialog::_okay $dialog]
    $dialog add -text "Cancel"
}

proc Apol_Level_Dialog::_get_level {dialog} {
    return [Apol_Widget::getLevelSelectorLevel [$dialog getframe].level]
}

# Check that the level is legal by validating it against the current
# policy.
proc Apol_Level_Dialog::_okay {dialog} {
    set level [_get_level $dialog]
    if {![ApolTop::is_policy_open] || [$level validate $::ApolTop::policy] != 1} {
        tk_messageBox -icon error -type ok -title "Invalid Level" \
            -message "The selected level is not valid for the current policy."
    } else {
        $dialog enddialog 0
    }
    $level -delete
}
