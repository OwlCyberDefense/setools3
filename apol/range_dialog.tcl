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

namespace eval Apol_Range_Dialog {
    variable dialog ""
    variable vars
}

# Create a dialog box to allow the user to select an MLS range (either
# a single level or two levels.  Ensure that the selected range is
# valid (i.e., high dominates low).  If the range is invalid or if no
# range is selected then return an empty list.  Returns an instance of
# an apol_mls_range_t; the caller must delete it afterwards.
proc Apol_Range_Dialog::getRange {{defaultRange {}} {parent .}} {
    variable dialog
    variable vars
    if {![winfo exists $dialog]} {
        _create_dialog $parent
    }
    set f [$dialog getframe]
    Apol_Widget::resetLevelSelectorToPolicy $f.low
    Apol_Widget::resetLevelSelectorToPolicy $f.high
    set vars($dialog:highenable) 0
    if {$defaultRange != {}} {
        set low_level [$defaultRange get_low]
        set high_level [$defaultRange get_high]
        
        Apol_Widget::setLevelSelectorLevel $f.low $low_level
        if {[apol_mls_level_compare $::ApolTop::policy $low_level $high_level] != $::APOL_MLS_EQ} {
            set vars($dialog:highenable) 1
            Apol_Widget::setLevelSelectorLevel $f.high $high_level
        }
    }

    _high_enabled $dialog
    # force a recomputation of button sizes  (bug in ButtonBox)
    $dialog.bbox _redraw
    set retval [$dialog draw]
    if {$retval == -1 || $retval == 1} {
        return {}
    }
    _get_range $dialog
}


########## private functions below ##########

proc Apol_Range_Dialog::_create_dialog {parent} {
    variable dialog
    variable vars

    set dialog [Dialog .range_dialog -modal local -parent $parent \
                    -separator 1 -homogeneous 1 -title "Select Range"]
    array unset vars $dialog:*

    set f [$dialog getframe]
    set low_label [label $f.ll -text "Single level"]
    set low_level [Apol_Widget::makeLevelSelector $f.low 12]

    set high_cb [checkbutton $f.high_enable \
                     -text "High level" \
                     -variable Apol_Range_Dialog::vars($dialog:highenable) \
                     -command [list Apol_Range_Dialog::_high_enabled $dialog]]
    set high_level [Apol_Widget::makeLevelSelector $f.high 12]
    Apol_Widget::setLevelSelectorState $high_level 0

    grid $low_label $high_cb -sticky w
    grid $low_level $high_level -sticky ns
    grid columnconfigure $f 0 -weight 1 -uniform 1 -pad 4
    grid columnconfigure $f 1 -weight 1 -uniform 1 -pad 4

    $dialog add -text "OK" -command [list Apol_Range_Dialog::_okay $dialog]
    $dialog add -text "Cancel"
}

proc Apol_Range_Dialog::_get_range {dialog} {
    variable vars
    set f [$dialog getframe]
    set range [new_apol_mls_range_t]

    if {[ApolTop::is_policy_open]} {
        set p $::ApolTop::policy
    } else {
        set p NULL
    }

    set low_level [Apol_Widget::getLevelSelectorLevel $f.low]
    $range set_low $p $low_level
    
    if {$vars($dialog:highenable)} {
        set high_level [Apol_Widget::getLevelSelectorLevel $f.high]
        $range set_high $p $high_level
    }

    return $range
}

proc Apol_Range_Dialog::_okay {dialog} {
    set range [_get_range $dialog]
    if {![ApolTop::is_policy_open] || [$range validate $::ApolTop::policy] != 1} {
        tk_messageBox -icon error -type ok -title "Invalid Range" \
            -message "The selected range is not valid.  The high level does not dominate the low level."
    } else {
        $dialog enddialog 0
    }
    $range -delete
}

proc Apol_Range_Dialog::_high_enabled {dialog} {
    variable vars
    set f [$dialog getframe]
    if {$vars($dialog:highenable)} {
        $f.ll configure -text "Low level"
        Apol_Widget::setLevelSelectorState $f.high 1
    } else {
        $f.ll configure -text "Single level"
        Apol_Widget::setLevelSelectorState $f.high 0
    }
}
