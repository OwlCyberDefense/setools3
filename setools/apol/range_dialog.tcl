# Copyright (C) 2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets 1.7+

namespace eval Apol_Range_Dialog {
    variable dialog ""
    variable vars
}

# Create a dialog box to allow the user to select an MLS range (either
# a single level or two levels.  Ensure that the selected range is
# valid (i.e., high dominates low).  If the range is invalid then
# return $defaultRange.
proc Apol_Range_Dialog::getRange {{defaultRange {{{} {}} {{} {}}}} {parent .}} {
    variable dialog
    variable vars
    if {![winfo exists $dialog]} {
        _create_dialog $parent
    }
    set f [$dialog getframe]
    Apol_Widget::resetLevelSelectorToPolicy $f.low
    Apol_Widget::resetLevelSelectorToPolicy $f.high
    set low [lindex $defaultRange 0]
    set high [lindex $defaultRange 1]
    Apol_Widget::setLevelSelectorLevel $f.low $low
    if {$low == $high} {
        set vars($dialog:highenable) 0
    } else {
        Apol_Widget::setLevelSelectorLevel $f.high $high
        set vars($dialog:highenable) 1
    }
    _high_enabled $dialog
    # force a recomputation of button sizes  (bug in ButtonBox)
    $dialog.bbox _redraw
    set retval [$dialog draw]
    if {$retval == -1 || $retval == 1} {
        return $defaultRange
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
    set low_label [label $f.ll -text "Single Level"]
    set low_level [Apol_Widget::makeLevelSelector $f.low 12]
    
    set high_cb [checkbutton $f.high_enable \
                     -text "High Level" \
                     -variable Apol_Range_Dialog::vars($dialog:highenable) \
                     -command [list Apol_Range_Dialog::_high_enabled $dialog]]
    set high_level [Apol_Widget::makeLevelSelector $f.high 12]
    Apol_Widget::setLevelSelectorState $high_level 0

    grid $low_label $high_cb -sticky w
    grid $low_level $high_level -sticky ns
    grid columnconfigure $f 0 -weight 1 -uniform 1 -pad 4
    grid columnconfigure $f 1 -weight 1 -uniform 1 -pad 4

    $dialog add -text "Ok" -command [list Apol_Range_Dialog::_okay $dialog]
    $dialog add -text "Cancel"
}

proc Apol_Range_Dialog::_get_range {dialog} {
    variable vars
    set f [$dialog getframe]
    set low [Apol_Widget::getLevelSelectorLevel $f.low]
    if {$vars($dialog:highenable)} {
        set high [Apol_Widget::getLevelSelectorLevel $f.high]
    } else {
        set high $low
    }
    list $low $high
}

proc Apol_Range_Dialog::_okay {dialog} {
    set range [_get_range $dialog]
    if {[catch {apol_IsValidRange [lindex $range 0] [lindex $range 1]} val]} {
        tk_messageBox -icon error -type ok -title "Could Not Validate Range" \
            -message "Could not validate selected range.  Make sure that the correct policy was loaded."
    } elseif {$val == 0} {
        tk_messageBox -icon error -type ok -title "Invalid Range" \
            -message "The selected range is not valid.  Make sure that the correct policy was loaded."
    } else {
        $dialog enddialog 0
    }
}

proc Apol_Range_Dialog::_high_enabled {dialog} {
    variable vars
    set f [$dialog getframe]
    if {$vars($dialog:highenable)} {
        $f.ll configure -text "Low Level"
        Apol_Widget::setLevelSelectorState $f.high 1
    } else {
        $f.ll configure -text "Single Level"
        Apol_Widget::setLevelSelectorState $f.high 0
    }
}
