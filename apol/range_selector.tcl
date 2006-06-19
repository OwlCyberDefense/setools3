# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget 1.7+

namespace eval Apol_Widget {
    variable vars
}

# Creates a widget that lets the user select an MLS range and a range
# search type (exact, subset, superset).  If the second argument is
# not "" then add a checkbutton that enables/disables the entire
# widget.
proc Apol_Widget::makeRangeSelector {path rangeMatchText {enableText "MLS range"} args} {
    variable vars
    array unset vars $path:*
    set vars($path:range) {{{} {}}}
    set vars($path:range_rendered) {}
    set vars($path:search_type) "exact"

    set f [frame $path]
    set range_frame [frame $f.range]
    set range2_frame [frame $f.range2]
    pack $range_frame $range2_frame -side left -expand 0 -anchor nw

    if {$enableText != {}} {
        set vars($path:enable) 0
        set range_cb [checkbutton $range_frame.enable -text $enableText \
                          -variable Apol_Widget::vars($path:enable)]
        pack $range_cb -side top -expand 0 -anchor nw
        trace add variable Apol_Widget::vars($path:enable) write [list Apol_Widget::_toggle_range_selector $path $range_cb]
    }
    set range_display [eval Entry $range_frame.display -textvariable Apol_Widget::vars($path:range_rendered) -width 20 -editable 0 $args]
    set range_button [button $range_frame.button -text "Select Range..." -state disabled -command [list Apol_Widget::_show_mls_range_dialog $path]]
    trace add variable Apol_Widget::vars($path:range) write [list Apol_Widget::_update_range_display $path]
    pack $range_display -side top -expand 1 -fill x -anchor nw
    pack $range_button -side top -expand 0 -anchor ne
    if {$enableText != {}} {
        pack configure $range_display -padx 4
        pack configure $range_button -padx 4
    }

    # range search type
    set range_label [label $range2_frame.label -text "Range matching:" \
                         -state disabled]
    set range_exact [radiobutton $range2_frame.exact -text "Exact matches" \
                         -state disabled \
                         -value exact -variable Apol_Widget::vars($path:search_type)]
    set range_subset [radiobutton $range2_frame.subset -text "$rangeMatchText containing range" \
                          -state disabled \
                          -value subset -variable Apol_Widget::vars($path:search_type)]
    set range_superset [radiobutton $range2_frame.superset -text "$rangeMatchText within range" \
                            -state disabled \
                            -value superset -variable Apol_Widget::vars($path:search_type)]
    pack $range_label $range_exact $range_subset $range_superset \
        -side top -expand 0 -anchor nw

    return $f
}

proc Apol_Widget::setRangeSelectorState {path newState} {
    if {$newState == 0 || $newState == "disabled"} {
        set new_state disabled
    } else {
        set new_state normal
    }
    foreach w {display button} {
        $path.range.$w configure -state $new_state
    }
    foreach w {label exact subset superset} {
        $path.range2.$w configure -state $new_state
    }
}

proc Apol_Widget::setRangeSelectorCompleteState {path newState} {
    if {$newState == 0 || $newState == "disabled"} {
        set new_state disabled
    } else {
        set new_state normal
    }
    catch {$path.range.enable configure -state $new_state}
}

proc Apol_Widget::clearRangeSelector {path} {
    set Apol_Widget::vars($path:range) {{{} {}}}
    set Apol_Widget::vars($path:search_type) exact
    catch {set Apol_Widget::vars($path:enable) 0}
}

proc Apol_Widget::getRangeSelectorState {path} {
    return $Apol_Widget::vars($path:enable)
}

# returns a 2-uple containing the range value and the search type
proc Apol_Widget::getRangeSelectorValue {path} {
    variable vars
    if {[llength $vars($path:range)] == 1} {
        set range [list [lindex $vars($path:range) 0] [lindex $vars($path:range) 0]]
    } else {
        set range $vars($path:range)
    }
    list $range $vars($path:search_type)
}

########## private functions below ##########

proc Apol_Widget::_toggle_range_selector {path cb name1 name2 op} {
    if {$Apol_Widget::vars($path:enable)} {
        Apol_Widget::setRangeSelectorState $path normal
    } else {
        Apol_Widget::setRangeSelectorState $path disabled
    }
}

proc Apol_Widget::_show_mls_range_dialog {path} {
    set Apol_Widget::vars($path:range) [Apol_Range_Dialog::getRange $Apol_Widget::vars($path:range)]
    # the trace on this variable will trigger [_update_range_display] to execute
}

proc Apol_Widget::_update_range_display {path name1 name2 op} {
    variable vars
    set display $path.range.display
    set low_level [lindex $vars($path:range) 0]
    if {[llength $vars($path:range)] == 1} {
        set high_level $low_level
    } else {
        set high_level [lindex $vars($path:range) 1]
    }
    if {$low_level == {{} {}} && $high_level == {{} {}}} {
        set vars($path:range_rendered) {}
        $display configure -helptext {}
    } else {
        set low_level [apol_RenderLevel $low_level]
        set high_level [apol_RenderLevel $high_level]
        if {$low_level == "" || $high_level == ""} {
            set vars($path:range_rendered) "<invalid MLS range>"
        } else {
            if {$low_level == $high_level} {
                set vars($path:range_rendered) $low_level
            } else {
                set vars($path:range_rendered) "$low_level - $high_level"
            }
        }
        $display configure -helptext $vars($path:range_rendered)
    }
}
