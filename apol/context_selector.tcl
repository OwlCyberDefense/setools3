# Copyright (C) 2001-2007 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget 1.7+

namespace eval Apol_Widget {
    variable vars
}

# Creates a widget that lets the user select a context (user + role +
# type + MLS range) and a range search type (exact, subset, superset).
# If the second argument is not "" then add a checkbutton that
# enables/disables the entire widget.
proc Apol_Widget::makeContextSelector {path rangeMatchText {enableText "Context"} args} {
    variable vars
    array unset vars $path:*
    set vars($path:context) {{} {} {} {{{} {}}}}
    set vars($path:context_rendered) {}
    set vars($path:search_type) "exact"

    set f [frame $path]
    set context_frame [frame $f.context]
    set context2_frame [frame $f.context2]
    pack $context_frame $context2_frame -side left -expand 0 -anchor nw

    if {$enableText != {}} {
        set vars($path:enable) 0
        set context_cb [checkbutton $context_frame.enable -text $enableText \
                          -variable Apol_Widget::vars($path:enable)]
        pack $context_cb -side top -expand 0 -anchor nw
        trace add variable Apol_Widget::vars($path:enable) write [list Apol_Widget::_toggle_context_selector $path $context_cb]
    }
    set context_display [eval Entry $context_frame.display -textvariable Apol_Widget::vars($path:context_rendered) -width 26 -editable 0 $args]
    set context_button [button $context_frame.button -text "Select Context..." -state disabled -command [list Apol_Widget::_show_context_dialog $path]]
    trace add variable Apol_Widget::vars($path:context) write [list Apol_Widget::_update_context_display $path]
    pack $context_display -side top -expand 1 -fill x -anchor nw
    pack $context_button -side top -expand 0 -anchor ne
    if {$enableText != {}} {
        pack configure $context_display -padx 4
        pack configure $context_button -padx 4
    }

    # range search type
    set range_label [label $context2_frame.label -text "MLS range matching:" \
                         -state disabled]
    set range_exact [radiobutton $context2_frame.exact -text "Exact matches" \
                         -state disabled \
                         -value exact -variable Apol_Widget::vars($path:search_type)]
    set range_subset [radiobutton $context2_frame.subset -text "$rangeMatchText containing range" \
                          -state disabled \
                          -value subset -variable Apol_Widget::vars($path:search_type)]
    set range_superset [radiobutton $context2_frame.superset -text "$rangeMatchText within range" \
                            -state disabled \
                            -value superset -variable Apol_Widget::vars($path:search_type)]
    pack $range_label $range_exact $range_subset $range_superset \
        -side top -expand 0 -anchor nw

    return $f
}

proc Apol_Widget::setContextSelectorState {path newState} {
    if {$newState == 0 || $newState == "disabled"} {
        set new_state disabled
    } else {
        set new_state normal
    }
    foreach w {display button} {
        $path.context.$w configure -state $new_state
    }
    if {![ApolTop::is_capable "mls"]} {
        set new_state disabled
    }
    foreach w {label exact subset superset} {
        $path.context2.$w configure -state $new_state
    }
}

proc Apol_Widget::clearContextSelector {path} {
    set Apol_Widget::vars($path:context) {{} {} {} {{{} {}}}}
    set Apol_Widget::vars($path:search_type) exact
    catch {set Apol_Widget::vars($path:enable) 0}
}

proc Apol_Widget::getContextSelectorState {path} {
    return $Apol_Widget::vars($path:enable)
}

# returns a 2-uple containing the context value and the search type
proc Apol_Widget::getContextSelectorValue {path} {
    variable vars
    # remove the attribute field from the third element
    set c $vars($path:context)
    # the following uses Tcl 8.4+ specific functions
    lset c 2 [lindex $c 2 0]
    list $c $vars($path:search_type)
}

########## private functions below ##########

proc Apol_Widget::_toggle_context_selector {path cb name1 name2 op} {
    if {$Apol_Widget::vars($path:enable)} {
        Apol_Widget::setContextSelectorState $path normal
    } else {
        Apol_Widget::setContextSelectorState $path disabled
    }
}

proc Apol_Widget::_show_context_dialog {path} {
    set Apol_Widget::vars($path:context) [Apol_Context_Dialog::getContext $Apol_Widget::vars($path:context)]
    # the trace on this variable will trigger [_update_context_display] to execute
}

proc Apol_Widget::_update_context_display {path name1 name2 op} {
    variable vars
    set display $path.context.display
    foreach {user role type range} $vars($path:context) {break}
    set context ""
    if {$user == ""} {
        lappend context "*"
    } else {
        lappend context $user
    }
    if {$role == ""} {
        lappend context "*"
    } else {
        lappend context $role
    }
    if {$type == ""} {
        lappend context "*"
    } else {
        lappend context [lindex $type 0]
    }
    if {[ApolTop::is_capable "mls"]} {
        if {$range == {} || $range == {{{} {}}}} {
            lappend context "*"
        } else {
            if {[catch {apol_RenderLevel [lindex $range 0]} level]} {
                set level "?"
            }
            if {[llength $range] > 1 && [lindex $range 0] != [lindex $range 1]} {
                if {[catch {apol_RenderLevel [lindex $range 1]} high]} {
                    append level " - ?"
                } else {
                    append level " - $high"
                }
            }
            if {$level == ""} {
                lappend context "*"
            } else {
                lappend context $level
            }
        }
    }
    set vars($path:context_rendered) [join $context ":"]
    $display configure -helptext $vars($path:context_rendered)
}
