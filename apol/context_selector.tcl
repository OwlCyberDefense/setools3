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
    set vars($path:context) {}
    set vars($path:attribute) {}
    set vars($path:context_rendered) {}
    set vars($path:search_type) $::APOL_QUERY_EXACT

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
    set vars($path:context) {}  ;# this will invoke the display function
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
                         -state disabled -value $::APOL_QUERY_EXACT \
                         -variable Apol_Widget::vars($path:search_type)]
    set range_subset [radiobutton $context2_frame.subset -text "$rangeMatchText containing range" \
                          -state disabled -value $::APOL_QUERY_SUB \
                          -variable Apol_Widget::vars($path:search_type)]
    set range_superset [radiobutton $context2_frame.superset -text "$rangeMatchText within range" \
                            -state disabled -value $::APOL_QUERY_SUPER \
                            -variable Apol_Widget::vars($path:search_type)]
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
    set Apol_Widget::vars($path:context) {}
    set Apol_Widget::vars($path:attribute) {}
    set Apol_Widget::vars($path:search_type) $::APOL_QUERY_EXACT
    catch {set Apol_Widget::vars($path:enable) 0}
}

proc Apol_Widget::getContextSelectorState {path} {
    return $Apol_Widget::vars($path:enable)
}

# Return the currently selected context and other stuff.  This will be
# a 3-ple list of:
#   <ol>
#   <li>The (possibly partial) context, an apol_context_t.  The caller
#       must delete this afterwards.
#   <li>The MLS range search type, one of $::APOL_QUERY_EXACT or its like.
#   <li>If not an empty string, the attribute used to filter types.
#   </ol>
proc Apol_Widget::getContextSelectorValue {path} {
    variable vars
    list $vars($path:context) $vars($path:search_type) $vars($path:attribute)
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
    variable vars
    set new_context [Apol_Context_Dialog::getContext $vars($path:context) $vars($path:attribute)]
    if {$new_context != {}} {
        set vars($path:context) [lindex $new_context 0]
        set vars($path:attribute) [lindex $new_context 1]
    }
    # the trace on this variable will trigger [_update_context_display] to execute
}

proc Apol_Widget::_update_context_display {path name1 name2 op} {
    variable vars
    set display $path.context.display
    if {$vars($path:context) == {}} {
        set context_str "*:*:*"
        if {[ApolTop::is_policy_open] && [ApolTop::is_capable "mls"]} {
            append context_str ":*"
        }
    } else {
        set context_str [$vars($path:context) render $::ApolTop::policy]
    }
    set vars($path:context_rendered) $context_str
    $display configure -helptext $vars($path:context_rendered)
}
