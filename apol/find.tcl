# Copyright (C) 2007 Tresys Technology, LLC
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

namespace eval Apol_Find {
    variable dialog .apol_find_dialog
    variable search_string {}
    variable case_sensitive 0
    variable enable_regexp 0
    variable direction "down"
}

proc Apol_Find::find {} {
    variable dialog
    if {![winfo exists $dialog]} {
        _create_dialog
    } else {
        raise $dialog
        variable entry
        focus $entry
        $entry selection range 0 end
    }
}


########## private functions below ##########

proc Apol_Find::_create_dialog {} {
    variable dialog
    Dialog $dialog -title "Find" -separator 0 -parent . \
        -side right -default 0 -cancel 1 -modal none -homogeneous 1
    set top_frame [frame [$dialog getframe].top]
    set bottom_frame [frame [$dialog getframe].bottom]
    pack $top_frame -expand 1 -fill both -padx 10 -pady 5
    pack $bottom_frame -expand 0 -fill both -padx 10 -pady 5

    set entry_label [label $top_frame.l -text "Find:" -anchor e]
    variable entry [entry $top_frame.e -bg [Apol_Prefs::getPref active_bg] \
                        -textvariable Apol_Find::search_string -width 16]
    pack $entry_label -side left -expand 0 -padx 10
    pack $entry -side left -expand 1 -fill x

    set options_frame [frame $bottom_frame.opts]
    pack $options_frame -side left -padx 5
    set options_case [checkbutton $options_frame.case -text "Match case" \
                          -variable Apol_Find::case_sensitive]
    set options_regex [checkbutton $options_frame.regex -text "Regular expression" \
                           -variable Apol_Find::enable_regexp]
    pack $options_case -anchor w
    pack $options_regex -anchor w

    set dir_frame [TitleFrame $bottom_frame.dir -text Direction]
    pack $dir_frame -side left
    set dir_up [radiobutton [$dir_frame getframe].up -text Up \
                    -variable Apol_Find::direction -value up]
    set dir_down [radiobutton [$dir_frame getframe].down -text Down \
                      -variable Apol_Find::direction -value down]
    pack $dir_up $dir_down -side left

    $dialog add -text "Find Next" -command Apol_Find::_do_find
    $dialog add -text "Cancel" -command [list destroy $dialog]

    focus $entry
    $dialog draw
    wm resizable $dialog 0 0
}

proc Apol_Find::_do_find {} {
    set w [ApolTop::getCurrentTextWidget]
    if {$w == {}} {
        return
    }

    variable search_string
    variable case_sensitive
    variable enable_regexp
    variable direction

    if {$search_string == {}} {
        return
    }

    set opts {}
    if {!$case_sensitive} {
        lappend opts "-nocase"
    }
    if {$enable_regexp} {
        lappend opts "-regexp"
    }
    if {$direction == "down"} {
        lappend opts "-forward"
        set start_pos [$w index insert]
    } else {
        lappend opts "-backward"
        set start_pos [lindex [$w tag ranges sel] 0]
    }
    if {$start_pos == {}} {
        set start_pos "1.0"
    }

    $w tag remove sel 0.0 end

    variable dialog
    if {[catch {eval $w search -count count $opts -- [list $search_string] $start_pos} pos]} {
        tk_messageBox -parent $dialog -icon warning -type ok -title "Find" -message \
                 "Invalid regular expression."
        return
    }

    if {$pos == {}} {
        tk_messageBox -parent $dialog -icon warning -type ok -title "Find" -message \
                 "String not found."
    } else {
        if {$direction == "down"} {
            $w mark set insert "$pos + $count char"
            $w see "$pos + $count char"
        } else {
            $w mark set insert "$pos"
            $w see $pos
        }
        $w tag add sel $pos "$pos + $count char"
    }
}
