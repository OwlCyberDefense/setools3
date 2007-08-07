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

namespace eval Apol_Goto {
    variable dialog .apol_goto_dialog
    variable line_num
}

proc Apol_Goto::goto {} {
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

proc Apol_Goto::_create_dialog {} {
    variable dialog
    Dialog $dialog -title "Goto Line" -separator 0 -parent . \
        -default 0 -cancel 1 -modal none -homogeneous 1
    set top_frame [$dialog getframe]
    set entry_label [label $top_frame.l -text "Goto Line:" -anchor e]
    variable entry [entry $top_frame.e -bg [Apol_Prefs::getPref active_bg] \
                        -textvariable Apol_Goto::line_num -width 10]
    pack $entry_label -side left -padx 5 -pady 5
    pack $entry -side left -padx 5 -pady 5 -expand 1 -fill x

    $dialog add -text "OK" -command [list Apol_Goto::_do_goto]
    $dialog add -text "Cancel" -command [list destroy $dialog]

    $entry selection range 0 end
    focus $entry
    $dialog draw
    wm resizable $dialog 0 0
}

proc Apol_Goto::_do_goto {} {
    set w [ApolTop::getCurrentTextWidget]
    if {$w == {}} {
        return
    }

    variable line_num
    if {[string is integer -strict $line_num] != 1} {
        tk_messageBox -icon error \
            -type ok  \
            -title "Goto Line" \
            -message "$line_num is not a valid line number."
    } else {
	$w tag remove sel 0.0 end
	$w mark set insert ${line_num}.0
	$w see ${line_num}.0
	$w tag add sel $line_num.0 $line_num.end
	focus $w
    }

    variable dialog
    destroy $dialog
}
