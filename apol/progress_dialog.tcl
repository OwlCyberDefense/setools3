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

namespace eval Apol_Progress_Dialog {
    variable text
    variable prev_text
    variable val
    variable waiting 0
}

# Create a dialog to display messages while some library process is
# running.
proc Apol_Progress_Dialog::wait {title initialtext lambda} {
    variable text "$title:\n    $initialtext"
    variable prev_text $initialtext
    variable val -1

    set title_width [string length $title]
    set text_width [expr {[string length $initialtext] + 4}]
    if {$text_width < $title_width} {
        set text_width $title_width
    }
    if {$text_width < 32} {
        set text_width 32
    }

    if {[info exists .apol_progress] == 0} {
        ProgressDlg .apol_progress -title $title \
            -type normal -stop {} -separator 1 -parent . -maximum 2 \
            -width $text_width -textvariable Apol_Progress_Dialog::text \
            -variable Apol_Progress_Dialog::val
    }

    set orig_cursor [. cget -cursor]
    . configure -cursor watch
    update idletasks

    apol_tcl_clear_info_string
    variable waiting 1
    set catchval [catch {uplevel 1 $lambda} retval]
    set waiting 0

    . configure -cursor $orig_cursor
    destroy .apol_progress
    update idletasks
    return -code $catchval $retval
}

proc Apol_Progress_Dialog::is_waiting {} {
    variable waiting
    set waiting
}

proc Apol_Progress_Dialog::_update_message {} {
    variable text
    variable prev_text
    if {[set infoString [apol_tcl_get_info_string]] != $prev_text} {
        set text "[lindex [split $text "\n"] 0]\n    $infoString"
        update idletasks
        set prev_text $infoString
    }
}
