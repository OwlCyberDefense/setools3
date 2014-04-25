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

namespace eval Apol_Polcaps {
    variable widgets
    variable polcap_list {}
}

proc Apol_Polcaps::create {tab_name nb} {
    variable widgets

    set frame [$nb insert end $tab_name -text "Policy Capabilities"]
    set pw [PanedWindow $frame.pw -side top]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    set polcap_box [TitleFrame $leftf.polcap_box -text "Policy Capabilities"]
    pack $polcap_box -fill both -expand yes

    set rlistbox [Apol_Widget::makeScrolledListbox [$polcap_box getframe].lb \
                      -width 60 -listvar Apol_Polcaps::polcap_list]
    pack $rlistbox -fill both -expand yes

    return $frame
}

proc Apol_Polcaps::open {ppath} {
    variable polcap_list

    set polcapnames {}
    set q [new_apol_polcap_query_t]
    # This reads in the polcap info
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    # This loop will process polcap name in the policy
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
            set q [qpol_polcap_from_void [$v get_element $i]]
            append polcapnames [$q get_name $::ApolTop::qpolicy]
            append polcapnames "\n"
        }
    }

    set polcap_list $polcapnames
}

proc Apol_Polcaps::close {} {
    variable widgets
    variable polcap_list {}
}

proc Apol_Polcaps::getTextWidget {} {
    variable widgets
}

#### private functions below ####



