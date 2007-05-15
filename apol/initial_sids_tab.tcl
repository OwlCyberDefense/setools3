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

namespace eval Apol_Initial_SIDS {
    variable widgets
    variable vals
}

proc Apol_Initial_SIDS::create {tab_name nb} {
    variable widgets
    variable vals

    array set vals {
        items {}
    }

    set frame [$nb insert end $tab_name -text "Initial SIDs"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    set sids_box [TitleFrame $leftf.sids_box -text "Initial SIDs"]
    set s_optionsbox [TitleFrame $rightf.obox -text "Search Options"]
    set rslts_frame [TitleFrame $rightf.rbox -text "Search Results"]
    pack $sids_box -expand 1 -fill both
    pack $s_optionsbox -side top -expand 0 -fill both -padx 2
    pack $rslts_frame -side top -expand yes -fill both -padx 2

    set widgets(items) [Apol_Widget::makeScrolledListbox [$sids_box getframe].lb -width 20 -listvar Apol_Initial_SIDS::vals(items)]
    Apol_Widget::setListboxCallbacks $widgets(items) \
        {{"Display Initial SID Context" {Apol_Initial_SIDS::_popupSIDInfo}}}
    pack $widgets(items) -expand 1 -fill both

    set f [frame [$s_optionsbox getframe].c]
    set widgets(context) [Apol_Widget::makeContextSelector $f.context "Context"]
    pack $widgets(context)
    pack $f -side left -anchor n -padx 4 -pady 2

    set ok [button [$s_optionsbox getframe].ok -text "OK" -width 6 \
                -command Apol_Initial_SIDS::_search]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$rslts_frame getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}

proc Apol_Initial_SIDS::open {ppath} {
    variable vals
    set q [new_apol_isid_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set vals(items) [lsort [isid_vector_to_list $v]]
    $v -delete
}

proc Apol_Initial_SIDS::close {} {
    variable vals
    variable widgets
    set vals(items) {}
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(context)
}

proc Apol_Initial_SIDS::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

#### private functions below ####

proc Apol_Initial_SIDS::_popupSIDInfo {sid} {
    set text "$sid:\n    [_render_isid $sid 1]"
    Apol_Widget::showPopupText "$sid Context" $text
}

proc Apol_Initial_SIDS::_search {} {
    variable vals
    variable widgets

    set name {}
    set context {}
    set range_match 0
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }

    set q [new_apol_isid_query_t]
    if {[Apol_Widget::getContextSelectorState $widgets(context)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(context)] {break}
        $q set_context $::ApolTop::policy $context $range_match
    }
    set v [$q run $::ApolTop::policy]
    $q -delete
    set isids [isid_vector_to_list $v]
    $v -delete

    set results "INITIAL SIDS:"
    if {[llength $isids] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach i [lsort -dictionary $isids] {
            append results "\n[_render_isid $i]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Initial_SIDS::_render_isid {isid_name {compact 0}} {
    set qpol_isid_datum [new_qpol_isid_t $::ApolTop::qpolicy $isid_name]
    set qpol_context [$qpol_isid_datum get_context $::ApolTop::qpolicy]
    set context_str [apol_qpol_context_render $::ApolTop::policy $qpol_context]
    if {$compact} {
        format "sid %s %s" $isid_name $context_str
    } else {
        format "sid  %-16s %s" $isid_name $context_str
    }
}
