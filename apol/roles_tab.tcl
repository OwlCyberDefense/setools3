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

namespace eval Apol_Roles {
    variable widgets
    variable opts
    variable role_list {}
}

proc Apol_Roles::create {tab_name nb} {
    variable widgets
    variable opts

    _initializeVars

    set frame [$nb insert end $tab_name -text "Roles"]
    set pw [PanedWindow $frame.pw -side top]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    set rolebox [TitleFrame $leftf.rolebox -text "Roles"]
    set s_optionsbox [TitleFrame $rightf.obox -text "Search Options"]
    set resultsbox [TitleFrame $rightf.rbox -text "Search Results"]
    pack $rolebox -fill both -expand yes
    pack $s_optionsbox -padx 2 -fill both -expand 0
    pack $resultsbox -padx 2 -fill both -expand yes

    set rlistbox [Apol_Widget::makeScrolledListbox [$rolebox getframe].lb \
                      -width 20 -listvar Apol_Roles::role_list]
    Apol_Widget::setListboxCallbacks $rlistbox \
        {{"Display Role Info" {Apol_Roles::_popupRoleInfo role}}}
    pack $rlistbox -fill both -expand yes

    # Search options subframes
    set ofm [$s_optionsbox getframe]
    set lfm [frame $ofm.to]
    set cfm [frame $ofm.co]
    pack $lfm $cfm -side left -anchor nw -padx 4 -pady 2

    radiobutton $lfm.all_info -text "All information" \
        -variable Apol_Roles::opts(showSelection) -value all
    radiobutton $lfm.names_only -text "Names only" \
        -variable Apol_Roles::opts(showSelection) -value names
    pack $lfm.all_info $lfm.names_only -anchor w -padx 5 -pady 4

    set cb_type [checkbutton $cfm.cb -variable Apol_Roles::opts(useType) -text "Type"]
    set widgets(combo_types) [Apol_Widget::makeTypeCombobox $cfm.combo_types]
    Apol_Widget::setTypeComboboxState $widgets(combo_types) disabled
    trace add variable Apol_Roles::opts(useType) write \
        [list Apol_Roles::_toggleTypeCombobox $widgets(combo_types)]
    pack $cb_type -anchor w
    pack $widgets(combo_types) -anchor w -padx 4

    button $ofm.ok -text OK -width 6 -command Apol_Roles::_searchRoles
    pack $ofm.ok -side top -anchor e -pady 5 -padx 5

    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].sw]
    pack $widgets(results) -expand 1 -fill both

    return $frame
}

proc Apol_Roles::open {ppath} {
    set q [new_apol_role_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    variable role_list [lsort [role_vector_to_list $v]]
    $v -acquire
    $v -delete

    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(combo_types)
}

proc Apol_Roles::close {} {
    variable widgets
    variable opts
    variable role_list {}

    _initializeVars
    Apol_Widget::clearTypeCombobox $widgets(combo_types)
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_Roles::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

# Return a list of all role names in the current policy.  If no policy
# is loaded then return an empty list.
proc Apol_Roles::getRoles {} {
    variable role_list
    set role_list
}

#### private functions below ####

proc Apol_Roles::_initializeVars {} {
    variable opts
    array set opts {
        useType 0
        showSelection all
    }
}

proc Apol_Roles::_toggleTypeCombobox {path name1 name2 op} {
    Apol_Widget::setTypeComboboxState $path $Apol_Roles::opts(useType)
}

proc Apol_Roles::_popupRoleInfo {which role} {
    Apol_Widget::showPopupText $role [_renderRole $role 1]
}

proc Apol_Roles::_searchRoles {} {
    variable widgets
    variable opts

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {$opts(useType)} {
        set type [lindex [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(combo_types)] 0]
        if {$type == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No type selected."
            return
        }
    } else {
        set type {}
    }
    if {$opts(showSelection) == "names"} {
        set show_all 0
    } else {
        set show_all 1
    }

    set q [new_apol_role_query_t]
    $q set_type $::ApolTop::policy $type
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set roles_data [role_vector_to_list $v]
    $v -acquire
    $v -delete
    set text "ROLES:\n"
    if {[llength $roles_data] == 0} {
        append text "Search returned no results."
    } else {
        foreach r [lsort $roles_data] {
            append text "\n[_renderRole $r $show_all]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
}

proc Apol_Roles::_renderRole {role_name show_all} {
    set qpol_role_datum [new_qpol_role_t $::ApolTop::qpolicy $role_name]
    if {!$show_all} {
        return $role_name
    }
    set i [$qpol_role_datum get_type_iter $::ApolTop::qpolicy]
    set types {}
    while {![$i end]} {
        set qpol_type_datum [qpol_type_from_void [$i get_item]]
        lappend types [$qpol_type_datum get_name $::ApolTop::qpolicy]
        $i next
    }
    $i -acquire
    $i -delete
    set text "$role_name ([llength $types] type"
    if {[llength $types] != 1} {
        append text "s"
    }
    append text ")\n"
    foreach t [lsort -dictionary $types] {
        append text "    $t\n"
    }
#    append text "  dominance: $dominates\n"
    return $text
}
