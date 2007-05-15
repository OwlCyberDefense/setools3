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

namespace eval Apol_Users {
    variable opts
    variable widgets
    variable users_list {}
}

proc Apol_Users::create {tab_name nb} {
    variable opts
    variable widgets

    _initializeVars

    # Layout frames
    set frame [$nb insert end $tab_name -text "Users"]
    set pw1   [PanedWindow $frame.pw -side top]
    set rpane [$pw1 add -weight 0]
    set spane [$pw1 add -weight 1]

    # Title frames
    set userbox [TitleFrame $rpane.userbox -text "Users"]
    set s_optionsbox [TitleFrame $spane.obox -text "Search Options"]
    set resultsbox [TitleFrame $spane.rbox -text "Search Results"]
    pack $pw1 -fill both -expand yes
    pack $s_optionsbox -side top -expand 0 -fill both -padx 2
    pack $userbox -fill both -expand yes
    pack $resultsbox -expand yes -fill both -padx 2

    # Users listbox widget
    set users_listbox [Apol_Widget::makeScrolledListbox [$userbox getframe].lb -width 20 -listvar Apol_Users::users_list]
    Apol_Widget::setListboxCallbacks $users_listbox \
        {{"Display User Info" {Apol_Users::_popupUserInfo users}}}
    pack $users_listbox -fill both -expand yes

    # Search options subframes
    set ofm [$s_optionsbox getframe]
    set verboseFrame [frame $ofm.verbose]
    set rolesFrame [frame $ofm.roles]
    set defaultFrame [frame $ofm.default]
    set rangeFrame [frame $ofm.range]
    pack $verboseFrame $rolesFrame $defaultFrame $rangeFrame \
        -side left -padx 4 -pady 2 -anchor nw -expand 0 -fill y

    radiobutton $verboseFrame.all_info -text "All information" \
        -variable Apol_Users::opts(showSelection) -value all
    radiobutton $verboseFrame.names_only -text "Names only" \
        -variable Apol_Users::opts(showSelection) -value names
    pack $verboseFrame.all_info $verboseFrame.names_only -anchor w -padx 5 -pady 4

    checkbutton $rolesFrame.cb -variable Apol_Users::opts(useRole) -text "Role"
    set widgets(role) [ComboBox $rolesFrame.combo -width 12 -textvariable Apol_Users::opts(role) \
                           -helptext "Type or select a role" -state disabled \
                           -autopost 1]
    trace add variable Apol_Users::opts(useRole) write \
        [list Apol_Users::_toggleRolesCheckbutton $widgets(role)]
    pack $rolesFrame.cb -anchor nw
    pack $widgets(role) -padx 4

    set widgets(defaultCB) [checkbutton $defaultFrame.cb -variable Apol_Users::opts(enable_default) -text "Default MLS level"]
    set defaultDisplay [Entry $defaultFrame.display -textvariable Apol_Users::opts(default_level_display) -width 16 -editable 0]
    set defaultButton [button $defaultFrame.button -text "Select Level..." -state disabled -command [list Apol_Users::_show_level_dialog]]
    trace add variable Apol_Users::opts(enable_default) write \
        [list Apol_Users::_toggleDefaultCheckbutton $widgets(defaultCB) $defaultDisplay $defaultButton]
    trace add variable Apol_Users::opts(default_level) write \
        [list Apol_Users::_updateDefaultDisplay $defaultDisplay]
    pack $widgets(defaultCB) -side top -anchor nw -expand 0
    pack $defaultDisplay -side top -expand 0 -fill x -padx 4
    pack $defaultButton -side top -expand 1 -fill none -padx 4 -anchor ne

    set widgets(range) [Apol_Widget::makeRangeSelector $rangeFrame.range Users]
    pack $widgets(range) -expand 1 -fill x

    # Action Buttons
    button $ofm.ok -text OK -width 6 -command Apol_Users::_searchUsers
    pack $ofm.ok -side right -pady 5 -padx 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Users::open {ppath} {
    set q [new_apol_user_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable users_list [lsort [user_vector_to_list $v]]
    $v -delete

    variable opts
    variable widgets
    $Apol_Users::widgets(role) configure -values [Apol_Roles::getRoles]
    if {[ApolTop::is_capable "mls"]} {
        Apol_Widget::setRangeSelectorCompleteState $widgets(range) normal
        $widgets(defaultCB) configure -state normal
    } else {
        Apol_Widget::clearRangeSelector $widgets(range)
        Apol_Widget::setRangeSelectorCompleteState $widgets(range) disabled
        set opts(enable_default) 0
        $widgets(defaultCB) configure -state disabled
    }
}

proc Apol_Users::close {} {
    variable widgets

    _initializeVars
    variable users_list {}
    $widgets(role) configure -values ""
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearRangeSelector $widgets(range)
    Apol_Widget::setRangeSelectorCompleteState $widgets(range) normal
    $widgets(defaultCB) configure -state normal
}

proc Apol_Users::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

# Return a list of all user names within the current policy.  If no
# policy is loaded then return an empty list.
proc Apol_Users::getUsers {} {
    variable users_list
    set users_list
}

#### private functions below ####

proc Apol_Users::_initializeVars {} {
    variable opts
    array set opts {
        showSelection all
        useRole 0         role {}
        enable_default 0  default_level {}
    }
}

proc Apol_Users::_toggleRolesCheckbutton {path name1 name2 op} {
    variable opts
    if {$opts($name2)} {
	$path configure -state normal -entrybg white
    } else {
        $path configure -state disabled -entrybg $ApolTop::default_bg_color
    }
}

proc Apol_Users::_toggleDefaultCheckbutton {cb display button name1 name2 op} {
    variable opts
    if {$opts($name2)} {
        $button configure -state normal
        $display configure -state normal
    } else {
        $button configure -state disabled
        $display configure -state disabled
    }
}

proc Apol_Users::_show_level_dialog {} {
    variable opts
    set new_level [Apol_Level_Dialog::getLevel $opts(default_level)]
    if {$new_level != {}} {
        set opts(default_level) $new_level
        $opts(default_level) -acquire
    }
}

proc Apol_Users::_updateDefaultDisplay {display name1 name2 op} {
    variable opts
    if {$opts(default_level) == {}} {
        set opts(default_level_display) {}
        $display configure -helptext {}
    } else {
        set level [$opts(default_level) render $::ApolTop::policy]
        if {$level == {}} {
            set opts(default_level_display) "<invalid MLS level>"
        } else {
            set opts(default_level_display) $level
        }
        $display configure -helptext $opts(default_level_display)
    }
}

proc Apol_Users::_popupUserInfo {which user} {
    Apol_Widget::showPopupText $user [_renderUser $user 1]
}

proc Apol_Users::_searchUsers {} {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {$opts(useRole)} {
        if {$opts(role) == ""} {
            tk_messageBox -icon error -type ok -title "Error" -message "No role selected."
            return
        }
        set role $opts(role)
    } else {
        set role {}
    }
    if {$opts(enable_default)} {
        if {$opts(default_level) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No default level selected."
            return
        }
        set default $opts(default_level)
        # the user query will handle destroying the apol_mls_level object
    } else {
        set default NULL
    }
    set range_enabled [Apol_Widget::getRangeSelectorState $widgets(range)]
    foreach {range range_type} [Apol_Widget::getRangeSelectorValue $widgets(range)] {break}
    if {$range_enabled} {
        if {$range == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No range selected."
            return
        }
        # the user query will handle destroying the apol_mls_range object
    } else {
        set range NULL
    }
    if {$opts(showSelection) == "all"} {
        set show_all 1
    } else {
        set show_all 0
    }

    set q [new_apol_user_query_t]
    $q set_role $::ApolTop::policy $role
    $q set_default_level $::ApolTop::policy $default
    $q set_range $::ApolTop::policy $range $range_type
    set v [$q run $::ApolTop::policy]
    $q -delete
    set users_data [user_vector_to_list $v]
    $v -delete

    set text "USERS:\n"
    if {[llength $users_data] == 0} {
        append text "Search returned no results."
    } else {
        foreach u [lsort -index 0 $users_data] {
            append text "\n[_renderUser $u $show_all]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
}

proc Apol_Users::_renderUser {user_name show_all} {
    set text "$user_name"
    if {!$show_all} {
        return $text
    }
    set qpol_user_datum [new_qpol_user_t $::ApolTop::qpolicy $user_name]
    if {[ApolTop::is_capable "mls"]} {
        set default [$qpol_user_datum get_dfltlevel $::ApolTop::qpolicy]
        set apol_default [new_apol_mls_level_t $::ApolTop::policy $default]
        append text " level [$apol_default render $::ApolTop::policy]"
        $apol_default -delete
        set range [$qpol_user_datum get_range $::ApolTop::qpolicy]
        set apol_range [new_apol_mls_range_t $::ApolTop::policy $range]
        append text " range [$apol_range render $::ApolTop::policy]"
        $apol_range -delete
    }
    set i [$qpol_user_datum get_role_iter $::ApolTop::qpolicy]
    set roles {}
    while {![$i end]} {
        set qpol_role_datum [new_qpol_role_t [$i get_item]]
        lappend roles [$qpol_role_datum get_name $::ApolTop::qpolicy]
        $i next
    }
    append text " ([llength $roles] role"
    if {[llength $roles] != 1} {
        append text "s"
    }
    append text ")\n"
    foreach r $roles {
        append text "    $r\n"
    }
    return $text
}
