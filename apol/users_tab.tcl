# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets


##############################################################
# ::Apol_Users
#  
# The Users page
##############################################################
namespace eval Apol_Users {
    variable opts
    variable users_list ""
    variable widgets
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Users::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Users::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Users::set_Focus_to_Text {} {
    focus $Apol_Users::widgets(results)
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::searchUsers
# ------------------------------------------------------------------------------
proc Apol_Users::searchUsers {} {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
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
        if {$opts(default_level) == {{} {}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No default level selected."
            return
        }
        set default $opts(default_level)
    } else {
        set default {}
    }
    set range_enabled [Apol_Widget::getRangeSelectorState $widgets(range)]
    foreach {range range_type} [Apol_Widget::getRangeSelectorValue $widgets(range)] {break}
    if {$range_enabled} {
        if {$range == {{{} {}} {{} {}}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No range selected."
            return
        }
    } else {
        set range {}
    }
    if {$opts(showSelection) == "all"} {
        set show_all 1
    } else {
        set show_all 0
    }

    if {[catch {apol_GetUsers {} $role $default $range $range_type 0} users_data]} {
	tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining users list:\n$users_data"
        return
    }
    set text "USERS:\n"
    if {[llength $users_data] == 0} {
        append text "Search returned no results."
    } else {
        foreach u [lsort -index 0 $users_data] {
            append text "\n[renderUser $u $show_all]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
}

proc Apol_Users::renderUser {user_datum show_all} {
    set text ""
    foreach {user roles default range} $user_datum {break}
    append text "$user"
    if {!$show_all} {
        return $text
    }
    if {[ApolTop::is_mls_policy]} {
        append text " level [apol_RenderLevel $default]"
        set low [apol_RenderLevel [lindex $range 0]]
        set high [apol_RenderLevel [lindex $range 1]]
        if {$low == $high} {
            append text " range $low"
        } else {
            append text " range $low - $high"
        }
    }
    append text " ([llength $roles] role"
    if {[llength $roles] != 1} {
        append text "s"
    }
    append text ")"
    append text "\n"
    foreach r $roles {
        append text "    $r\n"
    }
    return $text
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::open
# ------------------------------------------------------------------------------
proc Apol_Users::open { } {
    variable users_list {}
    variable widgets
    foreach u [apol_GetUsers {} {} {} {} {} 0] {
        lappend users_list [lindex $u 0]
    }
    set users_list [lsort $users_list]
    $Apol_Users::widgets(role) configure -values $Apol_Roles::role_list
    if {[ApolTop::is_mls_policy]} {
        Apol_Widget::setRangeSelectorCompleteState $widgets(range) normal
        $widgets(defaultCB) configure -state normal
    } else {
        Apol_Widget::clearRangeSelector $widgets(range)
        Apol_Widget::setRangeSelectorCompleteState $widgets(range) disabled
        set Apol_Users::opts(enable_default) 0
        $widgets(defaultCB) configure -state disabled
    }
    return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Users::close
# ------------------------------------------------------------------------------
proc Apol_Users::close { } {
    variable opts
    variable widgets
    set Apol_Users::users_list ""
    $widgets(role) configure -values ""
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearRangeSelector $widgets(range)
    Apol_Widget::setRangeSelectorCompleteState $widgets(range) normal
    $widgets(defaultCB) configure -state normal
    array set opts {
        showSelection all
        useRole 0         role {}
        enable_default 0  default_level {{} {}}
    }
}

proc Apol_Users::free_call_back_procs { } {
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::popupUserInfo
# ------------------------------------------------------------------------------
proc Apol_Users::popupUserInfo {which user} {
    set user_datum [lindex [apol_GetUsers $user] 0]
    Apol_Widget::showPopupText $user [renderUser $user_datum 1]
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Users::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::create
# ------------------------------------------------------------------------------
proc Apol_Users::create {nb} {
    variable opts
    variable widgets

    array set opts {
        showSelection all
        useRole 0          role {}
        enable_default 0   default_level {{} {}}
    }
    
    # Layout frames
    set frame [$nb insert end $ApolTop::users_tab -text "Users"]
    set pw1   [PanedWindow $frame.pw -side top]
    set rpane [$pw1 add -weight 0]
    set spane [$pw1 add -weight 1]

    # Title frames
    set userbox [TitleFrame $rpane.userbox -text "Users"]
    set s_optionsbox [TitleFrame $spane.obox -text "Search Options"]
    set resultsbox [TitleFrame $spane.rbox -text "Search Results"]

    # Placing layout
    pack $pw1 -fill both -expand yes

    # Placing title frames
    pack $s_optionsbox -side top -expand 0 -fill both -padx 2
    pack $userbox -fill both -expand yes
    pack $resultsbox -expand yes -fill both -padx 2
   
    # Users listbox widget
    set users_listbox [Apol_Widget::makeScrolledListbox [$userbox getframe].lb -width 20 -listvar Apol_Users::users_list]
    Apol_Widget::setListboxCallbacks $users_listbox \
        {{"Display User Info" {Apol_Users::popupUserInfo users}}}
    pack $users_listbox -fill both -expand yes

    # Search options subframes
    set ofm [$s_optionsbox getframe]
    
    set verboseFrame [frame $ofm.verbose -relief sunken -borderwidth 1]
    radiobutton $verboseFrame.names_only -text "Names Only" \
        -variable Apol_Users::opts(showSelection) -value names 
    radiobutton $verboseFrame.all_info -text "All Information" \
        -variable Apol_Users::opts(showSelection) -value all
    pack $verboseFrame.names_only $verboseFrame.all_info -side top -anchor nw -pady 5 -padx 5

    set rolesFrame [frame $ofm.roles -relief sunken -borderwidth 1]
    checkbutton $rolesFrame.cb -variable Apol_Users::opts(useRole) -text "Roles"
    set widgets(role) [ComboBox $rolesFrame.combo -width 12 -textvariable Apol_Users::opts(role) \
                           -helptext "Type or select a role" -state disabled]

    bind $widgets(role).e <KeyPress> [list ApolTop::_create_popup $widgets(role) %W %K]
    trace add variable Apol_Users::opts(useRole) write \
        [list Apol_Users::toggleRolesCheckbutton $widgets(role)]
    pack $rolesFrame.cb -side top -anchor nw
    pack $widgets(role) -side top -anchor nw -padx 4 -expand 0 -fill x

    set defaultFrame [frame $ofm.default -relief sunken -borderwidth 1]
    set widgets(defaultCB) [checkbutton $defaultFrame.cb -variable Apol_Users::opts(enable_default) -text "Default MLS Level"]
    set defaultDisplay [Entry $defaultFrame.display -textvariable Apol_Users::opts(default_level_display) -width 16 -editable 0]
    set defaultButton [button $defaultFrame.button -text "Select Level..." -state disabled -command [list Apol_Users::show_level_dialog]]
    trace add variable Apol_Users::opts(enable_default) write \
        [list Apol_Users::toggleDefaultCheckbutton $widgets(defaultCB) $defaultDisplay $defaultButton]
    trace add variable Apol_Users::opts(default_level) write \
        [list Apol_Users::updateDefaultDisplay $defaultDisplay]
    pack $widgets(defaultCB) -side top -anchor nw -expand 0
    pack $defaultDisplay -side top -expand 0 -fill x -padx 4
    pack $defaultButton -side top -expand 1 -fill none -padx 4 -anchor ne

    set rangeFrame [frame $ofm.range -relief sunken -borderwidth 1]
    set widgets(range) [Apol_Widget::makeRangeSelector $rangeFrame.range Users]
    pack $widgets(range) -expand 1 -fill x
    
    pack $verboseFrame $rolesFrame $defaultFrame $rangeFrame \
        -side left -padx 5 -pady 4 -anchor nw -expand 0 -fill y

    # Action Buttons
    button $ofm.ok -text OK -width 6 -command {Apol_Users::searchUsers}
    pack $ofm.ok -side right -pady 5 -padx 5 -anchor ne

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -expand yes -fill both 

    return $frame	
}

#### private functions below ####

proc Apol_Users::toggleRolesCheckbutton {path name1 name2 op} {
    variable opts
    if {$opts($name2)} {
	$path configure -state normal -entrybg white
    } else {
        $path configure -state disabled -entrybg $ApolTop::default_bg_color
    }
}

proc Apol_Users::toggleDefaultCheckbutton {cb display button name1 name2 op} {
    variable opts
    if {$opts($name2)} {
        $button configure -state normal
        $display configure -state normal
    } else {
        $button configure -state disabled
        $display configure -state disabled
    }
}

proc Apol_Users::show_level_dialog {} {
    set Apol_Users::opts(default_level) [Apol_Level_Dialog::getLevel $Apol_Users::opts(default_level)]
}

proc Apol_Users::updateDefaultDisplay {display name1 name2 op} {
    variable opts
    if {$opts(default_level) == {{} {}}} {
        set opts(default_level_display) ""
        $display configure -helptext {}
    } else {
        set level [apol_RenderLevel $opts(default_level)]
        if {$level == ""} {
            set opts(default_level_display) "<invalid MLS level>"
        } else {
            set opts(default_level_display) $level
        }
        $display configure -helptext $opts(default_level_display)
    }
}
