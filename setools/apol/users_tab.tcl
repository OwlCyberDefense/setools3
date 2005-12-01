# Copyright (C) 2001-2005 Tresys Technology, LLC
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
    if {$opts(useRole) && $opts(role) == ""} {
        tk_messageBox -icon error -type ok -title "Error" -message "No role selected."
        return
    }
    if {$opts(enable_default) && $opts(default_level) == {{} {}}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No default level selected."
        return
    }
    set range_state [Apol_Widget::getRangeSelectorState $widgets(range)]
    foreach {range search_type} [Apol_Widget::getRangeSelectorValue $widgets(range)] break
    if {$range_state && $range == {{{} {}} {{} {}}}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No range selected."
        return
    }
    
    if {[catch {apol_GetUsers} orig_users_info]} {
	tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining users list:\n$results"
        return
    }

    # apply filters to the list of users
    set users_info {}
    foreach user $orig_users_info {
        set keep 1
        if {$opts(useRole) && \
                [lsearch -exact [lindex $user 1] $opts(role)] == -1} {
                set keep 0
        }
        if {$opts(enable_default) && \
                [lindex $user 2] != $opts(default_level)} {
            set keep 0
        }
        if {$range_state && \
                ![apol_CompareRanges $range [lindex $user 3] $search_type]} {
            set keep 0
        }
        if {$keep} {
            lappend users_info $user
        }
    }

    # now display results
    set results "USERS:"
    if {[llength $users_info] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach user_list $users_info {
            foreach {user roles default range} $user_list break
            append results "\n$user"
            if {$opts(showSelection) == "names"} {
                # skip all further reporting
                continue
            }
            append results " ([llength $roles] role"
            if {[llength $roles] != 1} {
                append results "s"
            }
            append results ")"
            if {[ApolTop::is_mls_policy]} {
                if {[catch {apol_RenderLevel $default} level]} {
                    tk_messageBox -icon error -type ok -title "Error" -message $results
                    return
                }
                append results " level $level"
                if {[catch {apol_RenderLevel [lindex $range 0]} low] ||
                    [catch {apol_RenderLevel [lindex $range 1]} high]} {
                    tk_messageBox -icon error -type ok -title "Error" -message $results
                    return
                }
                append results " range $low - $high"
            }
            append results "\n"
            foreach role $roles {
                append results "    $role\n"
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::open
# ------------------------------------------------------------------------------
proc Apol_Users::open { } {
    variable users_list
  
    set rt [catch {set users_list [apol_GetNames users]} err]
    if {$rt != 0} {
	return -code error $err
    }
    set users_list [lsort $users_list]
    $Apol_Users::widgets(role) configure -values $Apol_Roles::role_list
  
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
    if {[catch {apol_UserRoles $user} info]} {
        tk_messageBox -icon error -type ok -title Error -message $info
    } else {
	set user_count [llength $info]
        set text "$user ($user_count roles)"
	foreach role $info {
		append text "\n\t$role"
	}
        Apol_Widget::showPopupText $user $text
    }
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

    bind $widgets(role) <KeyPress> [list ApolTop::_create_popup $widgets(role) %W %K]
    trace add variable Apol_Users::opts(useRole) write \
        [list Apol_Users::toggleRolesCheckbutton $widgets(role)]
    pack $rolesFrame.cb -side top -anchor nw
    pack $widgets(role) -side top -anchor nw -padx 4 -expand 0 -fill x

    set defaultFrame [frame $ofm.default -relief sunken -borderwidth 1]
    set defaultCB [checkbutton $defaultFrame.cb -variable Apol_Users::opts(enable_default) -text "Default Level"]
    set defaultDisplay [Entry $defaultFrame.display -textvariable Apol_Users::opts(default_level_display) -width 16 -editable 0]
    set defaultButton [button $defaultFrame.button -text "Select Level..." -state disabled -command [list Apol_Users::show_level_dialog]]
    trace add variable Apol_Users::opts(enable_default) write \
        [list Apol_Users::toggleDefaultCheckbutton $defaultCB $defaultButton]
    trace add variable Apol_Users::opts(default_level) write \
        [list Apol_Users::updateDefaultDisplay]
    pack $defaultCB -side top -anchor nw -expand 0
    pack $defaultDisplay -side top -expand 0 -fill x -padx 4
    pack $defaultButton -side top -expand 1 -fill none -padx 4 -anchor ne

    set rangeFrame [frame $ofm.range -relief sunken -borderwidth 1]
    set widgets(range) [Apol_Widget::makeRangeSelector $rangeFrame.range]
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

proc Apol_Users::toggleDefaultCheckbutton {cb button name1 name2 op} {
    variable opts
    if {$opts($name2)} {
        if {[ApolTop::is_mls_policy]} {
            $button configure -state normal
        } else {
            set opts($name2) 0
            $cb configure -state normal
            tk_messageBox -icon error -type ok -title Error -message "The currently loaded policy does not have MLS enabled."
        }
    } else {
        $button configure -state disabled
    }
}

proc Apol_Users::show_level_dialog {} {
    set Apol_Users::opts(default_level) [Apol_Level_Dialog::getLevel $Apol_Users::opts(default_level)]
}

proc Apol_Users::updateDefaultDisplay {name1 name2 op} {
    variable opts
    if {$opts(default_level) == {{} {}}} {
        set opts(default_level_display) ""
    } else {
        set level [apol_RenderLevel $opts(default_level)]
        if {$level == ""} {
            set opts(default_level_display) "<invalid MLS level>"
        } else {
            set opts(default_level_display) $level
        }
    }
}
