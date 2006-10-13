# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget


##############################################################
# ::Apol_Roles
#  
# The Roles page
##############################################################
namespace eval Apol_Roles {
    variable widgets
    variable opts
    set opts(useType)		0
    set opts(showSelection)     all
    variable role_list 		""
}

proc Apol_Roles::open { } {
    variable widgets
    variable role_list {}
    foreach r [apol_GetRoles {} {} 0] {
        lappend role_list [lindex $r 0]
    }
    set role_list [lsort $role_list]
    Apol_Widget::resetTypeComboboxToPolicy $widgets(combo_types)
}

proc Apol_Roles::close { } {
    variable widgets
    variable opts 
    set opts(useType)	0
    set opts(showSelection) 	all
    set Apol_Roles::role_list 	""
    Apol_Widget::clearTypeCombobox $widgets(combo_types)
    Apol_Widget::clearSearchResults $widgets(resultsbox)
}

proc Apol_Roles::free_call_back_procs { } {
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Roles::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Roles::set_Focus_to_Text {} {
    focus $Apol_Roles::widgets(resultsbox)
}

proc Apol_Roles::popupRoleInfo {which role} {
    set role_datum [lindex [apol_GetRoles $role] 0]
    Apol_Widget::showPopupText $role [renderRole $role_datum 1]
}

proc Apol_Roles::renderRole {role_datum show_all} {
    foreach {name types dominates} $role_datum {break}
    if {!$show_all} {
        return $name
    }
    set text "$name ([llength $types] type"
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

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Roles::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(resultsbox).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_Roles::searchRoles {} {
    variable widgets
    variable opts

    Apol_Widget::clearSearchResults $widgets(resultsbox)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {$opts(useType)} {
        set type [Apol_Widget::getTypeComboboxValue $widgets(combo_types)]
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

    if {[catch {apol_GetRoles {} $type 0} roles_data]} {
        tk_messageBox -icon error -type ok -title "Error" -message $roles_data
        return
    }

    set text "ROLES:\n"
    if {[llength $roles_data] == 0} {
        append text "Search returned no results."
    } else {
        foreach r [lsort -index 0 $roles_data] {
            append text "\n[renderRole $r $show_all]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(resultsbox) $text
}

proc Apol_Roles::toggleTypeCombobox {path name1 name2 op} {
    Apol_Widget::setTypeComboboxState $path $Apol_Roles::opts(useType)
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Roles::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(resultsbox) $line_num
}

proc Apol_Roles::create {nb} {
    variable widgets
    variable opts
    
    # Layout frames
    set frame [$nb insert end $ApolTop::roles_tab -text "Roles"]
    set pw [PanedWindow $frame.pw -side top]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes
    
    # Title frames
    set rolebox [TitleFrame $leftf.rolebox -text "Roles"]
    set s_optionsbox [TitleFrame $rightf.obox -text "Search Options"]
    set resultsbox [TitleFrame $rightf.rbox -text "Search Results"]
    
    # Placing title frames
    pack $rolebox -fill both -expand yes
    pack $s_optionsbox -padx 2 -fill both -expand 0
    pack $resultsbox -padx 2 -fill both -expand yes
    
    # Roles listbox widget
    set rlistbox [Apol_Widget::makeScrolledListbox [$rolebox getframe].lb \
                      -width 20 -listvar Apol_Roles::role_list]
    Apol_Widget::setListboxCallbacks $rlistbox \
        {{"Display Role Info" {Apol_Roles::popupRoleInfo role}}}
    pack $rlistbox -fill both -expand yes

    # Search options subframes
    set ofm [$s_optionsbox getframe]
    set lfm [frame $ofm.to]
    set cfm [frame $ofm.co]
    pack $lfm $cfm -side left -anchor nw -padx 4 -pady 2

    # Set default state for combo boxes
    radiobutton $lfm.all_info -text "All information" \
        -variable Apol_Roles::opts(showSelection) -value all
    radiobutton $lfm.names_only -text "Names only" \
        -variable Apol_Roles::opts(showSelection) -value names
    pack $lfm.all_info $lfm.names_only -anchor w -padx 5 -pady 4

    # Search options widget items
    set cb_type [checkbutton $cfm.cb -variable Apol_Roles::opts(useType) -text "Type"]
    set widgets(combo_types) [Apol_Widget::makeTypeCombobox $cfm.combo_types]
    Apol_Widget::setTypeComboboxState $widgets(combo_types) disabled
    trace add variable Apol_Roles::opts(useType) write \
        [list Apol_Roles::toggleTypeCombobox $widgets(combo_types)]
    pack $cb_type -anchor w
    pack $widgets(combo_types) -anchor w -padx 4

    button $ofm.ok -text OK -width 6 -command {Apol_Roles::searchRoles}      
    pack $ofm.ok -side top -anchor e -pady 5 -padx 5

    # Display results window
    set widgets(resultsbox) [Apol_Widget::makeSearchResults [$resultsbox getframe].sw]
    pack $widgets(resultsbox) -expand 1 -fill both

    return $frame	
}
