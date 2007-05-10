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

set COPYRIGHT_INFO "Copyright (C) 2001-2007 Tresys Technology, LLC"

namespace eval ApolTop {
    variable policy {} ;# handle to an apol_policy, or {} if none opened
    variable qpolicy {} ;# handle to policy's qpol_policy_t, or {} if none opened
    variable polstats

    # these three are shown along the status line of the toplevel window
    variable policy_version_string {}
    variable policyConf_lineno {}
    variable policy_stats_summary {}

    # user's preferences
    variable dot_apol_file [file join $::env(HOME) .apol]
    variable recent_files {}
    variable last_policy_path {}
    variable max_recent_files 5
    variable show_fake_attrib_warning 1 ;# warn if using fake attribute names

    variable goto_line_num

    # store the default background color for use when diabling widgets
    variable default_bg_color
    variable text_font {}
    variable title_font {}
    variable dialog_font {}
    variable general_font {}
    variable query_file_ext ".qf"
    # Main window dimension defaults
    variable mainframe_width 1000
    variable mainframe_height 700

    # Top-level dialog widgets
    variable searchDlg .apol_find_dialog
    variable goto_Dialog .apol_goto_dialog
    variable options_Dialog .apol_options_dialog

    ######################
    # Other global widgets
    variable mainframe
    variable textbox_policyConf
    variable searchDlg_entryBox
    variable gotoDlg_entryBox
    # Main top-level notebook widget
    variable notebook
    # Subordinate notebook widgets
    variable components_nb
    variable rules_nb

    variable mls_tabs {}  ;# list of notebook tabs that are only for MLS

    # Search-related variables
    variable searchString	""
    variable case_sensitive     0
    variable regExpr		0
    variable srch_Direction	"down"

    # Notebook tab IDENTIFIERS; NOTE: We name all tabs after their
    # related namespace qualified names.  We use the prefix 'Apol_'
    # for all notebook tabnames. Note that the prefix must end with an
    # underscore and that that tabnames may NOT have a colon.
    variable tabName_prefix	"Apol_"
    variable components_tab	"Apol_Components"
    variable types_tab		"Apol_Types"
    variable class_perms_tab	"Apol_Class_Perms"
    variable roles_tab		"Apol_Roles"
    variable users_tab		"Apol_Users"
    variable cond_bools_tab	"Apol_Cond_Bools"
    variable mls_tab            "Apol_MLS"
    variable initial_sids_tab	"Apol_Initial_SIDS"
    variable net_contexts_tab	"Apol_NetContexts"
    variable fs_contexts_tab	"Apol_FSContexts"

    variable rules_tab		"Apol_Rules"
    variable terules_tab	"Apol_TE"
    variable cond_rules_tab	"Apol_Cond_Rules"
    variable rbac_tab		"Apol_RBAC"
    variable range_tab		"Apol_Range"

    variable file_contexts_tab	"Apol_File_Contexts"

    variable analysis_tab	"Apol_Analysis"

    variable policy_conf_tab	"Apol_PolicyConf"

    variable tab_names {
        Types Class_Perms Roles Users Cond_Bools MLS Initial_SIDS NetContexts FSContexts
        TE Cond_Rules RBAC Range
        File_Contexts
        Analysis
        PolicyConf
    }
}

proc ApolTop::is_policy_open {} {
    if {$::ApolTop::policy == {}} {
        return 0
    }
    return 1
}

proc ApolTop::get_toplevel_dialog {} {
    return $ApolTop::mainframe
}

# If a policy is open and it has the given capability then return
# non-zero.  Valid capabilities are:
#   "attribute names"
#   "conditionals"
#   "line numbers"
#   "mls"
#   "source"
#   "syntactic rules"
proc ApolTop::is_capable {capability} {
    if {![is_policy_open]} {
        return 0;
    }
    switch -- $capability {
        "attribute names" { set cap $::QPOL_CAP_ATTRIB_NAMES }
        "conditionals" { set cap $::QPOL_CAP_CONDITIONALS }
        "line numbers" { set cap $::LINE_NUMBERS }
        "mls" { set cap $::QPOL_CAP_MLS }
        "source" { set cap $::QPOL_CAP_SOURCE }
        "syntactic rules" { set cap $::QPOL_CAP_SYN_RUSE }
        default { return 0 }
    }
    variable qpolicy
    $qpolicy has_capability $cap
}

proc ApolTop::load_fc_index_file {} {
    set rt [Apol_File_Contexts::load_fc_db]
    if {$rt == 1} {
        ApolTop::configure_load_index_menu_item 1
    }
}

proc ApolTop::create_fc_index_file {} {
    Apol_File_Contexts::display_create_db_dlg
}

proc ApolTop::load_perm_map_fileDlg {} {
    if {[Apol_Perms_Map::loadPermMapFromFile]} {
        ApolTop::configure_edit_pmap_menu_item 1
    }
}

proc ApolTop::load_default_perm_map_Dlg {} {
    if {[Apol_Perms_Map::loadDefaultPermMap]} {
        ApolTop::configure_edit_pmap_menu_item 1
    }
}

proc ApolTop::configure_edit_pmap_menu_item {enable} {
    variable mainframe

    if {$enable} {
        [$mainframe getmenu pmap_menu] entryconfigure last -state normal -label "Edit Perm Map..."
    } else {
        [$mainframe getmenu pmap_menu] entryconfigure last -state disabled -label "Edit Perm Map... (Not loaded)"
    }
}

proc ApolTop::configure_load_index_menu_item {enable} {
    variable mainframe

    if {$enable} {
        [$mainframe getmenu fc_index_menu] entryconfigure last -label "Load Index..."
    } else {
        [$mainframe getmenu fc_index_menu] entryconfigure last -label "Load Index... (Not loaded)"
    }
}

proc ApolTop::popup {parent x y menu callbacks callback_arg} {
    # determine where to place the popup menu
    set gx [winfo rootx $parent]
    set gy [winfo rooty $parent]
    set cmx [expr {$gx + $x}]
    set cmy [expr {$gy + $y}]

    $menu delete 0 end
    foreach callback $callbacks {
        $menu add command -label [lindex $callback 0] -command [concat [lindex $callback 1] $callback_arg]
    }
    tk_popup $menu $cmx $cmy
}

proc ApolTop::set_Focus_to_Text { tab } {
    variable components_nb
    variable rules_nb
    variable file_contexts_tab

    $ApolTop::mainframe setmenustate Disable_SearchMenu_Tag normal
    # The load query menu option should be enabled across all tabs.
    # However, we disable the save query menu option if it this is not
    # the Analysis or TE Rules tab.  Currently, these are the only
    # tabs providing the ability to save queries. It would be too
    # trivial to allow saving queries for the other tabs.
    $ApolTop::mainframe setmenustate Disable_LoadQuery_Tag normal
    set ApolTop::policyConf_lineno {}

    switch -exact -- $tab \
        $ApolTop::components_tab {
            $ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
            ApolTop::set_Focus_to_Text [$components_nb raise]
        } \
        $ApolTop::rules_tab {
            ApolTop::set_Focus_to_Text [$rules_nb raise]
        } \
        $ApolTop::terules_tab {
            $ApolTop::mainframe setmenustate Disable_SaveQuery_Tag normal
            set raisedPage [Apol_TE::get_results_raised_tab]
            if {$raisedPage != ""} {
                Apol_TE::set_Focus_to_Text $raisedPage
            } else {
                focus [$ApolTop::rules_nb getframe $ApolTop::terules_tab]
            }
        } \
        $ApolTop::analysis_tab {
            $ApolTop::mainframe setmenustate Disable_SaveQuery_Tag normal
        } \
        default {
            $ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
            ${tab}::set_Focus_to_Text
        }
}

# Search for an instances of a given string in a text widget and
# select matching text.
#
# @param w Text widget to search
# @str String to search.
# @param nocase If non-zero, search case insensitive.
# @param regexp If non-zero, treat $str as a regular expression.
# @param dir What direction to search in the text, either "up" or "down".
proc ApolTop::textSearch {w str nocase regexp dir} {
    if {$str == {}} {
        return
    }

    set opts {}
    if {$nocase} {
        lappend opts "-nocase"
    }
    if {$regexp} {
        lappend opts "-regexp"
    }
    if {$dir == "down"} {
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
    set pos [eval $w search -count count $opts -- [list $str] $start_pos]

    if {$pos == {}} {
        tk_messageBox -parent $ApolTop::searchDlg -icon warning -type ok -title "Find" -message \
                 "String not found."
    } else {
        if {$dir == "down"} {
            $w mark set insert "$pos + $count char"
            $w see "$pos + $count char"
        } else {
            $w mark set insert "$pos"
            $w see $pos
        }
        $w tag add sel $pos "$pos + $count char"
    }
}

##############################################################
# ::search
#	- Search raised text widget for a string
#
proc ApolTop::search {} {
    variable searchString
    variable case_sensitive
    variable regExpr
    variable srch_Direction
    variable notebook
    variable components_nb
    variable rules_nb
    variable components_tab
    variable rules_tab
    variable policy_conf_tab
    variable analysis_tab
    variable file_contexts_tab

    if {$case_sensitive} {
        set insens 0
    } else {
        set insens 1
    }
    set raised_tab [$notebook raise]
    switch -- $raised_tab \
        $policy_conf_tab {
            ${policy_conf_tab}::search $searchString $insens $regExpr $srch_Direction
        } \
        $analysis_tab {
            ${analysis_tab}::search $searchString $insens $regExpr $srch_Direction
        } \
        $rules_tab {
            [$rules_nb raise]::search $searchString $insens $regExpr $srch_Direction
        } \
        $components_tab {
            [$components_nb raise]::search $searchString $insens $regExpr $srch_Direction
        } \
        $file_contexts_tab {
            ${file_contexts_tab}::search $searchString $insens $regExpr $srch_Direction
        } \
        default {
            puts "Invalid raised tab!"
        }
}

##############################################################
# ::load_query_info
#	- Call load_query proc for valid tab
#
proc ApolTop::load_query_info {} {
    variable notebook
    variable rules_tab
    variable terules_tab
    variable analysis_tab
    variable rules_nb
    variable mainframe

    set query_file ""
    set types {
        {"Query files" {$ApolTop::query_file_ext}}
    }
    set query_file [tk_getOpenFile -filetypes $types -title "Select Query to Load..." \
                        -defaultextension $ApolTop::query_file_ext -parent $mainframe]
    if {$query_file != ""} {
        if {[file exists $query_file] == 0} {
            tk_messageBox -icon error -type ok -title "Error" \
                -message "File $query_file does not exist." -parent $mainframe
            return -1
        }
        if {[catch {::open $query_file r} f]} {
            tk_messageBox -icon error -type ok -title "Error" \
                -message "Cannot open $query_file: $f"
            return -1
        }
        # Search for the analysis type line
        gets $f line
        set query_id [string trim $line]
        while {[eof $f] != 1} {
            # Skip empty lines and comments
            if {$query_id == "" || [string compare -length 1 $query_id "#"] == 0} {
                gets $f line
                set query_id [string trim $line]
                continue
            }
            break
        }

        switch -- $query_id \
            $analysis_tab {
                set rt [catch {${analysis_tab}::load_query_options $f $mainframe} err]
                if {$rt != 0} {
                    tk_messageBox -icon error -type ok -title "Error" \
                        -message "$err"
                    return -1
                }
                $notebook raise $analysis_tab
            } \
            $terules_tab {
                if {[string equal [$rules_nb raise] $ApolTop::terules_tab]} {
                    set rt [catch {${ApolTop::terules_tab}::load_query_options $f $mainframe} err]
                    if {$rt != 0} {
                        tk_messageBox -icon error -type ok -title "Error" \
                            -message "$err"
                        return -1
                    }
                    $notebook raise $rules_tab
                    $rules_nb raise $ApolTop::terules_tab
                }
            } \
            default {
                tk_messageBox -icon error -type ok -title "Error" \
                    -message "Invalid query ID."
            }
        ApolTop::set_Focus_to_Text [$notebook raise]
        ::close $f
    }
}

##############################################################
# ::save_query_info
#	- Call save_query proc for valid tab
#
proc ApolTop::save_query_info {} {
    variable notebook
    variable rules_tab
    variable terules_tab
    variable analysis_tab
    variable rules_nb
    variable mainframe

    # Make sure we only allow saving from the Analysis and TERules tabs
    set raised_tab [$notebook raise]

    if {![string equal $raised_tab $analysis_tab] && ![string equal $raised_tab $rules_tab]} {
        tk_messageBox -icon error -type ok -title "Save Query Error" \
            -message "You cannot save a query from this tab. \
			You can only save from the Policy Rules->TE Rules tab and the Analysis tab."
        return -1
    }
    if {[string equal $raised_tab $rules_tab] && ![string equal [$rules_nb raise] $terules_tab]} {
        tk_messageBox -icon error -type ok -title "Save Query Error" \
            -message "You cannot save a query from this tab. \
			You can only save from the Policy Rules->TE Rules tab and the Analysis tab."
        return -1
    }

    set query_file ""
    set types {
        {"Query files" {$ApolTop::query_file_ext}}
    }
    set query_file [tk_getSaveFile -title "Save Query As?" \
                        -defaultextension $ApolTop::query_file_ext \
                        -filetypes $types -parent $mainframe]
    if {$query_file != ""} {
        set f [::open $query_file w+]
        switch -- $raised_tab \
            $analysis_tab {
                puts $f "$analysis_tab"
                set rt [catch {${analysis_tab}::save_query_options $f $query_file} err]
                if {$rt != 0} {
                    ::close $f
                    tk_messageBox -icon error -type ok -title "Save Query Error" \
                        -message "$err"
                    return -1
                }
            } \
            $rules_tab {
                if {[string equal [$rules_nb raise] $terules_tab]} {
                    puts $f "$terules_tab"
                    set rt [catch {${terules_tab}::save_query_options $f $query_file} err]
                    if {$rt != 0} {
                        ::close $f
                        tk_messageBox -icon error -type ok -title "Save Query Error" \
                            -message "$err"
                        return -1
                    }
                }
            } \
            default {
                ::close $f
                tk_messageBox -icon error -type ok -title "Save Query Error" \
                    -message "You cannot save a query from this tab!"
                return -1
            }
        ::close $f
    }
}

proc ApolTop::displayFindDialog {} {
    variable searchDlg
    variable searchDlg_entryBox

    if {[winfo exists $searchDlg]} {
        raise $searchDlg
        focus $searchDlg_entryBox
        $searchDlg_entryBox selection range 0 end
        return
    }

    Dialog $searchDlg -title "Find" -separator 0 -parent . \
        -side right -default 0 -cancel 1 -modal none -homogeneous 1
    set top_frame [frame [$searchDlg getframe].top]
    set bottom_frame [frame [$searchDlg getframe].bottom]
    pack $top_frame -expand 1 -fill both -padx 10 -pady 5
    pack $bottom_frame -expand 0 -fill both -padx 10 -pady 5

    set entry_label [label $top_frame.l -text "Find:" -anchor e]
    set searchDlg_entryBox [entry $top_frame.e -bg white \
                                -textvariable ApolTop::searchString -width 16]
    pack $entry_label -side left -expand 0 -padx 10
    pack $searchDlg_entryBox -side left -expand 1 -fill x

    set options_frame [frame $bottom_frame.opts]
    pack $options_frame -side left -padx 5
    set options_case [checkbutton $options_frame.case -text "Match case" \
                          -variable ApolTop::case_sensitive]
    set options_regex [checkbutton $options_frame.regex -text "Regular expression" \
                           -variable ApolTop::regExpr]
    pack $options_case -anchor w
    pack $options_regex -anchor w

    set dir_frame [TitleFrame $bottom_frame.dir -text Direction]
    pack $dir_frame -side left
    set dir_up [radiobutton [$dir_frame getframe].up -text Up \
                    -variable ApolTop::srch_Direction -value up]
    set dir_down [radiobutton [$dir_frame getframe].down -text Down \
                      -variable ApolTop::srch_Direction -value down]
    pack $dir_up $dir_down -side left

    $searchDlg add -text "Find Next" -command ApolTop::search
    $searchDlg add -text "Cancel" -command [list destroy $searchDlg]

    $searchDlg_entryBox selection range 0 end
    focus $searchDlg_entryBox
    $searchDlg draw
    wm resizable $searchDlg 0 0
}

########################################################################
# ::goto_line
#	- goes to indicated line in text box
#
proc ApolTop::goto_line { line_num textBox } {
    if {[string is integer -strict $line_num] != 1} {
        tk_messageBox -icon error \
            -type ok  \
            -title "Invalid Line Number" \
            -message "$line_num is not a valid line number."
    } else {
	# Remove any selection tags.
	$textBox tag remove sel 0.0 end
	$textBox mark set insert ${line_num}.0
	$textBox see ${line_num}.0
	$textBox tag add sel $line_num.0 $line_num.end
	focus $textBox
    }
}

proc ApolTop::goto {dialog} {
    variable goto_line_num
    variable notebook
    variable components_nb
    variable rules_nb
    variable components_tab
    variable rules_tab
    variable policy_conf_tab
    variable analysis_tab
    variable file_contexts_tab

    if {[string is integer -strict $goto_line_num] != 1} {
        tk_messageBox -icon error -type ok -parent $dialog \
            -title "Invalid Line Number" \
            -message "$goto_line_num is not a valid line number."
    } else {
	set raised_tab [$notebook raise]
	switch -- $raised_tab \
            $policy_conf_tab {
                ${policy_conf_tab}::goto_line $goto_line_num
            } \
            $analysis_tab {
                ${analysis_tab}::goto_line $goto_line_num
            } \
            $rules_tab {
                [$rules_nb raise]::goto_line $goto_line_num
            } \
            $components_tab {
                [$components_nb raise]::goto_line $goto_line_num
            } \
            $file_contexts_tab {
                ${file_contexts_tab}::goto_line $goto_line_num
            } \
            default {
                return -code error
            }
        destroy $dialog
    }
}

proc ApolTop::displayGotoDialog {} {
    variable goto_Dialog
    variable gotoDlg_entryBox

    if {[winfo exists $goto_Dialog]} {
        raise $goto_Dialog
        focus $gotoDlg_entryBox
        $gotoDlg_entryBox selection range 0 end
        return
    }

    Dialog $goto_Dialog -title "Goto Line" -separator 0 -parent . \
        -default 0 -cancel 1 -modal none -homogeneous 1
    set top_frame [$goto_Dialog getframe]
    set entry_label [label $top_frame.l -text "Goto Line:" -anchor e]
    set gotoDlg_entryBox [entry $top_frame.e -bg white \
                              -textvariable ApolTop::goto_line_num -width 10]
    pack $entry_label -side left -padx 5 -pady 5
    pack $gotoDlg_entryBox -side left -padx 5 -pady 5 -expand 1 -fill x

    $goto_Dialog add -text "OK" -command [list ApolTop::goto $goto_Dialog]
    $goto_Dialog add -text "Cancel" -command [list destroy $goto_Dialog]

    $gotoDlg_entryBox selection range 0 end
    focus $gotoDlg_entryBox
    $goto_Dialog draw
    wm resizable $goto_Dialog 0 0
}

proc ApolTop::create { } {
    variable notebook
    variable mainframe
    variable components_nb
    variable rules_nb

    # Menu description
    set descmenu {
	"&File" {} file 0 {
	    {command "&Open..." {} "Open a new policy" {Ctrl o} -command ApolTop::openPolicy}
	    {command "&Close" {} "Close current polocy" {Ctrl w} -command ApolTop::closePolicy}
	    {separator}
	    {command "&Quit" {} "Quit policy analysis tool" {Ctrl q} -command ApolTop::apolExit}
	    {separator}
	    {cascade "&Recent Files" {} recent 0 {}}
	}
	"&Search" {} search 0 {
	    {command "&Find..." {Disable_SearchMenu_Tag} "Find text in current buffer" {Ctrl f} -command ApolTop::displayFindDialog}
	    {command "&Goto Line..." {Disable_SearchMenu_Tag} "Goto a line in current buffer" {Ctrl g} -command ApolTop::displayGotoDialog}
	}
	"&Query" {} query 0 {
	    {command "&Load Query..." {Disable_LoadQuery_Tag} "Load query criteria " {} -command ApolTop::load_query_info}
	    {command "&Save Query..." {Disable_SaveQuery_Tag} "Save current query criteria" {} -command ApolTop::save_query_info}
	    {separator}
	    {command "&Policy Summary" {Disable_Summary} "Display summary statistics" {} -command ApolTop::popupPolicyStats}
	}
	"&Advanced" all options 0 {
	    {cascade "&Permission Mappings" {Perm_Map_Tag} pmap_menu 0 {
                {command "Load Default Perm Map" {} "Load the default permission map" {} -command ApolTop::load_default_perm_map_Dlg}
                {command "Load Perm Map from File" {} "Load a permission map from a file" {} -command ApolTop::load_perm_map_fileDlg}
                {separator}
                {command "Edit Perm Map... (Not loaded)" {} "Edit currently loaded permission map" {} -command Apol_Perms_Map::editPermMappings}
            }}
        }
	"&Help" {} helpmenu 0 {
	    {command "&General Help" {} "Show help on using apol" {} -command {ApolTop::helpDlg Help apol_help.txt}}
	    {command "&Domain Transition Analysis" {} "Show help on domain transitions" {} -command {ApolTop::helpDlg "Domain Transition Analysis Help" domaintrans_help.txt}}
	    {command "&Information Flow Analysis" {} "Show help on information flows" {} -command {ApolTop::helpDlg "Information Flow Analysis Help" infoflow_help.txt}}
	    {command "Direct &Relabel Analysis" {} "Show help on file relabeling" {} -command {ApolTop::helpDlg "Relabel Analysis Help" file_relabel_help.txt}}
	    {command "&Types Relationship Summary Analysis" {} "Show help on types relationships" {} -command {ApolTop::helpDlg "Types Relationship Summary Analysis Help" types_relation_help.txt}}
	    {separator}
	    {command "&About apol" {} "Show copyright information" {} -command ApolTop::aboutBox}
	}
    }

    set mainframe [MainFrame .mainframe -menu $descmenu -textvariable ApolTop::statu_line]

    #[$mainframe getmenu fc_index_menu] insert 0 command -label "Load Index... (Not loaded)" -command "ApolTop::load_fc_index_file"
    #[$mainframe getmenu fc_index_menu] insert 0 command -label "Create Index" -command "ApolTop::create_fc_index_file"

    $mainframe addindicator -textvariable ApolTop::policyConf_lineno -width 14
    $mainframe addindicator -textvariable ApolTop::policy_stats_summary -width 88
    $mainframe addindicator -textvariable ApolTop::policy_version_string -width 28

    # Disable menu items since a policy is not yet loaded.
    $ApolTop::mainframe setmenustate Disable_SearchMenu_Tag disabled
    $ApolTop::mainframe setmenustate Perm_Map_Tag disabled
    $ApolTop::mainframe setmenustate Disable_SaveQuery_Tag disabled
    $ApolTop::mainframe setmenustate Disable_LoadQuery_Tag disabled
    $ApolTop::mainframe setmenustate Disable_Summary disabled

    # NoteBook creation
    set frame    [$mainframe getframe]
    set notebook [NoteBook $frame.nb]

    # Create Top-level tab frames
    set components_frame [$notebook insert end $ApolTop::components_tab -text "Policy Components"]
    set rules_frame [$notebook insert end $ApolTop::rules_tab -text "Policy Rules"]

    if {[tcl_config_use_sefs]} {
        Apol_File_Contexts::create $notebook
    }
    Apol_Analysis::create $notebook
    Apol_PolicyConf::create $notebook

    # Create subordinate tab frames
    set components_nb [NoteBook $components_frame.components_nb]
    set rules_nb [NoteBook $rules_frame.rules_nb]

    variable mls_tabs

    # Subtabs for the main policy components tab.
    Apol_Types::create $components_nb
    Apol_Class_Perms::create $components_nb
    Apol_Roles::create $components_nb
    Apol_Users::create $components_nb
    Apol_Cond_Bools::create $components_nb
    Apol_MLS::create $components_nb
    lappend mls_tabs [list $components_nb [$components_nb pages end]]
    Apol_Initial_SIDS::create $components_nb
    Apol_NetContexts::create $components_nb
    Apol_FSContexts::create $components_nb

    # Subtabs for the main policy rules tab
    Apol_TE::create $rules_nb
    Apol_Cond_Rules::create $rules_nb
    Apol_RBAC::create $rules_nb
    Apol_Range::create $rules_nb
    lappend mls_tabs [list $rules_nb [$rules_nb pages end]]

    $components_nb compute_size
    pack $components_nb -fill both -expand yes -padx 4 -pady 4
    $components_nb raise [$components_nb page 0]
    $components_nb bindtabs <Button-1> { ApolTop::set_Focus_to_Text }

    $rules_nb compute_size
    pack $rules_nb -fill both -expand yes -padx 4 -pady 4
    $rules_nb raise [$rules_nb page 0]
    $rules_nb bindtabs <Button-1> { ApolTop::set_Focus_to_Text }

    $notebook compute_size
    pack $notebook -fill both -expand yes -padx 4 -pady 4
    $notebook raise [$notebook page 0]
    $notebook bindtabs <Button-1> { ApolTop::set_Focus_to_Text }
    pack $mainframe -fill both -expand yes
}

# Saves user data in their $HOME/.apol file
proc ApolTop::writeInitFile {} {
    variable dot_apol_file
    variable recent_files
    variable text_font
    variable title_font
    variable dialog_font
    variable general_font

    if {[catch {open $dot_apol_file w+} f]} {
        tk_messageBox -icon error -type ok -title "Error" \
            -message "Could not open $dot_apol_file for writing: $f"
        return
    }
    puts $f "recent_files"
    puts $f [llength $recent_files]
    foreach r $recent_files {
        puts $f [policy_path_to_list $r]
    }

    puts $f "\n"
    puts $f "# Font format: family ?size? ?style? ?style ...?"
    puts $f "# Possible values for the style arguments are as follows:"
    puts $f "# normal bold roman italic underline overstrike\n#\n#"
    puts $f "# NOTE: When configuring fonts, remember to remove the following "
    puts $f "# \[window height\] and \[window width\] entries before starting apol. "
    puts $f "# Not doing this may cause widgets to be obscured when running apol."
    puts $f "\[general_font\]"
    if {$general_font == {}} {
        puts $f "Helvetica 10"
    } else {
        puts $f "$general_font"
    }
    puts $f "\[title_font\]"
    if {$title_font == {}} {
        puts $f "Helvetica 10 bold italic"
    } else {
        puts $f "$title_font"
    }
    puts $f "\[dialog_font\]"
    if {$dialog_font == {}} {
        puts $f "Helvetica 10"
    } else {
        puts $f "$dialog_font"
    }
    puts $f "\[text_font\]"
    if {$text_font == {}} {
        puts $f "fixed"
    } else {
        puts $f "$text_font"
    }
    puts $f "\[window_height\]"
    puts $f [winfo height .]
    puts $f "\[window_width\]"
    puts $f [winfo width .]
    puts $f "\[show_fake_attrib_warning\]"
    variable show_fake_attrib_warning
    puts $f $show_fake_attrib_warning
    puts $f "\[max_recent_files\]"
    variable max_recent_files
    puts $f $max_recent_files
    close $f
}


# Reads in user data from their $HOME/.apol file
proc ApolTop::readInitFile {} {
    variable dot_apol_file
    variable recent_files

    # if it doesn't exist, it will be created later
    if {![file exists $dot_apol_file]} {
        return
    }

    if {[catch {open $dot_apol_file r} f]} {
        tk_messageBox -icon error -type ok -title "Error opening configuration file" \
            -message "Cannot open $dot_apol_file: $f"
        return
    }

    while {![eof $f]} {
        set option [string trim [gets $f]]
        if {$option == {} || [string compare -length 1 $option "\#"] == 0} {
            continue
        }
        set value [string trim [gets $f]]
        if {[eof $f]} {
            puts "EOF reached while reading $option"
            break
        }
        if {$value == {}} {
            puts "Empty value for option $option"
            continue
        }
        switch -- $option {
            "\[window_height\]" {
                if {[string is integer -strict $value] != 1} {
                    puts "window_height was not given as an integer and is ignored"
                    break
                }
                variable mainframe_height $value
            }
            "\[window_width\]" {
                if {[string is integer -strict $value] != 1} {
                    puts "window_width was not given as an integer and is ignored"
                    break
                }
                variable mainframe_width $value
            }
            "\[title_font\]" {
                variable title_font $value
            }
            "\[dialog_font\]" {
                variable dialog_font $value
            }
            "\[text_font\]" {
                variable text_font $value
            }
            "\[general_font\]" {
                variable general_font $value
            }
            "\[show_fake_attrib_warning\]" {
                variable show_fake_attrib_warning $value
            }

            # The form of [max_recent_file] is a single line that
            # follows containing an integer with the max number of
            # recent files to keep.  The default is 5 if this is not
            # specified.  The minimum is 2.
            "\[max_recent_files\]" {
                if {[string is integer -strict $value] != 1} {
                    puts "max_recent_files was not given as an integer and is ignored"
                } else {
                    if {$value < 2} {
                        variable max_recent_files 2
                    } else {
                        variable max_recent_files $value
                    }
                }
            }
            # The form of this key in the .apol file is as such
            #
            # recent_files
            # 5			(# indicating how many file names follows)
            # policy_path_0
            # policy_path_1
            # ...
            "recent_files" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "Number of recent files was not given as an integer and was ignored."
                    continue
                } elseif {$value < 0} {
                    puts stderr "Number of recent was less than 0 and was ignored."
                    continue
                }
                while {$value > 0} {
                    incr value -1
                    set line [gets $f]
                    if {[eof $f]} {
                        puts stderr "EOF reached trying to read recent files."
                        break
                    }
                    if {[llength $line] == 1} {
                        # reading older recent files, before advent of
                        # policy_path
                        set ppath [new_apol_policy_path_t $::APOL_POLICY_PATH_TYPE_MONOLITHIC $line {}]
                        $ppath -acquire
                    } else {
                        foreach {path_type primary modules} $line {break}
                        if {[catch {list_to_policy_path $path_type $primary $modules} ppath]} {
                            puts stderr "Invalid policy path line: $line"
                            continue
                        }
                    }
                    lappend recent_files $ppath
                }
            }
        }
    }
    close $f
}

# Add a policy path to the recently opened list, trim the menu to
# max_recent_files, and then regenerate the recent menu.
proc ApolTop::addRecent {ppath} {
    variable recent_files
    variable max_recent_files

    # add to recent list if the ppath is not already there
    foreach r $recent_files {
        if {[apol_policy_path_compare $r $ppath] == 0} {
            return
        }
    }
    set recent_files [lrange [concat $ppath $recent_files] 0 [expr {$max_recent_files - 1}]]
    buildRecentFilesMenu
}

proc ApolTop::buildRecentFilesMenu {} {
    variable mainframe
    variable recent_files
    variable max_recent_files
    set recent_menu [$mainframe getmenu recent]
    $recent_menu delete 0 $max_recent_files
    foreach r $recent_files {
        foreach {path_type primary_file modules} [policy_path_to_list $r] {break}
        if {$path_type == "monolithic"} {
            set label $primary_file
        } else {
            set label "$primary_file + [llength $modules] module"
            if {[llength $modules] != 1} {
                append label "s"
            }
        }
        $recent_menu add command -label $label \
            -command [list ApolTop::openPolicyFile $r]
    }
}

proc ApolTop::helpDlg {title file_name} {
    set helpfile [file join [tcl_config_get_install_dir] $file_name]
    if {[catch {open $helpfile} f]} {
        set info $f
    } else {
        set info [read $f]
        close $f
    }
    Apol_Widget::showPopupParagraph $title $info
}

proc ApolTop::popupPolicyStats {} {
    variable polstats

    set classes $polstats(classes)
    set common_perms $polstats(common_perms)
    set perms $polstats(perms)
    if {![regexp -- {^([^\(]+) \(([^,]+), ([^\)]+)} $ApolTop::policy_version_string -> policy_version policy_type policy_mls_type]} {
        set policy_version $ApolTop::policy_version_string
        set policy_type "unknown"
        set policy_mls_type "unknown"
    }
    set policy_version [string trim $policy_version]

    destroy .polstatsbox
    set dialog [Dialog .polstatsbox -separator 1 -title "Policy Summary" \
                    -modal none -parent .]
    $dialog add -text Close -command [list destroy $dialog]

    set w [$dialog getframe]

    label $w.title -text "Policy Summary Statistics"
    set f [frame $w.summary]
    label $f.l -justify left -text "    Policy Version:\n    Policy Type:\n    MLS Status:"
    label $f.r -justify left -text "$policy_version\n$policy_type\n$policy_mls_type"
    grid $f.l $f.r -sticky w
    grid configure $f.r -padx 30
    grid $w.title - -sticky w -padx 8
    grid $f - -sticky w -padx 8
    grid [Separator $w.sep] - -sticky ew -pady 5

    set f [frame $w.left]
    set i 0
    foreach {title block} {
        "Number of Classes and Permissions" {
            "Object Classes" classes
            "Common Perms" common_perms
            "Permissions" perms
        }
        "Number of Types and Attributes" {
            "Types" types
            "Attributes" attribs
        }
        "Number of Type Enforcement Rules" {
            "allow" teallow
            "neverallow" neverallow
            "auditallow" auditallow
            "dontaudit" dontaudit
            "type_transition" tetrans
            "type_member" temember
            "type_change" techange
        }
        "Number of Roles" {
            "Roles" roles
        }
        "Number of RBAC Rules" {
            "allow" roleallow
            "role_transition" roletrans
        }
    } {
        set ltext "$title:"
        set rtext {}
        foreach {l r} $block {
            append ltext "\n    $l:"
            append rtext "\n$polstats($r)"
        }
        label $f.l$i -justify left -text $ltext
        label $f.r$i -justify left -text $rtext
        grid $f.l$i $f.r$i -sticky w -padx 4 -pady 2
        incr i
    }

    set i 0
    set g [frame $w.right]
    foreach {title block} {
        "Number of Users" {
            "Users" users
        }
        "Number of Booleans" {
            "Bools" cond_bools
        }
        "Number of MLS Components" {
            "Sensitivities" sens
            "Categories" cats
        }
        "Number of MLS Rules" {
            "range_transition" rangetrans
        }
        "Number of Initial SIDs" {
            "SIDs" sids
        }
        "Number of OContexts" {
            "PortCons" portcons
            "NetIfCons" netifcons
            "NodeCons" nodecons
            "GenFSCons" genfscons
            "fs_use statements" fs_uses
        }
    } {
        set ltext "$title:"
        set rtext {}
        foreach {l r} $block {
            append ltext "\n    $l:"
            append rtext "\n$polstats($r)"
        }
        label $g.l$i -justify left -text $ltext
        label $g.r$i -justify left -text $rtext
        grid $g.l$i $g.r$i -sticky w -padx 4 -pady 2
        incr i
    }
    grid $f $g -sticky nw -padx 4
    $dialog draw
}

proc ApolTop::showPolicyStats {} {
    variable polstats
    variable policy_stats_summary
    return
    if {[catch {apol_GetStats} pstats]} {
        tk_messageBox -icon error -type ok -title "Error" -message $pstats
        return
    }
    array unset polstats
    array set polstats $pstats

    set policy_stats_summary ""
    append policy_stats_summary "Classes: $polstats(classes)   "
    append policy_stats_summary "Perms: $polstats(perms)   "
    append policy_stats_summary "Types: $polstats(types)   "
    append policy_stats_summary "Attribs: $polstats(attribs)   "
    set num_te_rules [expr {$polstats(teallow) + $polstats(neverallow) +
                            $polstats(auditallow) + $polstats(dontaudit) +
                            $polstats(tetrans) + $polstats(temember) +
                            $polstats(techange)}]
    append policy_stats_summary "TE rules: $num_te_rules   "
    append policy_stats_summary "Roles: $polstats(roles)   "
    append policy_stats_summary "Users: $polstats(users)"
}

proc ApolTop::aboutBox {} {
    if {[winfo exists .apol_about]} {
        raise .apol_about
    } else {
        variable apol_icon

        Dialog .apol_about -cancel 0 -default 0 -image $apol_icon \
            -modal none -parent . -separator 1 -title "About apol"
        set f [.apol_about getframe]
        set l1 [label $f.l1 -text "apol [tcl_config_get_version]" -height 2]
        foreach {name size} [$l1 cget -font] {break}
        incr size 6
        $l1 configure -font [list $name $size bold]
        set l2 [label $f.l2 -text "Security Policy Analysis Tool for Security Enhanced Linux\n${::COPYRIGHT_INFO}\nhttp://oss.tresys.com/projects/setools"]
        pack $l1 $l2
        .apol_about add -text "Close" -command [list destroy .apol_about]
        .apol_about draw
    }
}

proc ApolTop::closePolicy {} {
    variable policy_version_string {}
    variable policy_stats_summary {}

    wm title . "SELinux Policy Analysis"

    variable tab_names
    foreach tab $tab_names {
        Apol_${tab}::close
    }
    Apol_Perms_Map::close

    set_Focus_to_Text [$ApolTop::notebook raise]

    variable policy
    if {$policy != {}} {
        $policy -delete
        set policy {}
        variable qpolicy {}
    }

    variable mainframe
    $mainframe setmenustate Disable_SearchMenu_Tag disabled
    # Disable Edit perm map menu item since a perm map is not yet loaded.
    $mainframe setmenustate Perm_Map_Tag disabled
    $mainframe setmenustate Disable_SaveQuery_Tag disabled
    $mainframe setmenustate Disable_LoadQuery_Tag disabled
    $mainframe setmenustate Disable_Summary disabled
    enable_source_policy_tab
    enable_disable_conditional_widgets 1
    set_mls_tabs_state normal
    configure_edit_pmap_menu_item 0
}

proc ApolTop::open_apol_tabs {policy_path} {
    variable tab_names
    foreach tab $tab_names {
        if {$tab == "PolicyConf"} {
            Apol_PolicyConf::open $policy_path
        } else {
            Apol_${tab}::open
        }
    }
}

proc ApolTop::enable_disable_conditional_widgets {enable} {
    set tab [$ApolTop::notebook raise]
    switch -exact -- $tab \
        $ApolTop::components_tab {
            if {[$ApolTop::components_nb raise] == $ApolTop::cond_bools_tab} {
                if {$enable} {
                    $ApolTop::components_nb raise $ApolTop::cond_bools_tab
                } else {
                    set name [$ApolTop::components_nb pages 0]
                    $ApolTop::components_nb raise $name
                }
            }
        } \
        $ApolTop::rules_tab {
            if {[$ApolTop::rules_nb raise] == $ApolTop::cond_rules_tab} {
                if {$enable} {
                    $ApolTop::rules_nb raise $ApolTop::cond_rules_tab
                } else {
                    set name [$ApolTop::rules_nb pages 0]
                    $ApolTop::rules_nb raise $name
                }
            }
        } \
        default {
        }

    if {$enable} {
        $ApolTop::components_nb itemconfigure $ApolTop::cond_bools_tab -state normal
        $ApolTop::rules_nb itemconfigure $ApolTop::cond_rules_tab -state normal
    } else {
        $ApolTop::components_nb itemconfigure $ApolTop::cond_bools_tab -state disabled
        $ApolTop::rules_nb itemconfigure $ApolTop::cond_rules_tab -state disabled
    }
}

proc ApolTop::enable_source_policy_tab {} {
    $ApolTop::notebook itemconfigure $ApolTop::policy_conf_tab -state normal
}

proc ApolTop::disable_source_policy_tab {} {
    if {[$ApolTop::notebook raise] == $ApolTop::policy_conf_tab} {
        set name [$ApolTop::notebook pages 0]
        $ApolTop::notebook raise $name
    }
    $ApolTop::notebook itemconfigure $ApolTop::policy_conf_tab -state disabled
}

# Enable/disable all of apol's tabs that deal exclusively with MLS
# components.  If the currently raised page is one of those tabs then
# raise the first page (which hopefully is not MLS specific).
proc ApolTop::set_mls_tabs_state {new_state} {
    variable mls_tabs

    foreach tab $mls_tabs {
        foreach {notebook page} $tab break
        set current_tab [$notebook raise]
        $notebook itemconfigure $page -state $new_state
        if {$current_tab == $page && $new_state == "disabled"} {
            $notebook raise [$notebook pages 0]
        }
    }
}

proc ApolTop::set_initial_open_policy_state {} {
    if {![is_capable "conditionals"]} {
        enable_disable_conditional_widgets 0
    }
    if {![is_capable "source"]} {
        disable_source_policy_tab
    }
    if {![is_capable "mls"]} {
        set_mls_tabs_state disabled
    }
    if {![is_capable "attribute names"] && \
            [llength $::Apol_Types::attriblist] > 0 && \
            $show_fake_attrib_warning} {
        set d [Dialog .fake_attribute_dialog -modal local -parent . \
                   -title "Warning - Attribute Names" -separator 1]
        $d add -text "OK"
        set f [$d getframe]
        label $f.l -text "Warning: Apol has generated attribute names because\nthe original names were not preserved in the policy." -justify left
        checkbutton $f.cb -text "Show this message again next time." \
            -variable ApolTop::show_fake_attrib_warning
        pack $f.l $f.cb -padx 10 -pady 10
        $d draw
        destroy $d
    }

    set_Focus_to_Text [$ApolTop::notebook raise]

    variable mainframe
    # Enable perm map menu items since a policy is now open.
    $mainframe setmenustate Perm_Map_Tag normal
    $mainframe setmenustate Disable_Summary normal
    $mainframe setmenustate Disable_SearchMenu_Tag normal
}

# Open the given policy path.  Re-initialize all tabs and add the path
# to the list of recently opened policies.
#
# @param ppath Policy path to open.
proc ApolTop::openPolicyFile {ppath} {
    variable policy_version_string

    closePolicy

    set primary_file [$ppath get_primary]
    if {[catch {Apol_Progress_Dialog::wait $primary_file "Opening policy." [list new_apol_policy_t $ppath]} p]} {
        tk_messageBox -icon error -type ok -title "Open Policy" \
            -message "The selected file does not appear to be a valid SELinux Policy.\n\n$p"
        return -1
    }

    variable policy $p
    variable qpolicy [$p get_qpol]
    variable policy_version_string [$p get_version_type_mls_str]
    showPolicyStats

    open_apol_tabs $ppath
    set_initial_open_policy_state

    addRecent $ppath
    variable last_policy_path $ppath
    wm title . "SELinux Policy Analysis - $primary_file"
}

proc ApolTop::openPolicy {} {
    variable last_policy_path
    Apol_Open_Policy_Dialog::getPolicyPath $last_policy_path
}

proc ApolTop::apolExit {} {
    variable policy
    if {$policy != {}} {
        closePolicy
    }
    if {[tcl_config_use_sefs]} {
        Apol_File_Contexts::close
    }
    writeInitFile
    exit
}

proc ApolTop::load_fonts {} {
    variable title_font
    variable dialog_font
    variable general_font
    variable text_font

    tk scaling -displayof . 1.0
    # First set all fonts in general; then change specific fonts
    if {$general_font == ""} {
        set general_font "Helvetica 10"
    }
    option add *Font $general_font
    if {$title_font == {}} {
        set title_font "Helvetica 10 bold italic"
    }
    option add *TitleFrame.l.font $title_font
    if {$dialog_font == {}} {
        set dialog_font "Helvetica 10"
    }
    option add *Dialog*font $dialog_font
    option add *Dialog*TitleFrame.l.font $title_font
    if {$text_font == ""} {
        set text_font "fixed"
    }
    option add *text*font $text_font
}

proc ApolTop::main {} {
    variable notebook

    tcl_config_init

    # Prevent the application from responding to incoming send
    # requests and sending outgoing requests. This way any other
    # applications that can connect to our X server cannot send
    # harmful scripts to our application.
    rename send {}

    if {[catch {package require BWidget}]} {
        tk_messageBox -icon error -type ok -title "Missing BWidget package" -message \
            "Missing BWidget package.  Ensure that your installed version of Tcl/Tk includes BWidget, which can be found at http://sourceforge.net/projects/tcllib."
        exit -1
    }

    wm withdraw .
    wm title . "SELinux Policy Analysis"
    wm protocol . WM_DELETE_WINDOW ApolTop::apolExit
    variable default_bg_color   [. cget -background]

    # Read apol's default settings file, gather all font information,
    # create the gui and then load recent files into the menu.
    catch {tcl_config_patch_bwidget}
    load_fonts
    readInitFile
    create
    bind . <Button-1> {focus %W}
    bind . <Button-2> {focus %W}
    bind . <Button-3> {focus %W}
    buildRecentFilesMenu

    set icon_file [file join [tcl_config_get_install_dir] apol.gif]
    if {![catch {image create photo -file $icon_file} icon]} {
        wm iconphoto . -default $icon
    }
    variable apol_icon $icon

    variable mainframe_width [$notebook cget -width]
    variable mainframe_height [$notebook cget -height]
    wm geom . ${mainframe_width}x${mainframe_height}

    wm deiconify .
    raise .
    focus .
}

#######################################################
# Start script here

proc handle_args {argv0 argv} {
    set argvp 0
    while {$argvp < [llength $argv]} {
        set arg [lindex $argv $argvp]
        switch -- $arg {
            "-h" - "--help" { print_help $argv0 verbose; exit }
            "-V" - "--version" { print_version_info; exit }
            "--" { incr argvp; break }
            default {
                if {[string index $arg 0] != "-"} {
                    break
                } else {
                    puts stderr "$argv0: unrecognized option `$arg'"
                    print_help $argv0 brief
                    exit 1
                }
            }
        }
        incr argvp
    }
    if {[llength $argv] - $argvp > 0} {
        set path_type $::APOL_POLICY_PATH_TYPE_MONOLITHIC
        set policy_file [lindex $argv $argvp]
        set ppath {}
        if {[llength $argv] - $argvp > 1} {
            set path_type $::APOL_POLICY_PATH_TYPE_MODULAR
            set mod_paths [list_to_str_vector [lrange $argv [expr {$argvp + 1}] end]]
        } else {
            set mod_paths [list_to_str_vector {}]
            if {[apol_file_is_policy_path_list $policy_file]} {
                set ppath [new_apol_policy_path_t $policy_file]
            }
        }
        if {$ppath == {}} {
            set ppath [new_apol_policy_path_t $path_type $policy_file $mod_paths]
        }
        if {$ppath == {}} {
            puts stderr "Error loading $policy_file."
        } else {
            $ppath -acquire
        }
        return $ppath
    } else {
        return {}
    }
}

proc print_help {program_name verbose} {
    puts "Usage: $program_name \[OPTIONS\] \[POLICY ...\]\n"
    if {$verbose != "verbose"} {
        puts "\tTry $program_name --help for more help.\n"
    } else {
        puts "Policy Analysis tool for Security Enhanced Linux.\n"
        puts "   -h, --help              print this help text and exit"
        puts "   -V, --version           print version information and exit\n"
    }
}

proc print_version_info {} {
    puts "apol [tcl_config_get_version]\n$::COPYRIGHT_INFO"
}

if {[catch {tcl_config_init_libraries}]} {
    puts stderr "The SETools libraries could not be found in one of these subdirectories:\n$auto_path"
    exit -1
}
if {[catch {package require Tk}]} {
    puts stderr "This program requires Tk to run."
    exit -1
}
set path [handle_args $argv0 $argv]
ApolTop::main
if {$path != {}} {
    after idle [list ApolTop::openPolicyFile $path]
}
