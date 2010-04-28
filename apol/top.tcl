# Copyright (C) 2001-2008 Tresys Technology, LLC
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

set COPYRIGHT_INFO "Copyright (C) 2001-2008 Tresys Technology, LLC"

namespace eval ApolTop {
    variable policy {} ;# handle to an apol_policy, or {} if none opened
    variable qpolicy {} ;# handle to policy's qpol_policy_t, or {} if none opened
    # these three are shown on the status line of the toplevel window
    variable policy_version_string {}
    variable policy_source_linenum {}
    variable policy_stats_summary {}
    variable policy_stats  ;# array of statistics for the current policy

    # user's preferences
    variable dot_apol_file [file join $::env(HOME) .apol]
    variable recent_files {}
    variable last_policy_path {}
    variable max_recent_files 5
    variable show_fake_attrib_warning 1 ;# warn if using fake attribute names

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

    # Other global widgets
    variable mainframe
    variable notebook
    variable current_tab

    # The following list describes the layout of apol.  All tab names
    # must be unique and shall not contain colons.  For each tab, the
    # first element gives the identifier; this corresponds with the
    # namespace.  The second element describes the path to get to the
    # tab, starting from the topmost notebook.  For tabs that are to
    # be topmost, this is just an empty list.  The third element is a
    # list of tags for the tab.  Valid tags are:
    #   tag_conditionals - show this only if the policy supports conditionals
    #   tag_mls - show this only if policy supports MLS
    #   tag_query_saveable - if this tab is shown, enable query saving
    #   tag_source - show this only if a source policy is loaded
    variable tabs {
        {Apol_Types components {}}
        {Apol_Class_Perms components {}}
        {Apol_Roles components {}}
        {Apol_Users components {}}
        {Apol_Cond_Bools components {tag_conditionals}}
        {Apol_MLS components {tag_mls}}
        {Apol_Initial_SIDS components {}}
        {Apol_NetContexts components {}}
        {Apol_FSContexts components {}}
        {Apol_TE rules {tag_query_saveable}}
        {Apol_Cond_Rules rules {tag_conditionals}}
        {Apol_RBAC rules {}}
        {Apol_Range rules {tag_mls}}
        {Apol_File_Contexts {} {}}
        {Apol_Analysis {} {tag_query_saveable}}
        {Apol_PolicyConf {} {tag_source}}
    }
}

#################### public functions ####################

proc ApolTop::is_policy_open {} {
    if {$::ApolTop::policy == {}} {
        return 0
    }
    return 1
}

# If a policy is open and it has the given capability then return
# non-zero.  Valid capabilities are:
#   "attribute names"
#   "conditionals"
#   "line numbers"
#   "mls"
#   "neverallow"
#   "source"
#   "syntactic rules"
proc ApolTop::is_capable {capability} {
    if {![is_policy_open]} {
        return 0;
    }
    switch -- $capability {
        "attribute names" { set cap $::QPOL_CAP_ATTRIB_NAMES }
        "conditionals" { set cap $::QPOL_CAP_CONDITIONALS }
        "line numbers" { set cap $::QPOL_CAP_LINE_NUMBERS }
        "mls" { set cap $::QPOL_CAP_MLS }
        "neverallow" { set cap $::QPOL_CAP_NEVERALLOW }
        "source" { set cap $::QPOL_CAP_SOURCE }
        "syntactic rules" { set cap $::QPOL_CAP_SYN_RULES }
        default { return 0 }
    }
    variable qpolicy
    $qpolicy has_capability $cap
}

# Open the given policy path.  Re-initialize all tabs and add the path
# to the list of recently opened policies.
#
# @param ppath Policy path to open.
proc ApolTop::openPolicyPath {ppath} {
    _close_policy

    set primary_file [$ppath get_primary]
    if {[catch {Apol_Progress_Dialog::wait $primary_file "Opening policy." \
                    {
                        apol_tcl_open_policy $ppath
                    } \
                } p] || $p == "NULL"} {
        tk_messageBox -icon error -type ok -title "Open Policy" -parent . \
            -message "[apol_tcl_get_error_string]"
        return -1  ;# indicates failed to open policy
    }

    variable policy $p
    variable qpolicy [$p get_qpol]

    _toplevel_policy_open $ppath

    _add_recent $ppath
    variable last_policy_path $ppath

    variable show_fake_attrib_warning
    if {![is_capable "attribute names"] && \
            [llength $::Apol_Types::attriblist] > 0 && \
            $show_fake_attrib_warning} {
        set d [Dialog .fake_attribute_dialog -modal local -parent . \
                   -title "Open Policy" -separator 1]
        $d add -text "OK"
        set f [$d getframe]
        label $f.l -text "Warning: Apol has generated attribute names because\nthe original names were not preserved in the policy." -justify left
        checkbutton $f.cb -text "Show this message again next time." \
            -variable ApolTop::show_fake_attrib_warning
        pack $f.l $f.cb -padx 10 -pady 10
        $d draw
        destroy $d
    }

    return 0  ;# indicates policy opened successfully
}

proc ApolTop::loadNeverAllows {} {
    if {![is_capable "neverallow"]} {
        Apol_Progress_Dialog::wait "Loading neverallow rules" "Rebuilding policy" \
            {
                $::ApolTop::qpolicy rebuild 0
                _toplevel_update_stats
            }
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

# Return the name of the currently shown tab.  If the current tab is
# nested, show the inner-most tab.
proc ApolTop::getCurrentTab {} {
    variable current_tab
    set current_tab
}

proc ApolTop::getCurrentTextWidget {} {
    [getCurrentTab]::getTextWidget
}

proc ApolTop::setCurrentTab {tab_name} {
    variable tabs
    # search through all tabs until one is found
    foreach tab $tabs {
        if {[lindex $tab 0] == $tab_name} {
            variable notebook
            set parent_nb $notebook
            # raise all parent tabs as well
            foreach nb [lindex $tab 1] {
                $parent_nb raise $nb
                set parent_nb [$parent_nb getframe $nb].nb
            }
            $parent_nb raise $tab_name
            variable current_tab $tab_name
            _toplevel_tab_switched
            return
        }
    }
    puts stderr "\[setCurrentTab\] tried to set the tab to $tab_name"
    exit -1
}

proc ApolTop::setPolicySourceLinenumber {line} {
    variable policy_source_linenum "Line $line"
}

proc ApolTop::showPolicySourceLineNumber {line} {
    setCurrentTab Apol_PolicyConf
    Apol_PolicyConf::gotoLine $line
}

############### functions for creating and maintaining toplevel ###############

proc ApolTop::_create_toplevel {} {
    set menus {
        "&File" {} file 0 {
            {command "&Open..." {} "Open a new policy" {Ctrl o} -command ApolTop::_open_policy}
            {command "&Close" {tag_policy_open} "Close current polocy" {Ctrl w} -command ApolTop::_user_close_policy}
            {separator}
            {cascade "&Recent Files" {} recent 0 {}}
            {separator}
            {command "&Quit" {} "Quit policy analysis tool" {Ctrl q} -command ApolTop::_exit}
        }
        "&Edit" {} edit 0 {
            {command "&Copy" {tag_policy_open} {} {Ctrl c} -command ApolTop::_copy}
            {command "Select &All" {tag_policy_open} {} {Ctrl a} -command ApolTop::_select_all}
            {separator}
            {command "&Find..." {tag_policy_open} "Find text in current buffer" {Ctrl f} -command Apol_Find::find}
            {command "&Goto Line..." {tag_policy_open} "Goto a line in current buffer" {Ctrl g} -command Apol_Goto::goto}
            {separator}
        }
        "&Query" {} query 0 {
            {command "&Open Query..." {tag_policy_open} "Open query criteria file" {} -command ApolTop::_open_query_file}
            {command "&Save Query..." {tag_policy_open tag_query_saveable} "Save current query criteria to file" {} -command ApolTop::_save_query_file}
            {separator}
            {command "&Policy Summary" {tag_policy_open} "Display summary statistics" {} -command ApolTop::_show_policy_summary}
        }
        "&Tools" {} tools 0 {
            {command "&Open Perm Map..." {tag_policy_open} "Open a permission map from file" {} -command ApolTop::_open_perm_map_from_file}
            {command "Open &Default Perm Map" {tag_policy_open} "Open the default permission map" {} -command ApolTop::openDefaultPermMap}
            {command "&Save Perm Map..." {tag_policy_open tag_perm_map_open} "Save the permission map to a file" {} -command ApolTop::_save_perm_map}
            {command "Save Perm Map &As..." {tag_policy_open tag_perm_map_open} "Save the permission map to a file" {} -command ApolTop::_save_perm_map_as}
            {command "Save Perm Map as D&efault" {tag_policy_open tag_perm_map_open} "Save the permission map to default file" {} -command ApolTop::_save_perm_map_default}
            {command "&View Perm Map..." {tag_policy_open tag_perm_map_open} "Edit currently loaded permission map" {} -command Apol_Perms_Map::showPermMappings}
        }
        "&Help" {} helpmenu 0 {
            {command "&General Help" {} "Show help on using apol" {} -command {ApolTop::_show_file Help apol_help.txt}}
            {command "&Domain Transition Analysis" {} "Show help on domain transitions" {} -command {ApolTop::_show_file "Domain Transition Analysis Help" domaintrans_help.txt}}
            {command "&Information Flow Analysis" {} "Show help on information flows" {} -command {ApolTop::_show_file "Information Flow Analysis Help" infoflow_help.txt}}
            {command "Direct &Relabel Analysis" {} "Show help on file relabeling" {} -command {ApolTop::_show_file "Relabel Analysis Help" file_relabel_help.txt}}
            {command "&Types Relationship Summary Analysis" {} "Show help on types relationships" {} -command {ApolTop::_show_file "Types Relationship Summary Analysis Help" types_relation_help.txt}}
            {separator}
            {command "&About apol" {} "Show copyright information" {} -command ApolTop::_about}
        }
    }
    # Note that the name of the last menu is "helpmenu", not "help".
    # This is because Tk handles menus named "help" differently in X
    # Windows -- specifically, it is right justified on the menu bar.
    # See the man page for [menu] for details.  It was decided that
    # the behavior is undesirable; the Help menu is intended to be
    # left justified along with the other menus.  Therefore the menu
    # name is "helpmenu".

    variable mainframe [MainFrame .mainframe -menu $menus -textvariable ApolTop::statu_line]
    pack $mainframe -fill both -expand yes

    $mainframe addindicator -textvariable ApolTop::policy_source_linenum -width 14
    $mainframe addindicator -textvariable ApolTop::policy_stats_summary -width 88
    $mainframe addindicator -textvariable ApolTop::policy_version_string -width 28

    $mainframe setmenustate tag_policy_open disabled

    variable notebook [NoteBook [$mainframe getframe].nb]
    pack $notebook -fill both -expand yes -padx 4 -pady 4
    set page [$notebook insert end components -text "Policy Components"]
    set components [NoteBook $page.nb]
    pack $components -fill both -expand yes -padx 4 -pady 4
    set page [$notebook insert end rules -text "Policy Rules"]
    set rules [NoteBook $page.nb]
    pack $rules -fill both -expand yes -padx 4 -pady 4
    $notebook bindtabs <Button-1> [list ApolTop::_switch_tab $components $rules]
    $components bindtabs <Button-1> [list ApolTop::_switch_tab $components $rules]
    $rules bindtabs <Button-1> [list ApolTop::_switch_tab $components $rules]

    variable tabs
    foreach tab $tabs {
        set parent_nb $notebook
        foreach nb [lindex $tab 1] {
            # (intermediate notebooks were created just above here)
            set parent_nb [set $nb]
        }
        [lindex $tab 0]::create [lindex $tab 0] $parent_nb
    }

    $components raise [$components page 0]
    $rules raise [$rules page 0]
    $notebook raise [$notebook page 0]

    $notebook compute_size
    setCurrentTab [$components page 0]
}

# Callback invoked whenever the user clicks on a (possibly different)
# tab in the toplevel notebook(s).
proc ApolTop::_switch_tab {components_nb rules_nb new_tab} {
    if {$new_tab == "components"} {
        set new_tab [$components_nb raise]
    } elseif {$new_tab == "rules"} {
        set new_tab [$rules_nb raise]
    }
    variable current_tab $new_tab
    _toplevel_tab_switched
}

proc ApolTop::_toplevel_tab_switched {} {
    variable tabs
    variable current_tab
    variable mainframe
    foreach tab $tabs {
        if {[lindex $tab 0] != $current_tab} {
            continue
        }
        focus [getCurrentTextWidget]
        if {[lsearch [lindex $tab 2] "tag_query_saveable"] >= 0} {
            $mainframe setmenustate tag_query_saveable normal
        } else {
            $mainframe setmenustate tag_query_saveable disabled
        }
        if {[lsearch [lindex $tab 2] "tag_source"] >= 0} {
            [lindex $tab 0]::insertionMarkChanged
        } else {
            variable policy_source_linenum {}
        }
        break
    }
}

# Enable and disable various widgets in the toplevel window, based
# upon the type of policy that was opened.
proc ApolTop::_toplevel_policy_open {ppath} {
    variable tabs
    foreach tab $tabs {
        [lindex $tab 0]::open $ppath
    }

    if {![is_capable "conditionals"]} {
        _toplevel_enable_tabs tag_conditionals disabled
    }
    if {![is_capable "mls"]} {
        _toplevel_enable_tabs tag_mls disabled
    }
    if {![is_capable "source"]} {
        _toplevel_enable_tabs tag_source disabled
    }
    _toplevel_tab_switched

    variable mainframe
    $mainframe setmenustate tag_policy_open normal
    $mainframe setmenustate tag_perm_map_open disabled

    _toplevel_update_stats
    variable policy_version_string [$::ApolTop::policy get_version_type_mls_str]

    set primary_file [$ppath get_primary]
    wm title . "SELinux Policy Analysis - $primary_file"
}

# Enable/disable tabs that contain the given tag.  If the currently
# raised page is one of those tabs then raise the first tab (which
# hopefully does not have that tag).
proc ApolTop::_toplevel_enable_tabs {tag new_state} {
    variable tabs
    variable notebook
    foreach tab $tabs {
        if {[lsearch [lindex $tab 2] $tag] >= 0} {
            set parent_nb $notebook
            foreach nb [lindex $tab 1] {
                set parent_nb [$parent_nb getframe $nb].nb
            }
            $parent_nb itemconfigure [lindex $tab 0] -state $new_state
            if {[$parent_nb raise] == {}} {
                $parent_nb raise [$parent_nb pages 0]
                setCurrentTab [lindex $tabs 0 0]
            }
        }
    }
}

proc ApolTop::_build_recent_files_menu {} {
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
            -command [list ApolTop::openPolicyPath $r]
    }
}

# Add a policy path to the recently opened list, trim the menu to
# max_recent_files, and then regenerate the recent menu.
proc ApolTop::_add_recent {ppath} {
    variable recent_files
    variable max_recent_files

    # if ppath is already in recent files list, remove it from there
    set new_recent $ppath
    foreach r $recent_files {
        if {[apol_policy_path_compare $r $ppath] != 0} {
            lappend new_recent $r
        }
    }
    set recent_files [lrange $new_recent 0 [expr {$max_recent_files - 1}]]
    _build_recent_files_menu
}

proc ApolTop::_toplevel_update_stats {} {
    variable policy_stats
    variable policy_stats_summary

    set iter_funcs {
        "classes" get_class_iter
        "commons" get_common_iter

        "roles" get_role_iter
        "role_allow" get_role_allow_iter
        "role_trans" get_role_trans_iter

        "users" get_user_iter
        "bools" get_bool_iter
        "sens" get_level_iter
        "cats" get_cat_iter
        "range_trans" get_range_trans_iter

        "sids" get_isid_iter
        "portcons" get_portcon_iter
        "netifcons" get_netifcon_iter
        "nodecons" get_nodecon_iter
        "genfscons" get_genfscon_iter
        "fs_uses" get_fs_use_iter
    }
    foreach {key func} $iter_funcs {
        set i [$::ApolTop::qpolicy $func]
        set policy_stats($key) [$i get_size]
        $i -acquire
        $i -delete
    }

    set query_funcs {
        "perms" new_apol_perm_query_t
        "types" new_apol_type_query_t
        "attribs" new_apol_attr_query_t
    }
    
    foreach {key func} $query_funcs {
        set q [$func]
        set v [$q run $::ApolTop::policy]
        $q -acquire
        $q -delete
        set policy_stats($key) [$v get_size]
        $v -acquire
        $v -delete
    }

    set avrule_bits [list \
                         avrule_allow $::QPOL_RULE_ALLOW \
                         avrule_auditallow $::QPOL_RULE_AUDITALLOW \
                         avrule_dontaudit $::QPOL_RULE_DONTAUDIT \
                         avrule_neverallow $::QPOL_RULE_NEVERALLOW \
                        ]
    foreach {key bit} $avrule_bits {
        if {$bit == $::QPOL_RULE_NEVERALLOW && ![is_capable "neverallow"]} {
            # neverallow rules have not yet been loaded
            set policy_stats($key) 0
        } else {
            set i [$::ApolTop::qpolicy get_avrule_iter $bit]
            set policy_stats($key) [$i get_size]
            $i -acquire
            $i -delete
        }
    }

    set terule_bits [list \
                         type_trans $::QPOL_RULE_TYPE_TRANS \
                         type_member $::QPOL_RULE_TYPE_CHANGE \
                         type_change $::QPOL_RULE_TYPE_MEMBER \
                        ]
    foreach {key bit} $terule_bits {
        set i [$::ApolTop::qpolicy get_avrule_iter $bit]
        set policy_stats($key) [$i get_size]
        $i -acquire
        $i -delete
    }

    set policy_stats_summary ""
    append policy_stats_summary "Classes: $policy_stats(classes)   "
    append policy_stats_summary "Perms: $policy_stats(perms)   "
    append policy_stats_summary "Types: $policy_stats(types)   "
    append policy_stats_summary "Attribs: $policy_stats(attribs)   "
    set num_te_rules [expr {$policy_stats(avrule_allow) + $policy_stats(avrule_auditallow) +
                            $policy_stats(avrule_dontaudit) + $policy_stats(avrule_neverallow) +
                            $policy_stats(type_trans) + $policy_stats(type_member) +
                            $policy_stats(type_change)}]
    if {![is_capable "neverallow"]} {
        append num_te_rules "+"
    }
    append policy_stats_summary "AV + TE rules: $num_te_rules   "
    append policy_stats_summary "Roles: $policy_stats(roles)   "
    append policy_stats_summary "Users: $policy_stats(users)"
}

############### callbacks for top-level menu items ###############

proc ApolTop::_open_policy {} {
    variable last_policy_path
    Apol_Open_Policy_Dialog::getPolicyPath $last_policy_path
}

proc ApolTop::_user_close_policy {} {
	variable last_policy_path

	_close_policy
	set last_policy_path {}
}

proc ApolTop::_close_policy {} {
    variable policy_version_string {}
    variable policy_stats_summary {}

    wm title . "SELinux Policy Analysis"
    set i 0
    Apol_Progress_Dialog::wait "apol" "Closing policy." \
        {
            variable tabs
            foreach tab $tabs {
                if {[catch [lindex $tab 0]::close]} {
                set i [expr $i+2]
                }
            }
            Apol_Perms_Map::close
            variable policy
	    if {$policy != {}} {
                $policy -acquire
                $policy -delete
                set policy {}
                variable qpolicy {}
            }
        }

    variable mainframe
    $mainframe setmenustate tag_policy_open disabled
    $mainframe setmenustate tag_perm_map_open disabled

    _toplevel_enable_tabs tag_conditionals normal
    _toplevel_enable_tabs tag_mls normal
    _toplevel_enable_tabs tag_source normal
}

proc ApolTop::_exit {} {
    variable policy
    if {$policy != {}} {
        _close_policy
    }
    
    Apol_File_Contexts::close
    _write_configuration_file
    exit
}

proc ApolTop::_copy {} {
    set w [getCurrentTextWidget]
    if {$w != {} && [$w tag ranges sel] != {}} {
        set data [$w get sel.first sel.last]
        clipboard clear
        clipboard append -- $data
    }
}

proc ApolTop::_select_all {} {
    set w [getCurrentTextWidget]
    if {$w != {}} {
        $w tag add sel 1.0 end
    }
}

proc ApolTop::_find {} {
    Apol_Find::find
}

proc ApolTop::_goto {} {
    Apol_Goto::goto
}

proc ApolTop::_open_query_file {} {
    set types {
        {"Query files" {$ApolTop::query_file_ext}}
    }
    set query_file [tk_getOpenFile -filetypes $types -title "Open Apol Query" \
                        -defaultextension $ApolTop::query_file_ext -parent .]
    if {$query_file != {}} {
        if {[catch {::open $query_file r} f]} {
            tk_messageBox -icon error -type ok -title "Open Apol Query" \
                -message "Could not open $query_file: $f"
        }
        # Search for the analysis type line
        while {[gets $f line] >= 0} {
            set query_id [string trim $line]
            # Skip empty lines and comments
            if {$query_id == {} || [string index $query_id 0] == "#"} {
                continue
            }
            break
        }

        variable tabs
        foreach tab $tabs {
            if {$query_id == [lindex $tab 0] && [lsearch [lindex $tab 2] "tag_query_saveable"] >= 0} {
                if {[catch {${query_id}::load_query_options $f} err]} {
                    tk_messageBox -icon error -type ok -title "Open Apol Query" \
                        -message $err
                } else {
                    setCurrentTab $query_id
                }
                return
            }
        }
        tk_messageBox -icon error -type ok -title "Open Apol Query" \
            -message "The query criteria file could not be read and may be corrupted."
        close $f
    }
}

proc ApolTop::_save_query_file {} {
    set types {
        {"Query files" {$ApolTop::query_file_ext}}
    }
    set query_file [tk_getSaveFile -title "Save Apol Query" \
                        -defaultextension $ApolTop::query_file_ext \
                        -filetypes $types -parent .]
    if {$query_file != {}} {
        if {[catch {::open $query_file w} f]} {
            tk_messageBox -icon error -type ok -title "Save Apol Query" \
                -message "Could not save $query_file: $f"
        }
        if {[catch {puts $f [getCurrentTab]} err]} {
            tk_messageBox -icon error -type ok -title "Save Apol Query" \
                -message $err
        }
        if {[catch {[getCurrentTab]::save_query_options $f $query_file} err]} {
            tk_messageBox -icon error -type ok -title "Save Apol Query" \
                -message $err
        }
        close $f
    }
}

proc ApolTop::_show_policy_summary {} {
    variable policy_version_string
    variable policy_stats

    if {![regexp -- {^([^\(]+) \(([^,]+), ([^\)]+)} $ApolTop::policy_version_string -> policy_version policy_type policy_mls_type]} {
        set policy_version $ApolTop::policy_version_string
        set policy_type "unknown"
        set policy_mls_type "unknown"
    }
    set policy_version [string trim $policy_version]

    destroy .policy_statsbox
    set dialog [Dialog .policy_statsbox -separator 1 -title "Policy Summary" \
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
            "Common Permissions" commons
            "Permissions" perms
        }
        "Number of Types and Attributes" {
            "Types" types
            "Attributes" attribs
        }
        "Number of Type Enforcement Rules" {
            "allows" avrule_allow
            "auditallows" avrule_auditallow
            "dontaudits" avrule_dontaudit
            "neverallows" avrule_neverallow
            "type_transitions" type_trans
            "type_members" type_member
            "type_changes" type_change
        }
        "Number of Roles" {
            "Roles" roles
        }
        "Number of RBAC Rules" {
            "allows" role_allow
            "role_transitions" role_trans
        }
    } {
        set ltext "$title:"
        set rtext {}
        foreach {l r} $block {
            append ltext "\n    $l:"
            if {$r != "avrule_neverallow" || [is_capable "neverallow"]} {
                append rtext "\n$policy_stats($r)"
            } else {
                append rtext "\nN/A"
            }
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
            "Booleans" bools
        }
        "Number of MLS Components" {
            "Sensitivities" sens
            "Categories" cats
        }
        "Number of MLS Rules" {
            "range_transitions" range_trans
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
            append rtext "\n$policy_stats($r)"
        }
        label $g.l$i -justify left -text $ltext
        label $g.r$i -justify left -text $rtext
        grid $g.l$i $g.r$i -sticky w -padx 4 -pady 2
        incr i
    }
    grid $f $g -sticky nw -padx 4
    $dialog draw
}

proc ApolTop::_open_perm_map_from_file {} {
    if {[Apol_Perms_Map::openPermMapFromFile]} {
        variable mainframe
        $mainframe setmenustate tag_perm_map_open normal
    }
}

# Return non-zero if a permission map was found and opened, zero if
# not.
proc ApolTop::openDefaultPermMap {} {
    if {[Apol_Perms_Map::openDefaultPermMap]} {
        variable mainframe
        $mainframe setmenustate tag_perm_map_open normal
        return 1
    }
    return 0
}

proc ApolTop::_save_perm_map {} {
    Apol_Perms_Map::savePermMap
}

proc ApolTop::_save_perm_map_as {} {
    Apol_Perms_Map::savePermMapAs
}

proc ApolTop::_save_perm_map_default {} {
    Apol_Perms_Map::saveDefaultPermMap
}

proc ApolTop::_show_file {title file_name} {
    set helpfile [file join [tcl_config_get_install_dir] $file_name]
    if {[catch {::open $helpfile} f]} {
        set info $f
    } else {
        set info [read $f]
        close $f
    }
    Apol_Widget::showPopupParagraph $title $info
}

proc ApolTop::_about {} {
    if {[winfo exists .apol_about]} {
        raise .apol_about
    } else {
        variable apol_icon

        Dialog .apol_about -cancel 0 -default 0 -image $apol_icon \
            -modal none -parent . -separator 1 -title "About apol"
        set f [.apol_about getframe]
        set l1 [label $f.l1 -text "apol [tcl_config_get_version]" -height 2]
        set label_font [$l1 cget -font]
        # Tk 8.4 differs from 8.5 in how fonts are handled
        if {[llength $label_font] > 1} {
            foreach {name size} [$l1 cget -font] {break}
            incr size 6
            $l1 configure -font [list $name $size bold]
        }
        set l2 [label $f.l2 -text "Security Policy Analysis Tool for Security Enhanced Linux\n${::COPYRIGHT_INFO}\nhttp://oss.tresys.com/projects/setools"]
        pack $l1 $l2
        .apol_about add -text "Close" -command [list destroy .apol_about]
        .apol_about draw
    }
}

##### functions that load and write user's configuration file #####

proc ApolTop::_load_fonts {} {
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

# Reads in user data from their $HOME/.apol file
proc ApolTop::_read_configuration_file {} {
    variable dot_apol_file
    variable recent_files

    # if it doesn't exist, it will be created later
    if {![file exists $dot_apol_file]} {
        return
    }

    if {[catch {::open $dot_apol_file r} f]} {
        tk_messageBox -icon error -type ok -title "apol" \
            -message "Could not open $dot_apol_file: $f"
        return
    }

    while {![eof $f]} {
        set option [string trim [gets $f]]
        if {$option == {} || [string compare -length 1 $option "\#"] == 0} {
            continue
        }
        set value [string trim [gets $f]]
        if {[eof $f]} {
            puts stderr "EOF reached while reading $option"
            break
        }
        if {$value == {}} {
            puts stderr "Empty value for option $option"
            continue
        }
        switch -- $option {
            "\[window_height\]" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "window_height was not given as an integer and is ignored"
                    break
                }
                variable mainframe_height $value
            }
            "\[window_width\]" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "window_width was not given as an integer and is ignored"
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
                    puts stderr "max_recent_files was not given as an integer and is ignored"
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
            # 5			(# indicating how many file names follow)
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
                        set ppath [new_apol_policy_path_t $::APOL_POLICY_PATH_TYPE_MONOLITHIC $line NULL]
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

# Saves user data in their $HOME/.apol file
proc ApolTop::_write_configuration_file {} {
    variable dot_apol_file
    variable recent_files
    variable text_font
    variable title_font
    variable dialog_font
    variable general_font

    if {[catch {::open $dot_apol_file w} f]} {
        tk_messageBox -icon error -type ok -title "apol" \
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

#######################################################
# Start script here

proc ApolTop::main {} {
    variable notebook

    tcl_config_init

    # Prevent the application from responding to incoming send
    # requests and sending outgoing requests. This way any other
    # applications that can connect to our X server cannot send
    # harmful scripts to our application.
    rename send {}

    if {[catch {package require BWidget}]} {
        tk_messageBox -icon error -type ok -title "Apol Startup" -message \
            "The BWidget package could not be found.  Ensure that BWidget is installed in a location that Tcl/Tk can read."
        exit -1
    }

    wm withdraw .
    wm title . "SELinux Policy Analysis"
    wm protocol . WM_DELETE_WINDOW ApolTop::_exit
    variable default_bg_color [. cget -background]

    # Read apol's default settings file, gather all font information,
    # create the gui and then load recent files into the menu.
    catch {tcl_config_patch_bwidget}
    _load_fonts
    _read_configuration_file
    _create_toplevel
    bind . <Button-1> {focus %W}
    bind . <Button-2> {focus %W}
    bind . <Button-3> {focus %W}
    _build_recent_files_menu

    set icon_file [file join [tcl_config_get_install_dir] apol.gif]
    if {![catch {image create photo -file $icon_file} icon]} {
        catch {wm iconphoto . -default $icon}
    }
    variable apol_icon $icon

    variable mainframe_width [$notebook cget -width]
    variable mainframe_height [$notebook cget -height]
    wm geom . ${mainframe_width}x${mainframe_height}

    wm deiconify .
    raise .
    focus .
}

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

	set arglen [expr [llength $argv]-$argvp]
    set ppath {}
	if {$arglen <= 0} {
		return {}
	} elseif {$arglen == 1} {
        set path_type $::APOL_POLICY_PATH_TYPE_MONOLITHIC
        set policy_file [lindex $argv $argvp]
		set mod_paths [list_to_str_vector {}]
		if {[apol_file_is_policy_path_list $policy_file]} {
			set ppath [new_apol_policy_path_t $policy_file]
		}
	} elseif {$arglen > 1} {
		set path_type $::APOL_POLICY_PATH_TYPE_MODULAR
		set policy_file {} 
		foreach f [lrange $argv $argvp end] {
			if {[catch {Apol_Open_Policy_Dialog::getModuleInfo $f} modinfo]} {
				tk_messageBox -icon error -type ok -title "Module access error" -message $modinfo
			} else {
				foreach {name vers type} $modinfo {break}
				if {$type == 1} {	;# This file is a base 'module'
					if {$policy_file != {} && $policy_file != $f} {
							set rsp [tk_messageBox -icon error -type okcancel -title "Open Module" -message "Multiple base entries found." -detail "Current file: $policy_file\n\nNew file: $f\n\nClick OK to ignore new file, Cancel to exit"]
							if {$rsp == "cancel"} { exit 1}
					} else {
						set policy_file $f
					}
				} else {	;# Append regular modules to the list.
					lappend module_list $f
				}
			}
		}
		set mod_paths [list_to_str_vector $module_list]
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

proc print_init {s} {
    puts -nonewline $s
    flush stdout
}

if {[catch {tcl_config_init_libraries}]} {
    puts stderr "FAILED. The SETools libraries could not be found in any of these subdirectories:\n\t[join $auto_path "\n\t"]"
    exit -1
}

print_init "Initializing Tk... "
if {[catch {package require Tk}]} {
    puts stderr "FAILED. This library could not be found in any of these subdirectories:\n\t[join $auto_path "\n\t"]"
    puts stderr "This may indicate a problem with the tcl package's auto_path variable.\n"
    exit -1
}
puts "done."

set path [handle_args $argv0 $argv]
ApolTop::main
if {$path != {}} {
    after idle [list ApolTop::openPolicyPath $path]
}
