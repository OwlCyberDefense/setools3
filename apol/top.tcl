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
    # these three are shown on the status line of the toplevel window
    variable policy_version_string {}
    variable policy_source_linenum {}
    variable policy_stats_summary {}
    variable policy_stats  ;# array of statistics for the current policy

    variable last_policy_path {}
    variable query_file_ext ".qf"

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
                } p]} {
        tk_messageBox -icon error -type ok -title "Open Policy" \
            -message "The selected file does not appear to be a valid SELinux Policy.\n\n$p"
        return -1  ;# indicates failed to open policy
    }

    variable policy $p
    variable qpolicy [$p get_qpol]

    _toplevel_policy_open $ppath

    Apol_Prefs::addRecent $ppath
    _build_recent_files_menu
    variable last_policy_path $ppath

    if {![is_capable "attribute names"] && \
            [llength $::Apol_Types::attriblist] > 0 && \
            [Apol_Prefs::getPref show_attrib_warning]} {
        tk_messageBox -icon info -parent . -title "Open Policy" -type ok \
            -message "Apol has generated attribute names because the original names were not preserved in the policy."
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
	    {command "&Close" {tag_policy_open} "Close current polocy" {Ctrl w} -command ApolTop::_close_policy}
	    {separator}
	    {cascade "&Recent Files" {} recent 0 {}}
	    {separator}
            {command "&Quit" {} "Quit policy analysis tool" {Ctrl q} -command ApolTop::_exit}
	}
	"&Edit" {} edit 0 {
            {command "&Copy" {tag_policy_open} {} {Ctrl c} -command ApolTop::_copy}
            {command "Select &All" {tag_policy_open} {} {Ctrl a} -command ApolTop::_select_all}
            {separator}
	    {command "&Find..." {tag_policy_open} "Find text in current buffer" {Ctrl f} -command ApolTop::_find}
	    {command "&Goto Line..." {tag_policy_open} "Goto a line in current buffer" {Ctrl g} -command ApolTop::_goto}
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
    $notebook bindtabs <Button-1> ApolTop::_switch_tab
    pack $notebook -fill both -expand yes -padx 4 -pady 4
    set page [$notebook insert end components -text "Policy Components"]
    set components [NoteBook $page.nb]
    $components bindtabs <Button-1> ApolTop::_switch_tab
    pack $components -fill both -expand yes -padx 4 -pady 4
    set page [$notebook insert end rules -text "Policy Rules"]
    set rules [NoteBook $page.nb]
    $rules bindtabs <Button-1> ApolTop::_switch_tab
    pack $rules -fill both -expand yes -padx 4 -pady 4

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
proc ApolTop::_switch_tab {new_tab} {
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
    set recent_menu [$mainframe getmenu recent]
    $recent_menu delete 0 end
    foreach r [Apol_Prefs::getPref recent_files] {
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
    append policy_stats_summary "TE rules: $num_te_rules   "
    append policy_stats_summary "Roles: $policy_stats(roles)   "
    append policy_stats_summary "Users: $policy_stats(users)"
}

############### callbacks for top-level menu items ###############

proc ApolTop::_open_policy {} {
    variable last_policy_path
    Apol_Open_Policy_Dialog::getPolicyPath $last_policy_path
}

proc ApolTop::_close_policy {} {
    variable policy_version_string {}
    variable policy_stats_summary {}

    wm title . "SELinux Policy Analysis"

    Apol_Progress_Dialog::wait "apol" "Closing policy." \
        {
            variable tabs
            foreach tab $tabs {
                [lindex $tab 0]::close
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
    Apol_Prefs::savePrefs
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
        foreach {name size} [$l1 cget -font] {break}
        incr size 6
        $l1 configure -font [list $name $size bold]
        set l2 [label $f.l2 -text "Security Policy Analysis Tool for Security Enhanced Linux\n${::COPYRIGHT_INFO}\nhttp://oss.tresys.com/projects/setools"]
        pack $l1 $l2
        .apol_about add -text "Close" -command [list destroy .apol_about]
        .apol_about draw
    }
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

    # Read apol's default settings file, gather all font information,
    # create the gui and then load recent files into the menu.
    catch {tcl_config_patch_bwidget}

    tk scaling -displayof . 1.0

    Apol_Prefs::create
    Apol_Prefs::openPrefs

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

    wm geom . [Apol_Prefs::getPref top_width]x[Apol_Prefs::getPref top_height]

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
    after idle [list ApolTop::openPolicyPath $path]
}
