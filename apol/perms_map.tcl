# Copyright (C) 2003-2007 Tresys Technology, LLC
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

namespace eval Apol_Perms_Map {
    variable dialog .apol_perms
    variable user_default_pmap_name [file join $::env(HOME) .apol_perm_mapping]

    variable opts           ;# options for edit perm map dialog
    variable widgets
}

proc Apol_Perms_Map::close {} {
    variable opts

    _close_dialog
    set opts(filename) {}
    set opts(is_saveable) 0
    set opts(modified) 0
}

proc Apol_Perms_Map::showPermMappings {} {
    variable dialog
    if {[winfo exists $dialog]} {
        raise $dialog
    } else {
        _createEditDialog
        _refreshEditDialog
    }
}

# Let the user select a permission map file to load.  Returns 1 on
# success, 0 on error.
proc Apol_Perms_Map::openPermMapFromFile {} {
    set pmap_name [tk_getOpenFile -title "Select Perm Map to Load" -parent .]
    if {$pmap_name != {}} {
        return [_loadPermMap $pmap_name [file tail $pmap_name] 1]
    }
    return 0
}

# Attempt to load the "default" permission map.  If there exists
# within the user's home directory a file called ".apol_perm_mapping"
# then use that.  Otherwise look for the file
# "apol_perm_mapping_ver$ver", where $ver is the currently loaded
# policy version number.  If that fails then simply try
# "apol_perm_mapping".  If all of that fails, then display an error
# message and abort the loading.  Returns 1 on success, 0 on error.
proc Apol_Perms_Map::openDefaultPermMap {} {
    variable user_default_pmap_name
    if {[file exists $user_default_pmap_name]} {
        set pmap_name $user_default_pmap_name
        set pmap_short "User Default Permission Map"
        set pmap_editable 1
    } else {
        set pmap_editable 0
        # try policy-specific file
        set policy_version [apol_tcl_get_policy_version $::ApolTop::policy]
        set pmap_name [apol_file_find_path "apol_perm_mapping_ver${policy_version}"]
        if {$pmap_name == {}} {
            # finally try fallback one
            set pmap_name [apol_file_find_path apol_perm_mapping]
            if {$pmap_name == {}} {
                set message "Could not locate system default permission map.  You must explicitly load a permission map from file."
                if {[Apol_Progress_Dialog::is_waiting]} {
                    error $message
                }
                else {
                    tk_messageBox -icon error -type ok -title "Permission Maps" \
                        -message $message
                }
                return 0
            }
        }
        set pmap_short "System Default Permission Map (Read-Only)"
    }
    return [_loadPermMap $pmap_name $pmap_short $pmap_editable]
}

proc Apol_Perms_Map::savePermMap {} {
    variable opts
    if {!$opts(is_saveable)} {
        savePermMapAs
    } else {
        _savePermMap $opts(filename) $opts(shortname)
    }
}

proc Apol_Perms_Map::savePermMapAs {} {
    set pmap_name [tk_getSaveFile -title "Save Perm Map" -parent .]
    if {$pmap_name != {}} {
         _savePermMap $pmap_name [file tail $pmap_name]
    }
}

proc Apol_Perms_Map::saveDefaultPermMap {} {
    variable user_default_pmap_name
    variable opts
    _savePermMap $user_default_pmap_name "User Default Permission Map"
}

proc Apol_Perms_Map::is_pmap_loaded {} {
    variable opts
    if {$opts(filename) == {}} {
        return 0
    }
    return 1
}

#################### private functions below ####################


proc Apol_Perms_Map::_loadPermMap {filename shortname saveable} {
    if {[catch {$::ApolTop::policy open_permmap $filename} err]} {
        if {[Apol_Progress_Dialog::is_waiting]} {
            error $err
        } else {
            tk_messageBox -icon error -type ok -title "Permission Maps" -message $err
            return 0
        }
    }
    variable opts
    set opts(filename) $filename
    set opts(shortname) $shortname
    set opts(is_saveable) $saveable
    set opts(modified) 0
    if {$err != {}} {
        set len [llength [split $err "\n"]]
        if {$len > 5} {
            incr len -4
            set err [lrange [split $err "\n"] 0 3]
            lappend err "(plus $len more lines)"
            set err [join $err "\n"]
        }
        if {![Apol_Progress_Dialog::is_waiting]} {
            set message "There were warnings while opening the permission map:"
            tk_messageBox -icon warning -type ok -title "Permission Maps" \
                -message "$message\n\n$err"
        }
    } else {
        if {![Apol_Progress_Dialog::is_waiting]} {
            tk_messageBox -icon info -type ok -title "Permission Maps" \
                -message "Permission map successfully loaded."
        }
    }
    variable dialog
    if {[winfo exists $dialog]} {
        _refreshEditDialog
    }
    return 1
}

proc Apol_Perms_Map::_createEditDialog {} {
    variable dialog
    variable opts
    variable widgets

    set title "Permissions Mappings: $opts(shortname)"
    Dialog $dialog -parent . -separator 1 -title $title -modal none \
        -default 0 -cancel 2
    set topf [frame [$dialog getframe].top]
    pack $topf -side top -expand 1 -fill both

    set classes_box [TitleFrame $topf.classes -text "Object Classes"]
    pack $classes_box -side left -padx 2 -pady 2 -expand 0 -fill y
    set widgets(classes) [Apol_Widget::makeScrolledListbox [$classes_box getframe].c \
                              -height 16 -width 24 -listvar Apol_Perms_Map::opts(classes)]
    bind $widgets(classes).lb <<ListboxSelect>> Apol_Perms_Map::_refreshPermEdit
    pack $widgets(classes) -expand 1 -fill both

    set results_box [TitleFrame $topf.perms -text "Permission Mappings"]
    pack $results_box -side right -padx 2 -pady 2 -expand 1 -fill both
    set sw [ScrolledWindow [$results_box getframe].sw -auto both]
    set widgets(perms) [ScrollableFrame $sw.perms -width 300]
    $sw setwidget $widgets(perms)
    pack $sw -expand 1 -fill both

    set label_box [frame [$dialog getframe].l]
    pack $label_box -side bottom -anchor center
    set widgets(l1) [label $label_box.l1 -fg red -text ""]
    set widgets(l2) [label $label_box.l2 -text ""]
    pack $widgets(l1) $widgets(l2) -side left
    # delay setting the labels' text until [_refresh_edit_dialog], to
    # see if anything is unmapped

    $dialog add -text "Ok" -command Apol_Perms_Map::_okay
    $dialog add -text "Apply" -command Apol_Perms_Map::_apply
    $dialog add -text "Cancel" -command Apol_Perms_Map::_cancel

    trace add variable Apol_Perms_Map::opts(modified) write \
        Apol_Perms_Map::_toggleButtons

    # forcibly invoke the button callback
    set opts(modified) $opts(modified)
    $dialog draw
}

proc Apol_Perms_Map::_refreshEditDialog {} {
    variable opts
    variable widgets

    array set opts {
        classes {}
    }

    set all_mapped 1
    set class_index 0
    foreach class [Apol_Class_Perms::getClasses] {
        set suffix {}
        set perm_list {}
        foreach perm [Apol_Class_Perms::getPermsForClass $class] {
            set direction [$::ApolTop::policy get_permmap_direction $class $perm]
            set weight [$::ApolTop::policy get_permmap_weight $class $perm]
            set opts(p:${class}:${perm}:map) $direction
            set opts(p:${class}:${perm}:weight) $weight
            if {$direction == $::APOL_PERMMAP_UNMAPPED} {
                set suffix *
                set all_mapped 0
            }
            lappend perm_list [list $perm $direction $weight]
        }

        # store original perm map values, needed if user cancels dialog
        set opts(c:$class) $perm_list
        lappend opts(classes) "$class$suffix"
        if {$suffix != {}} {
            $widgets(classes).lb itemconfigure $class_index -foreground red
        }
        incr class_index
    }

    # add the warning to the bottom if there exists any unmapped permissions
    if {!$all_mapped} {
        $widgets(l1) configure -text "*"
        $widgets(l2) configure -text " - Undefined permission mapping(s)"
    } else {
        $widgets(l1) configure -text ""
        $widgets(l2) configure -text ""
    }
}

proc Apol_Perms_Map::_refreshPermEdit {} {
    variable opts
    variable widgets

    focus $widgets(classes).lb

    set perms [$widgets(perms) getframe]
    foreach w [winfo children $perms] {
        destroy $w
    }

    if {[set selection [$widgets(classes).lb curselection]] == {}} {
        return
    }
    set class [lindex $opts(classes) [lindex $selection 0]]
    set class [string trimright $class "*"]

    foreach perm $opts(c:$class) {
        foreach {perm map weight} $perm {break}
        if {$map != $::APOL_PERMMAP_UNMAPPED} {
            set l [label $perms.$perm:l -text $perm -anchor w]
        } else {
            set l [label $perms.$perm:l -text "${perm}*" -fg red -anchor w]
        }
        # tk_optionMenu does not have a -command flag, so implement an
        # option menu via a menubutton
        set menubutton [menubutton $perms.$perm:mb -bd 2 -relief raised \
                            -indicatoron 1 -width 8 \
                            -textvariable Apol_Perms_Map::opts(p:${class}:${perm}:map_label)]
        set menu [menu $menubutton.m -type normal -tearoff 0]
        $menubutton configure -menu $menu
        $menu add radiobutton -label "Read" -value $::APOL_PERMMAP_READ \
            -command [list Apol_Perms_Map::_togglePermMap $class $perm 1] \
            -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)
        $menu add radiobutton -label "Write" -value $::APOL_PERMMAP_WRITE \
            -command [list Apol_Perms_Map::_togglePermMap $class $perm 1] \
            -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)
        $menu add radiobutton -label "Both" -value $::APOL_PERMMAP_BOTH \
            -command [list Apol_Perms_Map::_togglePermMap $class $perm 1] \
            -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)
        $menu add radiobutton -label "None" -value $::APOL_PERMMAP_NONE \
            -command [list Apol_Perms_Map::_togglePermMap $class $perm 1] \
            -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)
        set l2 [label $perms.$perm:l2 -text "Weight:" -anchor e]
        set weight [spinbox $perms.$perm:weight -from 1 -to 10 -increment 1 \
                        -width 2 -bg white \
                        -command [list Apol_Perms_Map::_togglePermMap $class $perm 1] \
                        -textvariable Apol_Perms_Map::opts(p:${class}:${perm}:weight)]
        grid $l $menubutton $l2 $weight -padx 2 -sticky w -pady 4
        grid configure $l2 -ipadx 10
        _togglePermMap $class $perm 0
    }
    grid columnconfigure $perms 0 -minsize 100 -weight 1
    $widgets(perms) xview moveto 0
    $widgets(perms) yview moveto 0
}

proc Apol_Perms_Map::_togglePermMap {class perm modification} {
    variable opts
    set map $opts(p:${class}:${perm}:map)
    if {$map == $::APOL_PERMMAP_READ} {
        set opts(p:${class}:${perm}:map_label) "Read"
    } elseif {$map == $::APOL_PERMMAP_WRITE} {
        set opts(p:${class}:${perm}:map_label) "Write"
    } elseif {$map == $::APOL_PERMMAP_BOTH} {
        set opts(p:${class}:${perm}:map_label) "Both"
    } elseif {$map == $::APOL_PERMMAP_NONE} {
        set opts(p:${class}:${perm}:map_label) "None"
    } else {
        set opts(p:${class}:${perm}:map_label) "Unmapped"
    }
    set opts(modified) $modification
}

proc Apol_Perms_Map::_toggleButtons {name1 name2 op} {
    variable opts
    variable dialog
    if {$opts(modified)} {
        $dialog itemconfigure 1 -state normal
    } else {
        $dialog itemconfigure 1 -state disabled
    }
}

proc Apol_Perms_Map::_okay {} {
    _apply
    _close_dialog
}

proc Apol_Perms_Map::_apply {} {
    variable dialog
    variable opts

    if {[winfo exists $dialog] && $opts(modified)} {
        foreach class $opts(classes) {
            set class [string trimright $class "*"]
            set perm_list {}
            foreach perm [Apol_Class_Perms::getPermsForClass $class] {
                set map $opts(p:${class}:${perm}:map)
                set weight $opts(p:${class}:${perm}:weight)
                if {$map != $::APOL_PERMMAP_UNMAPPED} {
                    $::ApolTop::policy set_permmap $class $perm $map $weight
                }
                lappend perm_list [list $perm $map $weight]
            }
            # overwrite perm map values with applied values
            set opts(c:$class) $perm_list
        }
    }
    set opts(modified) 0
}

proc Apol_Perms_Map::_cancel {} {
    variable opts

    # revert the permission map to original values
    if {$opts(modified)} {
        foreach class $opts(classes) {
            set class [string trimright $class "*"]
            foreach perm $opts(c:$class) {
                foreach {perm map weight} $perm {break}
                $::ApolTop::policy set_permmap $class $perm $map $weight
            }
        }
    }
    _close_dialog
}

proc Apol_Perms_Map::_close_dialog {} {
    variable opts
    array unset opts c:*
    array unset opts p:*
    trace remove variable Apol_Perms_Map::opts(modified) write \
        Apol_Perms_Map::_toggleButtons

    variable dialog
    destroy $dialog
}

proc Apol_Perms_Map::_savePermMap {filename shortname} {
    variable opts
    variable dialog

    _apply
    if {[catch {$::ApolTop::policy save_permmap $filename} err]} {
        tk_messageBox -icon error -type ok -title "Permission Maps" -message "Error saving permission map: $err"
    } else {
        set opts(filename) $filename
        set opts(shortname) $shortname
        set opts(is_saveable) 1
        set opts(modified) 0
        set title "Permissions Mappings: $opts(shortname)"
        if {[winfo exists $dialog]} {
            $dialog configure -title $title
            _refreshEditDialog
            _refreshPermEdit
        }
    }
}
