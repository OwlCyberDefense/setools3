# Copyright (C) 2003-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget 1.7 or greater

##############################################################
# ::Apol_Perms_Map
#
# Permissions map namespace.
##############################################################
namespace eval Apol_Perms_Map {
    variable edit_dialog .apol_perms
    variable user_default_pmap_name  [file join "$::env(HOME)" ".apol_perm_mapping"]

    variable opts           ;# options for edit perm map dialog
    variable widgets
}

# Let the user select a permission map file to load.  Returns 1 on
# success, 0 on error.
proc Apol_Perms_Map::loadPermMapFromFile {} {
    set pmap_name [tk_getOpenFile -title "Select Perm Map to Load" -parent .]
    if {$pmap_name != {}} {
        return [loadPermMap $pmap_name [file tail $pmap_name] 1]
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
proc Apol_Perms_Map::loadDefaultPermMap {} {
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return 0
    }

    variable user_default_pmap_name
    if {[file exists $user_default_pmap_name]} {
        set pmap_name $user_default_pmap_name
        set pmap_short "User Default Permission Map"
        set pmap_editable 1
    } else {
        set pmap_editable 0
        # try policy-specific file
        set policy_version [apol_GetPolicyVersionNumber]
        set pmap_name [apol_GetDefault_PermMap "apol_perm_mapping_ver${policy_version}"]
        if {$pmap_name == {}} {
            # finally try fallback one
            set pmap_name [apol_GetDefault_PermMap apol_perm_mapping]
            if {$pmap_name == {}} {
                 tk_messageBox -icon error -type ok -title "Error" \
                     -message "Could not locate system default perm map. You must explicitly load a perm map from file."
                return 0
            }
        }
        set pmap_short "System Default Permission Map (Read-Only)"
    }
    return [loadPermMap $pmap_name $pmap_short $pmap_editable]
}

proc Apol_Perms_Map::close {} {
    variable opts
    variable edit_dialog
    trace remove variable Apol_Perms_Map::opts(modified) write \
        Apol_Perms_Map::toggleSaveButtons
    trace remove variable Apol_Perms_Map::opts(is_saveable) write \
        Apol_Perms_Map::toggleSaveButtons
    destroy $edit_dialog
    array unset opts c:*
    array unset opts p:*
}

proc Apol_Perms_Map::is_pmap_loaded {} {
    return [apol_IsPermMapLoaded]
}

proc Apol_Perms_Map::editPermMappings {} {
    variable edit_dialog
    if {[winfo exists $edit_dialog]} {
        raise $edit_dialog
    } else {
        createEditDialog
        refreshEditDialog
    }
}

#################### private functions below ####################


proc Apol_Perms_Map::loadPermMap {filename shortname saveable} {
    if {[catch {apol_LoadPermMap $filename} err]} {
        tk_messageBox -icon error -type ok \
            -title "Error Loading Permission Map File" -message $err
        return 0
    } elseif {$err != {}} {
        set len [llength [split $err "\n"]]
        if {$len > 5} {
            incr len -4
            set err [lrange [split $err "\n"] 0 3]
            lappend err "(plus $len more lines)"
            set err [join $err "\n"]
        }
        set message "The permission map has been loaded, but there were warnings:"
        tk_messageBox -icon warning -type ok \
            -title "Warning While Loading Permission Map" \
            -message "$message\n\n$err"
    }
    variable opts
    set opts(filename) $filename
    set opts(shortname) $shortname
    set opts(is_saveable) $saveable
    set opts(modified) 0
    variable edit_dialog
    if {[winfo exists $edit_dialog]} {
        refreshEditDialog
    }
    ApolTop::configure_edit_pmap_menu_item 1
    return 1
}

proc Apol_Perms_Map::createEditDialog {} {
    variable edit_dialog
    variable opts
    variable widgets

    set title "Edit Permissions Mappings: $opts(shortname)"
    Dialog $edit_dialog -parent . -separator 1 -title $title -modal none -cancel 3
    set topf [frame [$edit_dialog getframe].top]
    pack $topf -side top -expand 1 -fill both
    set classes_box [TitleFrame $topf.classes -text "Object Classes"]
    pack $classes_box -side left -padx 2 -pady 2 -expand 0 -fill y
    set widgets(classes) [Apol_Widget::makeScrolledListbox [$classes_box getframe].c \
                              -height 16 -width 30 -listvar Apol_Perms_Map::opts(classes)]
    bind $widgets(classes).lb <<ListboxSelect>> Apol_Perms_Map::refreshPermEdit
    pack $widgets(classes) -expand 1 -fill both

    set results_box [TitleFrame $topf.perms -text "Permission Mappings"]
    pack $results_box -side right -padx 2 -pady 2 -expand 1 -fill both
    set sw [ScrolledWindow [$results_box getframe].sw -auto both]
    set widgets(perms) [ScrollableFrame $sw.perms -bg white -width 450]
    $sw setwidget $widgets(perms)
    pack $sw -expand 1 -fill both

    set label_box [frame [$edit_dialog getframe].l]
    pack $label_box -side bottom -anchor center
    set widgets(l1) [label $label_box.l1 -fg red -text ""]
    set widgets(l2) [label $label_box.l2 -text ""]
    pack $widgets(l1) $widgets(l2) -side left
    # delay setting the labels' text until [refresh_edit_dialog], to
    # see if anything is unmapped

    $edit_dialog add -text "Save and Load Changes" -command Apol_Perms_Map::save -width -1
    $edit_dialog add -text "Save As..." -command Apol_Perms_Map::saveAs
    $edit_dialog add -text "Save As User Default" -command Apol_Perms_Map::saveAsDefault
    $edit_dialog add -text "Exit" -command Apol_Perms_Map::exitDialog

    trace add variable Apol_Perms_Map::opts(modified) write \
        Apol_Perms_Map::toggleSaveButtons
    trace add variable Apol_Perms_Map::opts(is_saveable) write \
        Apol_Perms_Map::toggleSaveButtons

    $edit_dialog draw
}

proc Apol_Perms_Map::refreshEditDialog {} {
    variable opts
    variable widgets

    array set opts {
        classes {}
    }

    if {[catch {apol_GetPermMap} perm_map]} {
        tk_messageBox -icon error -type ok \
            -title "Error Getting Permission Map" -message $perm_map
        return
    }

    set all_unmapped 1
    set class_index 0
    foreach class_tuple [lsort -index 0 $perm_map] {
        foreach {class perm_list} $class_tuple {break}
        set suffix {}
        # store original perm map values, needed if user exits without saving
        set opts(c:$class) [lsort -index 0 $perm_list]
        foreach perm $opts(c:$class) {
            foreach {perm map weight} $perm {break}
            set opts(p:${class}:${perm}:map) $map
            set opts(p:${class}:${perm}:weight) $weight
            if {$map == "u"} {
                set suffix *
                set all_unmapped 0
            }
        }
        lappend opts(classes) "$class$suffix"
        if {$suffix != {}} {
            $widgets(classes).lb itemconfigure $class_index -foreground red
        }
        incr class_index
    }

    # add the warning to the bottom if there exists any unmapped permissions
    if {!$all_unmapped} {
        $widgets(l1) configure -text "*"
        $widgets(l2) configure -text " - Undefined permission mapping(s)"
    } else {
        $widgets(l1) configure -text ""
        $widgets(l2) configure -text ""
    }

    # force refresh of button states, to invoke their traces
    set opts(modified) $opts(modified)
    set opts(is_saveable) $opts(is_saveable)
}

proc Apol_Perms_Map::refreshPermEdit {} {
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
        if {$map != "u"} {
            set l [label $perms.$perm:l -text $perm -bg white -anchor w]
        } else {
            set l [label $perms.$perm:l -text "${perm}*" -fg red -bg white -anchor w]
        }
        set r [radiobutton $perms.$perm:r -text "Read" -value r -bg white \
                   -highlightthickness 0 \
                   -command [list Apol_Perms_Map::togglePermMap $class $perm] \
                   -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)]
        set w [radiobutton $perms.$perm:w -text "Write" -value w -bg white \
                   -highlightthickness 0 \
                   -command [list Apol_Perms_Map::togglePermMap $class $perm] \
                   -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)]
        set b [radiobutton $perms.$perm:b -text "Both" -value b -bg white \
                   -highlightthickness 0 \
                   -command [list Apol_Perms_Map::togglePermMap $class $perm] \
                   -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)]
        set n [radiobutton $perms.$perm:n -text "None" -value n -bg white \
                   -highlightthickness 0 \
                   -command [list Apol_Perms_Map::togglePermMap $class $perm] \
                   -variable Apol_Perms_Map::opts(p:${class}:${perm}:map)]
        set l2 [label $perms.$perm:l2 -text "Weight:" -bg white -anchor e]
        set weight [spinbox $perms.$perm:weight -from 1 -to 10 -increment 1 \
                        -width 2 -bg white \
                        -command [list Apol_Perms_Map::togglePermMap $class $perm] \
                        -textvariable Apol_Perms_Map::opts(p:${class}:${perm}:weight)]
        grid $l $r $w $b $n $l2 $weight -padx 2 -sticky w -pady 4
        grid configure $l2 -ipadx 10
    }
    grid columnconfigure $perms 0 -minsize 100 -weight 1
    foreach i {1 2 3 4} {
        grid columnconfigure $perms $i -uniform 1 -weight 0
    }
    $widgets(perms) xview moveto 0
    $widgets(perms) yview moveto 0
}

proc Apol_Perms_Map::toggleSaveButtons {name1 name2 op} {
    variable opts
    variable widgets
    variable edit_dialog
    if {$opts(modified)} {
        if {$opts(is_saveable)} {
            $edit_dialog itemconfigure 0 -state normal
        } else {
            $edit_dialog itemconfigure 0 -state disabled
        }
        $edit_dialog itemconfigure 1 -state normal
        $edit_dialog itemconfigure 2 -state normal
    } else {
        $edit_dialog itemconfigure 0 -state disabled
        $edit_dialog itemconfigure 1 -state disabled
        $edit_dialog itemconfigure 2 -state disabled
    }
}

proc Apol_Perms_Map::togglePermMap {class perm} {
    variable opts
    set map $opts(p:${class}:${perm}:map)
    set weight $opts(p:${class}:${perm}:weight)
    if {[catch {apol_SetPermMap $class $perm $map $weight} err]} {
        tk_messageBox -icon error -type ok -title Error -message "Error setting permission map: $err"
    }
    set opts(modified) 1
}

proc Apol_Perms_Map::save {} {
    variable opts
    savePermMap $opts(filename) [file tail $opts(shortname)]
}

proc Apol_Perms_Map::saveAs {} {
    variable edit_dialog
    set pmap_name [tk_getSaveFile -title "Save Perm Map" -parent $edit_dialog]
    if {$pmap_name != {}} {
         savePermMap $pmap_name [file tail $pmap_name]
    }
}

proc Apol_Perms_Map::saveAsDefault {} {
    variable user_default_pmap_name
    variable opts
    savePermMap $user_default_pmap_name "User Default Permission Map"
}

proc Apol_Perms_Map::exitDialog {} {
    variable opts
    variable edit_dialog
    if {$opts(modified)} {
        set ans [tk_messageBox -icon question -type yesno -title "Exit Perm Map Editor" \
                     -parent $edit_dialog \
                     -message "There were unsaved changes to the perm map.  Exit without saving changes to the perm map?"]
        if {$ans == "no"} {
            return
        }
        # revert the permission map to original values
        foreach class $opts(classes) {
            set class [string trimright $class "*"]
            foreach perm $opts(c:$class) {
                foreach {perm map weight} $perm {break}
                if {[catch {apol_SetPermMap $class $perm $map $weight} err]} {
                    tk_messageBox -icon error -type ok -title Error -message "Error restoring permission map: $err"
                }
            }
        }
        set opts(modified) 0
    }
    Apol_Perms_Map::close  ;# invoke my close to remove traces and clear memory
}

proc Apol_Perms_Map::savePermMap {filename shortname} {
    variable opts
    variable edit_dialog

    if {[catch {apol_SavePermMap $filename} err]} {
        tk_messageBox -icon error -type ok -title Error -message "Error saving permission map: $err"
    } else {
        set opts(filename) $filename
        set opts(shortname) $shortname
        set opts(is_saveable) 1
        set opts(modified) 0
        set title "Edit Permissions Mappings: $opts(shortname)"
        $edit_dialog configure -title $title
        refreshEditDialog
        refreshPermEdit
    }
}
