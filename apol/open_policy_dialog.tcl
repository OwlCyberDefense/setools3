# Copyright (C) 2007 Tresys Technology, LLC
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

namespace eval Apol_Open_Policy_Dialog {
    variable dialog {}
    variable widgets
    variable vars
}

# Create a dialog box to allow the user to select a policy path.
proc Apol_Open_Policy_Dialog::getPolicyPath {defaultPath} {
    variable dialog
    variable vars

    array unset vars
    _create_dialog .

    set vars(path_type) "monolithic"
    set vars(primary_file) {}
    set vars(last_module) {}
    set vars(mod_names) {}
    set vars(mod_vers) {}
    set vars(mod_paths) {}

    if {$defaultPath != {}} {
        foreach {path_type primary modules} [policy_path_to_list $defaultPath] {break}
        set vars(path_type) $path_type
        if {[set vars(primary_file) $primary] != {}} {
            $dialog itemconfigure 0 -state normal
        }
        set vars(last_module) $vars(primary_file)
        foreach m $modules {
            if {[catch {getModuleInfo $m} info]} {
                tk_messageBox -icon error -type ok -title "Open Module" -message $info
            } else {
                foreach {name vers} $info {break}
                lappend vars(mod_names) $name
                lappend vars(mod_vers) $vers
                lappend vars(mod_paths) $m
                set vars(last_module) $m
            }
        }
    }
    # force a recomputation of button sizes  (bug in ButtonBox)
    $dialog.bbox _redraw
    $dialog draw
    destroy $dialog
}

########## private functions below ##########

proc Apol_Open_Policy_Dialog::_create_dialog {parent} {
    variable dialog
    variable widgets
    variable vars

    destroy $dialog
    set dialog [Dialog .open_policy_dialog -modal local -parent $parent \
                    -cancel 1 \
                    -separator 1 -homogeneous 1 -title "Open Policy"]

    set f [$dialog getframe]

    set policy_type_f [frame $f.policy_type]
    pack $policy_type_f -padx 4 -pady 4 -expand 0 -anchor w
    set l [label $policy_type_f.l -text "Policy Type:"]
    set mono_cb [radiobutton $policy_type_f.mono -text "Monolithic policy" \
                     -value monolithic \
                     -variable Apol_Open_Policy_Dialog::vars(path_type)]
    set mod_cb [radiobutton $policy_type_f.mod -text "Modular policy" \
                    -value modular \
                    -variable Apol_Open_Policy_Dialog::vars(path_type)]
    pack $l -anchor w
    pack $mono_cb $mod_cb -anchor w -padx 8

    set primary_f [frame $f.primary]
    pack $primary_f -padx 4 -pady 8 -expand 0 -fill x
    set widgets(main_label) [label $primary_f.l -text "Policy Filename:"]
    pack $widgets(main_label) -anchor w
    frame $primary_f.f
    pack $primary_f.f -expand 1 -fill x
    set e [entry $primary_f.f.e -width 32 -bg white \
               -textvariable Apol_Open_Policy_Dialog::vars(primary_file) \
               -validate key \
               -vcmd [list Apol_Open_Policy_Dialog::_validateEntryKey %P]]
    bind $e <Key-Return> Apol_Open_Policy_Dialog::tryOpenPolicy
    set b [button $primary_f.f.b -text "Browse" \
               -command Apol_Open_Policy_Dialog::browsePrimary]
    pack $e -side left -expand 1 -fill x -padx 4
    pack $b -side right -expand 0 -padx 4

    set modules_f [frame $f.modules]
    pack $modules_f -pady 4 -padx 4 -expand 1 -fill both
    set mod_list_f [frame $modules_f.mods -relief sunken]
    pack $mod_list_f -side left -expand 1 -fill both -padx 4
    set mlabel [label $mod_list_f.ml -text "Module:"]
    set vlabel [label $mod_list_f.vl -text "Version:"]
    set plabel [label $mod_list_f.pl -text "Path:"]
    grid $mlabel $vlabel $plabel x -sticky w
    set dis_bg [$mlabel cget -bg]
    set ml [listbox $mod_list_f.mods -height 6 -width 10 \
                -listvariable Apol_Open_Policy_Dialog::vars(mod_names)]
    set vl [listbox $mod_list_f.vers -height 6 -width 4 \
                -listvariable Apol_Open_Policy_Dialog::vars(mod_vers)]
    set pl [listbox $mod_list_f.paths -height 6 -width 24 \
                -listvariable Apol_Open_Policy_Dialog::vars(mod_paths)]
    set sb [scrollbar $mod_list_f.sb -orient vertical \
                -command [list Apol_Open_Policy_Dialog::multiscroll yview]]
    grid $ml $vl $pl $sb -sticky nsew
    set widgets(bb) [ButtonBox $modules_f.bb -homogeneous 1 -orient vertical -pady 2]
    $widgets(bb) add -text "Add" -command Apol_Open_Policy_Dialog::browseModule
    $widgets(bb) add -text "Remove" -command Apol_Open_Policy_Dialog::removeModule -state disabled
    $widgets(bb) add -text "Import" -command Apol_Open_Policy_Dialog::importList
    $widgets(bb) add -text "Export" -command Apol_Open_Policy_Dialog::exportList -state disabled
    pack $widgets(bb) -side right -expand 0 -anchor n -padx 4 -pady 10

    set widgets(listboxes) [list $ml $vl $pl]
    set widgets(scrollbar) $sb
    foreach lb $widgets(listboxes) {
        $lb configure -yscrollcommand Apol_Open_Policy_Dialog::multiyview \
                -relief groove -bg white -exportselection 0
        bind $lb <<ListboxSelect>> \
            [list Apol_Open_Policy_Dialog::multiselect $lb]
    }

    trace add variable Apol_Open_Policy_Dialog::vars(path_type) write \
        [list Apol_Open_Policy_Dialog::togglePathType \
             [list $mlabel $vlabel $plabel] $dis_bg]
    $dialog add -text "OK" -command Apol_Open_Policy_Dialog::tryOpenPolicy \
        -state disabled
    $dialog add -text "Cancel"
}

proc Apol_Open_Policy_Dialog::_validateEntryKey {newvalue} {
    variable vars
    variable dialog
    variable widgets
    if {$newvalue == {}} {
        $dialog itemconfigure 0 -state disabled
        $widgets(bb) itemconfigure 3 -state disabled
    } else {
        $dialog itemconfigure 0 -state normal
        if {$vars(path_type) == "modular"} {
            $widgets(bb) itemconfigure 3 -state normal
        } else {
            $widgets(bb) itemconfigure 3 -state disabled
        }
    }
    return 1
}

proc Apol_Open_Policy_Dialog::togglePathType {labels disabled_bg name1 name2 op} {
    variable vars
    variable widgets
    if {$vars(path_type) == "modular"} {
        set state normal
        set bg white
        $widgets(main_label) configure -text "Base Filename:"
    } else {
        set state disabled
        set bg $disabled_bg
        $widgets(main_label) configure -text "Policy Filename:"
    }
    foreach w $labels {
        $w configure -state $state
    }
    foreach w $widgets(listboxes) {
        $w configure -state $state -bg $bg
    }
    $widgets(bb) configure -state $state
    if {$state == "normal" && [[lindex $widgets(listboxes) 0] curselection] > 0} {
        $widgets(bb) itemconfigure 1 -state normal
    } else {
        $widgets(bb) itemconfigure 1 -state disabled
    }
    if {$state == "normal" && $vars(primary_file) != {}} {
        $widgets(bb) itemconfigure 3 -state normal
    } else {
        $widgets(bb) itemconfigure 3 -state disabled
    }
}

proc Apol_Open_Policy_Dialog::browsePrimary {} {
    variable vars
    variable dialog
    if {$vars(path_type) == "monolithic"} {
        set title "Open Monolithic Policy"
    } else {
        set title "Open Modular Policy"
    }
    set f [tk_getOpenFile -initialdir [file dirname $vars(primary_file)] \
               -initialfile $vars(primary_file) -parent $dialog -title $title]
    if {$f != {}} {
        set vars(primary_file) $f
        $dialog itemconfigure 0 -state normal
    }
}

proc Apol_Open_Policy_Dialog::browseModule {} {
    variable vars
    variable dialog
    set paths [tk_getOpenFile -initialdir [file dirname $vars(last_module)] \
                   -initialfile $vars(last_module) -parent $dialog \
                   -title "Open Module" -multiple 1]
    if {$paths == {}} {
        return
    }
    foreach f $paths {
        addModule $f
    }
}

proc Apol_Open_Policy_Dialog::addModule {f} {
    variable vars
    variable widgets
    if {[lsearch $vars(mod_paths) $f] >= 0} {
        tk_messageBox -icon error -type ok -title "Open Module" -message "Module $f was already added."
        return
    }
    if {[catch {getModuleInfo $f} info]} {
        tk_messageBox -icon error -type ok -title "Open Module" -message $info
    } else {
        foreach {name vers} $info {break}
        set vars(mod_names) [lsort [concat $vars(mod_names) $name]]
        set i [lsearch $vars(mod_names) $name]
        set vars(mod_vers) [linsert $vars(mod_vers) $i $vers]
        set vars(mod_paths) [linsert $vars(mod_paths) $i $f]
        foreach lb $widgets(listboxes) {
            $lb selection clear 0 end
            $lb selection set $i
        }
        [lindex $widgets(listboxes) 0] see $i
        set vars(last_module) $f
        $widgets(bb) itemconfigure 1 -state normal
    }
}

proc Apol_Open_Policy_Dialog::removeModule {} {
    variable widgets
    set i [[lindex $widgets(listboxes) 0] curselection]
    if {[llength $i] > 0} {
        foreach lb $widgets(listboxes) {
            $lb delete [lindex $i 0]
        }
    }
    $widgets(bb) itemconfigure 1 -state disabled
}

proc Apol_Open_Policy_Dialog::importList {} {
    variable vars
    variable dialog
    variable widgets
    set f [tk_getOpenFile -initialdir [file dirname $vars(primary_file)] \
               -parent $dialog -title "Import Policy List"]
    if {$f == {}} {
        return
    }
    if {[catch {new_apol_policy_path_t $f} ppath]} {
        tk_messageBox -icon error -type ok -title "Import Policy List" \
            -message "Error importing policy list $f: $ppath"
        return
    }
    foreach lb $widgets(listboxes) {
        $lb delete 0 end
    }
    foreach {path_type primary modules} [policy_path_to_list $ppath] {break}
    set vars(path_type) $path_type
    if {[set vars(primary_file) $primary] != {}} {
        $dialog itemconfigure 0 -state normal
    }
    set vars(last_module) $f
    foreach m $modules {
        addModule $m
    }
    _validateEntryKey $vars(primary_file)
    $ppath -acquire
    $ppath -delete
}

proc Apol_Open_Policy_Dialog::exportList {} {
    variable vars
    variable dialog
    set f [tk_getSaveFile -parent $dialog -title "Export Policy List"]
    if {$f == {}} {
        return
    }
    set ppath [list_to_policy_path $vars(path_type) $vars(primary_file) $vars(mod_paths)]
    if {[catch {$ppath to_file $f} err]} {
        tk_messageBox -icon error -type ok -title "Export Policy List" \
            -message "Error exporting policy list $f: $err"
    }
}

proc Apol_Open_Policy_Dialog::multiscroll {args} {
    variable widgets
    foreach lb $widgets(listboxes) {
        eval $lb $args
    }
}

proc Apol_Open_Policy_Dialog::multiselect {lb} {
    variable widgets
    set sellist [$lb curselection]
    set enable_remove 0
    foreach lb $widgets(listboxes) {
        $lb selection clear 0 end
        foreach item $sellist {
            $lb selection set $item
            set enable_remove 1
        }
    }
    if {$enable_remove} {
        $widgets(bb) itemconfigure 1 -state normal
    }
}

proc Apol_Open_Policy_Dialog::multiyview {args} {
    variable widgets
    eval $widgets(scrollbar) set $args
    multiscroll yview moveto [lindex $args 0]
}


# Generate a policy path and try to open the given policy.  Upon
# success end the dialog and return that path.  Otherwise do not close
# the dialog.
proc Apol_Open_Policy_Dialog::tryOpenPolicy {} {
    variable dialog
    variable vars

    if {[string trim $vars(primary_file)] != {}} {
        set ppath [list_to_policy_path $vars(path_type) $vars(primary_file) $vars(mod_paths)]
        if {[ApolTop::openPolicyPath $ppath] == 0} {
            $dialog enddialog {}
        }
    }
}

# Retrieve information about a policy module file, either source or
# binary, from disk.  This will be a 2-ple of module name and version.
# The policy module will be closed afterwards.
proc Apol_Open_Policy_Dialog::getModuleInfo {f} {
    set mod [new_qpol_module_t $f]
    set retval [list [$mod get_name] [$mod get_version]]
    $mod -acquire
    $mod -delete
    return $retval
}
