# Copyright (C) 2007 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget 1.7+

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

    if {$defaultPath == {}} {
        set defaultPath [list monolithic {} {}]
    }
    set vars(path_type) [lindex $defaultPath 0]
    set vars(primary_file) [lindex $defaultPath 1]
    set vars(last_module) $vars(primary_file)
    set vars(mod_names) {}
    set vars(mod_vers) {}
    set vars(mod_paths) {}
    foreach m [lindex $defaultPath 2] {
        if {[catch {apol_GetModuleInfo $m} info]} {
            tk_messageBox -icon error -type ok -title "Open Module" -message $info
        } else {
            foreach {name vers} $info {break}
            lappend vars(mod_names) $name
            lappend vars(mod_vers) $vers
            lappend vars(mod_paths) $m
            set vars(last_module) $m
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
    set l [label $primary_f.l -text "Policy Filename:"]
    pack $l -anchor w
    frame $primary_f.f
    pack $primary_f.f -expand 1 -fill x
    set e [entry $primary_f.f.e -width 32 -bg white \
               -textvariable Apol_Open_Policy_Dialog::vars(primary_file)]
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
    set bb [ButtonBox $modules_f.bb -homogeneous 1 -orient vertical -pady 2]
    $bb add -text "Add" -command Apol_Open_Policy_Dialog::browseModule
    $bb add -text "Remove" -command Apol_Open_Policy_Dialog::removeModule
    pack $bb -side right -expand 0 -anchor n -padx 4 -pady 10

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
             [list $mlabel $vlabel $plabel] $dis_bg $bb]
    $dialog add -text "Ok" -command Apol_Open_Policy_Dialog::tryOpenPolicy
    $dialog add -text "Cancel"
}

proc Apol_Open_Policy_Dialog::togglePathType {labels disabled_bg bb name1 name2 op} {
    variable vars
    variable widgets
    if {$vars(path_type) == "modular"} {
        set state normal
        set bg white
    } else {
        set state disabled
        set bg $disabled_bg
    }
    foreach w $labels {
        $w configure -state $state
    }
    foreach w $widgets(listboxes) {
        $w configure -state $state -bg $bg
    }
    $bb configure -state $state
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
    }
}

proc Apol_Open_Policy_Dialog::browseModule {} {
    variable vars
    variable dialog
    variable widgets
    set f [tk_getOpenFile -initialdir [file dirname $vars(last_module)] \
               -initialfile $vars(last_module) -parent $dialog \
               -title "Open Module"]
    if {$f == {}} {
        return
    }
    if {[lsearch $vars(mod_paths) $f] >= 0} {
        tk_messageBox -icon error -type ok -title "Open Module" -message "Module $f was already added."
        return
    }
    if {[catch {apol_GetModuleInfo $f} info]} {
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
    foreach lb $widgets(listboxes) {
        $lb selection clear 0 end
        foreach item $sellist {
            $lb selection set $item
        }
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

    set path [list $vars(path_type) $vars(primary_file) $vars(mod_paths)]
    if {[ApolTop::openPolicyFile $path] == 0} {
        $dialog enddialog {}
    }
}
