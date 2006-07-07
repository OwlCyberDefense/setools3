# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget


##############################################################
# ::Apol_TE
#
# The TE Rules page
##############################################################
namespace eval Apol_TE {
    variable vals
    variable widgets
    variable tabs
    variable enabled
}

########################################################################
# ::goto_line
#	- goes to indicated line in text box
#
proc Apol_TE::goto_line { line_num } {
    variable widgets
    variable tabs
    if {[$widgets(results) pages] != {}} {
        set raisedPage [$widgets(results) raise]
        if {$raisedPage != {}} {
            Apol_Widget::gotoLineSearchResults $tabs($raisedPage) $line_num
	}
    }
}

##############################################################
# ::search
#	- Search text widget for a string
#
proc Apol_TE::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    variable tabs
    if {[$widgets(results) pages] != {}} {
        set raisedPage [$widgets(results) raise]
        if {$raisedPage != {}} {
            ApolTop::textSearch $tabs($raisedPage).tb $str $case_Insensitive $regExpr $srch_Direction
	}
    }
}


proc Apol_TE::set_Focus_to_Text { tab } {
    variable widgets
    variable tabs
    if {[$widgets(results) pages] != {}} {
        set raisedPage [$widgets(results) raise]
        if {$raisedPage != {}} {
            focus $tabs($raisedPage)
	}
    }
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::get_results_raised_tab
# -----------------------------------------------------------------------------
proc Apol_TE::get_results_raised_tab {} {
    variable widgets
    $widgets(results) raise
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::open
# -----------------------------------------------------------------------------
proc Apol_TE::open { } {
    reinitialize_default_search_options
    reinitialize_search_widgets
    reinitialize_tabs

    variable vals
    variable enabled
    set vals(cp:classes) $Apol_Class_Perms::class_list
    set enabled(cp:classes) 1
    set enabled(cp:perms) 1
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::close
# -----------------------------------------------------------------------------
proc Apol_TE::close { } {
    reinitialize_tabs
    reinitialize_search_widgets
    reinitialize_default_search_options
    set enabled(cp:perms) 1
}

proc Apol_TE::free_call_back_procs { } {
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::reinitialize_default_search_options
# -----------------------------------------------------------------------------
proc Apol_TE::reinitialize_default_search_options { } {
    variable vals
    array set vals {
        rs:allow 1       rs:type_transition 1
        rs:neverallow 1  rs:type_member 1
        rs:auditallow 1  rs:type_change 1
        rs:dontaudit 1

        oo:enabled 0
        oo:regexp 0

        ta:use_source 0
        ta:source_indirect 1
        ta:source_which source
        ta:source_sym,types 1 ta:source_sym,attribs 0
        ta:source_sym {}

        ta:use_target 0
        ta:target_indirect 1
        ta:target_sym,types 1 ta:target_sym,attribs 0
        ta:target_sym {}

        ta:use_default 0
        ta:default_sym,types 1 ta:default_sym,attribs 0
        ta:default_sym {}

        cp:classes {}
        cp:classes_selected {}
        cp:perms {}
        cp:perms_selected {}
        cp:perms_toshow all
    }

    variable enabled
    array set enabled {
        ta:use_source 1
        ta:use_target 1
        ta:use_default 1

        cp:classes 0
        cp:perms 0
    }
}

proc Apol_TE::reinitialize_tabs {} {
    variable widgets
    variable tabs
    array set tabs {
        next_result_id 1
    }
    foreach p [$widgets(results) pages 0 end] {
        delete_results $p
    }
}

proc Apol_TE::reinitialize_search_widgets {} {
    variable widgets
    $widgets(search_opts) raise typeattrib

    $widgets(cp:classes) selection clear 0 end
    $widgets(cp:perms) selection clear 0 end
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::create
# -----------------------------------------------------------------------------
proc Apol_TE::create {nb} {
    variable vals
    variable widgets

    reinitialize_default_search_options

    # Layout Frames
    set frame [$nb insert end $ApolTop::terules_tab -text "TE Rules"]
    set pw [PanedWindow $frame.pw -side left -weights extra]
    set topf [$pw add -weight 0]
    set bottomf [$pw add -weight 1]
    pack $pw -expand 1 -fill both

    # Major SubFrames:
    # rsbox - rule selection
    # oobox - other search options
    # obox - holds search options widgets
    # rbox - holds display window widgets
    # abox - action buttons
    set top_leftf [frame $topf.tl]
    set widgets(search_opts) [NoteBook $topf.nb]
    set abox [frame $topf.abox]
    pack $top_leftf -side left -expand 0 -fill y
    pack $widgets(search_opts) -side left -expand 1 -fill both -padx 10
    pack $abox -side right -fill y -padx 5
    set rsbox [TitleFrame $top_leftf.rsbox -text "Rule Selection"]
    set oobox [TitleFrame $top_leftf.oobox -text "Search Options"]
    set rbox [TitleFrame $bottomf.rbox -text "Type Enforcement Rules Display"]
    pack $rsbox -side top -expand 0 -fill both
    pack $oobox -side top -expand 1 -fill both -pady 2
    pack $rbox -expand yes -fill both -padx 2

    # Rule selection subframe
    set fm_rules [$rsbox getframe]
    set allow [checkbutton $fm_rules.allow -text "allow" \
                   -variable Apol_TE::vals(rs:allow)]
    set neverallow [checkbutton $fm_rules.neverallow -text "neverallow" \
                        -variable Apol_TE::vals(rs:neverallow)]
    set auditallow [checkbutton $fm_rules.auditallow -text "auditallow" \
                        -variable Apol_TE::vals(rs:auditallow)]
    set dontaudit [checkbutton $fm_rules.dontaudit -text "dontaudit" \
                       -variable Apol_TE::vals(rs:dontaudit)]
    set type_transition [checkbutton $fm_rules.type_transition -text "type_trans" \
                             -variable Apol_TE::vals(rs:type_transition)]
    set type_member [checkbutton $fm_rules.type_member -text "type_member" \
                         -variable Apol_TE::vals(rs:type_member)]
    set type_change [checkbutton $fm_rules.type_change -text "type_change" \
                         -variable Apol_TE::vals(rs:type_change)]
    grid $allow $type_transition -sticky w -padx 2
    grid $neverallow $type_member -sticky w -padx 2
    grid $auditallow $type_change -sticky w -padx 2
    grid $dontaudit x -sticky w -padx 2
    foreach x {allow neverallow auditallow dontaudit type_transition type_member type_change} {
        trace add variable Apol_TE::vals(rs:$x) write \
            [list Apol_TE::toggle_rule_selection]
    }

    # Other search options subframe
    set fm_options [$oobox getframe]
    set enabled [checkbutton $fm_options.enabled -text "Search only enabled rules" \
                     -variable Apol_TE::vals(oo:enabled)]
    set regexp [checkbutton $fm_options.regex -text "Search using regular expression" \
                    -variable Apol_TE::vals(oo:regexp)]
    pack $enabled $regexp -expand 0 -fill none -anchor w

    createTypesAttribsTab
    createClassesPermsTab

    # Action buttons
    set widgets(new) [button $abox.new -text "New Search" -width 12 \
                       -command [list Apol_TE::search_terules new]]
    set widgets(update) [button $abox.update -text "Update Search" -width 12 -state disabled \
                             -command [list Apol_TE::search_terules update]]
    set widgets(reset) [button $abox.reset -text "Reset Criteria" -width 12 \
                            -command Apol_TE::reset]
    pack $widgets(new) $widgets(update) $widgets(reset) \
        -side top -pady 5 -padx 5 -anchor ne

    $widgets(search_opts) compute_size

    # Popup menu widget
    set popupTab_Menu [menu .popup_terules -tearoff 0]
    set tab_menu_callbacks \
        [list {"Close Tab" Apol_TE::delete_results} \
             {"Rename Tab" Apol_TE::display_rename_tab_dialog}]

    # Notebook creation for results
    set widgets(results) [NoteBook [$rbox getframe].results]
    $widgets(results) bindtabs <Button-1> Apol_TE::switch_to_tab
    $widgets(results) bindtabs <Button-3> \
        [list ApolTop::popup_Tab_Menu \
             %W %x %y $popupTab_Menu $tab_menu_callbacks]
    set close [button [$rbox getframe].close -text "Close Tab" \
                   -command Apol_TE::delete_current_results]
    pack $widgets(results) -expand 1 -fill both -padx 4
    pack $close -expand 0 -fill x -padx 4 -pady 2

    reinitialize_tabs

    return $frame
}

#### private functions below ####

# -----------------------------------------------------------------------------
#  Command Apol_TE::createTypesAttribsTab
#
#  Description: This function is called by Apol_TE::create.
# -----------------------------------------------------------------------------
proc Apol_TE::createTypesAttribsTab {} {
    variable vals
    variable widgets
    variable enabled

    set ta_tab [$widgets(search_opts) insert end typeattrib -text "Types/Attributes"]
    set fm_source [frame $ta_tab.source]
    set fm_target [frame $ta_tab.target]
    set fm_default [frame $ta_tab.default]
    grid $fm_source $fm_target $fm_default -padx 4 -sticky ewns
    foreach i {0 1 2} {
        grid columnconfigure $ta_tab $i -weight 1 -uniform 1
    }
    grid rowconfigure $ta_tab 0 -weight 1

    create_ta_box source $fm_source "Source type/attribute" 1 1 1
    create_ta_box target $fm_target "Target type/attribute" 1 0 1
    create_ta_box default $fm_default "Default type" 0 0 0

    $widgets(search_opts) raise typeattrib
}

proc Apol_TE::create_ta_box {prefix f title has_indirect has_which has_attribs} {
    variable vals
    variable widgets

    set widgets(ta:use_${prefix}) [checkbutton $f.use -text $title \
                                       -variable Apol_TE::vals(ta:use_${prefix})]
    pack $widgets(ta:use_${prefix}) -side top -anchor w
    trace add variable Apol_TE::vals(ta:use_${prefix}) write \
        [list Apol_TE::toggle_ta_box $prefix]

    set w {}

    if {$has_attribs} {
        set helptext "Type or select a type or attribute"
    } else {
        set helptext "Type or select a type"
    }
    set widgets(ta:${prefix}_sym) [ComboBox $f.sym \
                                       -state disabled -entrybg $ApolTop::default_bg_color \
                                       -textvariable Apol_TE::vals(ta:${prefix}_sym) \
                                       -helptext $helptext -autopost 1]
    pack $widgets(ta:${prefix}_sym) -expand 0 -fill x -padx 8
    lappend w $widgets(ta:${prefix}_sym)

    if {$has_attribs} {
        set ta_frame [frame $f.ta]
        pack $ta_frame -expand 0 -anchor center -pady 2
        set types [checkbutton $ta_frame.types -text "Types" -state disabled \
                       -variable Apol_TE::vals(ta:${prefix}_sym,types)]
        set attribs [checkbutton $ta_frame.attribs -text "Attribs" -state disabled \
                         -variable Apol_TE::vals(ta:${prefix}_sym,attribs)]
        $types configure -command [list Apol_TE::toggle_ta_pushed $prefix $types]
        $attribs configure -command [list Apol_TE::toggle_ta_pushed $prefix $attribs]
        trace add variable Apol_TE::vals(ta:${prefix}_sym,attribs) write \
            [list Apol_TE::toggle_ta_sym $prefix]
        pack $types $attribs -side left -padx 2
        lappend w $types $attribs
    }

    if {$has_indirect} {
        set indirect [checkbutton $f.indirect -text "Only direct matches" \
                          -state disabled -variable Apol_TE::vals(ta:${prefix}_indirect) \
                          -onvalue 0 -offvalue 1]
        pack $indirect -anchor w -padx 8
        lappend w $indirect
    }

    if {$has_which} {
        set which_fm [frame $f.which]
        set which_source [radiobutton $which_fm.source \
                              -text "As source" -state disabled \
                              -variable Apol_TE::vals(ta:${prefix}_which) \
                              -value source]
        set which_any [radiobutton $which_fm.any \
                           -text "Any" -state disabled \
                           -variable Apol_TE::vals(ta:${prefix}_which) \
                           -value either]
        trace add variable Apol_TE::vals(ta:${prefix}_which) write \
            [list Apol_TE::toggle_which]
        pack $which_source $which_any -side left -padx 2
        pack $which_fm -anchor w -padx 6
        lappend w $which_source $which_any
    }

    # update contents of the combobox whenever the 'Types' checkbutton
    # is enabled; for default type, this is invoked by a call to
    # reinitialize_default_search_options
    trace add variable Apol_TE::vals(ta:${prefix}_sym,types) write \
            [list Apol_TE::toggle_ta_sym $prefix]

    set widgets(ta:${prefix}_widgets) $w
    trace add variable Apol_TE::enabled(ta:use_${prefix}) write \
        [list Apol_TE::toggle_enable_ta ${prefix}]
}

proc Apol_TE::toggle_rule_selection {name1 name2 op} {
    maybe_enable_default_type
    maybe_enable_perms
}


## lots of obscure callbacks here to determine when to enable a ta box ##


# called when there is a change in state to the top checkbutton within
# a ta box
proc Apol_TE::toggle_ta_box {col name1 name2 op} {
    variable vals
    variable enabled
    if {$col == "source"} {
        maybe_enable_target_type
        maybe_enable_default_type
    }

    # force a refresh of this box's state; this invokes
    # toggle_enable_ta callback
    set enabled(ta:use_${col}) $enabled(ta:use_${col})
}

# disable target type/attrib and default type if source box is marked as "any"
proc Apol_TE::toggle_which {name1 name2 op} {
    maybe_enable_target_type
    maybe_enable_default_type
}

proc Apol_TE::maybe_enable_target_type {} {
    variable vals
    variable enabled

    set any_set 0
    if {$enabled(ta:use_source) && $vals(ta:use_source) && $vals(ta:source_which) == "either"} {
        set any_set 1
    }
    if {!$any_set} {
        set enabled(ta:use_target) 1
    } else {
        set enabled(ta:use_target) 0
    }
}

proc Apol_TE::maybe_enable_default_type {} {
    variable vals
    variable enabled

    set typerule_set 0
    set any_set 0
    foreach x {type_transition type_member type_change} {
        if {$vals(rs:$x)} {
            set typerule_set 1
            break
        }
    }
    if {$enabled(ta:use_source) && $vals(ta:use_source) && $vals(ta:source_which) == "either"} {
        set any_set 1
    }
    if {$typerule_set && !$any_set} {
        set enabled(ta:use_default) 1
    } else {
        set enabled(ta:use_default) 0
    }
}

# called whenever a ta box is enabled or disabled
proc Apol_TE::toggle_enable_ta {col name1 name2 op} {
    variable vals
    variable widgets
    variable enabled
    if {$enabled(ta:use_${col})} {
        $widgets(ta:use_${col}) configure -state normal
    } else {
        $widgets(ta:use_${col}) configure -state disabled
    }
    if {$enabled(ta:use_${col}) && $vals(ta:use_${col})} {
        foreach w $widgets(ta:${col}_widgets) {
            $w configure -state normal
        }
        $widgets(ta:${col}_sym) configure -entrybg white
    } else {
        foreach w $widgets(ta:${col}_widgets) {
            $w configure -state disabled
        }
        $widgets(ta:${col}_sym) configure -entrybg $ApolTop::default_bg_color
    }

    # update this tab's name if one of the columns is enabled and used
    if {($enabled(ta:use_source) && $vals(ta:use_source)) || \
            ($enabled(ta:use_target) && $vals(ta:use_target)) || \
            ($enabled(ta:use_default) && $vals(ta:use_default))} {
        $widgets(search_opts) itemconfigure typeattrib -text "Types/Attributes *"
    } else {
        $widgets(search_opts) itemconfigure typeattrib -text "Types/Attributes"
    }
}

proc Apol_TE::toggle_ta_sym {col name1 name2 op} {
    variable vals
    variable widgets

    if {!$vals(ta:${col}_sym,types) && !$vals(ta:${col}_sym,attribs)} {
        # don't change combobox if both types and attribs are deselected
        return
    }
    if {$vals(ta:${col}_sym,types) && $vals(ta:${col}_sym,attribs)} {
        set items [lsort [concat $Apol_Types::typelist $Apol_Types::attriblist]]
    } elseif {$vals(ta:${col}_sym,types)} {
        set items $Apol_Types::typelist
    } else {
        set items $Apol_Types::attriblist
    }
    $widgets(ta:${col}_sym) configure -values $items
}

# disallow both types and attribs to be deselected within a ta box
proc Apol_TE::toggle_ta_pushed {col cb} {
    variable vals
    if {!$vals(ta:${col}_sym,types) && !$vals(ta:${col}_sym,attribs)} {

        $cb select
    }
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::createClassesPermsTab
# -----------------------------------------------------------------------------
proc Apol_TE::createClassesPermsTab {} {
    variable vals
    variable widgets
    variable enabled

    set objects_tab [$widgets(search_opts) insert end classperms -text "Classes/Permissions"]
    set fm_objs [TitleFrame $objects_tab.objs -text "Object Classes"]
    set fm_perms [TitleFrame $objects_tab.perms -text "Allow and Audit Rule Permissions"]
    pack $fm_objs -side left -expand 0 -fill both -padx 2 -pady 2
    pack $fm_perms -side left -expand 1 -fill both -padx 2 -pady 2

    # object classes subframe
    set sw [ScrolledWindow [$fm_objs getframe].sw -auto both]
    set widgets(cp:classes) [listbox [$sw getframe].lb -height 5 -width 24 \
                                 -highlightthickness 0 -selectmode multiple \
                                 -exportselection 0 -state disabled \
                                 -bg $ApolTop::default_bg_color \
                                 -listvar Apol_TE::vals(cp:classes)]
    $sw setwidget $widgets(cp:classes)
    bind $widgets(cp:classes) <<ListboxSelect>> \
        [list Apol_TE::toggle_cp_select classes]
    pack $sw -expand 1 -fill both
    set clear [button [$fm_objs getframe].b -text "Clear" -width 6 -state disabled \
                   -command [list Apol_TE::clear_cp_listbox $widgets(cp:classes) classes]]
    pack $clear -expand 0 -pady 2
    set widgets(cp:classes_widgets) [list $widgets(cp:classes) $clear]

    # permissions subframe
    set f [$fm_perms getframe]
    set sw [ScrolledWindow $f.sw -auto both]
    set widgets(cp:perms) [listbox [$sw getframe].lb -height 5 -width 24 \
                               -highlightthickness 0 -selectmode multiple \
                               -exportselection 0 -bg white \
                               -listvar Apol_TE::vals(cp:perms)]
    $sw setwidget $widgets(cp:perms)
    bind $widgets(cp:perms) <<ListboxSelect>> \
        [list Apol_TE::toggle_cp_select perms]
    set clear [button $f.clear -text "Clear" \
                   -command [list Apol_TE::clear_cp_listbox $widgets(cp:perms) perms]]
    set reverse [button $f.reverse -text "Reverse" \
                     -command [list Apol_TE::reverse_cp_listbox $widgets(cp:perms)]]
    set perm_rb_f [frame $f.rb]
    set l [label $perm_rb_f.l -text "Permissions to show:" -state disabled]
    set all [radiobutton $perm_rb_f.all -text "All" \
                       -variable Apol_TE::vals(cp:perms_toshow) -value all]
    set union [radiobutton $perm_rb_f.union -text "All for selected classes" \
                       -variable Apol_TE::vals(cp:perms_toshow) -value union]
    set intersect [radiobutton $perm_rb_f.inter -text "Common to selected classes" \
                       -variable Apol_TE::vals(cp:perms_toshow) -value intersect]
    trace add variable Apol_TE::vals(cp:perms_toshow) write \
        Apol_TE::toggle_perms_toshow
    pack $l $all $union $intersect -anchor w -padx 4
    grid $sw - $perm_rb_f -sticky nsw
    grid $clear $reverse ^ -pady 2 -sticky ew
    grid columnconfigure $f 0 -weight 0 -uniform 1 -pad 2
    grid columnconfigure $f 1 -weight 0 -uniform 1 -pad 2
    grid columnconfigure $f 2 -weight 1
    grid rowconfigure $f 0 -weight 1
    set widgets(cp:perms_widgets) \
        [list $widgets(cp:perms) $clear $reverse $l $all $union $intersect]

    trace add variable Apol_TE::vals(cp:classes_selected) write \
        [list Apol_TE::update_cp_tabname]
    trace add variable Apol_TE::vals(cp:perms_selected) write \
        [list Apol_TE::update_cp_tabname]
    trace add variable Apol_TE::enabled(cp:classes) write \
        [list Apol_TE::toggle_enable_cp classes]
    trace add variable Apol_TE::enabled(cp:perms) write \
        [list Apol_TE::toggle_enable_cp perms]
}

proc Apol_TE::toggle_enable_cp {prefix name1 name2 op} {
    variable vals
    variable widgets
    variable enabled
    if {$enabled(cp:${prefix})} {
        foreach w $widgets(cp:${prefix}_widgets) {
            $w configure -state normal
        }
        $widgets(cp:${prefix}) configure -bg white
    } else {
        foreach w $widgets(cp:${prefix}_widgets) {
            $w configure -state disabled
        }
        $widgets(cp:${prefix}) configure -bg $ApolTop::default_bg_color
    }
    # force a refresh of this tab's name
    set vals(cp:${prefix}_selected) $vals(cp:${prefix}_selected)
}

proc Apol_TE::maybe_enable_perms {} {
    variable vals
    variable enabled

    set avrule_set 0
    foreach x {allow neverallow auditallow dontaudit} {
        if {$vals(rs:$x)} {
            set avrule_set 1
            break
        }
    }
    if {$avrule_set} {
        set enabled(cp:perms) 1
    } else {
        set enabled(cp:perms) 0
    }
}

proc Apol_TE::toggle_perms_toshow {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(cp:perms_toshow) == "all"} {
        # don't change the list of permissions if there was a new
        # object class selection and the current radiobutton is all
        if {$op != "update"} {
            set vals(cp:perms) $Apol_Class_Perms::perms_list
            set vals(cp:perms_selected) {}
        }
    } elseif {$vals(cp:perms_toshow) == "union"} {
        set vals(cp:perms) {}
        set vals(cp:perms_selected) {}
        foreach class $vals(cp:classes_selected) {
            set vals(cp:perms) [lsort -unique -dictionary [concat $vals(cp:perms) [get_perms $class]]]
        }
    } else {  ;# intersection
        set vals(cp:perms) {}
        set vals(cp:perms_selected) {}
        set classes {}
        foreach i [$widgets(cp:classes) curselection] {
            lappend classes [$widgets(cp:classes) get $i]
        }
        if {$classes == {}} {
            return
        }
        set vals(cp:perms) [get_perms [lindex $classes 0]]
        foreach class [lrange $classes 1 end] {
            set this_perms [get_perms $class]
            set new_perms {}
            foreach p $vals(cp:perms) {
                if {[lsearch -exact $this_perms $p] >= 0} {
                    lappend new_perms $p
                }
            }
            set vals(cp:perms) $new_perms
        }
    }
}

# called whenever an item with a class/perm listbox is
# selected/deselected
proc Apol_TE::toggle_cp_select {col} {
    variable vals
    variable widgets
    set items {}
    foreach i [$widgets(cp:${col}) curselection] {
        lappend items [$widgets(cp:${col}) get $i]
    }
    set vals(cp:${col}_selected) $items
    if {$col == "classes"} {
        toggle_perms_toshow {} {} update
    }
}

# given a class name, return all of the permissions, both this class's
# and its common class
proc Apol_TE::get_perms {class} {
    foreach {class common perms} [lindex [apol_GetClasses $class] 0] {break}
    if {$common != {}} {
        foreach {common p classes} [lindex [apol_GetCommons $common] 0] {break}
        lsort -dictionary -unique [concat $perms $p]
    } else {
        lsort -dictionary $perms
    }
}

proc Apol_TE::clear_cp_listbox {lb prefix} {
    variable vals
    $lb selection clear 0 end
    set vals(cp:${prefix}_selected) {}
    if {$prefix == "classes"} {
        toggle_perms_toshow {} {} update
    }
}

proc Apol_TE::reverse_cp_listbox {lb} {
    variable vals
    set old_selection [$lb curselection]
    set items {}
    for {set i 0} {$i < [$lb index end]} {incr i} {
        if {[lsearch $old_selection $i] >= 0} {
            $lb selection clear $i
        } else {
            $lb selection set $i
            lappend items [$lb get $i]
        }
    }
    set vals(cp:perms_selected) $items
}

proc Apol_TE::update_cp_tabname {name1 name2 op} {
    variable vals
    variable widgets
    variable enabled
    if {($enabled(cp:classes) && $vals(cp:classes_selected) > 0) || \
            ($enabled(cp:perms) && $vals(cp:perms_selected) > 0)} {
            $widgets(search_opts) itemconfigure classperms -text "Classes/Permissions *"
    } else {
        $widgets(search_opts) itemconfigure classperms -text "Classes/Permissions"
    }
}

########################################################################

# -----------------------------------------------------------------------------
#  Command Apol_TE::delete_results
# -----------------------------------------------------------------------------
proc Apol_TE::delete_results {pageID} {
    variable widgets
    variable tabs

    # Remove tab and its widgets
    set curpos [$widgets(results) index $pageID]
    $widgets(results) delete $pageID
    array unset tabs $pageID:*
    array unset tabs $pageID

    # try to raise the next tab
    if {[set next_id [$widgets(results) pages $curpos]] != {}} {
        switch_to_tab $next_id
    } elseif {$curpos > 0} {
        # raise the previous page instead
        switch_to_tab [$widgets(results) pages [expr {$curpos - 1}]]
    } else {
        # no tabs remaining
        $widgets(update) configure -state disabled
    }
}

proc Apol_TE::display_rename_tab_dialog {pageID} {
    variable widgets
    variable tabs
    set d [Dialog .apol_te_tab_rename -homogeneous 1 -spacing 2 -cancel 1 \
               -default 0 -modal local -parent . -place center -separator 1 \
               -side bottom -title "Rename Results Tab"]
    $d add -text "OK" -command [list $d enddialog "ok"]
    $d add -text "Cancel" -command [list $d enddialog "cancel"]
    set f [$d getframe]
    set l [label $f.l -text "Tab name:"]
    set tabs(tab:new_name) [$widgets(results) itemcget $pageID -text]
    set e [entry $f.e -textvariable Apol_TE::tabs(tab:new_name) -width 16 -bg white]
    pack $l $e -side left -padx 2
    set retval [$d draw]
    destroy $d
    if {$retval == "ok"} {
        $widgets(results) itemconfigure $pageID -text $tabs(tab:new_name)
    }
}

proc Apol_TE::delete_current_results {} {
    variable widgets
    if {[set curid [$widgets(results) raise]] != {}} {
        delete_results $curid
    }
}

proc Apol_TE::create_new_results_tab {} {
    variable vals
    variable widgets
    variable tabs

    set i $tabs(next_result_id)
    incr tabs(next_result_id)
    set id "results$i"
    set frame [$widgets(results) insert end "$id" -text "Results $i"]
    $widgets(results) raise $id
    set tabs($id) [Apol_Widget::makeSearchResults $frame.results]
    pack $tabs($id) -expand 1 -fill both

    set tabs($id:vals) [array get vals]
    return $tabs($id)
}

proc Apol_TE::switch_to_tab {pageID} {
    variable vals
    variable widgets
    variable tabs

    # check if switching to already visible tab
    if {[$Apol_TE::widgets(results) raise] == $pageID} {
        return
    }
    $widgets(results) raise $pageID
    set cur_search_opts [$widgets(search_opts) raise]

    # restore the tab's search criteria
    array set tmp_vals $tabs($pageID:vals)
    set classes_selected $tmp_vals(cp:classes_selected)
    set perms_selected $tmp_vals(cp:perms_selected)
    array set vals $tabs($pageID:vals)
    reinitialize_search_widgets
    set vals(cp:classes_selected) $classes_selected
    set vals(cp:perms_selected) $perms_selected
    foreach c $classes_selected {
        $widgets(cp:classes) selection set [lsearch $vals(cp:classes) $c]
    }
    foreach p $perms_selected {
        $widgets(cp:perms) selection set [lsearch $vals(cp:perms) $p]
    }
    $widgets(search_opts) raise $cur_search_opts
}

########################################################################

proc Apol_TE::reset {} {
    variable enabled
    set old_classes_enabled $enabled(cp:classes)
    reinitialize_default_search_options
    reinitialize_search_widgets
    if {[set enabled(cp:classes) $old_classes_enabled]} {
        variable vals
        set vals(cp:classes) $Apol_Class_Perms::class_list
        set enabled(cp:classes) 1
        set enabled(cp:perms) 1
    }
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::search_terules
# -----------------------------------------------------------------------------

proc Apol_TE::search_terules {whichButton} {
    variable vals
    variable widgets
    variable enabled
    variable tabs

    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }

    # check search options
    if {$enabled(ta:use_source) && $vals(ta:use_source) && $vals(ta:source_sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No source type/attribute was selected."
        return
    }
    if {$enabled(ta:use_target) && $vals(ta:use_target) && $vals(ta:target_sym) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No target type/attribute was selected."
        return
    }
    if {$enabled(ta:use_default) && $vals(ta:use_default) && $vals(ta:default_sym) == {}} {

        tk_messageBox -icon error -type ok -title "Error" -message "No default type selected."
        return
    }

    set rule_selection {}
    foreach {key value} [array get vals rs:*] {
        if {$value} {
            lappend rule_selection [string range $key 3 end]
        }
    }
    if {$rule_selection == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "At least one rule must be selected."
            return
    }

    # gather other options
    set source_any 0
    if {$enabled(ta:use_source) && $vals(ta:use_source)} {
        if {$vals(ta:source_which) == "either"} {
            set source_any 1
        }
        set source [list $vals(ta:source_sym) $vals(ta:source_indirect)]
    } else {
        set source [list {} 0]
    }
    if {$enabled(ta:use_target) && $vals(ta:use_target)} {
        set target [list $vals(ta:target_sym) $vals(ta:target_indirect)]
    } else {
        set target [list {} 0]
    }
    if {$enabled(ta:use_default) && $vals(ta:use_default)} {
        set default [list $vals(ta:default_sym) 0]
    } else {
        set default [list {} 0]
    }
    if {$enabled(cp:classes)} {
        set classes $vals(cp:classes_selected)
    } else {
        set classes {}
    }
    if {$enabled(cp:perms)} {
        set perms $vals(cp:perms_selected)
    } else {
        set perms {}
    }
    set other_opts {}
    if {$vals(oo:enabled)} {
        lappend other_opts "only_enabled"
    }
    if {$source_any} {
        lappend other_opts "source_any"
    }
    if {$vals(oo:regexp)} {
        lappend other_opts "regex"
    }

    foreach x {new update reset} {
        $widgets($x) configure -state disabled
    }

    set tabs(searches_done) -1
    set tabs(searches_text) "Searching for TE Rules..."
    set last_focus [focus -lastfor .]
    ProgressDlg .terules_busy -title "TE Rules Search" \
        -type normal -stop {} -separator 1 -parent . -maximum 2 \
        -textvariable Apol_TE::tabs(searches_text) \
        -variable Apol_TE::tabs(searches_done)
    ApolTop::setBusyCursor
    update idletasks

    # run search here
    set retval [catch {apol_SearchTERules $rule_selection $other_opts \
                           $source $target $default $classes $perms} results]

    ApolTop::resetBusyCursor
    destroy .terules_busy
    focus $last_focus

    if {$retval} {
        tk_messageBox -icon error -type ok -title Error -message "Error searching TE rules:\n$results"
    } else {
        if {$whichButton == "new"} {
            set sr [create_new_results_tab]
        } else {
            set id [$widgets(results) raise]
            set tabs($id:vals) [array get vals]
            set sr $tabs($id)
            Apol_Widget::clearSearchResults $sr
        }
        set header "[llength $results] rule"
        if {[llength $results] != 1} {
            append header s
        }
        append header " match the search criteria.\n\n"
        Apol_Widget::appendSearchResultText $sr $header
        if {[ApolTop::is_binary_policy]} {
            foreach rule [lsort $results] {
                renderRule $sr $rule
            }
        } else {
            foreach rule $results {
                renderRule $sr $rule
            }
        }
    }

    foreach x {new reset} {
        $widgets($x) configure -state normal
    }
    if {[$widgets(results) pages] != {} || $retval == 0} {
        $widgets(update) configure -state normal
    }
}


proc Apol_TE::renderRule {sr rule} {
    foreach {rule_type source_set target_set class perm_default line_num cond_info} $rule {break}
    Apol_Widget::appendSearchResultLine $sr 0 $line_num $cond_info $rule_type "\{ $source_set \}" "\{ $target_set \}" : $class "\{ $perm_default \}"
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::load_query_options
# -----------------------------------------------------------------------------
proc Apol_TE::load_query_options {file_channel parentDlg} {
    variable vals
    variable widgets
    variable enabled
    reinitialize_default_search_options

    # load as many values as possible
    set classes_selected {}
    set perms_selected {}
    while {[gets $file_channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        if {$key == "cp:classes_selected"} {
            set classes_selected $value
        } elseif {$key == "cp:perms_selected"} {
            set perms_selected $value
        } else {
            set vals($key) $value
        }
    }

    # update the display
    reinitialize_search_widgets
    set vals(cp:classes) $Apol_Class_Perms::class_list
    set enabled(cp:classes) 1
    set enabled(cp:perms) 1
    toggle_perms_toshow -> -> reset

    # then verify that selected object classes and permissions exist
    # for this policy

    set unknowns {}
    set vals(cp:classes_selected) {}
    foreach class $classes_selected {
        if {[set i [lsearch $vals(cp:classes) $class]] >= 0} {
            $widgets(cp:classes) selection set $i
            lappend vals(cp:classes_selected) $class
        } else {
            lappend unknowns $class
        }
    }
    if {[llength $unknowns] > 0} {
        tk_messageBox -icon warning -type ok -title "Invalid Object Classes" \
            -message "The following object classes do not exist in the currently loaded policy and were ignored:\n\n[join $unknowns ", "]" \
            -parent $parentDlg
    }

    set unknowns {}
    set vals(cp:perms_selected) {}
    foreach perm $perms_selected {
        if {[set i [lsearch $vals(cp:perms) $perm]] >= 0} {
            $widgets(cp:perms) selection set $i
            lappend vals(cp:perms_selected) $perm
        } else {
            lappend unknowns $perm
        }
    }
    if {[llength $unknowns] > 0} {
        tk_messageBox -icon warning -type ok -title "Invalid Permissions" \
            -message "The following permissions do not exist in the currently loaded policy and were ignored:\n\n[join $unknowns ", "]" \
            -parent $parentDlg
    }
}

# -----------------------------------------------------------------------------
#  Command Apol_TE::save_query_options
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# -----------------------------------------------------------------------------
proc Apol_TE::save_query_options {file_channel query_file} {
    variable vals
    foreach {key value} [array get vals] {
        if {$key != "cp:classes" && $key != "cp:perms"} {
            puts $file_channel "$key $value"
        }
    }
}
