# This tab will allow searching of constrain and validatetrans constraint
# rules within the policy. The mls versions are also searched if an
# mls policy is loaded.
#
# This tab has been derived from the terules_tab.
#
# Author: Richard Haines richard_c_haines@btinternet.com
#
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

namespace eval Apol_Constraint {
    variable vals
    variable widgets
    variable tabs
    variable enabled

    variable opts
    variable constraint_list {}
    variable left_expr_list {}
    variable right_expr_list {}
    variable mls_enabled {0}
    variable match_right_type_names 0
    variable statement_count 0
}

proc Apol_Constraint::create {tab_name nb} {
    variable vals
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "Constraints"]
    set pw [PanedWindow $frame.pw -side left -weights extra]
    set topf [$pw add -weight 0]
    set bottomf [$pw add -weight 1]
    pack $pw -expand 1 -fill both

    # Major SubFrames:
    # rsbox - constrain selection
    # rbox - holds display window widgets
    # abox - action buttons
    set top_leftf [frame $topf.tl]
    set widgets(search_opts) [NoteBook $topf.nb]
    set abox [frame $topf.abox]
    pack $top_leftf -side left -expand 0 -fill y
    pack $widgets(search_opts) -side left -expand 1 -fill both -padx 10
    pack $abox -side right -fill y -padx 5
    set rsbox [TitleFrame $top_leftf.rsbox -text "Constraint Selection"]
    set rbox [TitleFrame $bottomf.rbox -text "Constraint Search Results"]
    pack $rsbox -side top -fill both -expand 1
    pack $rbox -expand yes -fill both -padx 2

    # Constraint selection subframe
    set fm_constraints [$rsbox getframe]
    set constrain [checkbutton $fm_constraints.constrain -text "constrain" \
                   -onvalue 1 -offvalue 0 \
                   -variable Apol_Constraint::vals(rs:constrain_enabled)]
    set mlsconstrain [checkbutton $fm_constraints.mlsconstrain -text "mlsconstrain" \
                        -onvalue 1 -offvalue 0 \
                        -variable Apol_Constraint::vals(rs:mlsconstrain_enabled)]
    set validatetrans [checkbutton $fm_constraints.validatetrans -text "validatetrans" \
                        -onvalue 1 -offvalue 0 \
                        -variable Apol_Constraint::vals(rs:validatetrans_enabled)]
    set mlsvalidatetrans [checkbutton $fm_constraints.mlsvalidatetrans -text "mlsvalidatetrans" \
                       -onvalue 1 -offvalue 0 \
                       -variable Apol_Constraint::vals(rs:mlsvalidatetrans_enabled)]
    grid $constrain -sticky w -padx 10
    grid $mlsconstrain -sticky w -padx 10
    grid $validatetrans -sticky w -padx 10 -pady {30 0}
    grid $mlsvalidatetrans -sticky w -padx 10

    _createClassesPermsTab
    _createLeftExpressionTab
    _createRightExpressionTab

    # Action buttons
    set widgets(new) [button $abox.new -text "New Search" -width 12 \
                       -command [list Apol_Constraint::_search_constraints new]]
    set widgets(update) [button $abox.update -text "Update Search" -width 12 -state disabled \
                             -command [list Apol_Constraint::_search_constraints update]]
    set widgets(reset) [button $abox.reset -text "Reset Criteria" -width 12 \
                            -command Apol_Constraint::_reset]
    pack $widgets(new) $widgets(update) $widgets(reset) \
        -side top -pady 5 -padx 5 -anchor ne

    $widgets(search_opts) compute_size

    # Popup menu widget
    set popupTab_Menu [menu .popup_constrain_rules -tearoff 0]
    set tab_menu_callbacks \
        [list {"Close Tab" Apol_Constraint::_delete_results} \
             {"Rename Tab" Apol_Constraint::_display_rename_tab_dialog}]

    # Notebook creation for results
    set widgets(results) [NoteBook [$rbox getframe].results]
    $widgets(results) bindtabs <Button-1> Apol_Constraint::_switch_to_tab
    $widgets(results) bindtabs <Button-3> \
        [list ApolTop::popup \
             %W %x %y $popupTab_Menu $tab_menu_callbacks]
    set close [button [$rbox getframe].close -text "Close Tab" \
                   -command Apol_Constraint::_delete_current_results]
    pack $widgets(results) -expand 1 -fill both -padx 4
    pack $close -expand 0 -fill x -padx 4 -pady 2

    _initializeVars
    return $frame
}


proc Apol_Constraint::open {ppath} {
    variable mls_enabled

    if {[ApolTop::is_capable "mls"]} {
        set mls_enabled 1
    } else {
        set mls_enabled 0
    }

    _initializeVars
    _initializeWidgets
    _initializeTabs

    variable vals
    variable enabled
    set vals(cp:classes) [Apol_Class_Perms::getClasses]
    set enabled(cp:classes) 1
    set enabled(cp:perms) 1
}


proc Apol_Constraint::close {} {
    _initializeTabs
    _initializeWidgets
    _initializeVars
    set enabled(cp:perms) 1

    variable constraint_list {}
    variable left_expr_list {}
    variable right_expr_list {}
}


proc Apol_Constraint::getTextWidget {} {
    variable widgets
    variable tabs

    if {[$widgets(results) pages] != {}} {
        set raisedPage [$widgets(results) raise]
        if {$raisedPage != {}} {
            return $tabs($raisedPage).tb
        }
    }
    return {}
}


proc Apol_Constraint::save_query_options {file_channel query_file} {
    variable vals

    foreach {key value} [array get vals] {
        if {$key != "cp:classes" && $key != "cp:perms"} {
            puts $file_channel "$key $value"
        }
    }
}


proc Apol_Constraint::load_query_options {file_channel} {
    variable vals
    variable widgets
    variable enabled
    _initializeVars

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
    _initializeWidgets
    set vals(cp:classes) [Apol_Class_Perms::getClasses]
    set enabled(cp:classes) 1
    set enabled(cp:perms) 1
    _toggle_perms_toshow -> -> reset

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
        tk_messageBox -icon warning -type ok -title "Open Apol Query" \
            -message "The following object classes do not exist in the currently loaded policy and were ignored:\n\n[join $unknowns ", "]" \
            -parent .
    }

    _toggle_perms_toshow {} {} {}
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
        tk_messageBox -icon warning -type ok -title "Open Apol Query" \
            -message "The following permissions do not exist in the currently loaded policy and were ignored:\n\n[join $unknowns ", "]" \
            -parent $parentDlg
    }
}


#### private functions below ####

proc Apol_Constraint::_initializeVars {} {
    variable vals
    variable mls_enabled

    array set vals [list \
                        rs:constrain_enabled 1 \
                        rs:mlsconstrain_enabled $mls_enabled  \
                        rs:validatetrans_enabled 1 \
                        rs:mlsvalidatetrans_enabled $mls_enabled  \

                        kta:left_expr,left_keyword 1 \
                        kta:right_expr,right_keyword 0 \
                        kta:right_expr,types 0 \
                        kta:right_expr,users 0 \
                        kta:right_expr,roles 0 \
                        kta:right_expr,attribs 0 \
                       ]

    array set vals {
        kta:use_left_expr 0
        kta:left_expr {}

        kta:use_right_expr 0
        kta:right_expr {}
        kta:right_expr_replace_types 0

        cp:classes {}
        cp:classes_selected {}
        cp:perms {}
        cp:perms_selected {}
        cp:perms_toshow all
        cp:perms_matchall 0
    }

    variable enabled
    array set enabled {
        kta:use_left_expr 1
        kta:use_right_expr 1

        cp:classes 0
        cp:perms 0
    }
}


proc Apol_Constraint::_initializeTabs {} {
    variable widgets
    variable tabs

    array set tabs {
        next_result_id 1
    }
    foreach p [$widgets(results) pages 0 end] {
        _delete_results $p
    }
}


proc Apol_Constraint::_initializeWidgets {} {
    variable widgets

    $widgets(search_opts) raise left_expr_entry
    $widgets(search_opts) raise right_expr_entry

    $widgets(cp:classes) selection clear 0 end
    $widgets(cp:perms) selection clear 0 end
}


proc Apol_Constraint::_createLeftExpressionTab {} {
    variable vals
    variable widgets
    variable enabled

    set ta_tab [$widgets(search_opts) insert end left_expr_entry -text "Left Side of Expression"]
    set fm_left_expr [frame $ta_tab.left_expr]
    grid $fm_left_expr -padx 4 -sticky ewns
    foreach i {0} {
        grid columnconfigure $ta_tab $i -weight 1 -uniform 1
    }
    grid rowconfigure $ta_tab 0 -weight 1
#                           prefix    frame        title  left_side right_side
    _create_expression_box left_expr $fm_left_expr "Keyword" 1 0

    $widgets(search_opts) raise left_expr_entry
}


proc Apol_Constraint::_createRightExpressionTab {} {
    variable vals
    variable widgets
    variable enabled

    set ta_tab [$widgets(search_opts) insert end right_expr_entry -text "Right Side of Expression"]
    set fm_right_expr [frame $ta_tab.right_expr]
    grid $fm_right_expr -padx 4 -sticky ewns
    foreach i {0} {
        grid columnconfigure $ta_tab $i -weight 1 -uniform 1
    }
    grid rowconfigure $ta_tab 0 -weight 1
#                          prefix      frame             title                          left_side right_side
    _create_expression_box right_expr $fm_right_expr "Select either a keyword, user, role, type or type attribute" 0 1

    $widgets(search_opts) raise right_expr_entry
}


proc Apol_Constraint::_create_expression_box {prefix f title left_expr right_expr} {
    variable vals
    variable widgets

    set widgets(kta:use_${prefix}) [checkbutton $f.use -text $title \
                                       -variable Apol_Constraint::vals(kta:use_${prefix})]
    pack $widgets(kta:use_${prefix}) -side top -anchor w
    trace add variable Apol_Constraint::vals(kta:use_${prefix}) write \
        [list Apol_Constraint::_toggle_expression_box $prefix]

    set w {}

    if {$right_expr} {
        set helptext "Select a keyword, user, role, type or type attribute for the right hand side of the constraint expression e.g.: \
\n    (left         right) \
\n    (t1    ==   mlstrustedobject) \
\n    (r1  dom  r2) \
\n    (r1    !=    system_r)\n \
\nIf a type or attribute is selected the \"Only direct matches\" box can be used to determine searching as follows:\n \
\n   - If selected the type or type attribute identifier will be used for the match.\n \
\n   - If unselected and a type is selected: \
\n         The type identifier will be used for matching, also any type attributes found within the constraints expression will \
\n         be expanded and its list of types searched for a match.\n \
\n   - If unselected and an attribute is selected: \
\n         The type attribute identifier will be used for matching, also any types found within the constraints expression will \
\n         have its associated type attributes searched for a match.\n"
    } else {
        set helptext "Select a keyword for the left hand side of the constraint expression e.g.: \
\n    (left     right)\n    (r1   ==   r2)"
    }

    set widgets(kta:${prefix}) [ComboBox $f.sym \
                                       -state disabled -entrybg $ApolTop::default_bg_color \
                                       -textvariable Apol_Constraint::vals(kta:${prefix}) \
                                       -helptext $helptext -autopost 1]
    pack $widgets(kta:${prefix}) -expand 0 -fill x -padx 8
    lappend w $widgets(kta:${prefix})

    if {$left_expr} {
        set ta_frame [frame $f.ta]
        pack $ta_frame -expand 0 -anchor center -pady 2
        trace add variable Apol_Constraint::vals(kta:${prefix},left_keyword) write \
            [list Apol_Constraint::_toggle_left_side $prefix]
        pack $widgets(kta:${prefix}) -expand 0 -fill x -padx 8
        lappend w $widgets(kta:${prefix})

    }

    if {$right_expr} {
        set ta_frame [frame $f.ta]
        pack $ta_frame -expand 0 -anchor w -pady 2
        set right_keyword [checkbutton $ta_frame.right_keyword -text "Keyword" -state disabled \
                       -onvalue 1 -offvalue 0 \
                       -variable Apol_Constraint::vals(kta:${prefix},right_keyword)]

        set users [checkbutton $ta_frame.users -text "Users" -state disabled \
                       -onvalue 1 -offvalue 0 \
                       -variable Apol_Constraint::vals(kta:${prefix},users)]

        set roles [checkbutton $ta_frame.roles -text "Roles" -state disabled \
                       -onvalue 1 -offvalue 0 \
                       -variable Apol_Constraint::vals(kta:${prefix},roles)]

        set types [checkbutton $ta_frame.types -text "Types" -state disabled \
                       -onvalue 1 -offvalue 0 \
                       -variable Apol_Constraint::vals(kta:${prefix},types)]
        set attribs [checkbutton $ta_frame.attribs -text "Attributes" -state disabled \
                         -onvalue 1 -offvalue 0 \
                         -variable Apol_Constraint::vals(kta:${prefix},attribs)]

        $right_keyword configure -command [list Apol_Constraint::_toggle_kta_pushed $prefix $right_keyword]
        $users configure -command [list Apol_Constraint::_toggle_kta_pushed $prefix $users]
        $roles configure -command [list Apol_Constraint::_toggle_kta_pushed $prefix $roles]
        $types configure -command [list Apol_Constraint::_toggle_kta_pushed $prefix $types]
        $attribs configure -command [list Apol_Constraint::_toggle_kta_pushed $prefix $attribs]

        trace add variable Apol_Constraint::vals(kta:${prefix},right_keyword) write \
            [list Apol_Constraint::_toggle_right_side $prefix]
        trace add variable Apol_Constraint::vals(kta:${prefix},users) write \
            [list Apol_Constraint::_toggle_right_side $prefix]
        trace add variable Apol_Constraint::vals(kta:${prefix},roles) write \
            [list Apol_Constraint::_toggle_right_side $prefix]
        trace add variable Apol_Constraint::vals(kta:${prefix},types) write \
            [list Apol_Constraint::_toggle_right_side $prefix]
        trace add variable Apol_Constraint::vals(kta:${prefix},attribs) write \
            [list Apol_Constraint::_toggle_right_side $prefix]

        pack $right_keyword $users $roles $types $attribs -side left -anchor w -padx 2
        lappend w $right_keyword $users $roles $types $attribs
    }

    set widgets(kta:${prefix}_widgets) $w
    trace add variable Apol_Constraint::enabled(kta:use_${prefix}) write \
        [list Apol_Constraint::_toggle_left_right_box $prefix]
}


# called when there is a change in state to the top checkbutton within
# an expression box
proc Apol_Constraint::_toggle_expression_box {col name1 name2 op} {
    variable enabled

    # force a refresh of this box's state; this invokes
    # _toggle_left_right_box callback
    set enabled(kta:use_${col}) $enabled(kta:use_${col})
}


# disallow keyword, types and attribs to be selected within a kta box
proc Apol_Constraint::_toggle_kta_pushed {col cb} {
    variable vals

    if {($vals(kta:${col},right_keyword) &&  $vals(kta:${col},attribs)) || \
        ($vals(kta:${col},right_keyword) && $vals(kta:${col},users)) || \
        ($vals(kta:${col},right_keyword) && $vals(kta:${col},roles)) || \
        ($vals(kta:${col},right_keyword) && $vals(kta:${col},types)) || \
        ($vals(kta:${col},attribs) && $vals(kta:${col},users)) || \
        ($vals(kta:${col},attribs) && $vals(kta:${col},roles)) || \
        ($vals(kta:${col},attribs) && $vals(kta:${col},types)) || \
        ($vals(kta:${col},users) && $vals(kta:${col},roles)) || \
        ($vals(kta:${col},users) && $vals(kta:${col},types)) || \
        ($vals(kta:${col},roles) && $vals(kta:${col},types)) } {
       tk_messageBox -icon error -type ok -title "Constraint Search" -message "Select either a keyword, user, role, type or type attribute."
        $cb deselect
        return
    }
}


# called whenever the left or right box is enabled or disabled
proc Apol_Constraint::_toggle_left_right_box {col name1 name2 op} {
    variable vals
    variable widgets
    variable enabled

    if {$enabled(kta:use_${col})} {
        $widgets(kta:use_${col}) configure -state normal
    } else {
        $widgets(kta:use_${col}) configure -state disabled
    }
    if {$enabled(kta:use_${col}) && $vals(kta:use_${col})} {
        foreach w $widgets(kta:${col}_widgets) {
            $w configure -state normal
        }
        $widgets(kta:${col}) configure -entrybg white
    } else {
        foreach w $widgets(kta:${col}_widgets) {
            $w configure -state disabled
        }
        $widgets(kta:${col}) configure -entrybg $ApolTop::default_bg_color
    }

    # update this tab's name if one of the columns is enabled and used
    if {($enabled(kta:use_left_expr) && $vals(kta:use_left_expr))} {
        $widgets(search_opts) itemconfigure left_expr_entry -text "Left Side of Expression *"
    } else {
        $widgets(search_opts) itemconfigure left_expr_entry -text "Left Side of Expression"
    }

    if {($enabled(kta:use_right_expr) && $vals(kta:use_right_expr))} {
        $widgets(search_opts) itemconfigure right_expr_entry -text "Right Side of Expression *"
    } else {
        $widgets(search_opts) itemconfigure right_expr_entry -text "Right Side of Expression"
    }
}


proc Apol_Constraint::_toggle_left_side {col name1 name2 op} {
    variable vals
    variable widgets

    set items {}

    if {$vals(kta:${col},left_keyword)} {
        append items [Apol_Constraint::getLeftKeyword]
    }
    $widgets(kta:${col}) configure -values $items
}


proc Apol_Constraint::_toggle_right_side {col name1 name2 op} {
    variable vals
    variable widgets

    set items {}

    if {$vals(kta:${col},right_keyword)} {
           append items [Apol_Constraint::getRightKeyword]
       }
    if {$vals(kta:${col},users)} {
           append items [Apol_Users::getUsers]
       }
    if {$vals(kta:${col},roles)} {
           append items [Apol_Roles::getRoles]
       }
    if {$vals(kta:${col},types)} {
           append items [Apol_Types::getTypes]
       }
    if {$vals(kta:${col},attribs)} {
           append items [Apol_Types::getAttributes]
    }

    $widgets(kta:${col}) configure -values $items
}


# Returns a list of left keywords
proc Apol_Constraint::getLeftKeyword {} {
    variable vals
    variable left_expr_list
    set left_expr_list {}

    if {[ApolTop::is_policy_open]} {
        if { $vals(rs:constrain_enabled) == 1 ||  $vals(rs:mlsconstrain_enabled) == 1 } {
            append left_expr_list [Apol_Constraint::_getKeywords "l" new_apol_constraint_query_t]
        }
        if { $vals(rs:validatetrans_enabled) == 1 || $vals(rs:mlsvalidatetrans_enabled) == 1 } {
            append left_expr_list [Apol_Constraint::_getKeywords "l" new_apol_validatetrans_query_t]
        }
        lsort -unique $left_expr_list
    } else {
        set left_expr_list ""
    }
}


# Returns a list of right keywords
proc Apol_Constraint::getRightKeyword {} {
    variable vals
    variable right_expr_list
    set right_expr_list {}

    if {[ApolTop::is_policy_open]} {
        if { $vals(rs:constrain_enabled) == 1 ||  $vals(rs:mlsconstrain_enabled) == 1 } {
            append right_expr_list [Apol_Constraint::_getKeywords "r" new_apol_constraint_query_t]
        }
        if { $vals(rs:validatetrans_enabled) == 1 || $vals(rs:mlsvalidatetrans_enabled) == 1 } {
            append right_expr_list [Apol_Constraint::_getKeywords "r" new_apol_validatetrans_query_t]
        }
        lsort -unique $right_expr_list
    } else {
        set right_expr_list ""
    }
}



# code to create and handle the classe/permissions subtab
proc Apol_Constraint::_createClassesPermsTab {} {
    variable vals
    variable widgets
    variable enabled

    set objects_tab [$widgets(search_opts) insert end classperms -text "Classes/Permissions"]
    set fm_objs [TitleFrame $objects_tab.objs -text "Object Classes"]
    set fm_perms [TitleFrame $objects_tab.perms -text "Permissions"]
    pack $fm_objs -side left -expand 0 -fill both -padx 2 -pady 2
    pack $fm_perms -side left -expand 1 -fill both -padx 2 -pady 2

    # object classes subframe
    set sw [ScrolledWindow [$fm_objs getframe].sw -auto both]
    set widgets(cp:classes) [listbox [$sw getframe].lb -height 5 -width 24 \
                                 -highlightthickness 0 -selectmode multiple \
                                 -exportselection 0 -state disabled \
                                 -bg $ApolTop::default_bg_color \
                                 -listvar Apol_Constraint::vals(cp:classes)]
    $sw setwidget $widgets(cp:classes)
    update
    grid propagate $sw 0
    bind $widgets(cp:classes) <<ListboxSelect>> \
        [list Apol_Constraint::_toggle_cp_select classes]
    pack $sw -expand 1 -fill both
    set clear [button [$fm_objs getframe].b -text "Clear" -width 6 -state disabled \
                   -command [list Apol_Constraint::_clear_cp_listbox $widgets(cp:classes) classes]]
    pack $clear -expand 0 -pady 2
    set widgets(cp:classes_widgets) [list $widgets(cp:classes) $clear]

    # permissions subframe
    set f [$fm_perms getframe]
    set sw [ScrolledWindow $f.sw -auto both]
    set widgets(cp:perms) [listbox [$sw getframe].lb -height 5 -width 24 \
                               -highlightthickness 0 -selectmode multiple \
                               -exportselection 0 -bg white \
                               -listvar Apol_Constraint::vals(cp:perms)]
    $sw setwidget $widgets(cp:perms)
    update
    grid propagate $sw 0
    bind $widgets(cp:perms) <<ListboxSelect>> \
        [list Apol_Constraint::_toggle_cp_select perms]
    set clear [button $f.clear -text "Clear" \
                   -command [list Apol_Constraint::_clear_cp_listbox $widgets(cp:perms) perms]]
    set reverse [button $f.reverse -text "Reverse" \
                     -command [list Apol_Constraint::_reverse_cp_listbox $widgets(cp:perms)]]
    set perm_opts_f [frame $f.perms]
    set perm_rb_f [frame $perm_opts_f.rb]
    set l [label $perm_rb_f.l -text "Permissions to show:" -state disabled]
    set all [radiobutton $perm_rb_f.all -text "All" \
                       -variable Apol_Constraint::vals(cp:perms_toshow) -value all]
    set union [radiobutton $perm_rb_f.union -text "All for selected classes" \
                       -variable Apol_Constraint::vals(cp:perms_toshow) -value union]
    set intersect [radiobutton $perm_rb_f.inter -text "Common to selected classes" \
                       -variable Apol_Constraint::vals(cp:perms_toshow) -value intersect]
    trace add variable Apol_Constraint::vals(cp:perms_toshow) write \
        Apol_Constraint::_toggle_perms_toshow
    pack $l $all $union $intersect -anchor w
    set all_perms [checkbutton $perm_opts_f.all -text "Constraint must have all selected permissions" \
                       -variable Apol_Constraint::vals(cp:perms_matchall)]
    pack $perm_rb_f $all_perms -anchor w -pady 4 -padx 4
    grid $sw - $perm_opts_f -sticky nsw
    grid $clear $reverse ^ -pady 2 -sticky ew
    grid columnconfigure $f 0 -weight 0 -uniform 1 -pad 2
    grid columnconfigure $f 1 -weight 0 -uniform 1 -pad 2
    grid columnconfigure $f 2 -weight 1
    grid rowconfigure $f 0 -weight 1
    set widgets(cp:perms_widgets) \
        [list $widgets(cp:perms) $clear $reverse $l $all $union $intersect $all_perms]

    trace add variable Apol_Constraint::vals(cp:classes_selected) write \
        [list Apol_Constraint::_update_cp_tabname]
    trace add variable Apol_Constraint::vals(cp:perms_selected) write \
        [list Apol_Constraint::_update_cp_tabname]
    trace add variable Apol_Constraint::enabled(cp:classes) write \
        [list Apol_Constraint::_toggle_enable_cp classes]
    trace add variable Apol_Constraint::enabled(cp:perms) write \
        [list Apol_Constraint::_toggle_enable_cp perms]
}


proc Apol_Constraint::_toggle_enable_cp {prefix name1 name2 op} {
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


proc Apol_Constraint::_toggle_perms_toshow {name1 name2 op} {
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
            set vals(cp:perms) [lsort -unique -dictionary [concat $vals(cp:perms) [Apol_Class_Perms::getPermsForClass $class]]]
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
        set vals(cp:perms) [Apol_Class_Perms::getPermsForClass [lindex $classes 0]]
        foreach class [lrange $classes 1 end] {
            set this_perms [Apol_Class_Perms::getPermsForClass $class]
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
proc Apol_Constraint::_toggle_cp_select {col} {
    variable vals
    variable widgets

    set items {}
    foreach i [$widgets(cp:${col}) curselection] {
        lappend items [$widgets(cp:${col}) get $i]
    }
    set vals(cp:${col}_selected) $items
    if {$col == "classes"} {
        _toggle_perms_toshow {} {} update
    }
}


proc Apol_Constraint::_clear_cp_listbox {lb prefix} {
    variable vals

    $lb selection clear 0 end
    set vals(cp:${prefix}_selected) {}
    if {$prefix == "classes"} {
        _toggle_perms_toshow {} {} update
    }
}


proc Apol_Constraint::_reverse_cp_listbox {lb} {
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


proc Apol_Constraint::_update_cp_tabname {name1 name2 op} {
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


proc Apol_Constraint::_delete_results {pageID} {
    variable widgets
    variable tabs

    # Remove tab and its widgets
    set curpos [$widgets(results) index $pageID]
    $widgets(results) delete $pageID
    array unset tabs $pageID:*
    array unset tabs $pageID

    # try to raise the next tab
    if {[set next_id [$widgets(results) pages $curpos]] != {}} {
        _switch_to_tab $next_id
    } elseif {$curpos > 0} {
        # raise the previous page instead
        _switch_to_tab [$widgets(results) pages [expr {$curpos - 1}]]
    } else {
        # no tabs remaining
        $widgets(update) configure -state disabled
    }
}


proc Apol_Constraint::_display_rename_tab_dialog {pageID} {
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
    set e [entry $f.e -textvariable Apol_Constraint::tabs(tab:new_name) -width 16 -bg white]
    pack $l $e -side left -padx 2
    set retval [$d draw]
    destroy $d
    if {$retval == "ok"} {
        $widgets(results) itemconfigure $pageID -text $tabs(tab:new_name)
    }
}


proc Apol_Constraint::_delete_current_results {} {
    variable widgets

    if {[set curid [$widgets(results) raise]] != {}} {
        _delete_results $curid
    }
}


proc Apol_Constraint::_create_new_results_tab {} {
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


proc Apol_Constraint::_switch_to_tab {pageID} {
    variable vals
    variable widgets
    variable tabs

    # check if switching to already visible tab
    if {[$Apol_Constraint::widgets(results) raise] == $pageID} {
        return
    }
    $widgets(results) raise $pageID
    set cur_search_opts [$widgets(search_opts) raise]

    # restore the tab's search criteria
    array set tmp_vals $tabs($pageID:vals)
    set classes_selected $tmp_vals(cp:classes_selected)
    set perms_selected $tmp_vals(cp:perms_selected)
    array set vals $tabs($pageID:vals)
    _initializeWidgets
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


proc Apol_Constraint::_reset {} {
    variable enabled

    set old_classes_enabled $enabled(cp:classes)
    _initializeVars
    _initializeWidgets
    if {[set enabled(cp:classes) $old_classes_enabled]} {
        variable vals
        set vals(cp:classes) [Apol_Class_Perms::getClasses]
        set enabled(cp:classes) 1
        set enabled(cp:perms) 1
    }
}

# This is the main constraint search option
proc Apol_Constraint::_search_constraints {whichButton} {
    variable vals
    variable widgets
    variable enabled
    variable tabs
    variable statement_count

    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Constraint Search" \
            -message "No current policy file is opened."
        return
    }

    if { $vals(rs:constrain_enabled) == 0 && \
        $vals(rs:mlsconstrain_enabled) == 0 && \
        $vals(rs:validatetrans_enabled) == 0 && \
        $vals(rs:mlsvalidatetrans_enabled) == 0 } {
        tk_messageBox -icon error -type ok -title "Constraint Search" \
            -message "At least one constraint must be selected."
        return
    }

    if {$whichButton == "new"} {
        set sr [_create_new_results_tab]
    } else {
        set id [$widgets(results) raise]
        set tabs($id:vals) [array get vals]
        set sr $tabs($id)
        Apol_Widget::clearSearchResults $sr
    }

    if {$enabled(kta:use_left_expr) && $vals(kta:use_left_expr) && $vals(kta:left_expr) == {}} {
        tk_messageBox -icon error -type ok -title "Constraint Search" -message "No left keyword has been selected."
        return
    }
    if {$enabled(kta:use_right_expr) && $vals(kta:use_right_expr) && $vals(kta:right_expr) == {}} {
        tk_messageBox -icon error -type ok -title "Constraint Search" -message "No right keyword, type or attribute has been selected."
        return
    }

    set results {}
    set header {}

    # Check if the statements are enabled for mls/constrain and then get info
    if { $vals(rs:constrain_enabled) == 1 } {
        append results [Apol_Constraint::_searchForMatch "constrain" "constrain" new_apol_constraint_query_t]
        append header "$statement_count constrain rules match the search criteria.\n"
    }
    if { $vals(rs:mlsconstrain_enabled) == 1 } {
        append results [Apol_Constraint::_searchForMatch "mlsconstrain" "constrain" new_apol_constraint_query_t]
        append header "$statement_count mlsconstrain rules match the search criteria.\n"
    }

    # Check if the statements are enabled for mls/validatetrans and then get info
    if { $vals(rs:validatetrans_enabled) == 1 } {
        append results [Apol_Constraint::_searchForMatch "validatetrans" "validatetrans" new_apol_validatetrans_query_t]
        append header "$statement_count validatetrans rules match the search criteria.\n"
    }
    if { $vals(rs:mlsvalidatetrans_enabled) == 1 } {
        append results [Apol_Constraint::_searchForMatch "mlsvalidatetrans" "validatetrans" new_apol_validatetrans_query_t]
        append header "$statement_count mlsvalidatetrans match the search criteria.\n"
    }

    foreach x {new update reset} {
        $widgets($x) configure -state disabled
    }

    Apol_Progress_Dialog::wait "Constraint Rules" "Searching rules" {
        Apol_Widget::appendSearchResultText $sr "$header\n"
        Apol_Widget::appendSearchResultText $sr $results
    }

    $widgets(new) configure -state normal
    $widgets(reset) configure -state normal
    if {[$widgets(results) pages] != {} || $retval == 0} {
        $widgets(update) configure -state normal
    }
    return
}


# Start here to process constraints
proc Apol_Constraint::_searchForMatch {statement family command} {
    variable vals
    variable widgets
    variable enabled
    variable match_right_type_names
    variable statement_count

    set statement_count 0
    set entries {}

    set q [$command]
    # This reads in the constraint info
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete

    # This loop will process each constraint in the policy
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set constrain_type {}
        set perm_list {}
        set class_list {}
        set expr_type {}
        set op {}
        set sym_type {}

        # These are used to check if the search criteria has been met when
        # the left or right expression info has been set.
        set match_left_keyword_names 0
        set match_left_keyword_attr 0
        set match_right_keyword_attr 0
        set match_right_type_names 0

        set q [qpol_constraint_from_void [$v get_element $i]]

        # Find if this is an mls rule or not
        set x [$q get_expr_iter $::ApolTop::qpolicy]
        while {![$x end]} {
            foreach t [iter_to_list $x] {
                set t [qpol_constraint_expr_node_from_void $t]
                # Get Symbol type and save it
                set sym_type [$t get_sym_type $::ApolTop::qpolicy]
                if { $sym_type >= $::QPOL_CEXPR_SYM_L1L2 } {
                    set constrain_type "mls"
                    break
                }
            }
        }
        append constrain_type $family
        $x -acquire
        $x -delete

        # Check if the statement is the requested type
        if { $statement != $constrain_type } {
            continue
        }

        # This gets the class name
        set match_class 0
        append class_list "\{ "
        set class_name [[$q get_class $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
        append class_list $class_name
        append class_list " \}"

        # Check if class selected
        if {($enabled(cp:classes) && $vals(cp:classes_selected) > 0)} {
             foreach c $vals(cp:classes_selected) {
                if { $c == $class_name } {
                    set match_class 1
                }
            }
        }
        # Skip this constraint if it does not match criteria
        if {($match_class == 0 && $vals(cp:classes_selected) > 0)} {
            continue
        }

        # validatetrans does not use permissions
        if { $family == "constrain" } {
            # This gets perm list:
            set x [$q get_perm_iter $::ApolTop::qpolicy]
             set match_perm 0
            append perm_list "\{ "
            foreach perm [iter_to_str_list $x] {
                append perm_list "$perm "
                # Check if perm selected
                if {($enabled(cp:perms) && $vals(cp:perms_selected) > 0)} {
                        foreach c $vals(cp:perms_selected) {
                        if { $c == $perm } {
                            set match_perm 1
                        }
                    }
                }
            }
            # Skip this constraint as it does not match criteria
            if {($match_perm == 0 && $vals(cp:perms_selected) > 0)} {
                continue
            }
            append perm_list "\}"
            $x -acquire
            $x -delete
        }

        # This get expressions
        set x [$q get_expr_iter $::ApolTop::qpolicy]

        # This contains the number of constraint expr's processed.
        set constraint_expr_counter 0
        # This is the constraint_expr buffer that is indexed by the
        # $constraint_expr_counter
        set array constraint_expr_buf($constraint_expr_counter)
        array unset constraint_expr_buf

        # This loop will process each part of the expression consisting of:
        #    Operators: !, &&, ||. The ! applies only to an operand.
        #    Operands/expressions such as: (r1 == r2), (t1 != name)
        while {![$x end]} {
            foreach t [iter_to_list $x] {
                set t [qpol_constraint_expr_node_from_void $t]

                # Get Operator and save it
                set op [$t get_op $::ApolTop::qpolicy]

                # Get Symbol type and save it
                set sym_type [$t get_sym_type $::ApolTop::qpolicy]

                # Get expression and save it
                set expr_type [$t get_expr_type $::ApolTop::qpolicy]

                # Now check expression for entry type !, && or ||.
                # These are the operators between constraint expressions
                if { $expr_type == $::QPOL_CEXPR_TYPE_NOT } {
                    set constraint_expr_counter [expr $constraint_expr_counter + 1]
                    append constraint_expr_buf($constraint_expr_counter) "not"
                }

                if { $expr_type == $::QPOL_CEXPR_TYPE_AND } {
                    set constraint_expr_counter [expr $constraint_expr_counter + 1]
                    append constraint_expr_buf($constraint_expr_counter) "and"
                }

                if { $expr_type == $::QPOL_CEXPR_TYPE_OR } {
                    set constraint_expr_counter [expr $constraint_expr_counter + 1]
                    append constraint_expr_buf($constraint_expr_counter) "or"
                }

                # If the expression is TYPE_ATTR then it's form is (t1 == t2)
                if { $expr_type == $::QPOL_CEXPR_TYPE_ATTR } {
                    set constraint_expr_counter [expr $constraint_expr_counter + 1]

                    # Get the symbol name, this will be used twice, once
                    # to retrieve the string name for source entry, then
                    # the string name for the target entry.
                    set sym_name [Apol_Constraint::_getSym $sym_type]
                    append constraint_expr_buf($constraint_expr_counter) "( $sym_name "

                    # Check if keyword selected
                    if {$vals(kta:use_left_expr) == 1 && $vals(kta:left_expr) == $sym_name} {
                        set match_left_keyword_attr 1
                    }

                    # Get the operator and change to "eq" if required
                    set op [$t get_op $::ApolTop::qpolicy]
                    set op_name [Apol_Constraint::_getOp $op]
                    if { $op_name == "==" && \
                            ([string compare -length 1 $sym_name "r"] == 0 || \
                            [string compare -length 1 $sym_name "l"] == 0 || \
                            [string compare -length 1 $sym_name "h"] == 0) } {
                        set op_name "eq"
                    }
                    append constraint_expr_buf($constraint_expr_counter) $op_name

                    # Then using the sym_name again, get the target entry.
                    set sym_type [expr $sym_type | $::QPOL_CEXPR_SYM_TARGET]
                    set sym_name [Apol_Constraint::_getSym $sym_type]
                    append constraint_expr_buf($constraint_expr_counter) " $sym_name )"

                    # Check if keyword selected
                    if {$vals(kta:use_right_expr) == 1 && \
                                $vals(kta:right_expr) == $sym_name && \
                                $vals(kta:right_expr,right_keyword) == 1} {
                        set match_right_keyword_attr 1
                    }
                }

                # If the expression is TYPE_NAMES then expand the source
                # types or attributes using 'get_names_iter'
                # Example entries: ( t1 == mlstrustedobject )
                #                  ( t1 != { unconfined_t init_t } )
                # Note that if an attribute has been selected it could be
                # an empty_set.
                if { $expr_type == $::QPOL_CEXPR_TYPE_NAMES } {
                    set constraint_expr_counter [expr $constraint_expr_counter + 1]

                    # Get the symbol name, this is only used once to
                    # to retrieve the string name for source entry.
                    set sym_name [Apol_Constraint::_getSym $sym_type]
                    append constraint_expr_buf($constraint_expr_counter) "( $sym_name "

                    # Check if keyword selected
                    if {$vals(kta:use_left_expr) == 1 && \
                                $vals(kta:left_expr) == $sym_name} {
                        set match_left_keyword_names 1
                    }

                    set op [$t get_op $::ApolTop::qpolicy]
                    set op_name [Apol_Constraint::_getOp $op]
                    append constraint_expr_buf($constraint_expr_counter) $op_name

                    # Need to get the number of entries. These can be
                    # type or attribute identifiers.
                    set tmp_list {}
                    set return_list {}
                    set n [$t get_names_iter $::ApolTop::qpolicy]
                    set n_size [[$t get_names_iter $::ApolTop::qpolicy] get_size]

                    # If > 0 then put entries in a tmp_list for later processing.
                    if { $n_size > 0 } {
                        foreach name [iter_to_str_list $n] {
                            append tmp_list "$name "
                        }
                        #
                        # Now check search parameters for the $name entries of
                        # the right side of the expression. The $tmp_list can
                        # contain user, role, type or type attribute names
                        # depending on the initial letter of $sym_name.
                        #
                        if { ([string compare -length 1 $sym_name "t"] == 0 && \
                                $vals(kta:use_right_expr) == 1) && \
                                ($vals(kta:right_expr,types) == 1 || \
                                $vals(kta:right_expr,attribs) == 1) } {
                            # This calls type and attribute processing:
                            set tmp_list [Apol_Constraint::_process_TA $vals(kta:right_expr) $tmp_list]
                        } elseif { ($vals(kta:use_right_expr) == 1 && \
                                    $vals(kta:right_expr,roles) == 1 && \
                                    [string compare -length 1 $sym_name "r"] == 0) || \
                                    ($vals(kta:use_right_expr) == 1 && \
                                    $vals(kta:right_expr,users) == 1 && \
                                    [string compare -length 1 $sym_name "u"] == 0) } {
                            foreach c $tmp_list {
                                if { $c == $vals(kta:right_expr) } {
                                    set  match_right_type_names 1
                                    set tmp_list $name
                                    continue
                                }
                            }
                        }
                    # else if size == 0 then just say an empty set. Also
                    # check if the requested attribute is an empty set.
                    } elseif { $n_size == 0 } {
                        set tmp_list "<empty_set>"
                        if { [Apol_Constraint::_checkIfEmptyAttr $vals(kta:right_expr)] && \
                                [string compare -length 1 $sym_name "t"] == 0 } {
                            set  match_right_type_names 1
                        }
                    }

                    # Copy tmp_list to the constraint buffer.
                    if { [llength $tmp_list] > 1 } {
                        append constraint_expr_buf($constraint_expr_counter) " \{ $tmp_list\} )"
                    } else {
                        append constraint_expr_buf($constraint_expr_counter) " $tmp_list )"
                    }
                    $n -acquire
                    $n -delete
                }
            }
        }
        $x -acquire
        $x -delete
        # Done with processing all the expressions, now check if they
        # were enabled or not and valid search entries found.
        if {($vals(kta:use_left_expr) == 1 && $vals(kta:use_right_expr) == 1) && \
                [expr (($match_left_keyword_names | $match_left_keyword_attr) & \
                ($match_right_keyword_attr | $match_right_type_names))] == 0} {
            continue
        }

        if {($vals(kta:use_left_expr) == 1 && $vals(kta:use_right_expr) == 0) && \
                [expr $match_left_keyword_names | $match_left_keyword_attr] == 0} {
            continue
        }

        if {($vals(kta:use_left_expr) == 0 && $vals(kta:use_right_expr) == 1) && \
                ($vals(kta:right_expr,users) == 1 || \
                $vals(kta:right_expr,roles) == 1 || \
                $vals(kta:right_expr,attribs) == 1 || \
                $vals(kta:right_expr,types) == 1 || \
                $vals(kta:right_expr,right_keyword) == 1) && \
                [expr $match_right_type_names | $match_right_keyword_attr ] == 0} {
             continue
        }

        #
        # This takes each entry in the RPN formatted constraint_expr_buf and
        # converts to infix format that resembles the constraint string in
        # policy language format. It is a modified version from:
        #    http://rosettacode.org/wiki/Parsing/RPN_to_infix_conversion
        #
        set stack {}
        foreach entry [lsort -integer [array names constraint_expr_buf]] {
            set token $constraint_expr_buf($entry)
            switch $token {
                "not" - "and" - "or" {
                    lassign [Apol_Constraint::_pop stack] expr2rec expr2
                    # The ! is not treated the same as && || as it only
                    # applies to a single expression i.e. !(expression)
                    # So just pop the stack and add the !. Should there be
                    # another ! in the expression, then add brackets.
                    if { $token == "not" } {
                        set ans [string compare -length 1 $expr2 "not"]
                        if { $ans == 0 } {
                            lappend stack [list 1 "$token \($expr2\)"]
                        } else {
                            lappend stack [list 1 "$token$expr2"]
                        }
                        continue
                    } else {
                        lassign [Apol_Constraint::_pop stack] expr1rec expr1
                        lappend stack [list 1 "$expr1 $token $expr2"]
                    }
                }
                default {
                    lappend stack [list 2 $token]
                }
            }
        }
        if { [array size constraint_expr_buf] == 1 } {
            set expression "[lindex $stack end 1];"
        } else {
            set expression "([lindex $stack end 1]);"
        }
        set statement_count [expr $statement_count + 1]
        append entries "$constrain_type $class_list $perm_list\n    $expression\n\n"
    }
    return $entries
}

######### End of search routine - Start supporting procs ################

# The pop stack routine for RPN conversion
proc Apol_Constraint::_pop {stk} {
    upvar 1 $stk s
    set val [lindex $s end]
    set s [lreplace $s end end]
    return $val
}


# Take an attribute name and expands it to a list of types.
proc Apol_Constraint::_renderAttrib {attrib_name} {
    set type_list {}
    set qpol_type_datum [new_qpol_type_t $::ApolTop::qpolicy $attrib_name]
    set i [$qpol_type_datum get_type_iter $::ApolTop::qpolicy]
    foreach t [iter_to_list $i] {
        set t [qpol_type_from_void $t]
        lappend type_list [$t get_name $::ApolTop::qpolicy]
    }
    if { $type_list == "" } {
        lappend type_list "<empty_set>"
    }
    $i -acquire
    $i -delete
    return $type_list
}


# This will return a list of attributes linked to the type_name
proc Apol_Constraint::_renderType {type_name} {
    set qpol_type_datum [new_qpol_type_t $::ApolTop::qpolicy $type_name]
    set aliases {}
    set attribs {}

    set i [$qpol_type_datum get_alias_iter $::ApolTop::qpolicy]
    set aliases [iter_to_str_list $i]
    $i -acquire
    $i -delete

    set i [$qpol_type_datum get_attr_iter $::ApolTop::qpolicy]
    foreach a [iter_to_list $i] {
        set a [qpol_type_from_void $a]
        lappend attribs [$a get_name $::ApolTop::qpolicy]
    }
    $i -acquire
    $i -delete
    return $attribs
}


# Check if the name is a type or attribute.
proc Apol_Constraint::_checkTypeOrAttr {name} {
    set type_list {}

    set qpol_type_datum [new_qpol_type_t $::ApolTop::qpolicy $name]
    set x [$qpol_type_datum get_isattr $::ApolTop::qpolicy ]
    if { $x == 1 } {
        return "attribute"
    } else {
        return "type"
    }
    $x -acquire
    $x -delete
}


# Return Left or Right expr keywords
proc Apol_Constraint::_getKeywords {side command} {
    set list {}
    set left_list {}
    set right_list {}

    set q [$command]
    # This reads in the constraint info
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete

    # This loop will process each constraint in the policy
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set expr_type {}
        set sym_type {}
        set q [qpol_constraint_from_void [$v get_element $i]]

        # This get expressions
        set x [$q get_expr_iter $::ApolTop::qpolicy]
        while {![$x end]} {
            foreach t [iter_to_list $x] {
                set t [qpol_constraint_expr_node_from_void $t]
                set sym_type [$t get_sym_type $::ApolTop::qpolicy]
                set expr_type [$t get_expr_type $::ApolTop::qpolicy]

                if { $expr_type == $::QPOL_CEXPR_TYPE_ATTR } {
                    set sym_name [Apol_Constraint::_getSym $sym_type]
                    append left_list "$sym_name "
                    # Then using the sym_name again, get the target entry.
                    set sym_type [expr $sym_type | $::QPOL_CEXPR_SYM_TARGET]
                    set sym_name [Apol_Constraint::_getSym $sym_type]
                    append right_list "$sym_name "
                }

                if { $expr_type == $::QPOL_CEXPR_TYPE_NAMES } {
                    set sym_name [Apol_Constraint::_getSym $sym_type]
                    append left_list "$sym_name "
                }
            }
        }
        $x -acquire
        $x -delete

        if {$side == "l"} {
            append list $left_list
        } else {
            append list $right_list
        }
    }
    $v -acquire
    $v -delete
    return $list
}


# Here because a type or type_attribute search has been actioned
proc Apol_Constraint::_process_TA {name search_list} {
    variable match_right_type_names
    variable vals

    foreach ta $search_list {
        if { $ta == $name } {
            set match_right_type_names 1
            return $search_list
        }
    }
    return $search_list
}


# Get symbol from expression
proc Apol_Constraint::_getSym {sym_type} {
    set symbol {}

    # These are source for mls/constrain and old for mls/validatetrans
    if { $sym_type == $::QPOL_CEXPR_SYM_USER } {
        append symbol  "u1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_ROLE } {
        append symbol  "r1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_TYPE } {
        append symbol  "t1"
    }

    # These are target for mls/constrain and new for mls/validatetrans
    if { $sym_type == $::QPOL_CEXPR_SYM_USER+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "u2"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_ROLE+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "r2"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_TYPE+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "t2"
    }
    # These are source for mls/validatetrans
    if { $sym_type == $::QPOL_CEXPR_SYM_USER+$::QPOL_CEXPR_SYM_XTARGET } {
        append symbol  "u3"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_ROLE+$::QPOL_CEXPR_SYM_XTARGET } {
        append symbol  "r3"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_TYPE+$::QPOL_CEXPR_SYM_XTARGET } {
        append symbol  "t3"
    }

    # Source levels for mlsconstrain and mlsvalidatetrans
    if { $sym_type == $::QPOL_CEXPR_SYM_L1L2 } {
        append symbol  "l1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_L1H2 } {
        append symbol  "l1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_H1L2 } {
        append symbol  "h1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_H1H2 } {
        append symbol  "h1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_L1H1 } {
        append symbol  "l1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_L2H2 } {
        append symbol  "l2"
    }

    # Target levels for mlsconstrain and mlsvalidatetrans
    if { $sym_type == $::QPOL_CEXPR_SYM_L1L2+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "l2"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_L1H2+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "h2"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_H1L2+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "l2"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_H1H2+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "h2"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_L1H1+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "h1"
    }
    if { $sym_type == $::QPOL_CEXPR_SYM_L2H2+$::QPOL_CEXPR_SYM_TARGET } {
        append symbol  "h2"
    }
    if { $symbol == "" } {
        append symbol "err_sym_missing"
    }
    return $symbol
}


# Get Operator
proc Apol_Constraint::_getOp {op} {
    set entry {}

	if { $op == $::QPOL_CEXPR_OP_EQ } {
		append entry "=="
	}
	if { $op == $::QPOL_CEXPR_OP_NEQ } {
		append entry "!="
	}
	if { $op == $::QPOL_CEXPR_OP_DOM } {
		append entry "dom"
	}
	if { $op == $::QPOL_CEXPR_OP_DOMBY } {
		append entry "domby"
	}
	if { $op == $::QPOL_CEXPR_OP_INCOMP } {
		append entry "incomp"
	}
	if { $entry == "" } {
		append entry "op_missing"
	}
    return $entry
}

