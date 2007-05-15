# Copyright (C) 2004-2007 Tresys Technology, LLC
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

namespace eval Apol_Cond_Bools {
    variable cond_bools_list {}
    variable cond_bools_defaults
    variable cond_bools_values
    variable opts
    variable widgets
}

proc Apol_Cond_Bools::search_bools {} {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    set name [string trim $opts(name)]
    if {$opts(enable_bool) && $name == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No boolean variable provided."
        return
    }

    set q [new_apol_bool_query_t]
    $q set_bool $::ApolTop::policy $name
    $q set_regex $::ApolTop::policy $opts(use_regexp)
    set v [$q run $::ApolTop::policy]
    $q -delete
    set bools_data [bool_vector_to_list $v]
    $v -delete
    
    set results {}
    set results "BOOLEANS:\n"
    if {[llength $bools_data] == 0} {
        append results "Search returned no results."
    } else {
        foreach b [lsort $bools_data] {
            append results "\n[renderBool $b $opts(show_default) $opts(show_current)]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Cond_Bools::renderBool {bool_name show_default show_current} {
    variable cond_bools_defaults
    set qpol_bool_datum [new_qpol_bool_t $::ApolTop::qpolicy $bool_name]
    set cur_state [$qpol_bool_datum get_state $::ApolTop::qpolicy]
    set text [format "%-28s" $bool_name]
    if {$show_default} {
        if {$cond_bools_defaults($bool_name)} {
            append text "  Default State: True "
        } else {
            append text "  Default State: False"
        }
    }
    if {$show_current} {
        if {$cur_state} {
            append text "  Current State: True "
        } else {
            append text "  Current State: False"
        }
    }
    return $text
}

proc Apol_Cond_Bools::reset_bools {} {
    variable cond_bools_defaults
    variable cond_bools_values

    # hopefully each of the traces associated with each boolean
    # triggers, causing the policy to be updated
    array set cond_bools_values [array get cond_bools_defaults]
}

proc Apol_Cond_Bools::set_bool_value {name1 name2 op} {
    variable cond_bools_values
    set qpol_bool_datum [new_qpol_bool_t $::ApolTop::qpolicy $name2]
    $qpol_bool_datum set_state $::ApolTop::qpolicy $cond_bools_values($name2)
}

proc Apol_Cond_Bools::insert_listbox_item {bool initial_state} {
    variable widgets
    variable cond_bools_values

    set cond_bools_values($bool) $initial_state
    set subf [$widgets(listbox) getframe]
    set rb_true [radiobutton $subf.t:$bool -bg white \
                     -variable Apol_Cond_Bools::cond_bools_values($bool) \
                     -value 1 -highlightthickness 0 -text "True"]
    set rb_false [radiobutton $subf.f:$bool -bg white \
                      -variable Apol_Cond_Bools::cond_bools_values($bool) \
                      -value 0 -highlightthickness 0 -text "False"]
    trace add variable Apol_Cond_Bools::cond_bools_values($bool) write \
        [list Apol_Cond_Bools::set_bool_value]
    set rb_label [label $subf.l:$bool -bg white -text "- $bool"]
    grid $rb_true $rb_false $rb_label -padx 2 -pady 5 -sticky w
}

proc Apol_Cond_Bools::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

proc Apol_Cond_Bools::open {ppath} {
    set q [new_apol_bool_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable cond_bools_list [lsort [bool_vector_to_list $v]]
    $v -delete

    variable cond_bools_defaults
    foreach bool $cond_bools_list {
        set b [new_qpol_bool_t $::ApolTop::qpolicy $bool]
        set cond_bools_defaults($bool) [$b get_state $::ApolTop::qpolicy]
        insert_listbox_item $bool $cond_bools_defaults($bool)
    }

    variable widgets
    $widgets(listbox) xview moveto 0
    $widgets(listbox) yview moveto 0
    $widgets(listbox) configure -areaheight 0 -areawidth 0
    $widgets(combo_box) configure -values $cond_bools_list
}

proc Apol_Cond_Bools::close {} {
    variable widgets
    variable cond_bools_list {}
    variable cond_bools_defaults
    variable cond_bools_values

    initializeVars
    $widgets(combo_box) configure -values {}
    # clean up bools listbox, then hide its scrollbars
    foreach w [winfo children [$widgets(listbox) getframe]] {
        destroy $w
    }
    [$widgets(listbox) getframe] configure -width 1 -height 1
    Apol_Widget::clearSearchResults $widgets(results)
    array unset cond_bools_defaults
    array unset cond_bools_values
}

proc Apol_Cond_Bools::initializeVars {} {
    variable opts
    array set opts {
        enable_bool 0
        name ""
        use_regexp 0

        show_default 1
        show_current 1
    }
}

proc Apol_Cond_Bools::create {tab_name nb} {
    variable opts
    variable widgets

    initializeVars

    # Layout frames
    set frame [$nb insert end $tab_name -text "Booleans"]
    set pw [PanedWindow $frame.pw -side top]
    set left_pane [$pw add -weight 0]
    set right_pane [$pw add -weight 1]
    pack $pw -expand 1 -fill both

    # Title frames
    set cond_bools_box [TitleFrame $left_pane.cond_bools_box -text "Booleans"]
    set s_optionsbox   [TitleFrame $right_pane.obox -text "Search Options"]
    set rslts_frame    [TitleFrame $right_pane.rbox -text "Search Results"]
    pack $cond_bools_box -expand 1 -fill both
    pack $s_optionsbox -padx 2 -fill x -expand 0
    pack $rslts_frame -padx 2 -fill both -expand yes

    # Booleans listbox widget
    set left_frame [$cond_bools_box getframe]
    set sw_b [ScrolledWindow $left_frame.sw -auto both]
    set widgets(listbox) [ScrollableFrame $sw_b.listbox -bg white -width 200]
    $sw_b setwidget $widgets(listbox)
    set button_defaults [button $left_frame.button_defaults \
                             -text "Reset to Policy Defaults" \
                             -command Apol_Cond_Bools::reset_bools]
    pack $sw_b -side top -expand 1 -fill both
    pack $button_defaults -side bottom -pady 2 -expand 0 -fill x

    # Search options subframes
    set ofm [$s_optionsbox getframe]
    set bool_frame [frame $ofm.bool]
    set show_frame [frame $ofm.show]
    pack $bool_frame $show_frame -side left -padx 4 -pady 2 -anchor nw

    set enable [checkbutton $bool_frame.enable \
                    -variable Apol_Cond_Bools::opts(enable_bool) \
                    -text "Boolean"]
    set widgets(combo_box) [ComboBox $bool_frame.combo_box \
                                -textvariable Apol_Cond_Bools::opts(name) \
                                -helptext "Type or select a boolean variable" \
                                -state disabled -entrybg white -autopost 1]
    set widgets(regexp) [checkbutton $bool_frame.regexp \
                             -text "Search using regular expression" \
                             -state disabled \
                             -variable Apol_Cond_Bools::opts(use_regexp)]
    trace add variable Apol_Cond_Bools::opts(enable_bool) write \
        [list Apol_Cond_Bools::toggleSearchBools]
    pack $enable -anchor w
    pack $widgets(combo_box) $widgets(regexp) -padx 4 -anchor nw -expand 0 -fill x

    set show_default [checkbutton $show_frame.show_default \
                           -variable Apol_Cond_Bools::opts(show_default) \
                          -text "Show default state"]
    set show_current [checkbutton $show_frame.show_current \
                        -variable Apol_Cond_Bools::opts(show_current) \
                        -text "Show current state"]
    pack $show_default $show_current -anchor w

    # Action Buttons
    set ok_button [button $ofm.ok -text "OK" -width 6 \
                       -command Apol_Cond_Bools::search_bools]
    pack $ok_button -side right -anchor ne -padx 5 -pady 5

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$rslts_frame getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Cond_Bools::toggleSearchBools {name1 name2 op} {
    variable opts
    variable widgets
    if {$opts(enable_bool)} {
        $widgets(combo_box) configure -state normal
        $widgets(regexp) configure -state normal
    } else {
        $widgets(combo_box) configure -state disabled
        $widgets(regexp) configure -state disabled
    }
}
