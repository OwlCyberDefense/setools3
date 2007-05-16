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

namespace eval Apol_Cond_Rules {
    variable vals
    variable widgets
}

proc Apol_Cond_Rules::create {tab_name nb} {
    variable vals
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "Conditional Expressions"]
    set topf [frame $frame.top]
    set bottomf [frame $frame.bottom]
    pack $topf -expand 0 -fill both -pady 2
    pack $bottomf -expand 1 -fill both -pady 2

    set rules_box [TitleFrame $topf.rules_box -text "Rule Selection"]
    set obox [TitleFrame $topf.obox -text "Search Options"]
    set dbox [TitleFrame $bottomf.dbox -text "Conditional Expressions Display"]
    pack $rules_box -side left -expand 0 -fill both -padx 2
    pack $obox -side left -expand 1 -fill both -padx 2
    pack $dbox -expand 1 -fill both -padx 2

    # Rule selection subframe
    set fm_rules [$rules_box getframe]
    set allow [checkbutton $fm_rules.allow -text "allow" \
                   -variable Apol_Cond_Rules::vals(rs:allow)]
    set auditallow [checkbutton $fm_rules.auditallow -text "auditallow" \
                        -variable Apol_Cond_Rules::vals(rs:auditallow)]
    set dontaudit [checkbutton $fm_rules.dontaudit -text "dontaudit" \
                       -variable Apol_Cond_Rules::vals(rs:dontaudit)]
    set type_transition [checkbutton $fm_rules.type_transition -text "type_trans" \
                             -variable Apol_Cond_Rules::vals(rs:type_transition)]
    set type_member [checkbutton $fm_rules.type_member -text "type_member" \
                         -variable Apol_Cond_Rules::vals(rs:type_member)]
    set type_change [checkbutton $fm_rules.type_change -text "type_change" \
                         -variable Apol_Cond_Rules::vals(rs:type_change)]
    grid $allow $type_transition -sticky w -padx 2
    grid $auditallow $type_member -sticky w -padx 2
    grid $dontaudit $type_change -sticky w -padx 2

    # Search options subframes
    set ofm [$obox getframe]
    set bool_frame [frame $ofm.bool]
    pack $bool_frame -side left -padx 4 -pady 2 -anchor nw
    set enable [checkbutton $bool_frame.enable \
                    -variable Apol_Cond_Rules::vals(enable_bool) \
                    -text "Boolean"]
    set widgets(combo_box) [ComboBox $bool_frame.combo_box \
                                -textvariable Apol_Cond_Rules::vals(name) \
                                -helptext "Type or select a boolean variable" \
                                -state disabled -entrybg white -autopost 1]
    set widgets(regexp) [checkbutton $bool_frame.regexp \
                             -text "Search using regular expression" \
                             -state disabled \
                             -variable Apol_Cond_Rules::vals(use_regexp)]
    trace add variable Apol_Cond_Rules::vals(enable_bool) write \
        [list Apol_Cond_Rules::_toggleSearchBools]
    pack $enable -anchor w
    pack $widgets(combo_box) $widgets(regexp) -padx 4 -anchor nw -expand 0 -fill x

    set ok_button [button $ofm.ok -text OK -width 6 \
                       -command Apol_Cond_Rules::_search]
    pack $ok_button -side right -anchor ne -padx 5 -pady 5

    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Cond_Rules::open {ppath} {
    variable widgets
    $widgets(combo_box) configure -values [Apol_Cond_Bools::getBooleans]
}

proc Apol_Cond_Rules::close {} {
    variable widgets

    _initializeVars
    $widgets(combo_box) configure -values {}
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_Cond_Rules::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

#### private functions below ####

proc Apol_Cond_Rules::_initializeVars {} {
    variable vals
    array set vals {
        rs:allow 1       rs:type_transition 1
        rs:auditallow 1  rs:type_member 1
        rs:dontaudit 1   rs:type_change 1

        enable_bool 0
        name {}
        use_regexp 0
    }
}

proc Apol_Cond_Rules::_toggleSearchBools {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(enable_bool)} {
        $widgets(combo_box) configure -state normal
        $widgets(regexp) configure -state normal
    } else {
        $widgets(combo_box) configure -state disabled
        $widgets(regexp) configure -state disabled
    }
}

proc Apol_Cond_Rules::_search {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }

    # check search options
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
    set other_opts {}
    if {$vals(use_regexp)} {
        lappend other_opts regex
    }
    set bool_name {}
    if {$vals(enable_bool)} {
        if {[set bool_name $vals(name)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No booleean selected."
            return
        }
    }

    if {[catch {apol_SearchConditionalRules $rule_selection $other_opts $bool_name} results]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error searching conditionals:\n$results"
        return
    }

    if {[llength $results] == 0} {
        set text "Search returned no results."
    } else {
        set text "[llength $results] conditional"
        if {[llength $results] != 1} {
            append text s
        }
        append text " match the search criteria.  Expressions are in Reverse Polish Notation.\n\n"
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
    set counter 1
    foreach r [lsort -index 0 $results] {
        _renderConditional $r $counter
        Apol_Widget::appendSearchResultText $widgets(results) "\n\n"
        incr counter
    }
}

proc Apol_Cond_Rules::_renderConditional {cond cond_number} {
    variable widgets
    foreach {cond_expr true_list false_list} $cond {break}
    set text "conditional expression $cond_number: \[ [join $cond_expr] \]\n"
    append text "\nTRUE list:\n"
    Apol_Widget::appendSearchResultText $widgets(results) $text
    if {![ApolTop::is_capable "syntactic rules"]} {
        Apol_Widget::appendSearchResultAVRules $widgets(results) 4 [lindex $true_list 0]
        Apol_Widget::appendSearchResultTERules $widgets(results) 4 [lindex $true_list 1]
    } else {
        set syn_avrules [apol_GetSynAVRules [lindex $true_list 0] {}]
        Apol_Widget::appendSearchResultSynAVRules $widgets(results) 4 $syn_avrules
        set syn_terules [apol_GetSynTERules [lindex $true_list 1]]
        Apol_Widget::appendSearchResultSynTERules $widgets(results) 4 $syn_terules
    }
    Apol_Widget::appendSearchResultText $widgets(results) "\nFALSE list:\n"
    if {![ApolTop::is_capable "source"]} {
        Apol_Widget::appendSearchResultAVRules $widgets(results) 4 [lindex $false_list 0]
        Apol_Widget::appendSearchResultTERules $widgets(results) 4 [lindex $false_list 1]
    } else {
        set syn_avrules [apol_GetSynAVRules [lindex $false_list 0] {}]
        Apol_Widget::appendSearchResultSynAVRules $widgets(results) 4 $syn_avrules
        set syn_terules [apol_GetSynTERules [lindex $false_list 1]]
        Apol_Widget::appendSearchResultSynTERules $widgets(results) 4 $syn_terules
    }
}
