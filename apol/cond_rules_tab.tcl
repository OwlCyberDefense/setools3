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
                   -onvalue $::QPOL_RULE_ALLOW -offvalue 0 \
                   -variable Apol_Cond_Rules::vals(rs:avrule_allow)]
    set auditallow [checkbutton $fm_rules.auditallow -text "auditallow" \
                        -onvalue $::QPOL_RULE_AUDITALLOW -offvalue 0 \
                        -variable Apol_Cond_Rules::vals(rs:avrule_auditallow)]
    set dontaudit [checkbutton $fm_rules.dontaudit -text "dontaudit" \
                       -onvalue $::QPOL_RULE_DONTAUDIT -offvalue 0 \
                       -variable Apol_Cond_Rules::vals(rs:avrule_dontaudit)]
    set type_transition [checkbutton $fm_rules.type_transition -text "type_trans" \
                             -onvalue $::QPOL_RULE_TYPE_TRANS -offvalue 0 \
                             -variable Apol_Cond_Rules::vals(rs:type_transition)]
    set type_member [checkbutton $fm_rules.type_member -text "type_member" \
                         -onvalue $::QPOL_RULE_TYPE_MEMBER -offvalue 0 \
                         -variable Apol_Cond_Rules::vals(rs:type_member)]
    set type_change [checkbutton $fm_rules.type_change -text "type_change" \
                         -onvalue $::QPOL_RULE_TYPE_CHANGE -offvalue 0 \
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
                                -state disabled -entrybg [Apol_Prefs::getPref active_bg] -autopost 1]
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
    array set vals [list \
                        rs:avrule_allow $::QPOL_RULE_ALLOW \
                        rs:avrule_auditallow $::QPOL_RULE_AUDITALLOW \
                        rs:avrule_dontaudit $::QPOL_RULE_DONTAUDIT \
                        rs:type_transition $::QPOL_RULE_TYPE_TRANS \
                        rs:type_member $::QPOL_RULE_TYPE_MEMBER \
                        rs:type_change $::QPOL_RULE_TYPE_CHANGE \
                        enable_bool 0 \
                        name {} \
                        use_regexp 0]
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
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }

    set avrule_selection 0
    foreach {key value} [array get vals rs:avrule_*] {
        set avrule_selection [expr {$avrule_selection | $value}]
    }
    set terule_selection 0
    foreach {key value} [array get vals rs:type_*] {
        set terule_selection [expr {$terule_selection | $value}]
    }
    if {$avrule_selection == 0 && $terule_selection == 0} {
            tk_messageBox -icon error -type ok -title "Error" -message "At least one rule must be selected."
            return
    }

    set bool_name {}
    if {$vals(enable_bool)} {
        if {[set bool_name $vals(name)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No booleean selected."
            return
        }
    }

    set q [new_apol_cond_query_t]
    $q set_bool $::ApolTop::policy $bool_name
    if {$vals(use_regexp)} {
        $q set_regex $::ApolTop::policy 1
    }

    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set results [cond_vector_to_list $v]
    $v -acquire
    $v -delete

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
    Apol_Progress_Dialog::wait "Conditional Expressions" "Rendering conditionals" \
        {
            if {[ApolTop::is_capable "syntactic rules"]} {
                $::ApolTop::qpolicy build_syn_rule_table
            }
            set counter 1
            set num_results [llength $results]
            foreach r [lsort -index 0 $results] {
                apol_tcl_set_info_string $::ApolTop::policy "Rendering $counter of $num_results"
                set text [_renderConditional $r $avrule_selection $terule_selection $counter]
                Apol_Widget::appendSearchResultText $widgets(results) "$text\n\n"
                incr counter
            }
        }
}

proc Apol_Cond_Rules::_renderConditional {cond avrules terules cond_number} {
    set cond_expr [apol_cond_expr_render $::ApolTop::policy $cond]
    set i [$cond get_av_true_iter $::ApolTop::qpolicy $avrules]
    set av_true_vector [new_apol_vector_t $i]
    $i -acquire
    $i -delete
    set i [$cond get_av_false_iter $::ApolTop::qpolicy $avrules]
    set av_false_vector [new_apol_vector_t $i]
    $i -acquire
    $i -delete
    set i [$cond get_te_true_iter $::ApolTop::qpolicy $terules]
    set te_true_vector [new_apol_vector_t $i]
    $i -acquire
    $i -delete
    set i [$cond get_te_false_iter $::ApolTop::qpolicy $terules]
    set te_false_vector [new_apol_vector_t $i]
    $i -acquire
    $i -delete

    variable widgets
    set text "conditional expression $cond_number: \[ [join $cond_expr] \]\n"

    Apol_Widget::appendSearchResultText $widgets(results) "$text\nTRUE list:\n"
    if {![ApolTop::is_capable "syntactic rules"]} {
        apol_tcl_avrule_sort $::ApolTop::policy $av_true_vector
        Apol_Widget::appendSearchResultRules $widgets(results) 4 $av_true_vector qpol_avrule_from_void
        apol_tcl_terule_sort $::ApolTop::policy $te_true_vector
        Apol_Widget::appendSearchResultRules $widgets(results) 4 $te_true_vector qpol_terule_from_void
    } else {
        set syn_avrules [apol_avrule_list_to_syn_avrules $::ApolTop::policy $av_true_vector NULL]
        Apol_Widget::appendSearchResultSynRules $widgets(results) 4 $syn_avrules qpol_syn_avrule_from_void
        set syn_terules [apol_terule_list_to_syn_terules $::ApolTop::policy $te_true_vector]
        Apol_Widget::appendSearchResultSynRules $widgets(results) 4 $syn_terules qpol_syn_terule_from_void
        $syn_avrules -acquire
        $syn_avrules -delete
        $syn_terules -acquire
        $syn_terules -delete
    }

    Apol_Widget::appendSearchResultText $widgets(results) "\nFALSE list:\n"
    if {![ApolTop::is_capable "syntactic rules"]} {
        apol_tcl_avrule_sort $::ApolTop::policy $av_false_vector
        Apol_Widget::appendSearchResultRules $widgets(results) 4 $av_false_vector qpol_avrule_from_void
        apol_tcl_terule_sort $::ApolTop::policy $te_false_vector
        Apol_Widget::appendSearchResultRules $widgets(results) 4 $te_false_vector qpol_terule_from_void
    } else {
        set syn_avrules [apol_avrule_list_to_syn_avrules $::ApolTop::policy $av_false_vector NULL]
        Apol_Widget::appendSearchResultSynRules $widgets(results) 4 $syn_avrules qpol_syn_avrule_from_void
        set syn_terules [apol_terule_list_to_syn_terules $::ApolTop::policy $te_false_vector]
        Apol_Widget::appendSearchResultSynRules $widgets(results) 4 $syn_terules qpol_syn_terule_from_void
        $syn_avrules -acquire
        $syn_avrules -delete
        $syn_terules -acquire
        $syn_terules -delete
    }

    $av_true_vector -acquire
    $av_true_vector -delete
    $av_false_vector -acquire
    $av_false_vector -delete
    $te_true_vector -acquire
    $te_true_vector -delete
    $te_false_vector -acquire
    $te_false_vector -delete
}
