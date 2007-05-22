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

namespace eval Apol_Range {
    variable widgets
    variable vals
}

proc Apol_Range::create {tab_name nb} {
    variable widgets
    variable vals

    set frame [$nb insert end $tab_name -text "Range Transition Rules"]
    set obox [TitleFrame $frame.obox -text "Search Options"]
    set dbox [TitleFrame $frame.dbox -text "Range Transition Rules Display"]
    pack $obox -fill x -expand 0 -padx 2 -pady 2
    pack $dbox -fill both -expand yes -padx 2 -pady 2

    set source_frame [frame [$obox getframe].source]
    set target_frame [frame [$obox getframe].target]
    set classes_frame [frame [$obox getframe].classes]
    pack $source_frame $target_frame $classes_frame -side left -padx 4 -pady 2 -expand 0 -anchor nw

    # source type
    set vals(enable_source) 0
    set source_cb [checkbutton $source_frame.cb -text "Source type" \
                       -variable Apol_Range::vals(enable_source)]
    set widgets(source_type) [Apol_Widget::makeTypeCombobox $source_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(source_type) 0
    trace add variable Apol_Range::vals(enable_source) write \
        [list Apol_Range::_toggleTypeCombobox $widgets(source_type)]
    pack $source_cb -side top -expand 0 -anchor nw
    pack $widgets(source_type) -side top -expand 0 -anchor nw -padx 4

    # target type
    set vals(enable_target) 0
    set target_cb [checkbutton $target_frame.cb -text "Target type" \
                       -variable Apol_Range::vals(enable_target)]
    set widgets(target_type) [Apol_Widget::makeTypeCombobox $target_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(target_type) 0
    trace add variable Apol_Range::vals(enable_target) write \
        [list Apol_Range::_toggleTypeCombobox $widgets(target_type)]
    pack $target_cb -side top -expand 0 -anchor nw
    pack $widgets(target_type) -side top -expand 0 -anchor nw -padx 4

    # object classes
    set l [label $classes_frame.l -text "Target Classes"]
    set sw [ScrolledWindow $classes_frame.sw -auto both]
    set widgets(classes) [listbox [$sw getframe].lb -height 5 -width 24 \
                              -highlightthickness 0 -selectmode multiple \
                              -exportselection 0 -state disabled \
                              -bg $ApolTop::default_bg_color \
                              -listvar Apol_Range::vals(classes)]
    $sw setwidget $widgets(classes)
    update
    grid propagate $sw 0
    pack $l $sw -side top -expand 0 -anchor nw

    set widgets(range) [Apol_Widget::makeRangeSelector [$obox getframe].range Rules]
    pack $widgets(range) -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set ok [button [$obox getframe].ok -text "OK" -width 6 -command Apol_Range::_searchRanges]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Range::open {ppath} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(source_type)
    Apol_Widget::resetTypeComboboxToPolicy $widgets(target_type)
    set vals(classes) [Apol_Class_Perms::getClasses]
    $widgets(classes) configure -bg white -state normal
}

proc Apol_Range::close {} {
    variable vals
    variable widgets
    Apol_Widget::clearTypeCombobox $widgets(source_type)
    Apol_Widget::clearTypeCombobox $widgets(target_type)
    set vals(classes) {}
    $widgets(classes) configure -bg $ApolTop::default_bg_color -state disabled
    Apol_Widget::clearRangeSelector $widgets(range)
    Apol_Widget::clearSearchResults $widgets(results)
    set vals(enable_source) 0
    set vals(enable_target) 0
}

proc Apol_Range::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

#### private functions below ####

proc Apol_Range::_toggleTypeCombobox {path name1 name2 op} {
    Apol_Widget::setTypeComboboxState $path $Apol_Range::vals($name2)
}

proc Apol_Range::_searchRanges {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }

    if {$vals(enable_source)} {
        set source [lindex [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(source_type)] 0]
        if {$source == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No source type provided."
            return
        }
    } else {
        set source {}
    }
    if {$vals(enable_target)} {
        set target [lindex [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(target_type)] 0]
        if {$target == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No target type provided."
            return
        }
    } else {
        set target {}
    }
    if {[Apol_Widget::getRangeSelectorState $widgets(range)]} {
        foreach {range range_match} [Apol_Widget::getRangeSelectorValue $widgets(range)] break
        if {$range == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No range selected."
            return
        }
    } else {
        set range NULL
        set range_match 0
    }

    set q [new_apol_range_trans_query_t]
    $q set_source $::ApolTop::policy $source 0
    $q set_target $::ApolTop::policy $target 0
    foreach c [$widgets(classes) curselection] {
        $q append_class $::ApolTop::policy [$widgets(classes) get $c]
    }
    $q set_range $::ApolTop::policy $range $range_match

    set v [$q run $::ApolTop::policy]
    $q -delete
    set results [range_trans_vector_to_list $v]
    $v -delete

    if {[llength $results] == 0} {
        set text "Search returned no results."
    } else {
        set text "[llength $results] rule"
        if {[llength $results] != 1} {
            append text s
        }
        append text " match the search criteria.\n\n"
    }
    foreach r [lsort -command _range_trans_sort $results] {
        append text "[_renderRangeTrans $r]\n"
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
}

proc Apol_Range::_renderRangeTrans {rule} {
    apol_range_trans_render $::ApolTop::policy $rule
}

proc Apol_Range::_range_trans_sort {a b} {
    set t1 [[$a get_source_type $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set t2 [[$b get_source_type $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    if {[set z [string compare $t1 $t2]] != 0} {
        return $z
    }

    set t1 [[$a get_target_type $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set t2 [[$b get_target_type $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    if {[set z [string compare $t1 $t2]] != 0} {
        return $z
    }

    set c1 [[$a get_target_class $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    set c2 [[$b get_target_class $::ApolTop::qpolicy] get_name $::ApolTop::qpolicy]
    string compare $c1 $c2
}
