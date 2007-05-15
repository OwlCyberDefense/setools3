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

proc Apol_Range::open {ppath} {
    variable vals
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(source_type)
    Apol_Widget::resetTypeComboboxToPolicy $widgets(target_type)
    set vals(classes) $Apol_Class_Perms::class_list
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

proc Apol_Range::create {tab_name nb} {
    variable widgets
    variable vals

    # Layout frames
    set frame [$nb insert end $tab_name -text "Range Transition Rules"]
    set obox [TitleFrame $frame.obox -text "Search Options"]
    set dbox [TitleFrame $frame.dbox -text "Range Transition Rules Display"]
    pack $obox -fill x -expand 0 -padx 2 -pady 2
    pack $dbox -fill both -expand yes -padx 2 -pady 2

    # Create the options widgets
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
        [list Apol_Range::toggleTypeCombobox $widgets(source_type)]
    pack $source_cb -side top -expand 0 -anchor nw
    pack $widgets(source_type) -side top -expand 0 -anchor nw -padx 4

    # target type
    set vals(enable_target) 0
    set target_cb [checkbutton $target_frame.cb -text "Target type" \
                       -variable Apol_Range::vals(enable_target)]
    set widgets(target_type) [Apol_Widget::makeTypeCombobox $target_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(target_type) 0
    trace add variable Apol_Range::vals(enable_target) write \
        [list Apol_Range::toggleTypeCombobox $widgets(target_type)]
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

    # range display
    set widgets(range) [Apol_Widget::makeRangeSelector [$obox getframe].range Rules]
    pack $widgets(range) -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set ok [button [$obox getframe].ok -text "OK" -width 6 -command Apol_Range::searchRanges]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

#### private functions below ####

proc Apol_Range::searchRanges {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
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
    set classes {}
    foreach c [$widgets(classes) curselection] {
        lappend classes [$widgets(classes) get $c]
    }
    set range_enabled [Apol_Widget::getRangeSelectorState $widgets(range)]
    foreach {range range_match} [Apol_Widget::getRangeSelectorValue $widgets(range)] break
    if {$range_enabled} {
        if {$range == {{{} {}} {{} {}}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No range provided!"
            return
        }
    } else {
        set range {}
    }

    if {[catch {apol_SearchRangeTransRules $source $target $classes $range $range_match} results]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error searching range transitions:\n$results"
        return
    }

    if {[llength $results] == 0} {
        set text "Search returned no results."
    } else {
        set text "[llength $results] rule"
        if {[llength $results] != 1} {
            append text s
        }
        append text " match the search criteria.\n\n"
    }
    Apol_Widget::appendSearchResultText $widgets(results) $text
    foreach r [lsort $results] {
        renderRangeTrans $r
    }
}

proc Apol_Range::renderRangeTrans {rule} {
    variable widgets
    foreach {source_set target_set target_class range} $rule {
        if {[llength $source_set] > 1} {
            set source_set "\{ $source_set \}"
        }
        if {[llength $target_set] > 1} {
            set target_set "\{ $target_set \}"
        }
        set text "$source_set $target_set : $target_class "
        set low [apol_RenderLevel [lindex $range 0]]
        set high [apol_RenderLevel [lindex $range 1]]
        if {$low == $high} {
            append text $low
        } else {
            append text "$low - $high"
        }
        Apol_Widget::appendSearchResultLine $widgets(results) 0 {} range_transition $text
    }
}

proc Apol_Range::toggleTypeCombobox {path name1 name2 op} {
    Apol_Widget::setTypeComboboxState $path $Apol_Range::vals($name2)
}
