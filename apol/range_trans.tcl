# Copyright (C) 2001-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets


##############################################################
# ::Apol_Range
#  
# 
##############################################################
namespace eval Apol_Range {
    variable widgets
    variable vals
}

proc Apol_Range::set_Focus_to_Text {} {
    focus $Apol_Range::widgets(results)
}

proc Apol_Range::open {} {
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(source_type)
    Apol_Widget::resetTypeComboboxToPolicy $widgets(target_type)
}

proc Apol_Range::close {} {
    variable vals
    variable widgets
    Apol_Widget::clearTypeCombobox $widgets(source_type)
    Apol_Widget::clearTypeCombobox $widgets(target_type)
    set vals(range) {}
    Apol_Widget::clearSearchResults $widgets(results)
    set vals(enable_source) 0
    set vals(enable_target) 0
    set vals(enable_range) 0
    set vals(search_type) exact
}

proc Apol_Range::goto_line { line_num } {
    variable widgets
    ApolTop::goto_line $line_num $widgets(results)
}

proc Apol_Range::create {nb} {
    variable widgets
    variable vals

    # Layout frames
    set frame [$nb insert end $ApolTop::range_tab -text "Range Transition Rules"]
    set pw [PanedWindow $frame.pw -side left -weights extra]
    $pw add -weight 0
    $pw add -weight 1
    set topf [$pw getframe 0]
    set bottomf [$pw getframe 1]
    pack $pw -fill both -expand yes

    set obox [TitleFrame $topf.obox -text "Search Criteria"]
    set dbox [TitleFrame $bottomf.dbox -text "Range Transition Rules Display"]
    pack $obox -fill both -expand yes -padx 5
    pack $dbox -fill both -expand yes -padx 5

    # Create the options widgets
    set source_frame [frame [$obox getframe].source]
    set target_frame [frame [$obox getframe].target]
    set range_frame [frame [$obox getframe].range]
    set range2_frame [frame [$obox getframe].range2]
    pack $source_frame $target_frame $range_frame \
        -side left -padx 10 -pady 4 -expand 0 -anchor nw
    pack $range2_frame -side left -pady 4 -expand 0 -anchor nw

    # source type
    set vals(enable_source) 0
    set source_cb [checkbutton $source_frame.cb -text "Source Type" \
                       -variable Apol_Range::vals(enable_source)]
    set widgets(source_type) [Apol_Widget::makeTypeCombobox $source_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(source_type) 0
    trace add variable Apol_Range::vals(enable_source) write \
        [list Apol_Range::toggleTypeCombobox $widgets(source_type)]
    pack $source_cb $widgets(source_type) -side top -expand 0 -anchor nw

    # target type
    set vals(enable_target) 0
    set target_cb [checkbutton $target_frame.cb -text "Target Type" \
                       -variable Apol_Range::vals(enable_target)]
    set widgets(target_type) [Apol_Widget::makeTypeCombobox $target_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(target_type) 0
    trace add variable Apol_Range::vals(enable_target) write \
        [list Apol_Range::toggleTypeCombobox $widgets(target_type)]
    pack $target_cb $widgets(target_type) -side top -expand 0 -anchor nw

    # range display
    set vals(enable_range) 0
    set range_cb [checkbutton $range_frame.cb -text "Range" \
                      -variable Apol_Range::vals(enable_range)]
    set vals(range) {}
    set vals(range_rendered) {}
    set widgets(range_display) [Entry $range_frame.display -textvariable Apol_Range::vals(range_rendered) -width 28 -editable 0]
    set widgets(range_button) [button $range_frame.button -text "Select Range..." -state disabled -command Apol_Range::showMLSRangeDialog]
    trace add variable Apol_Range::vals(range) write Apol_Range::updateRangeDisplay
    pack $range_cb -side top -expand 0 -anchor nw
    pack $widgets(range_display) -side top -expand 1 -fill x -anchor nw
    pack $widgets(range_button) -side top -expand 0 -anchor ne

    # range search type
    set vals(search_type) "exact"
    set widgets(range_label) [label $range2_frame.range_label -text "Range Matching:" -state disabled]
    set widgets(range_exact) [radiobutton $range2_frame.exact -text "Exact Matches" \
                            -state disabled \
                            -value exact -variable Apol_Range::vals(search_type)]
    set widgets(range_subset) [radiobutton $range2_frame.subset -text "Rules Containing Range" \
                             -state disabled \
                             -value subset -variable Apol_Range::vals(search_type)]
    set widgets(range_superset) [radiobutton $range2_frame.superset -text "Rules Within Range" \
                               -state disabled \
                               -value superset -variable Apol_Range::vals(search_type)]
    trace add variable Apol_Range::vals(enable_range) write Apol_Range::toggleRangeBox
    pack $widgets(range_label) $widgets(range_exact) $widgets(range_subset) $widgets(range_superset) \
        -side top -expand 0 -anchor nw

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
    if {$vals(enable_source)} {
        set source [Apol_Widget::getTypeComboboxValue $widgets(source_type)]
        if {$source == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No source type provided!"
            return
        }
    } else {
        set source {}
    }
    if {$vals(enable_target)} {
        set target [Apol_Widget::getTypeComboboxValue $widgets(target_type)]
        if {$target == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No target type provided!"
            return
        }
    } else {
        set target {}
    }
    if {$vals(enable_range)} {
        set range $vals(range)
        if {$range == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No range provided!"
            return
        }
        set type $vals(search_type)
    } else {
        set range {}
        set type {}
    }
    if {[catch {apol_SearchRangeTransRules $source $target [lindex $range 0] [lindex $range 1] $type} lines]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error while performing range transition:\n$lines"
        return
    }
    
    if {[llength $lines] == 0} {
        Apol_Widget::appendSearchResultText $widgets(results) "Search returned no results."
        return
    } elseif {[llength $lines] == 1} {
        Apol_Widget::appendSearchResultText $widgets(results) "1 rule match the search criteria.\n\n"
    } else {
        Apol_Widget::appendSearchResultText $widgets(results) "[llength $lines] rules match the search criteria.\n\n"
    }
    foreach line $lines {
        if {[catch {apol_RenderRangeTrans $line} rendered_line]} {
            tk_messageBox -icon error -type ok -title "Error" -message "Error while displaying range transition results:\n$rendered_line"
            return
        }
        if {[lindex $rendered_line 1 0] == {}} {
            set source [lindex $rendered_line 1 1]
        } else {
            set source "[lindex $rendered_line 1 0][lindex $rendered_line 1 1]"
        }
        if {[lindex $rendered_line 2 0] == {}} {
            set target [lindex $rendered_line 2 1]
        } else {
            set target "[lindex $rendered_line 2 0][lindex $rendered_line 2 1]"
        }
        Apol_Widget::appendSearchResultLine $widgets(results) [lindex $rendered_line 0] "range_transition" $source $target [lindex $rendered_line 3]
    }
}

proc Apol_Range::showMLSRangeDialog {} {
    set Apol_Range::vals(range) [Apol_Range_Dialog::getRange $Apol_Range::vals(range)]
    # the trace on this variable will trigger [updateRangeDisplay] to execute
}

proc Apol_Range::toggleTypeCombobox {path name1 name2 op} {
    Apol_Widget::setTypeComboboxState $path $Apol_Range::vals($name2)
}

proc Apol_Range::toggleRangeBox {name1 name2 op} {
    variable widgets
    if {$Apol_Range::vals(enable_range)} {
        set new_state normal
    } else {
        set new_state disabled
    }
    foreach w {range_display range_button range_label \
                   range_exact range_subset range_superset} {
        $widgets($w) configure -state $new_state
    }
}

proc Apol_Range::updateRangeDisplay {name1 name2 op} {
    variable vals
    if {$vals(range) == "" || $vals(range) == {{{} {}} {{} {}}}} {
        set vals(range_rendered) {}
    } else {
        set low_level [apol_RenderLevel [lindex $vals(range) 0]]
        set high_level [apol_RenderLevel [lindex $vals(range) 1]]
        if {$low_level == "" || $high_level == ""} {
            set vals(range_rendered) "<invalid MLS range>"
        } else {
            if {$low_level == $high_level} {
                set vals(range_rendered) $low_level
            } else {
                set vals(range_rendered) "$low_level - $high_level"
            }
        }
    }
}
