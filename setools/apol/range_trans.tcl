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
    Apol_Widget::clearRangeSelector $widgets(range)
    Apol_Widget::clearSearchResults $widgets(results)
    set vals(enable_source) 0
    set vals(enable_target) 0
}

proc Apol_Range::search { str case_Insensitive regExpr srch_Direction } {
	variable widgets
	ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_Range::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
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
    pack $source_frame $target_frame -side left -padx 10 -pady 4 -expand 0 -anchor nw

    # source type
    set vals(enable_source) 0
    set source_cb [checkbutton $source_frame.cb -text "Source Type" \
                       -variable Apol_Range::vals(enable_source)]
    set widgets(source_type) [Apol_Widget::makeTypeCombobox $source_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(source_type) 0
    trace add variable Apol_Range::vals(enable_source) write \
        [list Apol_Range::toggleTypeCombobox $widgets(source_type)]
    pack $source_cb -side top -expand 0 -anchor nw
    pack $widgets(source_type) -side top -expand 0 -anchor nw -padx 4

    # target type
    set vals(enable_target) 0
    set target_cb [checkbutton $target_frame.cb -text "Target Type" \
                       -variable Apol_Range::vals(enable_target)]
    set widgets(target_type) [Apol_Widget::makeTypeCombobox $target_frame.tcb]
    Apol_Widget::setTypeComboboxState $widgets(target_type) 0
    trace add variable Apol_Range::vals(enable_target) write \
        [list Apol_Range::toggleTypeCombobox $widgets(target_type)]
    pack $target_cb -side top -expand 0 -anchor nw
    pack $widgets(target_type) -side top -expand 0 -anchor nw -padx 4

    # range display
    set widgets(range) [Apol_Widget::makeRangeSelector [$obox getframe].range Rules]
    pack $widgets(range) -side left -padx 10 -pady 4 -expand 0 -anchor nw
    
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
    if {[Apol_Widget::getRangeSelectorState $widgets(range)]} {
        foreach {range type} [Apol_Widget::getRangeSelectorValue $widgets(range)] break
        if {$range == {{{} {}} {{} {}}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No range provided!"
            return
        }
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

proc Apol_Range::toggleTypeCombobox {path name1 name2 op} {
    Apol_Widget::setTypeComboboxState $path $Apol_Range::vals($name2)
}
