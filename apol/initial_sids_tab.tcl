# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_Initial_SIDS
#
# The Initial SIDS page
##############################################################
namespace eval Apol_Initial_SIDS {
    variable widgets
    variable vals
}

##############################################################
# ::search
#	- Search text widget for a string
#
proc Apol_Initial_SIDS::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::set_Focus_to_Text
#
#  Description:
# ----------------------------------------------------------------------------------------
proc Apol_Initial_SIDS::set_Focus_to_Text {} {
    focus $Apol_Initial_SIDS::widgets(results)
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::searchSIDs
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::searchSIDs {} {
    variable vals
    variable widgets

    set name {}
    set context {}
    set range_match 0
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {[Apol_Widget::getContextSelectorState $widgets(context)]} {
        foreach {context range_match} [Apol_Widget::getContextSelectorValue $widgets(context)] {break}
    }
    if {[catch {apol_GetInitialSIDs $name $context $range_match} isids]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining initial SIDs list: $isids"
        return
    }
    set results "INITIAL SIDS:"
    if {[llength $isids] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach i [lsort -index 0 -dictionary $isids] {
            append results "\n[render_isid $i]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::open
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::open { } {
    variable vals
    set vals(items) {}
    foreach sid [lsort -index 0 -dictionary [apol_GetInitialSIDs {} {} 0]] {
        lappend vals(items) [lindex $sid 0]
    }
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::close
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::close { } {
    variable vals
    variable widgets
    set vals(items) {}
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(context)
}

proc Apol_Initial_SIDS::free_call_back_procs { } {
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::popupSIDInfo
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::render_isid {isid {compact 0}} {
    foreach {name context} $isid {break}
    set context [apol_RenderContext $context]
    if {$compact} {
        format "sid %s %s" $name $context
    } else {
        format "sid  %-16s %s" $name $context
    }
}

proc Apol_Initial_SIDS::popupSIDInfo {sid} {
    set info [apol_GetInitialSIDs $sid]
    set text "$sid:"
    foreach s [lsort -index 0 -dictionary $info] {
        append text "\n\t[render_isid $s 1]"
    }
    Apol_Widget::showPopupText "$sid Context" $text
}

########################################################################
# ::goto_line
#	- goes to indicated line in text box
#
proc Apol_Initial_SIDS::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::create
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::create {nb} {
    variable widgets
    variable vals

    array set vals {
        items {}
    }

    # Layout frames
    set frame [$nb insert end $ApolTop::initial_sids_tab -text "Initial SIDs"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    # Title frames
    set sids_box [TitleFrame $leftf.sids_box -text "Initial SIDs"]
    set s_optionsbox [TitleFrame $rightf.obox -text "Search Options"]
    set rslts_frame [TitleFrame $rightf.rbox -text "Search Results"]
    pack $sids_box -expand 1 -fill both
    pack $s_optionsbox -side top -expand 0 -fill both -padx 2
    pack $rslts_frame -side top -expand yes -fill both -padx 2

    # Initial SIDs listbox widget
    set widgets(items) [Apol_Widget::makeScrolledListbox [$sids_box getframe].lb -width 20 -listvar Apol_Initial_SIDS::vals(items)]
    Apol_Widget::setListboxCallbacks $widgets(items) \
        {{"Display Initial SID Context" {Apol_Initial_SIDS::popupSIDInfo}}}
    pack $widgets(items) -expand 1 -fill both

    # Search options subframes
    set f [frame [$s_optionsbox getframe].c]
    set widgets(context) [Apol_Widget::makeContextSelector $f.context "Context"]
    pack $widgets(context)
    pack $f -side left -anchor n -padx 4 -pady 2

    set ok [button [$s_optionsbox getframe].ok -text "OK" -width 6 \
                -command Apol_Initial_SIDS::searchSIDs]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$rslts_frame getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}
