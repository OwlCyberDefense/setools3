#############################################################
#  analysis_tab.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com>
#  Modified by: <kcarr@tresys.com>
# -----------------------------------------------------------

##############################################################
# ::Apol_Analysis
#
# The Analysis tab
##############################################################
namespace eval Apol_Analysis {
    variable vals
    variable widgets
    variable tabs
}

#------------------------------------------------------------------------------
#  Command Apol_Analysis::open
#------------------------------------------------------------------------------
proc Apol_Analysis::open {} {
    variable vals
    foreach m $vals(modules) {
        ${m}::open
    }
}

#------------------------------------------------------------------------------
#  Command Apol_Analysis::close
#------------------------------------------------------------------------------
proc Apol_Analysis::close {} {
    variable vals
    variable widgets
    foreach m $vals(modules) {
        ${m}::close
    }
    reinitializeTabs
}

proc Apol_Analysis::free_call_back_procs { } {
}

proc Apol_Analysis::set_Focus_to_Text { tab } {
}

proc Apol_Analysis::goto_line { line_num } {
}

proc Apol_Analysis::search { str case_Insensitive regExpr srch_Direction } {
}

proc Apol_Analysis::save_query_options {file_channel query_file} {
    variable widgets
    set m [$widgets(search_opts) raise]
    puts $file_channel $m
    ${m}::saveQuery $file_channel
}

proc Apol_Analysis::load_query_options {file_channel parentDlg} {
    variable vals
    variable widgets

    # Search for the module name
    set line {}
    while {[gets $file_channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        break
    }
    if {$line == {} || [set i [lsearch -exact $vals(modules) $line]] == -1} {
        tk_messageBox -icon error -type ok -title Error -message "The specified query is not a valid analysis module."
    }
    ${line}::loadQuery $file_channel
    $widgets(modules).lb selection clear 0 end
    set module [lindex $vals(modules) $i]
    $widgets(search_opts) raise $module
    $widgets(modules).lb selection set [lsearch $vals(module_names) $vals($module:name)]
}

# -----------------------------------------------------------------------------
#  Command Apol_Analysis::create
# -----------------------------------------------------------------------------
proc Apol_Analysis::create {nb} {
    variable vals
    variable widgets

    # Layout frames
    set frame [$nb insert end $ApolTop::analysis_tab -text "Analysis"]
    set pw [PanedWindow $frame.pw -side left -weights extra]
    set topf [$pw add -weight 0]
    set bottomf [$pw add -weight 1]
    pack $pw -expand 1 -fill both

    # Major subframes
    set top_leftf [TitleFrame $topf.left -text "Analysis Type"]
    set opts_f [TitleFrame $topf.opts -text "Analysis Options"]
    set buttons_f [frame $topf.buttons]
    pack $top_leftf -side left -expand 0 -fill y -padx 2
    pack $opts_f -side left -expand 1 -fill both -padx 2
    pack $buttons_f -side right -expand 0 -anchor ne -padx 2
    set results_f [TitleFrame $bottomf.r -text "Analysis Results"]
    pack $results_f -expand 1 -fill both -padx 2

    # Module selection list
    set widgets(modules) [Apol_Widget::makeScrolledListbox [$top_leftf getframe].m \
                              -height 8 -width 24 -listvar Apol_Analysis::vals(module_names) -exportselection 0]
    $widgets(modules).lb selection set 0
    bind $widgets(modules).lb <<ListboxSelect>> Apol_Analysis::selectModule
    pack $widgets(modules) -expand 1 -fill both

    set widgets(search_opts) [PagesManager [$opts_f getframe].s]
    foreach m $vals(modules) {
        ${m}::create [$widgets(search_opts) add $m]
    }
    $widgets(search_opts) compute_size
    $widgets(search_opts) raise [lindex $vals(modules) 0]
    pack $widgets(search_opts) -expand 1 -fill both

    # Action buttons
    set widgets(new) [button $buttons_f.new -text "New Analysis" -width 12 \
                          -command [list Apol_Analysis::analyze new]]
    set widgets(update) [button $buttons_f.update -text "Update Analysis" -width 12 -state disabled \
                             -command [list Apol_Analysis::analyze update]]
    set widgets(reset) [button $buttons_f.reset -text "Reset Criteria" -width 12 \
                            -command Apol_Analysis::reset]
    set widgets(info) [button $buttons_f.info -text "Info" -width 12 \
                            -command Apol_Analysis::info]
    pack $widgets(new) $widgets(update) $widgets(reset) $widgets(info) \
        -side top -pady 5 -padx 5 -anchor ne

    # Popup menu widget
    set popupTab_Menu [menu .popup_analysis -tearoff 0]
    set tab_menu_callbacks \
        [list {"Close Tab" Apol_Analysis::deleteResults} \
             {"Rename Tab" Apol_Analysis::displayRenameTabDialog}]

    # Notebook creation for results
    set widgets(results) [NoteBook [$results_f getframe].results]
    $widgets(results) bindtabs <Button-1> Apol_Analysis::switchTab
    $widgets(results) bindtabs <Button-3> \
        [list ApolTop::popup_Tab_Menu \
             %W %x %y $popupTab_Menu $tab_menu_callbacks]
    set close [button [$results_f getframe].close -text "Close Tab" \
                   -command Apol_Analysis::deleteCurrentResults]
    pack $widgets(results) -expand 1 -fill both -padx 4
    pack $close -expand 0 -fill x -padx 4 -pady 2

    reinitializeTabs
    return $frame
}

#################### functions invoked by modules ####################

proc Apol_Analysis::registerAnalysis {mod_proc mod_name} {
    variable vals
    lappend vals(modules) $mod_proc
    lappend vals(module_names) $mod_name
    set vals($mod_proc:name) $mod_name
}

proc Apol_Analysis::createResultTab {short_name criteria} {
    variable widgets
    variable tabs

    set i $tabs(next_result_id)
    incr tabs(next_result_id)
    set m [$widgets(search_opts) raise]
    set id "results$i"
    set frame [$widgets(results) insert end $id -text "($i) $short_name"]
    $widgets(results) raise $id

    set tabs($id:module) $m
    set tabs($id:vals) $criteria
    return $frame
}

proc Apol_Analysis::setResultTabCriteria {criteria} {
    variable widgets
    variable tabs
    set id [$widgets(results) raise]
    if {$id != {}} {
        set tabs($id:vals) $criteria
    }
}

#################### private functions ####################

proc Apol_Analysis::selectModule {} {
    variable vals
    variable widgets
    variable tabs

    focus $widgets(modules).lb
    if {[set selection [$widgets(modules).lb curselection]] == {}} {
        return
    }
    set module [lindex $vals(modules) [lindex $selection 0]]
    $widgets(search_opts) raise $module
    set result_tab [$widgets(results) raise]
    if {$result_tab != {} && $tabs($result_tab:module) == $module} {
        $widgets(update) configure -state normal
    } else {
        $widgets(update) configure -state disabled
    }
}

proc Apol_Analysis::analyze {which_button} {
    variable vals
    variable widgets
    variable tabs

    set m [$widgets(search_opts) raise]
    set tabs(analyses_done) -1
    set tabs(analyses_text) "Performing $vals($m:name) Analysis..."
    ProgressDlg .analysis_busy -title "$vals($m:name) Analysis" \
        -type normal -stop {} -separator 1 -parent . -maximum 2 \
        -width [string length $tabs(analyses_text)] \
        -textvariable Apol_Analysis::tabs(analyses_text) \
        -variable Apol_Analysis::tabs(analyses_done)
    ApolTop::setBusyCursor
    update idletasks

    if {$which_button == "new"} {
        set retval [${m}::newAnalysis]
    } else {
        set f [$widgets(results) getframe [$widgets(results) raise]]
        if {[set retval [${m}::updateAnalysis $f]] != {}} {
            deleteCurrentResults
        }
    }

    ApolTop::resetBusyCursor
    destroy .analysis_busy

    if {$retval != {}} {
        tk_messageBox -icon error -type ok -title Error -message "Error while performing analysis:\n\n$retval"
    }
    if {[$widgets(results) raise] == {}} {
        $widgets(update) configure -state disabled
    } else {
        $widgets(update) configure -state normal
    }
}

proc Apol_Analysis::reset {} {
    variable vals
    variable widgets
    set m [$widgets(search_opts) raise]
    ${m}::reset
}

proc Apol_Analysis::info {} {
    variable vals
    variable widgets
    set m [$widgets(search_opts) raise]
    Apol_Widget::showPopupParagraph $vals(${m}:name) [${m}::getInfo]
}

proc Apol_Analysis::reinitializeTabs {} {
    variable widgets
    variable tabs
    array set tabs {
        next_result_id 1
    }
    foreach p [$widgets(results) pages 0 end] {
        deleteResults $p
    }
}

proc Apol_Analysis::switchTab {pageID} {
    variable vals
    variable widgets
    variable tabs

    $widgets(update) configure -state normal
    # check if switching to already visible tab
    if {[$Apol_TE::widgets(results) raise] == $pageID} {
        return
    }
    $widgets(results) raise $pageID
    set cur_search_opts [$widgets(search_opts) raise]

    # restore the tab's search criteria
    set m $tabs($pageID:module)
    ${m}::switchTab $tabs($pageID:vals)

    # update the analysis type selection
    $widgets(modules).lb selection clear 0 end
    $widgets(modules).lb selection set [lsearch $vals(module_names) $vals(${m}:name)]
    $widgets(search_opts) raise $m
}

proc Apol_Analysis::deleteResults {pageID} {
    variable widgets
    variable tabs

    # Remove tab and its widgets
    set curpos [$widgets(results) index $pageID]
    $widgets(results) delete $pageID
    array unset tabs $pageID:*
    array unset tabs $pageID

    # try to raise the next tab
    if {[set next_id [$widgets(results) pages $curpos]] != {}} {
        switchTab $next_id
    } elseif {$curpos > 0} {
        # raise the previous page instead
        switchTab [$widgets(results) pages [expr {$curpos - 1}]]
    } else {
        # no tabs remaining
        $widgets(update) configure -state disabled
    }
}

proc Apol_Analysis::deleteCurrentResults {} {
    variable widgets
    if {[set curid [$widgets(results) raise]] != {}} {
        deleteResults $curid
    }
}

proc Apol_Analysis::displayRenameTabDialog {pageID} {
    variable widgets
    variable tabs
    set d [Dialog .apol_analysis_tab_rename -homogeneous 1 -spacing 2 -cancel 1 \
               -default 0 -modal local -parent . -place center -separator 1 \
               -side bottom -title "Rename Results Tab"]
    $d add -text "OK" -command [list $d enddialog "ok"]
    $d add -text "Cancel" -command [list $d enddialog "cancel"]
    set f [$d getframe]
    set l [label $f.l -text "Tab name:"]
    set tabs(tab:new_name) [$widgets(results) itemcget $pageID -text]
    set e [entry $f.e -textvariable Apol_Analysis::tabs(tab:new_name) -width 16 -bg white]
    pack $l $e -side left -padx 2
    set retval [$d draw]
    destroy $d
    if {$retval == "ok"} {
        $widgets(results) itemconfigure $pageID -text $tabs(tab:new_name)
    }
}
