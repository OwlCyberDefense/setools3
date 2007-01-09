# Copyright (C) 2004-2007 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SELinux policy analysis
# Requires tcl and tk 8.4+, with BWidget
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_Cond_Bools
#
# The Conditional Booleans tab namespace
##############################################################
namespace eval Apol_Cond_Bools {
    variable cond_bools_list {}
    variable cond_bools_defaults
    variable cond_bools_values
    variable opts
    variable widgets
}

###############################################################
#  ::cond_bool_search_bools
#
proc Apol_Cond_Bools::search_bools {} {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    set name [string trim $opts(name)]
    if {$opts(enable_bool) && $name == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No boolean variable provided!"
        return
    }
    set results {}
    if {[catch {apol_GetBools $name $opts(use_regexp)} bools_data]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining booleans list:\n$bools_data"
        return
    }
    set results "BOOLEANS:\n"
    if {[llength $bools_data] == 0} {
        append results "Search returned no results."
    } else {
        foreach b [lsort -index 0 $bools_data] {
            append results "\n[renderBool $b $opts(show_default) $opts(show_current)]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Cond_Bools::renderBool {bool_datum show_default show_current} {
    variable cond_bools_defaults
    foreach {bool_name cur_value} $bool_datum {break}
    set text [format "%-28s" $bool_name]
    if {$show_default} {
        if {$cond_bools_defaults($bool_name)} {
            append text "  Default State: True "
        } else {
            append text "  Default State: False"
        }
    }
    if {$show_current} {
        if {$cur_value} {
            append text "  Current State: True "
        } else {
            append text "  Current State: False"
        }
    }
    return $text
}

###############################################################
#  ::cond_bool_set_bool_values_to_policy_defaults
#
proc Apol_Cond_Bools::reset_bools {} {
    variable cond_bools_defaults
    variable cond_bools_values

    # hopefully each of the traces associated with each boolean
    # triggers, causing the policy to be updated
    array set cond_bools_values [array get cond_bools_defaults]
}

###############################################################
#  ::cond_bool_set_bool_value
#
proc Apol_Cond_Bools::set_bool_value {name1 name2 op} {
    variable cond_bools_values
    apol_SetBoolValue $name2 $cond_bools_values($name2)
}

################################################################
#  ::insert_listbox_item
#
proc Apol_Cond_Bools::insert_listbox_item {bool_datum} {
    variable widgets
    variable cond_bools_values

    set subf [$widgets(listbox) getframe]
    foreach {bool_name bool_value} $bool_datum {break}
    set cond_bools_values($bool_name) $bool_value
    set rb_true [radiobutton $subf.t:$bool_name -bg white \
                     -variable Apol_Cond_Bools::cond_bools_values($bool_name) \
                     -value 1 -highlightthickness 0 -text "True"]
    set rb_false [radiobutton $subf.f:$bool_name -bg white \
                      -variable Apol_Cond_Bools::cond_bools_values($bool_name) \
                      -value 0 -highlightthickness 0 -text "False"]
    trace add variable Apol_Cond_Bools::cond_bools_values($bool_name) write \
        [list Apol_Cond_Bools::set_bool_value]
    set rb_label [label $subf.l:$bool_name -bg white -text "- $bool_name"]
    grid $rb_true $rb_false $rb_label -padx 2 -pady 5 -sticky w
}

################################################################
# ::search
#	- Search text widget for a string
#
proc Apol_Cond_Bools::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

################################################################
# ::goto_line
#	- goes to indicated line in text box
#
proc Apol_Cond_Bools::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

################################################################
# ::set_Focus_to_Text
#
proc Apol_Cond_Bools::set_Focus_to_Text {} {
    focus $Apol_Cond_Bools::widgets(results)
}

################################################################
#  ::open
#
proc Apol_Cond_Bools::open {} {
    variable cond_bools_list {}
    variable cond_bools_defaults
    variable widgets

    foreach bool_datum [lsort [apol_GetBools {} 0]] {
        foreach {name value} $bool_datum {break}
        lappend cond_bools_list $name
        set cond_bools_defaults($name) $value
        insert_listbox_item $bool_datum
    }
    $widgets(listbox) xview moveto 0
    $widgets(listbox) yview moveto 0
    $widgets(listbox) configure -areaheight 0 -areawidth 0
    $widgets(combo_box) configure -values $cond_bools_list
}

################################################################
#  ::close
#
proc Apol_Cond_Bools::close { } {
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

################################################################
#  ::create
#
proc Apol_Cond_Bools::create {nb} {
    variable opts
    variable widgets

    initializeVars

    # Layout frames
    set frame [$nb insert end $ApolTop::cond_bools_tab -text "Booleans"]
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
