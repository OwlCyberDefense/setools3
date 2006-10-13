# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget


##############################################################
# ::Apol_MLS
#
#
##############################################################
namespace eval Apol_MLS {
    variable widgets
    variable vals
}

proc Apol_MLS::set_Focus_to_Text {} {
    focus $Apol_MLS::widgets(results)
}

proc Apol_MLS::open {} {
    variable vals
    set vals(senslist) {}
    foreach s [lsort -integer -index 3 [apol_GetLevels {} 0]] {
        lappend vals(senslist) [lindex $s 0]
    }
    set vals(catslist) {}
    foreach c [lsort -integer -index 3 [apol_GetCats {} 0]] {
        lappend vals(catslist) [lindex $c 0]
    }
}

proc Apol_MLS::close {} {
    variable widgets

    initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_MLS::initializeVars {} {
    variable vals
    array set vals {
        senslist {}      catslist {}
        enable_sens 1    show_cats_too 1
        enable_cats 0    show_sens_too 1
    }
}

proc Apol_MLS::search { str case_Insensitive regExpr srch_Direction } {
	variable widgets
	ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_MLS::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

proc Apol_MLS::create {nb} {
    variable widgets
    variable vals

    initializeVars

    # Layout frames
    set frame [$nb insert end $ApolTop::mls_tab -text "MLS"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    # build the left column, where one may browse sensitivities and categories
    set sensbox [TitleFrame $leftf.sensbox -text "Sensitivities"]
    set catsbox [TitleFrame $leftf.catsbox -text "Categories"]
    pack $sensbox -fill both -expand 0
    pack $catsbox -fill both -expand yes

    set sensbox [Apol_Widget::makeScrolledListbox [$sensbox getframe].sens \
                     -height 10 -width 20 -listvar Apol_MLS::vals(senslist)]
    Apol_Widget::setListboxCallbacks $sensbox \
        {{"Show Sensitivity Info" {Apol_MLS::popupSensInfo}}}
    pack $sensbox -expand 1 -fill both
    set catsbox [Apol_Widget::makeScrolledListbox [$catsbox getframe].cats \
                     -height 16 -width 20 -listvar Apol_MLS::vals(catslist)]
    Apol_Widget::setListboxCallbacks $catsbox \
        {{"Show Category Info" {Apol_MLS::popupCatsInfo}}}
    pack $catsbox -expand 1 -fill both

    # build the search options
    set optsbox [TitleFrame $rightf.optsbox -text "Search Options"]
    pack $optsbox -side top -expand 0 -fill both -padx 2
    set sensf [frame [$optsbox getframe].sensf]
    set catsf [frame [$optsbox getframe].catsf]
    pack $sensf $catsf -side left -padx 4 -pady 2 -anchor nw

    set enable_sens [checkbutton $sensf.enable -text "Sensitivities" \
                         -variable Apol_MLS::vals(enable_sens)]
    set show_cats [checkbutton $sensf.cats -text "Show levels (categories)" \
                       -variable Apol_MLS::vals(show_cats_too)]
    trace add variable Apol_MLS::vals(enable_sens) write \
        [list Apol_MLS::toggleCheckbutton $show_cats]
    pack $enable_sens -side top -anchor nw
    pack $show_cats -side top -anchor nw -padx 8

    set enable_cats [checkbutton $catsf.enable -text "Categories" \
                         -variable Apol_MLS::vals(enable_cats)]
    set show_sens [checkbutton $catsf.cats -text "Show sensitivities" \
                       -variable Apol_MLS::vals(show_sens_too) -state disabled]
    trace add variable Apol_MLS::vals(enable_cats) write \
        [list Apol_MLS::toggleCheckbutton $show_sens]
    pack $enable_cats -side top -anchor nw
    pack $show_sens -side top -anchor nw -padx 8

    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$optsbox getframe].regexpf]
    pack $widgets(regexp) -side left -padx 4 -pady 2 -anchor nw

    set ok [button [$optsbox getframe].ok -text "OK" -width 6 \
                -command Apol_MLS::runSearch]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # build the results box
    set resultsbox [TitleFrame $rightf.resultsbox -text "Search Results"]
    pack $resultsbox -expand yes -fill both -padx 2
    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}

#### private functions below ####

proc Apol_MLS::toggleCheckbutton {path name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $path configure -state normal
    } else {
        $path configure -state disabled
    }
    if {$vals(enable_sens) == 0 && $vals(enable_cats) == 0} {
        Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    } else {
        Apol_Widget::setRegexpEntryState $widgets(regexp) 1
    }
}

proc Apol_MLS::popupSensInfo {sens} {
    set sens_datum [lindex [apol_GetLevels $sens] 0]
    Apol_Widget::showPopupText $sens [renderLevel $sens_datum 1]
}

proc Apol_MLS::popupCatsInfo {cats} {
    set cats_datum [lindex [apol_GetCats $cats] 0]
    Apol_Widget::showPopupText $cats [renderCats $cats_datum 1]
}

proc Apol_MLS::runSearch {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {$vals(enable_sens) == 0 && $vals(enable_cats) == 0} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided!"
        return
    }
    set results ""
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    if {$use_regexp} {
        set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
        if {$regexp == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided."
            return
        }
    } else {
        set regexp {}
    }
    if {$vals(enable_sens)} {
        if {[catch {apol_GetLevels $regexp $use_regexp} level_data]} {
            tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining sensitivities list:\n$level_data"
            return
        }
        append results "SENSITIVITIES (ordered by dominance from low to high):"
        if {[llength $level_data] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach l [lsort -integer -index 3 $level_data] {
                append results "\n[renderLevel $l $vals(show_cats_too)]"
            }
        }
    }
    if {$vals(enable_cats)} {
        if {$vals(enable_sens)} {
            append results "\n\n"
        }
        if {[catch {apol_GetCats $regexp $use_regexp} cats_data]} {
            tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining categories list:\n$cats_data"
            return
        }
        append results "CATEGORIES (ordered by appearance within policy):"
        if {[llength $cats_data] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach c [lsort -integer -index 3 $cats_data] {
                append results "\n[renderCats $c $vals(show_sens_too)]"
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_MLS::renderLevel {level_datum show_level} {
    foreach {sens aliases cats dom_value} $level_datum {break}
    set text $sens
    if {[llength $aliases] > 0} {
        append text " alias \{$aliases\}"
    }
    if {$show_level} {
        append text " ([llength $cats] categor"
        if {[llength $cats] == 1} {
            append text "y)"
        } else {
            append text "ies)"
        }
        append text "\n    level [apol_RenderLevel [list $sens $cats]]\n"
    }
    return $text
}

proc Apol_MLS::renderCats {cats_datum show_sens} {
    foreach {cats aliases sens cat_value} $cats_datum {break}
    set text $cats
    if {[llength $aliases] > 0} {
        append text " alias \{$aliases\}"
    }
    append text "\n"
    if {$show_sens} {
        set sens_list {}
        foreach s $sens {
            lappend sens_list [lindex [apol_GetLevels $s] 0]
        }
        foreach s [lsort -integer -index 3 $sens_list] {
            append text "    [lindex $s 0]\n"
        }
    }
    return $text
}
