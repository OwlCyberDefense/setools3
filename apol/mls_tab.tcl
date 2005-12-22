# Copyright (C) 2001-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets


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
    foreach s [lsort -index 0 -dictionary [apol_GetSens]] {
        lappend vals(senslist) [lindex $s 0]
    }
    set vals(catslist) {}
    foreach c [lsort -index 0 -dictionary [apol_GetCats]] {
        lappend vals(catslist) [lindex $c 0]
    }
}

proc Apol_MLS::close {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    array set vals {
        senslist {}      catslist {}
        enable_sens 1    show_cats_too 1
        enable_cats 0    show_sens_too 0
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

    array set vals {
        senslist {}      catslist {}
        enable_sens 1    show_cats_too 1
        enable_cats 0    show_sens_too 0
    }

    # Layout frames
    set frame [$nb insert end $ApolTop::mls_tab -text "MLS"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    # build the left column, where one may browse sensitivities and categories
    set leftpw [PanedWindow $leftf.pw -side left]
    $leftpw add -weight 1
    $leftpw add -weight 1
    set sensbox [TitleFrame [$leftpw getframe 0].sensbox -text "Sensitivities"]
    set catsbox [TitleFrame [$leftpw getframe 1].catsbox -text "Categories"]
    pack $sensbox -fill both -expand yes
    pack $catsbox -fill both -expand yes
    pack $leftpw -fill both -expand yes

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
    set sensf [frame [$optsbox getframe].sensf -relief sunken -bd 1]
    set catsf [frame [$optsbox getframe].catsf -relief sunken -bd 1]
    pack $sensf $catsf -side left -padx 5 -pady 4 -anchor nw
    set enable_sens [checkbutton $sensf.enable -text "Sensitivities" \
                         -variable Apol_MLS::vals(enable_sens)]
    set show_cats [checkbutton $sensf.cats -text "Show Level (Categories)" \
                       -variable Apol_MLS::vals(show_cats_too) -state disabled]
    trace add variable Apol_MLS::vals(enable_sens) write \
        [list Apol_MLS::toggleCheckbutton $show_cats]
    pack $enable_sens -side top -anchor nw
    pack $show_cats -side top -anchor nw -padx 4
    
    set enable_cats [checkbutton $catsf.enable -text "Categories" \
                         -variable Apol_MLS::vals(enable_cats)]
    set show_sens [checkbutton $catsf.cats -text "Show Sensitivities" \
                       -variable Apol_MLS::vals(show_sens_too) -state disabled]
    trace add variable Apol_MLS::vals(enable_cats) write \
        [list Apol_MLS::toggleCheckbutton $show_sens]
    pack $enable_cats -side top -anchor nw
    pack $show_sens -side top -anchor nw -padx 4

    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$optsbox getframe].regexpf]
    Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    pack $widgets(regexp) -side left -padx 5 -pady 4 -anchor nw

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
    Apol_Widget::showPopupText $sens [renderSens $sens 1]
}

proc Apol_MLS::popupCatsInfo {cats} {
    Apol_Widget::showPopupText $cats [renderCats $cats 1]
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
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    if {$use_regexp && $regexp == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided."
        return
    }
    if {$vals(enable_sens)} {
        append results "SENSITIVITIES (ordered by dominance):"
        set orig_sens_list [apol_GetSens]
        set sens_list {}
        foreach s $orig_sens_list {
            foreach {sens aliases} $s {break}
            if {$use_regexp} {
                set keep 0
                if {[regexp -- $regexp $sens]} {
                    set keep 1
                }
                foreach a $aliases {
                    if {[regexp -- $regexp $a]} {
                        set keep 1
                        break
                    }
                }
            } else {
                set keep 1
            }
            if {$keep} {
                lappend sens_list $sens                
            }
        }
        if {[llength $sens_list] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach sens $sens_list {
                append results "\n[renderSens $sens $vals(show_cats_too)]"
            }
        }
    }
    if {$vals(enable_cats)} {
        if {$vals(enable_sens)} {
            append results "\n\n"
        }
        append results "CATEGORIES:"
        set orig_cats_list [apol_GetCats]
        set cats_list {}
        foreach c $orig_cats_list {
            foreach {cats aliases} $c {break}
            if {$use_regexp} {
                set keep 0
                if {[regexp -- $regexp $cats]} {
                    set keep 1
                }
                foreach a $aliases {
                    if {[regexp -- $regexp $a]} {
                        set keep 1
                        break
                    }
                }
            } else {
                set keep 1
            }
            if {$keep} {
                lappend cats_list $cats
            }
        }
        if {[llength $cats_list] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach cats $cats_list {
                append results "\n[renderCats $cats $vals(show_sens_too)]"
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_MLS::renderSens {sens show_level} {
    set text $sens
    set aliases [lindex [apol_GetSens $sens] 0 1]
    if {[llength $aliases] > 0} {
        append text " alias \{$aliases\}"
    }
    if {$show_level} {
        set cats {}
        foreach c [apol_SensCats $sens] {
            lappend cats [lindex $c 0]
        }
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

proc Apol_MLS::renderCats {cats show_sens} {
    set text $cats
    set aliases [lindex [apol_GetCats $cats] 0 1]
    if {[llength $aliases] > 0} {
        append text " alias \{$aliases\}"
    }
    if {$show_sens} {
        set sens_list [apol_CatsSens $cats]
        foreach sens $sens_list {
            append text "\n    $sens"
        }
    }
    return $text
}
