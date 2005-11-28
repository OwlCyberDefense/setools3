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
    variable popup {}
}

proc Apol_MLS::set_Focus_to_Text {} {
    focus $Apol_MLS::widgets(results)
}

proc Apol_MLS::open {} {
    variable vals
    if {[catch {apol_GetSens} senslist]} {
        return -code error $senslist
    }
    set vals(senslist) $senslist
    if {[catch {apol_SensCats} catslist]} {
        return -code error $catslist
    }
    set vals(catslist) $catslist
}

proc Apol_MLS::close {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    array set vals {
        senslist {}      catslist {}
        enable_sens 0
        enable_cats 0
    }
}

proc Apol_MLS::goto_line { line_num } {
    variable widgets
    ApolTop::goto_line $line_num $widgets(results)
}

proc Apol_MLS::create {nb} {
    variable widgets
    variable vals

    array set vals {
        senslist {}      catslist {}
        enable_sens 0    show_cats_too 0
        enable_cats 0    show_sens_too 0
    }

    # Layout frames
    set frame [$nb insert end $ApolTop::mls_tab -text "MLS"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    $pw add -weight 0
    $pw add -weight 1
    set leftf [$pw getframe 0]
    set rightf [$pw getframe 1]
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
                -command Apol_MLS::search]
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
    if {[catch {getSensInfo $sens 1} info]} {
        tk_messageBox -icon error -type ok -title "Error" -message $info
    } else {
        Apol_Widget::showPopupText $sens $info
    }
}

proc Apol_MLS::popupCatsInfo {cats} {
    if {[catch {getCatsInfo $cats 1} info]} {
        tk_messageBox -icon error -type ok -title "Error" -message $info
        return
    }        
    Apol_Widget::showPopupText $cats $info
}

proc Apol_MLS::search {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {$vals(enable_sens) == 0 && $vals(enable_cats) == 0} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided!"
        return
    }
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
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
        append results "SENSITIVITIES:"
        set sens_list [apol_GetSens]
        if {$use_regexp} {
            set new_list {}
            foreach sens $sens_list {
                if {[regexp -- $regexp $sens]} {
                    lappend new_list $sens
                }
            }
            set sens_list $new_list
        }
        if {[llength $sens_list] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach sens $sens_list {
                append results "\n[getSensInfo $sens $vals(show_cats_too)]"
            }
        }
    }
    if {$vals(enable_cats)} {
        if {$vals(enable_sens)} {
            append results "\n\n"
        }
        append results "CATEGORIES:"
        set cats_list [apol_SensCats]
        if {$use_regexp} {
            set new_list {}
            foreach cats $cats_list {
                if {[regexp -- $regexp $cats]} {
                    lappend new_list $cats
                }
            }
            set cats_list $new_list
        }
        if {[llength $cats_list] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach cats $cats_list {
                append results "\n[getCatsInfo $cats $vals(show_sens_too)]"
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_MLS::getSensInfo {sens show_level} {
    set text $sens
    if {$show_level} {
        set cats [apol_SensCats $sens]
        set level [apol_RenderLevel [list $sens $cats]]
        append text "\n    level $level"
    }
    return $text
}

proc Apol_MLS::getCatsInfo {cats show_sens} {
    set text $cats
    if {$show_sens} {
        set sens_list [apol_CatsSens $cats]
        foreach sens $sens_list {
            append text "\n    $sens"
        }
    }
    return $text
}
