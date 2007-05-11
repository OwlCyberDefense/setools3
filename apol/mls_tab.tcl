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

namespace eval Apol_MLS {
    variable widgets
    variable vals
}

proc Apol_MLS::set_Focus_to_Text {} {
    focus $Apol_MLS::widgets(results)
}

proc Apol_MLS::open {} {
    variable vals

    set q [new_apol_level_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set vals(senslist) [lsort [level_vector_to_list $v]]
    $v -delete

    set q [new_apol_cat_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set vals(catslist) [lsort [cat_vector_to_list $v]]
    $v -delete
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

proc Apol_MLS::search {str case_Insensitive regExpr srch_Direction} {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_MLS::goto_line {line_num} {
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

# Given a sensitivity name, return a non-empty string if that
# sensitivity is within the loaded policy.  This string is the same as
# the given parameter if the name is a sensitivity; it will be the
# real sensitivity's name if the parameter is an alias.  If no policy
# has been loaded then return an empty string.
proc Apol_MLS::isSensInPolicy {sens} {
    variable vals
    if {![ApolTop::is_policy_open]} {
        return {}
    }
    if {[lsearch $vals(senslist) $sens] >= 0} {
        return $sens
    }
    # try looking up aliases
    foreach s $vals(senslist) {
        set qpol_level_t [new_qpol_level_t $::ApolTop::qpolicy $s]
        set i [$qpol_level_t get_alias_iter $::ApolTop::qpolicy]
        set l [iter_to_str_list $i]
        $i -delete
        if {[lsearch $l $sens] >= 0} {
            return $s
        }
    }
    return {}
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
    Apol_Widget::showPopupText $sens [renderLevel $sens 1]
}

proc Apol_MLS::popupCatsInfo {cats} {
    Apol_Widget::showPopupText $cats [renderCats $cats 1]
}

proc Apol_MLS::runSearch {} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {$vals(enable_sens) == 0 && $vals(enable_cats) == 0} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided."
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
        set q [new_apol_level_query_t]
        $q set_sens $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete

        set level_data {}
        for {set i 0} {$i < [$v get_size]} {incr i} {
            set qpol_level_datum [new_qpol_level_t [$v get_element $i]]
            set level_name [$qpol_level_datum get_name $::ApolTop::qpolicy]
            set level_value [$qpol_level_datum get_value $::ApolTop::qpolicy]
            lappend level_data [list $level_name $level_value]
        }
        $v -delete

        append results "SENSITIVITIES (ordered by dominance from low to high):"
        if {[llength $level_data] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach l [lsort -integer -index 1 $level_data] {
                append results "\n[renderLevel [lindex $l 0] $vals(show_cats_too)]"
            }
        }
    }
    if {$vals(enable_cats)} {
        if {$vals(enable_sens)} {
            append results "\n\n"
        }
        
        set q [new_apol_cat_query_t]
        $q set_cat $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete

        set cats_data {}
        for {set i 0} {$i < [$v get_size]} {incr i} {
            set qpol_cat_datum [new_qpol_cat_t [$v get_element $i]]
            set cat_name [$qpol_cat_datum get_name $::ApolTop::qpolicy]
            set cat_value [$qpol_cat_datum get_value $::ApolTop::qpolicy]
            lappend cats_data [list $cat_name $cat_value]
        }
        $v -delete

        append results "CATEGORIES (ordered by appearance within policy):"
        if {[llength $cats_data] == 0} {
            append results "\nSearch returned no results."
        } else {
            foreach c [lsort -integer -index 1 $cats_data] {
                append results "\n[renderCats [lindex $c 0] $vals(show_sens_too)]"
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_MLS::renderLevel {level_name show_level} {
    set qpol_level_datum [new_qpol_level_t $::ApolTop::qpolicy $level_name]
    set i [$qpol_level_datum get_alias_iter $::ApolTop::qpolicy]
    set aliases [iter_to_str_list $i]
    $i -delete

    set text $level_name
    if {[llength $aliases] > 0} {
        append text " alias \{$aliases\}"
    }
    if {$show_level} {
        set i [$qpol_level_datum get_cat_iter $::ApolTop::qpolicy]
        set num_cats [$i get_size]
        $i -delete
        append text " ($num_cats categor"
        if {$num_cats == 1} {
            append text "y)"
        } else {
            append text "ies)"
        }
        set level [new_apol_mls_level_t $::ApolTop::policy $qpol_level_datum]
        append text "\n    level [$level render $::ApolTop::policy]\n"
        $level -delete
    }
    return $text
}

proc Apol_MLS::renderCats {cat_name show_sens} {
    set qpol_cat_datum [new_qpol_cat_t $::ApolTop::qpolicy $cat_name]
    set i [$qpol_cat_datum get_alias_iter $::ApolTop::qpolicy]
    set aliases [iter_to_str_list $i]
    $i -delete

    set text $cat_name
    if {[llength $aliases] > 0} {
        append text " alias \{$aliases\}"
    }
    if {$show_sens} {
        append text "\n"
        set q [new_apol_level_query_t]
        $q set_cat $::ApolTop::policy $cat_name
        set v [$q run $::ApolTop::policy]
        $q -delete
        set sens_list {}
        for {set i 0} {$i < [$v get_size]} {incr i} {
            set qpol_level_datum [new_qpol_level_t [$v get_element $i]]
            set level_name [$qpol_level_datum get_name $::ApolTop::qpolicy]
            set level_value [$qpol_level_datum get_value $::ApolTop::qpolicy]
            lappend sens_list [list $level_name $level_value]
        }
        $v -delete
        foreach s [lsort -integer -index 1 $sens_list] {
            append text "    [lindex $s 0]\n"
        }
    }
    return $text
}
