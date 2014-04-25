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

namespace eval Apol_Namespaces {
    variable widgets
    variable namespace_list {}
}

proc Apol_Namespaces::create {tab_name nb} {
    variable widgets
    variable namespace_list {}

    set frame [$nb insert end $tab_name -text "Policy Namespaces"]
    set pw [PanedWindow $frame.pw -side top]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    set namespaces_box [TitleFrame $leftf.namespaces_box -text "Policy Namespaces"]
    pack $namespaces_box -fill both -expand yes

    set nlistbox [Apol_Widget::makeScrolledListbox [$namespaces_box getframe].lb \
                      -width 60 -listvar Apol_Namespaces::namespace_list]
    Apol_Widget::setListboxCallbacks $nlistbox \
        {{"Show Namespace Users, Roles, Types, Attributes and Classes Info" {Apol_Namespaces::popupNsInfo nfi}}}
    pack $nlistbox -expand 1 -fill both
    pack $nlistbox -fill both -expand yes

    return $frame
}

proc Apol_Namespaces::open {ppath} {
    variable namespace_list {}

    append list1 "$Apol_Users::users_list $Apol_Roles::role_list $Apol_Types::typelist $Apol_Types::attriblist $Apol_Class_Perms::class_list"
    set names [split $list1 " "]
    # Split on the ns separator, chop off the end entry then add "." back
    set list1 {}
    foreach n $names {
        set ns [split $n "."]
        set ns [lreplace $ns end end]
        set l [string length $ns]
        if {$l > 0} {
            regsub -all " " $ns "." ns
            lappend list1 "$ns"
        }
    }
    set list2 {}
    set namespace_list "GLOBAL-NS\n"
    lappend list2 [lsort -dictionary -unique $list1]

    foreach entry $list2 {
        append namespace_list "$entry\n"
    }
}

proc Apol_Namespaces::close {} {
    variable namespace_list {}

    set namespace_list {}
}

proc Apol_Namespaces::getTextWidget {} {
    variable widgets
}


proc Apol_Namespaces::popupNsInfo {which ns} {

    set w .ns_infobox
    destroy $w

    set w [Dialog .ns_infobox -cancel 0 -default 0 -modal none -parent . -separator 1 -title $ns]
    $w add -text "Close" -command [list destroy $w]

    set notebook [NoteBook [$w getframe].nb]
    pack $notebook -expand 1 -fill both

    set user_info_tab [$notebook insert end user_info_tab -text "Users"]
    set role_info_tab [$notebook insert end role_info_tab -text "Roles"]
    set type_info_tab [$notebook insert end type_info_tab -text "Types"]
    set attrib_info_tab [$notebook insert end attrib_info_tab -text "Attributes"]
    set class_info_tab [$notebook insert end class_info_tab -text "Classes"]
    set boolean_info_tab [$notebook insert end boolean_info_tab -text "Booleans"]

    if {[ApolTop::is_capable "mls"]} {
        set sensitivity_info_tab [$notebook insert end sensitivity_info_tab -text "Sensitivities"]
        set category_info_tab [$notebook insert end category_info_tab -text "Categories"]
    }

    # Display users
    set sw [ScrolledWindow [$notebook getframe user_info_tab].sw -scrollbar both -auto both]
    set user_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $user_text
    pack $sw -expand 1 -fill both
    Apol_Namespaces::DisplayMatches $Apol_Users::users_list $user_text $ns "users"

    # Display roles
    set sw [ScrolledWindow [$notebook getframe role_info_tab].sw -scrollbar both -auto both]
    set role_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $role_text
    pack $sw -expand 1 -fill both
    Apol_Namespaces::DisplayMatches $Apol_Roles::role_list $role_text $ns "roles"

    # Display types
    set sw [ScrolledWindow [$notebook getframe type_info_tab].sw -scrollbar both -auto both]
    set type_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $type_text
    pack $sw -expand 1 -fill both
    Apol_Namespaces::DisplayMatches $Apol_Types::typelist $type_text $ns "types"

    # Display attributes
    set sw [ScrolledWindow [$notebook getframe attrib_info_tab].sw -scrollbar both -auto both]
    set attrib_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $attrib_text
    pack $sw -expand 1 -fill both
    Apol_Namespaces::DisplayMatches $Apol_Types::attriblist $attrib_text $ns "attributes"

    # Display classes
    set sw [ScrolledWindow [$notebook getframe class_info_tab].sw -scrollbar both -auto both]
    set class_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $class_text
    pack $sw -expand 1 -fill both
    Apol_Namespaces::DisplayMatches $Apol_Class_Perms::class_list $class_text $ns "classes"

    # Display booleans
    set sw [ScrolledWindow [$notebook getframe boolean_info_tab].sw -scrollbar both -auto both]
    set boolean_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $boolean_text
    pack $sw -expand 1 -fill both
    Apol_Namespaces::DisplayMatches $Apol_Cond_Bools::cond_bools_list $boolean_text $ns "booleans"

    if {[ApolTop::is_capable "mls"]} {
        # Display sensitivities
        set sw [ScrolledWindow [$notebook getframe sensitivity_info_tab].sw -scrollbar both -auto both]
        set sensitivity_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
        $sw setwidget $sensitivity_text
        pack $sw -expand 1 -fill both
        Apol_Namespaces::DisplayMatches $Apol_MLS::vals(senslist) $sensitivity_text $ns "sensitivities"

        # Display categories
        set sw [ScrolledWindow [$notebook getframe category_info_tab].sw -scrollbar both -auto both]
        set category_text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
        $sw setwidget $category_text
        pack $sw -expand 1 -fill both
        Apol_Namespaces::DisplayMatches $Apol_MLS::vals(catslist) $category_text $ns "categories"
    }

    $notebook raise [$notebook page 0]
    $w draw {} 0 600x400
}

proc Apol_Namespaces::DisplayMatches {item_list display_entry ns text} {
    set counter 0
    set print_list {}

    if {$ns == "GLOBAL-NS"} {
        set ns {}
        set off_set 0
    } else {
        set off_set 1
    }
    # Get len of the ns selected
    set l [string length $ns]
    #For each entry check if in this ns
    foreach t $item_list {
        set i [string compare -length $l $t $ns]
        # kludge to get round a problem.
        # If $z is same as $ns, but no . in $t then ignore as $t just
        # happens to begin with a match to $ns. So reset $i
        set z [string range $t 0 $l-1]
        if {![regexp -nocase {[.]} $t] && $z == $ns && $ns != ""} {
            set i 1
        }

        if {$i == 0} {
            set x [string range $t $l+$off_set end]
            if {![regexp -nocase {[.]} $x]} {
                append print_list "    $x\n"
                set counter [expr $counter + 1]
            }
        }
    }
    if {$counter == 0} {
        $display_entry insert end "No entries\n"
    } else {
        if {$ns == ""} {
            set ns "global"
        }
        $display_entry insert end "$ns namespace ($counter $text)\n$print_list"
    }
    $display_entry configure -state disabled

}
