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

namespace eval Apol_Class_Perms {
    variable class_list {}
    variable common_list {}
    variable perms_list {}
    variable opts
    variable widgets
}

proc Apol_Class_Perms::create {tab_name nb} {
    variable opts
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "Classes/Perms"]

    set pw1 [PanedWindow $frame.pw -side top]
    set left_pane   [$pw1 add -weight 0]
    set center_pane [$pw1 add -weight 1]
    set class_pane  [frame $left_pane.class]
    set common_pane [frame $left_pane.common]
    set perms_pane  [frame $left_pane.perms]

    set classes_box [TitleFrame $class_pane.tbox -text "Object Classes"]
    set common_box  [TitleFrame $common_pane.tbox -text "Common Permissions"]
    set perms_box   [TitleFrame $perms_pane.tbox -text "Permissions"]
    set options_box [TitleFrame $center_pane.obox -text "Search Options"]
    set results_box [TitleFrame $center_pane.rbox -text "Search Results"]
    pack $classes_box -fill both -expand yes
    pack $common_box -fill both -expand yes
    pack $perms_box -fill both -expand yes
    pack $options_box -padx 2 -fill both -expand 0
    pack $results_box -padx 2 -fill both -expand yes
    pack $pw1 -fill both -expand yes
    pack $class_pane $common_pane -expand 0 -fill both
    pack $perms_pane -expand 1 -fill both

    # Object Classes listbox
    set class_listbox [Apol_Widget::makeScrolledListbox [$classes_box getframe].lb -height 8 -width 20 -listvar Apol_Class_Perms::class_list]
    Apol_Widget::setListboxCallbacks $class_listbox \
        {{"Display Object Class Info" {Apol_Class_Perms::_popupInfo class}}}
    pack $class_listbox -fill both -expand yes

    # Common Permissions listbox
    set common_listbox [Apol_Widget::makeScrolledListbox [$common_box getframe].lb -height 5 -width 20 -listvar Apol_Class_Perms::common_perms_list]
    Apol_Widget::setListboxCallbacks $common_listbox \
        {{"Display Common Permission Class Info" {Apol_Class_Perms::_popupInfo common}}}
    pack $common_listbox -fill both -expand yes

    # Permissions listbox
    set perms_listbox [Apol_Widget::makeScrolledListbox [$perms_box getframe].lb -height 10 -width 20 -listvar Apol_Class_Perms::perms_list]
    Apol_Widget::setListboxCallbacks $perms_listbox \
        {{"Display Permission Info" {Apol_Class_Perms::_popupInfo perm}}}
    pack $perms_listbox -fill both -expand yes

    # Search options section
    set ofm [$options_box getframe]
    set classesfm [frame $ofm.classes]
    set commonsfm [frame $ofm.commons]
    set permsfm [frame $ofm.perms]
    pack $classesfm $commonsfm $permsfm -side left -padx 4 -pady 2 -anchor ne

    # First set of checkbuttons
    set classes [checkbutton $classesfm.classes -text "Object classes" \
                     -variable Apol_Class_Perms::opts(classes:show)]
    set perms [checkbutton $classesfm.perms -text "Include perms" \
                   -variable Apol_Class_Perms::opts(classes:perms)]
    set commons [checkbutton $classesfm.commons -text "Expand common perms" \
                     -variable Apol_Class_Perms::opts(classes:commons)]
    trace add variable Apol_Class_Perms::opts(classes:show) write \
        [list Apol_Class_Perms::_toggleCheckbuttons $perms $commons]
    trace add variable Apol_Class_Perms::opts(classes:perms) write \
        [list Apol_Class_Perms::_toggleCheckbuttons $commons {}]
    pack $classes -anchor w
    pack $perms $commons -anchor w -padx 8

    # Second set of checkbuttons
    set commons [checkbutton $commonsfm.commons -text "Common permissions" \
                     -variable Apol_Class_Perms::opts(commons:show)]
    set perms [checkbutton $commonsfm.perms2 -text "Include perms" \
                   -variable Apol_Class_Perms::opts(commons:perms) \
                   -state disabled]
    set classes [checkbutton $commonsfm.classes -text "Object classes" \
                     -variable Apol_Class_Perms::opts(commons:classes) \
                     -state disabled]
    trace add variable Apol_Class_Perms::opts(commons:show) write \
        [list Apol_Class_Perms::_toggleCheckbuttons $perms $classes]
    pack $commons -anchor w
    pack $perms $classes -anchor w -padx 8

    # Third set of checkbuttons
    set perms [checkbutton $permsfm.prems -text "Permissions" \
                   -variable Apol_Class_Perms::opts(perms:show)]
    set classes [checkbutton $permsfm.classes -text "Object classes" \
                     -variable Apol_Class_Perms::opts(perms:classes) \
                     -state disabled]
    set commons [checkbutton $permsfm.commons -text "Common perms" \
                     -variable Apol_Class_Perms::opts(perms:commons) \
                     -state disabled]
    trace add variable Apol_Class_Perms::opts(perms:show) write \
        [list Apol_Class_Perms::_toggleCheckbuttons $classes $commons]
    pack $perms -anchor w
    pack $classes $commons -anchor w -padx 8

    set widgets(regexp) [Apol_Widget::makeRegexpEntry $ofm.regexp]

    pack $widgets(regexp) -side left -padx 2 -pady 2 -anchor ne

    set ok [button $ofm.ok -text OK -width 6 \
                -command Apol_Class_Perms::_search]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$results_box getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Class_Perms::open {ppath} {
    set q [new_apol_class_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable class_list [lsort [class_vector_to_list $v]]
    $v -delete

    set q [new_apol_common_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable common_perms_list [lsort [common_vector_to_list $v]]
    $v -delete

    set q [new_apol_perm_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable perms_list [lsort [str_vector_to_list $v]]
    $v -delete
}

proc Apol_Class_Perms::close {} {
    variable class_list {}
    variable common_perms_list {}
    variable perms_list {}
    variable widgets

    _initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_Class_Perms::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

proc Apol_Class_Perms::getClasses {} {
    variable class_list
    set class_list
}

# Return a sorted list of all permissions assigned to a class.  If the
# class has a common, include the common's permissions as well.
proc Apol_Class_Perms::getPermsForClass {class_name} {
    set qpol_class_datum [new_qpol_class_t $::ApolTop::qpolicy $class_name]
    set i [$qpol_class_datum get_perm_iter $::ApolTop::qpolicy]
    set perms [iter_to_str_list $i]
    $i -delete
    if {[set qpol_common_datum [$qpol_class_datum get_common $::ApolTop::qpolicy]] != "NULL"} {
        set i [$qpol_common_datum get_perm_iter $::ApolTop::qpolicy]
        set perms [concat $perms [iter_to_str_list $i]]
        $i -delete
    }
    lsort -dictionary -unique $perms
}

# Given a permission name, return a 2-ple of lists.  The first list
# will contain all classes that directly declare the permission.  The
# second list is a list of classes that inherited from a common that
# declared the permission.  Both lists will be sorted and uniquified
# when returned.
proc Apol_Class_Perms::getClassesForPerm {perm_name} {
    set classes_list {}
    set i [$::ApolTop::qpolicy get_class_iter $perm_name]
    while {![$i end]} {
        set qpol_class_datum [new_qpol_class_t [$i get_item]]
        lappend classes_list [$qpol_class_datum get_name $::ApolTop::qpolicy]
        $i next
    }
    $i -delete
    set indirect_classes_list {}
    set i [$::ApolTop::qpolicy get_common_iter $perm_name]
    while {![$i end]} {
        set qpol_common_datum [new_qpol_common_t [$i get_item]]
        set q [new_apol_class_query_t]
        $q set_common $::ApolTop::policy [$qpol_common_datum get_name $::ApolTop::qpolicy]
        set v [$q run $::ApolTop::policy]
        $q -delete
        set indirect_classes_list [concat $indirect_classes_list [class_vector_to_list $v]]
        $v -delete
        $i next
    }
    $i -delete
    list [lsort $classes_list] [lsort -unique $indirect_classes_list]
}

#### private functions below ####

proc Apol_Class_Perms::_initializeVars {} {
    variable opts
    array set opts {
        classes:show 1  classes:perms 1  classes:commons 1
        commons:show 0  commons:perms 1  commons:classes 1
        perms:show 0    perms:classes 1  perms:commons 1
    }
}

proc Apol_Class_Perms::_popupInfo {which name} {
    if {$which == "class"} {
        set text [_renderClass $name 1 0]
    } elseif {$which == "common"} {
        set text [_renderCommon $name 1 0]
    } else {
        set text [_renderPerm $name 1 1]
    }
    Apol_Widget::showPopupText $name $text
}

proc Apol_Class_Perms::_toggleCheckbuttons {cb1 cb2 name1 name2 op} {
    variable opts
    variable widgets
    if {$opts($name2)} {
        $cb1 configure -state normal
        if {$name2 == "classes:show"} {
            if {$opts(classes:perms)} {
                $cb2 configure -state normal
            } else {
                $cb2 configure -state disabled
            }
        } elseif {$cb2 != {}} {
            $cb2 configure -state normal
        }
    } else {
        $cb1 configure -state disabled
        if {$cb2 != {}} {
            $cb2 configure -state disabled
        }
    }
    if {!$opts(classes:show) && !$opts(commons:show) && !$opts(perms:show)} {
        Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    } else {
        Apol_Widget::setRegexpEntryState $widgets(regexp) 1
    }
}

proc Apol_Class_Perms::_search {} {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {!$opts(classes:show) && !$opts(commons:show) && !$opts(perms:show)} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided."
        return
    }
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    if {$use_regexp} {
        if {$regexp == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided."
            return
        }
    } else {
        set regexp {}
    }

    set results {}

    if {$opts(classes:show)} {
        if {[set classes_perms $opts(classes:perms)]} {
            set classes_commons $opts(classes:commons)
        } else {
            set classes_commons 0
        }
        set q [new_apol_class_query_t]
        $q set_class $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete
        set classes_data [class_vector_to_list $v]
        $v -delete
        append results "OBJECT CLASSES:\n"
        if {$classes_data == {}} {
            append results "Search returned no results.\n"
        } else {
            foreach c [lsort -index 0 $classes_data] {
                append results [_renderClass $c $opts(classes:perms) $classes_commons]
            }
        }
    }

    if {$opts(commons:show)} {
        set q [new_apol_common_query_t]
        $q set_common $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete
        set commons_data [common_vector_to_list $v]
        $v -delete
        append results "\nCOMMON PERMISSIONS:  \n"
        if {$commons_data == {}} {
            append results "Search returned no results.\n"
        } else {
            foreach c [lsort -index 0 $commons_data] {
                append results [_renderCommon $c $opts(commons:perms) $opts(commons:classes)]
            }
        }
    }

    if {$opts(perms:show)} {
        set q [new_apol_perm_query_t]
        $q set_perm $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete
        set perms_data [str_vector_to_list $v]
        $v -delete
        append results "\nPERMISSIONS"
        if {$opts(perms:classes)} {
            append results "  (* means class uses permission via a common permission)"
        }
        append results ":\n"
        if {$perms_data == {}} {
            append results "Search returned no results.\n"
        } else {
            foreach p [lsort -index 0 $perms_data] {
                append results [_renderPerm $p $opts(perms:classes) $opts(perms:commons)]
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) [string trim $results]
}

proc Apol_Class_Perms::_renderClass {class_name show_perms expand_common} {
    set qpol_class_datum [new_qpol_class_t $::ApolTop::qpolicy $class_name]
    if {[set qpol_common_datum [$qpol_class_datum get_common $::ApolTop::qpolicy]] == "NULL"} {
        set common_name {}
    } else {
        set common_name [$qpol_common_datum get_name $::ApolTop::qpolicy]
    }
    set text "$class_name\n"
    if {$show_perms} {
        set i [$qpol_class_datum get_perm_iter $::ApolTop::qpolicy]
        set perms_list [iter_to_str_list $i]
        $i -delete
        foreach perm [lsort $perms_list] {
            append text "    $perm\n"
        }
        if {$common_name != {}} {
            append text "    $common_name  (common perm)\n"
            if {$expand_common} {
                set i [$qpol_common_datum get_perm_iter $::ApolTop::qpolicy]
                foreach perm [lsort [iter_to_str_list $i]] {
                    append text "        $perm\n"
                }
                $i -delete
            }
        }
        append text \n
    }
    return $text
}

proc Apol_Class_Perms::_renderCommon {common_name show_perms show_classes} {
    set qpol_common_datum [new_qpol_common_t $::ApolTop::qpolicy $common_name]
    set text "$common_name\n"
    if {$show_perms} {
        set i [$qpol_common_datum get_perm_iter $::ApolTop::qpolicy]
        foreach perm [lsort [iter_to_str_list $i]] {
            append text "    $perm\n"
        }
        $i -delete
    }
    if {$show_classes} {
        append text "  Object classes that use this common permission:\n"
        set i [$::ApolTop::qpolicy get_class_iter]
        set classes_list {}
        while {![$i end]} {
            set qpol_class_t [new_qpol_class_t [$i get_item]]
            set q [$qpol_class_t get_common $::ApolTop::qpolicy]
            if {$q != "NULL" && [$q get_name $::ApolTop::qpolicy] == $common_name} {
                lappend classes_list [$qpol_class_t get_name $::ApolTop::qpolicy]
            }
            $i next
        }
        $i -delete
        foreach class [lsort $classes_list] {
            append text "      $class\n"
        }
    }
    if {$show_perms || $show_classes} {
        append text "\n"
    }
    return $text
}

proc Apol_Class_Perms::_renderPerm {perm_name show_classes show_commons} {
    set text "$perm_name\n"
    if {$show_classes} {
        append text "  object classes:\n"
        foreach {classes_list indirect_classes_list} [getClassesForPerm $perm_name] {break}
        foreach c $indirect_classes_list {
            lappend classes_list ${c}*
        }
        if {$classes_list == {}} {
            append text "    <none>\n"
        } else {
            foreach class [lsort -uniq $classes_list] {
                append text "    $class\n"
            }
        }
    }
    if {$show_commons} {
        append text "  common permissions:\n"
        set commons_list {}
        set i [$::ApolTop::qpolicy get_common_iter $perm_name]
        while {![$i end]} {
            set qpol_common_datum [new_qpol_common_t [$i get_item]]
            lappend commons_list [$qpol_common_datum get_name $::ApolTop::qpolicy]
            $i next
        }
        $i -delete

        if {$commons_list == {}} {
            append text "    <none>\n"
        } else {
            foreach common [lsort $commons_list] {
                append text "    $common\n"
            }
        }
    }
    if {$show_classes || $show_commons} {
        append text "\n"
    }
    return $text
}
