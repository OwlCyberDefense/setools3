# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets

##############################################################
# ::Apol_Class_Perms
#  
# The Classes/Permissions page
##############################################################
namespace eval Apol_Class_Perms {
    variable class_list {}
    variable common_perms_list {}
    variable perms_list {}
    variable opts
    variable widgets
}

proc Apol_Class_Perms::open { } {
    variable class_list {}
    foreach class [lsort -index 0 [apol_GetClasses {} 0]] {
        lappend class_list [lindex $class 0]
    }
    variable common_perms_list {}
    foreach common [lsort -index 0 [apol_GetCommons {} 0]] {
        lappend common_perms_list [lindex $common 0]
    }
    variable perms_list {}
    foreach perm [lsort -index 0 [apol_GetPerms {} 0]] {
        lappend perms_list [lindex $perm 0]
    }
}

proc Apol_Class_Perms::close { } {
    variable class_list {}
    variable common_perms_list {}
    variable perms_list {}
    variable opts
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    array set opts {
        classes:show 1  classes:perms 0  classes:commons 0
        commons:show 0  commons:perms 0  commons:classes 0
        perms:show 0    perms:classes 0  perms:commons 0
    }
}

proc Apol_Class_Perms::free_call_back_procs { } {
}

proc Apol_Class_Perms::set_Focus_to_Text {} {
    focus $Apol_Class_Perms::widgets(results)
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Class_Perms::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

proc Apol_Class_Perms::popupInfo {which name} {
    if {$which == "class"} {
        set text [renderClass [lindex [apol_GetClasses $name] 0] 1 0]
    } elseif {$which == "common"} {
        set text [renderCommon [lindex [apol_GetCommons $name] 0] 1 0]
    } else {
        set text [renderPerm [lindex [apol_GetPerms $name] 0] 1 1]
    }
    Apol_Widget::showPopupText $name $text
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Class_Perms::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_Class_Perms::search_Class_Perms {} {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {!$opts(classes:show) && !$opts(commons:show) && !$opts(perms:show)} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided!"
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
        if {[catch {apol_GetClasses $regexp $use_regexp} classes_data]} {
            tk_messageBox -icon error -type ok -title Error -message "Error obtaining classes list:\n$classes_data"
            return
        }
        append results "OBJECT CLASSES:\n"
        if {$classes_data == {}} {
            append results "Search returned no results.\n"
        } else {
            foreach c [lsort -index 0 $classes_data] {
                append results [renderClass $c $opts(classes:perms) $classes_commons]
            }
        }
    }

    if {$opts(commons:show)} {
        if {[catch {apol_GetCommons $regexp $use_regexp} commons_data]} {
            tk_messageBox -icon error -type ok -title Error -message "Error obtaining common permissions list:\n$commons_data"
            return
        }
        append results "\nCOMMON PERMISSIONS:  \n"
        if {$commons_data == {}} {
            append results "Search returned no results.\n"
        } else {
            foreach c [lsort -index 0 $commons_data] {
                append results [renderCommon $c $opts(commons:perms) $opts(commons:classes)]
            }
        }
    }

    if {$opts(perms:show)} {
        if {[catch {apol_GetPerms $regexp $use_regexp} perms_data]} {
            tk_messageBox -icon error -type ok -title Error -message "Error obtaining permissions list:\n$perms_data"
            return
        }
        append results "\nPERMISSIONS"
        if {$opts(perms:classes)} {
            append results "  (* means class uses permission via a common permission)"
        }
        append results ":\n"
        if {$perms_data == {}} {
            append results "Search returned no results.\n"
        } else {
            foreach p [lsort -index 0 $perms_data] {
                append results [renderPerm $p $opts(perms:classes) $opts(perms:commons)]
            }
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) [string trim $results]
}

proc Apol_Class_Perms::renderClass {class_datum show_perms expand_common} {
    foreach {class_name common_class perms_list} $class_datum {break}
    set text "$class_name\n"
    if {$show_perms} {
        foreach perm [lsort $perms_list] {
            append text "    $perm\n"
        }
        if {$common_class != {}} {
            append text "    $common_class  (common perm)\n"
            if {$expand_common} {
                foreach perm [lsort [lindex [apol_GetCommons $common_class] 0 1]] {
                    append text "        $perm\n"
                }
            }
        }
        append text \n
    }
    return $text
}

proc Apol_Class_Perms::renderCommon {common_datum show_perms show_classes} {
    foreach {common_name perms_list classes_list} $common_datum {break}
    set text "$common_name\n"
    if {$show_perms} {
        foreach perm [lsort $perms_list] {
            append text "    $perm\n"
        }
    }
    if {$show_classes} {
        append text "  Object classes that use this common permission:\n"
        foreach class [lsort $classes_list] {
            append text "      $class\n"
        }
    }
    if {$show_perms || $show_classes} {
        append text "\n"
    }
    return $text
}

proc Apol_Class_Perms::renderPerm {perm_datum show_classes show_commons} {
    foreach {perm_name classes_list commons_list} $perm_datum {break}
    set text "$perm_name\n"
    if {$show_classes} {
        append text "  object classes:\n"
        # recurse through each class that inherits from a commons
        foreach common $commons_list {
            foreach class [lindex [apol_GetCommons $common] 0 2] {
                lappend classes_list ${class}*
            }
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

proc Apol_Class_Perms::create {nb} {
    variable opts
    variable widgets

    array set opts {
        classes:show 1  classes:perms 0  classes:commons 0
        commons:show 0  commons:perms 0  commons:classes 0
        perms:show 0    perms:classes 0  perms:commons 0
    }

    # Layout frames
    set frame [$nb insert end $ApolTop::class_perms_tab -text "Classes/Perms"]

    # Paned Windows
    set pw1 [PanedWindow $frame.pw -side top]
    set left_pane   [$pw1 add -weight 0]
    set center_pane [$pw1 add -weight 1]
    set pw2 [PanedWindow $left_pane.pw -side left]
    set class_pane  [$pw2 add -weight 1]
    set common_pane [$pw2 add -weight 0]
    set perms_pane  [$pw2 add -weight 1]

    # Major subframes
    set classes_box [TitleFrame $class_pane.tbox -text "Object Classes"]
    set common_box  [TitleFrame $common_pane.tbox -text "Common Permissions"]
    set perms_box   [TitleFrame $perms_pane.tbox -text "Permissions"]
    set options_box [TitleFrame $center_pane.obox -text "Search Options"]
    set results_box [TitleFrame $center_pane.rbox -text "Search Results"]

    # Placing layout frames and major subframe
    pack $classes_box -fill both -expand yes
    pack $common_box -fill both -expand yes
    pack $perms_box -fill both -expand yes
    pack $options_box -padx 2 -fill both -expand 0
    pack $results_box -padx 2 -fill both -expand yes
    pack $pw1 -fill both -expand yes
    pack $pw2 -fill both -expand yes

    # Object Classes listbox
    set class_listbox [Apol_Widget::makeScrolledListbox [$classes_box getframe].lb -height 10 -width 20 -listvar Apol_Class_Perms::class_list]
    Apol_Widget::setListboxCallbacks $class_listbox \
        {{"Display Object Class Info" {Apol_Class_Perms::popupInfo class}}}
    pack $class_listbox -fill both -expand yes

    # Common Permissions listbox
    set common_listbox [Apol_Widget::makeScrolledListbox [$common_box getframe].lb -height 5 -width 20 -listvar Apol_Class_Perms::common_perms_list]
    Apol_Widget::setListboxCallbacks $common_listbox \
        {{"Display Common Permission Class Info" {Apol_Class_Perms::popupInfo common}}}
    pack $common_listbox -fill both -expand yes

    # Permissions listbox 
    set perms_listbox [Apol_Widget::makeScrolledListbox [$perms_box getframe].lb -height 10 -width 20 -listvar Apol_Class_Perms::perms_list]
    Apol_Widget::setListboxCallbacks $perms_listbox \
        {{"Display Permission Info" {Apol_Class_Perms::popupInfo perm}}}
    pack $perms_listbox -fill both -expand yes

    # Search options section      
    set ofm [$options_box getframe]

    # First set of checkbuttons
    set classesfm [frame $ofm.classes -relief sunken -borderwidth 1]
    set classes [checkbutton $classesfm.classes -text "Object Classes" \
                     -variable Apol_Class_Perms::opts(classes:show)]
    set perms [checkbutton $classesfm.perms -text "Include Perms" \
                   -variable Apol_Class_Perms::opts(classes:perms) -padx 10]
    set commons [checkbutton $classesfm.commons -text "Expand Common Perms" \
                     -variable Apol_Class_Perms::opts(classes:commons) \
                     -state disabled -padx 10]
    trace add variable Apol_Class_Perms::opts(classes:show) write \
        [list Apol_Class_Perms::toggleCheckbuttons $perms $commons]
    trace add variable Apol_Class_Perms::opts(classes:perms) write \
        [list Apol_Class_Perms::toggleCheckbuttons $commons {}]
    pack $classes $perms $commons -anchor w

    # Second set of checkbuttons
    set commonsfm [frame $ofm.commons -relief sunken -borderwidth 1]
    set commons [checkbutton $commonsfm.commons -text "Common Permissions" \
                     -variable Apol_Class_Perms::opts(commons:show)]
    set perms [checkbutton $commonsfm.perms2 -text "Include Perms" \
                   -variable Apol_Class_Perms::opts(commons:perms) \
                   -state disabled -padx 10]
    set classes [checkbutton $commonsfm.classes -text "Object Classes" \
                     -variable Apol_Class_Perms::opts(commons:classes) \
                     -state disabled -padx 10]
    trace add variable Apol_Class_Perms::opts(commons:show) write \
        [list Apol_Class_Perms::toggleCheckbuttons $perms $classes]
    pack $commons $perms $classes -anchor w

    # Third set of checkbuttons
    set permsfm [frame $ofm.perms -relief sunken -borderwidth 1]
    set perms [checkbutton $permsfm.prems -text "Permissions" \
                   -variable Apol_Class_Perms::opts(perms:show)]
    set classes [checkbutton $permsfm.classes -text "Object Classes" \
                     -variable Apol_Class_Perms::opts(perms:classes) \
                     -state disabled -padx 10]
    set commons [checkbutton $permsfm.commons -text "Common Perms" \
                     -variable Apol_Class_Perms::opts(perms:commons) \
                     -state disabled -padx 10]
    trace add variable Apol_Class_Perms::opts(perms:show) write \
        [list Apol_Class_Perms::toggleCheckbuttons $classes $commons]
    pack $perms $classes $commons -anchor w

    set widgets(regexp) [Apol_Widget::makeRegexpEntry $ofm.regexp]

    pack $classesfm $commonsfm $permsfm $widgets(regexp) \
        -side left -padx 5 -pady 4 -anchor ne

    set ok [button $ofm.ok -text OK -width 6 \
                -command Apol_Class_Perms::search_Class_Perms]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$results_box getframe].results]
    pack $widgets(results) -expand yes -fill both 

    return $frame	
}

proc Apol_Class_Perms::toggleCheckbuttons {cb1 cb2 name1 name2 op} {
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
