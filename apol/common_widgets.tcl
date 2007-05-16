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

namespace eval Apol_Widget {
    variable menuPopup {}
    variable infoPopup {}
    variable infoPopup2 {}
    variable vars
}

# Create a listbox contained within a scrolled window.  Whenever the
# listbox has focus, if the user hits an alphanum key then scroll to
# the first entry beginning with that letter.  That entry is then
# selected, with all others being cleared.  Repeatedly hitting the
# same key causes the widget to select succesive entries, wrapping
# back to the first when at the end of the list.  (This behavior
# assumes that the listbox has been alphabetized.)
proc Apol_Widget::makeScrolledListbox {path args} {
    set sw [ScrolledWindow $path -scrollbar both -auto both]
    set lb [eval listbox $sw.lb $args -bg white -highlightthickness 0]
    $sw setwidget $lb

    update
    grid propagate $sw 0
    bind $lb <<ListboxSelect>> [list focus $lb]

    # if the user hits a letter while the listbox has focus, jump to
    # the first entry that begins with that letter
    bind $lb <Key> [list Apol_Widget::_listbox_key $lb %K]
    return $sw
}

# Add callback(s) to a listbox.  The callback_list is a list of
# 2-uple entries like so:
#
#  menu_name  {function ?args?}
#
# The first entry is executed upon double-clicks.
proc Apol_Widget::setListboxCallbacks {path callback_list} {
    set lb [getScrolledListbox $path]

    # add double-click on an item to immediately do something
    bind $lb <Double-Button-1> [eval list Apol_Widget::_listbox_double_click $lb [lindex $callback_list 0 1]]

    # enable right-clicks on listbox to popup a menu; that menu lets
    # the user see more info
    set lb [getScrolledListbox $path]
    bind $lb <Button-3> [list Apol_Widget::_listbox_popup %W %x %y $callback_list $lb]
}

proc Apol_Widget::getScrolledListbox {path} {
    return $path.lb
}

proc Apol_Widget::setScrolledListboxState {path newState} {
    if {$newState == 0 || $newState == "disabled"} {
        $path.lb configure -state disabled
    } else {
        $path.lb configure -state normal
    }
}

# Create combobox from which the user may choose a type.  Then create
# a combobox from which the user may select an attribute; this
# attribute filters the allowable types.
proc Apol_Widget::makeTypeCombobox {path args} {
    variable vars
    array unset vars $path:*
    set vars($path:type) ""
    set vars($path:attribenable) 0
    set vars($path:attrib) ""

    set f [frame $path]
    set type_box [eval ComboBox $f.tb -helptext {{Type or select a type}} \
                      -textvariable Apol_Widget::vars($path:type) \
                      -entrybg white -width 20 -autopost 1 $args]
    pack $type_box -side top -expand 1 -fill x

    set attrib_width [expr {[$type_box cget -width] - 4}]
    set attrib_enable [checkbutton $f.ae \
                           -anchor w -text "Filter by attribute"\
                           -variable Apol_Widget::vars($path:attribenable) \
                           -command [list Apol_Widget::_attrib_enabled $path]]
    set attrib_box [ComboBox $f.ab -autopost 1 -entrybg white -width $attrib_width \
                        -textvariable Apol_Widget::vars($path:attrib)]
    trace add variable Apol_Widget::vars($path:attrib) write [list Apol_Widget::_attrib_changed $path]
    pack $attrib_enable -side top -expand 0 -fill x -anchor sw -padx 5 -pady 2
    pack $attrib_box -side top -expand 1 -fill x -padx 9
    _attrib_enabled $path
    return $f
}

proc Apol_Widget::resetTypeComboboxToPolicy {path} {
    $path.tb configure -values [Apol_Types::getTypes]
    $path.ab configure -values [Apol_Types::getAttributes]
}

proc Apol_Widget::clearTypeCombobox {path} {
    variable vars
    set vars($path:attribenable) 0
    set vars($path:attrib) ""
    set vars($path:type) ""
    $path.tb configure -values {}
    $path.ab configure -values {}
    _attrib_enabled $path
}

# Return the currently selected type.  If an attribute is acting as a
# filter, the return value will instead be a 2-ple list of the
# selected type and the selected attribute.
proc Apol_Widget::getTypeComboboxValueAndAttrib {path} {
    variable vars
    if {$vars($path:attribenable)} {
        list [string trim $vars($path:type)] $vars($path:attrib)
    } else {
        string trim $vars($path:type)
    }
}

# Set the type and possibly attribute for a type combobox.  The first
# element of $type is the type to set.  If $type has more than one
# element, then the second element is the attribute upon which to
# filter.
proc Apol_Widget::setTypeComboboxValue {path type} {
    variable vars
    if {[llength $type] <= 1} {
        set vars($path:type) $type
        set vars($path:attribenable) 0
        set vars($path:attrib) ""
    } else {
        set vars($path:type) [lindex $type 0]
        set vars($path:attribenable) 1
        set vars($path:attrib) [lindex $type 1]
    }
    _attrib_enabled $path
}

proc Apol_Widget::setTypeComboboxState {path newState} {
    variable vars
    if {$newState == 0 || $newState == "disabled"} {
        $path.tb configure -state disabled
        $path.ae configure -state disabled
        $path.ab configure -state disabled
    } else {
        $path.tb configure -state normal
        $path.ae configure -state normal
        if {$vars($path:attribenable)} {
            $path.ab configure -state normal
        }
    }
}


# Create a mega-widget used to select a single MLS level (a
# sensitivity + 0 or more categories).
#
# @param catSize Number of categories to show in the dropdown box.
proc Apol_Widget::makeLevelSelector {path catSize args} {
    variable vars
    array unset vars $path:*
    set vars($path:sens) {}
    set vars($path:cats) {}

    set f [frame $path]
    set sens_box [eval ComboBox $f.sens $args \
                      -textvariable Apol_Widget::vars($path:sens) \
                      -entrybg white -width 16 -autopost 1]
    trace add variable Apol_Widget::vars($path:sens) write [list Apol_Widget::_sens_changed $path]
    pack $sens_box -side top -expand 0 -fill x

    set cats_label [label $f.cl -text "Categories:"]
    pack $cats_label -side top -anchor sw -pady 2 -expand 0

    set cats [makeScrolledListbox $f.cats -width 16 -height $catSize \
                  -listvariable Apol_Widget::vars($path:cats) \
                  -selectmode extended -exportselection 0]
    pack $cats -side top -expand 1 -fill both

    set reset [button $f.reset -text "Clear Categories" \
                   -command [list [getScrolledListbox $cats] selection clear 0 end]]
    pack $reset -side top -anchor center -pady 2
    return $f
}

# Return an apol_mls_level_t object that represents the level
# selected.  The caller must delete it afterwards.
proc Apol_Widget::getLevelSelectorLevel {path} {
    variable vars
    set apol_level [new_apol_mls_level_t]
    # convert sensitivity aliases to its real name, if necessary
    set l [Apol_MLS::isSensInPolicy $vars($path:sens)]
    if {[ApolTop::is_policy_open]} {
        set p $::ApolTop::policy
    } else {
        set p NULL
    }
    if {$l == {}} {
        $apol_level set_sens $p $vars($path:sens)
    } else {
        $apol_level set_sens $p $l
    }
    set sl [getScrolledListbox $path.cats]
    set cats {}
    foreach idx [$sl curselection] {
        $apol_level append_cats $p [$sl get $idx]
    }
    return $apol_level
}

# Given an apol_mls_level_t object, set the level selector's display
# to match the level.
proc Apol_Widget::setLevelSelectorLevel {path level} {
    variable vars
    if {$level == "NULL"} {
        set sens {}
    } else {
        set sens [$level get_sens]
    }
    set sens_list [$path.sens cget -values]
    if {$sens != {} && [lsearch -exact $sens_list $sens] != -1} {
        set vars($path:sens) $sens
        set cats_list $vars($path:cats)
        set first_idx -1
        set listbox [getScrolledListbox $path.cats]
        set cats [str_vector_to_list [$level get_cats]]
        foreach cat $cats {
            if {[set idx [lsearch -exact $cats_list $cat]] != -1} {
                $listbox selection set $idx
                if {$first_idx == -1 || $idx < $first_idx} {
                    set first_idx $idx
                }
            }
        }
        # scroll the listbox so that the first one selected is visible
        # near the top
        incr first_idx -1
        $listbox yview scroll $first_idx units
    }
}

proc Apol_Widget::resetLevelSelectorToPolicy {path} {
    variable vars
    set vars($path:sens) {}

    if {![ApolTop::is_policy_open]} {
        $path.sens configure -values {}
    } else {
        set level_data {}
        set i [$::ApolTop::qpolicy get_level_iter]
        while {![$i end]} {
            set qpol_level_datum [new_qpol_level_t [$i get_item]]
            if {![$qpol_level_datum get_isalias $::ApolTop::qpolicy]} {
                set level_name [$qpol_level_datum get_name $::ApolTop::qpolicy]
                set level_value [$qpol_level_datum get_value $::ApolTop::qpolicy]
                lappend level_data [list $level_name $level_value]
            }
            $i next
        }
        $i -delete
        set level_names {}
        foreach l [lsort -integer -index 1 $level_data] {
            lappend level_names [lindex $l 0]
        }
        $path.sens configure -values $level_names
    }
}

proc Apol_Widget::clearLevelSelector {path} {
    variable vars
    set vars($path:sens) {}
    $path.sens configure -values {}
    # the category box will be cleared because of the trace on $path:sens
}

proc Apol_Widget::setLevelSelectorState {path newState} {
    if {$newState == 0 || $newState == "disabled"} {
        set newState disabled
    } else {
        set newState normal
    }
    $path.sens configure -state $newState
    $path.cl configure -state $newState
    $path.reset configure -state $newState
    setScrolledListboxState $path.cats $newState
}

# Create a common "search using regular expression" checkbutton + entry.
proc Apol_Widget::makeRegexpEntry {path args} {
    variable vars
    array unset vars $path:*
    set vars($path:enable_regexp) 0

    set f [frame $path]
    set cb [checkbutton $f.cb -text "Search using regular expression" \
                -variable Apol_Widget::vars($path:enable_regexp)]
    set regexp [eval entry $f.entry $args \
                    -textvariable Apol_Widget::vars($path:regexp) \
                    -width 32 -state disabled -bg $ApolTop::default_bg_color]
    trace add variable Apol_Widget::vars($path:enable_regexp) write \
        [list Apol_Widget::_toggle_regexp_check_button $regexp]
    pack $cb -side top -anchor nw
    pack $regexp -side top -padx 4 -anchor nw -expand 0 -fill x
    return $f
}

proc Apol_Widget::setRegexpEntryState {path newState} {
    variable vars
    if {$newState == 0 || $newState == "disabled"} {
        set vars($path:enable_regexp) 0
        $path.cb configure -state disabled
    } else {
        $path.cb configure -state normal
    }
}

proc Apol_Widget::setRegexpEntryValue {path newState newValue} {
    variable vars
    set old_state [$path.cb cget -state]
    set vars($path:enable_regexp) $newState
    set vars($path:regexp) $newValue
    $path.cb configure -state $old_state
}

proc Apol_Widget::getRegexpEntryState {path} {
    return $Apol_Widget::vars($path:enable_regexp)
}

proc Apol_Widget::getRegexpEntryValue {path} {
    return $Apol_Widget::vars($path:regexp)
}

# Create a scrolled non-editable text widget, from which search
# results may be displayed.
proc Apol_Widget::makeSearchResults {path args} {
    variable vars
    array unset vars $path:*
    set sw [ScrolledWindow $path -scrollbar both -auto both]
    set tb [eval text $sw.tb $args -bg white -wrap none -state disabled -font $ApolTop::text_font]
    set vars($path:cursor) [$tb cget -cursor]
    bind $tb <Button-3> [list Apol_Widget::_searchresults_popup %W %x %y]
    $tb tag configure linenum -foreground blue -underline 1
    $tb tag configure selected -foreground red -underline 1
    $tb tag configure enabled -foreground green -underline 1
    $tb tag configure disabled -foreground red -underline 1
    $tb tag bind linenum <Button-1> [list Apol_Widget::_hyperlink $path %x %y]
    $tb tag bind linenum <Enter> [list $tb configure -cursor hand2]
    $tb tag bind linenum <Leave> [list $tb configure -cursor $Apol_Widget::vars($path:cursor)]
    $sw setwidget $tb
    return $sw
}

proc Apol_Widget::clearSearchResults {path} {
    $path.tb configure -state normal
    $path.tb delete 0.0 end
    $path.tb configure -state disabled
}

proc Apol_Widget::copySearchResults {path} {
    if {[$path tag ranges sel] != {}} {
        set data [$path get sel.first sel.last]
        clipboard clear
        clipboard append -- $data
    }
}

proc Apol_Widget::selectAllSearchResults {path} {
    $path tag add sel 1.0 end
}

proc Apol_Widget::appendSearchResultHeader {path header} {
    $path.tb configure -state normal
    $path.tb insert 1.0 "$header\n"
    $path.tb configure -state disabled
}

proc Apol_Widget::appendSearchResultText {path text} {
    $path.tb configure -state normal
    $path.tb insert end $text
    $path.tb configure -state disabled
}

# Append a list of values to the search results box.  Add $indent
# number of spaces preceeding the line.  If $linenum is non-empty,
# create a hyperlink from it to the policy.  If $cond_info is
# non-empty, then mark this line as enabled or disabled.
proc Apol_Widget::appendSearchResultLine {path indent cond_info line_type args} {
    $path.tb configure -state normal
    $path.tb insert end [string repeat " " $indent]
    set text [join [concat $line_type $args]]
    $path.tb insert end "[string trim $text];"
    if {$cond_info != {}} {
        if {[lindex $cond_info 0] == "enabled"} {
            $path.tb insert end "  \[" {} "Enabled" enabled "\]"
        } else {
            $path.tb insert end "  \[" {} "Disabled" disabled "\]"
        }
    }
    $path.tb insert end "\n"
    $path.tb configure -state disabled
}

# Append a list of avrules, as specified by their unique ids, to a
# search results box.  Sort the rules by string representation.
# Returns the number of rules that were appended, number of enabled
# rules, and number of disabled rules.
proc Apol_Widget::appendSearchResultAVRules {path indent rule_list {varname {}}} {
    set curstate [$path.tb cget -state]
    $path.tb configure -state normal
    set rules {}
    if {$varname != {}} {
        upvar $varname progressvar
        set progressvar "Sorting [llength $rule_list] semantic av rule(s)..."
        update idletasks
    }
    set rules [lsort -command apol_RenderAVRuleComp [lsort -unique $rule_list]]
    if {$varname != {}} {
        set progressvar "Rendering [llength $rules] semantic av rule(s)..."
        update idletasks
    }

    set num_enabled 0
    set num_disabled 0
    foreach r $rules {
        $path.tb insert end [string repeat " " $indent]
        foreach {rule_type source_set target_set class perms cond_info} [apol_RenderAVRule $r] {break}
        set text [list "$rule_type $source_set $target_set" {}]
        if {[llength $perms] > 1} {
            set perms "\{$perms\}"
        }
        lappend text " : $class $perms;" {}
        eval $path.tb insert end $text
        if {$cond_info != {}} {
            if {[lindex $cond_info 0] == "enabled"} {
                $path.tb insert end "  \[" {} "Enabled" enabled "\]"
                incr num_enabled
            } else {
                $path.tb insert end "  \[" {} "Disabled" disabled "\]"
                incr num_disabled
            }
        }
        $path.tb insert end "\n"
    }
    $path.tb configure -state $curstate
    list [llength $rules] $num_enabled $num_disabled
}

# Append a list of syntactic avrules, as specified by their unique
# ids, to a search results box.  The rules will be sorted by line
# number.  Returns the number of rules that were appended, number of
# enabled rules, and number of disabled rules.
proc Apol_Widget::appendSearchResultSynAVRules {path indent rules {varname {}}} {
    set curstate [$path.tb cget -state]
    $path.tb configure -state normal
    if {$varname != {}} {
        upvar $varname progressvar
        set progressvar "Rendering [llength $rules] syntactic av rule(s)..."
        update idletasks
    }

    set num_enabled 0
    set num_disabled 0
    if {[ApolTop::is_capable "line numbers"]} {
        set do_linenums 1
    } else {
        set do_linenums 0
    }
    foreach r $rules {
        $path.tb insert end [string repeat " " $indent]
        foreach {rule_type source_set target_set class perms line_num cond_info} [apol_RenderSynAVRule $r] {break}
        if {$do_linenums} {
            set text [list \[ {} \
                          $line_num linenum \
                          "\] " {} \
                          $rule_type {}]
        } else {
            set text [list $rule_type {}]
        }
        set source_set [_render_typeset $source_set]
        set target_set [_render_typeset $target_set]
        if {[llength $class] > 1} {
            set class "\{$class\}"
        }
        lappend text " $source_set $target_set" {}
        if {[llength $perms] > 1} {
            set perms "\{$perms\}"
        }
        lappend text " : $class $perms;" {}
        eval $path.tb insert end $text
        if {$cond_info != {}} {
            if {[lindex $cond_info 0] == "enabled"} {
                $path.tb insert end "  \[" {} "Enabled" enabled "\]"
                incr num_enabled
            } else {
                $path.tb insert end "  \[" {} "Disabled" disabled "\]"
                incr num_disabled
            }
        }
        $path.tb insert end "\n"
    }
    $path.tb configure -state $curstate
    list [llength $rules] $num_enabled $num_disabled
}

# Append a list of terules, as specified by their unique ids, to a
# search results box.  Sort the rules by string representation.
# Returns the number of rules that were appended, number of enabled
# rules, and number of disabled rules.
proc Apol_Widget::appendSearchResultTERules {path indent rule_list {varname {}}} {
    set curstate [$path.tb cget -state]
    $path.tb configure -state normal
    if {$varname != {}} {
        upvar $varname progressvar
        set progressvar "Sorting [llength $rule_list] semantic type rule(s)..."
        update idletasks
    }
    set rules [lsort -command apol_RenderTERuleComp [lsort -unique $rule_list]]
    if {$varname != {}} {
        set progressvar "Rendering [llength $rules] semantic type rule(s)..."
        update idletasks
    }

    set num_enabled 0
    set num_disabled 0
    foreach r $rules {
        $path.tb insert end [string repeat " " $indent]
        foreach {rule_type source_set target_set class default_type cond_info} [apol_RenderTERule $r] {break}
        set text [list "$rule_type $source_set $target_set" {}]
        lappend text " : $class $default_type;" {}
        eval $path.tb insert end $text
        if {$cond_info != {}} {
            if {[lindex $cond_info 0] == "enabled"} {
                $path.tb insert end "  \[" {} "Enabled" enabled "\]"
                incr num_enabled
            } else {
                $path.tb insert end "  \[" {} "Disabled" disabled "\]"
                incr num_disabled
            }
        }
        $path.tb insert end "\n"
    }
    $path.tb configure -state $curstate
    list [llength $rules] $num_enabled $num_disabled
}

# Append a list of syntactic terules, as specified by their unique
# ids, to a search results box.  The rules will be sorted by line
# number.  Returns the number of rules that were appended, number of
# enabled rules, and number of disabled rules.
proc Apol_Widget::appendSearchResultSynTERules {path indent rules {varname {}}} {
    set curstate [$path.tb cget -state]
    $path.tb configure -state normal
    if {$varname != {}} {
        upvar $varname progressvar
        set progressvar "Rendering [llength $rules] syntactic type rule(s)..."
        update idletasks
    }
    set num_enabled 0
    set num_disabled 0
    if {[ApolTop::is_capable "line numbers"]} {
        set do_linenums 1
    } else {
        set do_linenums 0
    }
    foreach r $rules {
        $path.tb insert end [string repeat " " $indent]
        foreach {rule_type source_set target_set class default_type line_num cond_info} [apol_RenderSynTERule $r] {break}
        if {$do_linenums} {
            set text [list \[ {} \
                          $line_num linenum \
                          "\] " {} \
                          $rule_type {}]
        } else {
            set text [list $rule_type {}]
        }
        set source_set [_render_typeset $source_set]
        set target_set [_render_typeset $target_set]
        if {[llength $class] > 1} {
            set class "\{$class\}"
        }
        lappend text " $source_set $target_set" {}
        lappend text " : $class $default_type;" {}
        eval $path.tb insert end $text
        if {$cond_info != {}} {
            if {[lindex $cond_info 0] == "enabled"} {
                $path.tb insert end "  \[" {} "Enabled" enabled "\]"
                incr num_enabled
            } else {
                $path.tb insert end "  \[" {} "Disabled" disabled "\]"
                incr num_disabled
            }
        }
        $path.tb insert end "\n"
    }
    $path.tb configure -state $curstate
    list [llength $rules] $num_enabled $num_disabled
}

proc Apol_Widget::gotoLineSearchResults {path line_num} {
    if {![string is integer -strict $line_num]} {
        tk_messageBox -icon error -type ok -title "Invalid line number" \
            -message "$line_num is not a valid line number."
        return
    }
    set textbox $path.tb
    # Remove any selection tags.
    $textbox tag remove sel 0.0 end
    $textbox mark set insert ${line_num}.0
    $textbox see ${line_num}.0
    $textbox tag add sel $line_num.0 $line_num.end
    focus $textbox
}

proc Apol_Widget::showPopupText {title info} {
    variable infoPopup
    if {![winfo exists $infoPopup]} {
        set infoPopup [toplevel .apol_widget_info_popup]
        wm withdraw $infoPopup
        set sw [ScrolledWindow $infoPopup.sw -scrollbar both -auto horizontal]
        set text [text [$sw getframe].text -font {helvetica 10} -wrap none -width 35 -height 10]
        $sw setwidget $text
        pack $sw -expand 1 -fill both
        set b [button $infoPopup.close -text "Close" -command [list destroy $infoPopup]]
        pack $b -side bottom -expand 0 -pady 5
        wm geometry $infoPopup 250x200+50+50
        update
        grid propagate $sw 0
    }
    wm title $infoPopup $title
    set text [$infoPopup.sw getframe].text
    $text configure -state normal
    $text delete 1.0 end
    $text insert 0.0 $info
    $text configure -state disabled
    wm deiconify $infoPopup
    raise $infoPopup
}

# Used to show pre-rendered paragraphs of text.
proc Apol_Widget::showPopupParagraph {title info} {
    variable infoPopup2
    if {![winfo exists $infoPopup2]} {
        set infoPopup2 [Dialog .apol_widget_info_popup2 -modal none -parent . \
                            -transient false -cancel 0 -default 0 -separator 1]
        $infoPopup2 add -text "Close" -command [list destroy $infoPopup2]
        set sw [ScrolledWindow [$infoPopup2 getframe].sw -auto both -scrollbar both]
        $sw configure -relief sunken
        set text [text [$sw getframe].text -font $ApolTop::text_font \
                      -wrap none -width 75 -height 25 -bg white]
        $sw setwidget $text
        update
        grid propagate $sw 0
        pack $sw -expand 1 -fill both -padx 4 -pady 4
        $infoPopup2 draw
    } else {
        raise $infoPopup2
        wm deiconify $infoPopup2
    }
    $infoPopup2 configure -title $title
    set text [[$infoPopup2 getframe].sw getframe].text
    $text configure -state normal
    $text delete 1.0 end
    $text insert 0.0 $info
    $text configure -state disabled
}

########## private functions below ##########

proc Apol_Widget::_listbox_key {listbox key} {
    if {[string length $key] == 1} {
        # only scroll with non-function keys
        set values [set ::[$listbox cget -listvar]]
        set x [lsearch $values $key*]
        if {$x >= 0} {
            # if the current value already begins with that letter,
            # cycle to the next one, wrapping back to the first value
            # as necessary
            set curvalue [$listbox get active]
            set curindex [$listbox curselection]
            if {$curindex != "" && [string index $curvalue 0] == $key} {
                set new_x [expr {$curindex + 1}]
                if {[string index [lindex $values $new_x] 0] != $key} {
                    # wrap around
                    set new_x $x
                }
            } else {
                set new_x $x
            }

            $listbox selection clear 0 end
            $listbox selection set $new_x
            $listbox activate $new_x
            $listbox see $new_x
        }
        event generate $listbox <<ListboxSelect>>
    }
}

proc Apol_Widget::_listbox_double_click {listbox callback_func args} {
    eval $callback_func $args [$listbox get active]
}

proc Apol_Widget::_listbox_popup {w x y callbacks lb} {
    focus $lb
    set selected_item [$lb get active]
    if {$selected_item == {}} {
        return
    }

    # create a global popup menu widget if one does not already exist
    variable menuPopup
    if {![winfo exists $menuPopup]} {
        set menuPopup [menu .apol_widget_menu_popup -tearoff 0]
    }

    ApolTop::popup $w $x $y $menuPopup $callbacks $selected_item
}

proc Apol_Widget::_attrib_enabled {path} {
    variable vars
    if {$vars($path:attribenable)} {
        $path.ab configure -state normal
        _filter_type_combobox $path $vars($path:attrib)
    } else {
        $path.ab configure -state disabled
        _filter_type_combobox $path ""
    }
}

proc Apol_Widget::_attrib_changed {path name1 name2 op} {
    variable vars
    if {$vars($path:attribenable)} {
        _filter_type_combobox $path $vars($name2)
    }
}

proc Apol_Widget::_attrib_validate {path} {
    # check that the attribute given was valid
}

proc Apol_Widget::_filter_type_combobox {path attribvalue} {
    variable vars
    if {$attribvalue != {}} {
        set typesList {}
        if {[Apol_Types::isAttributeInPolicy $attribvalue]} {
            set qpol_type_datum [new_qpol_type_t $::ApolTop::qpolicy $attribvalue]
            set i [$qpol_type_datum get_type_iter $::ApolTop::qpolicy]
            foreach t [iter_to_list $i] {
                set t [new_qpol_type_t $t]
                lappend typesList [$t get_name $::ApolTop::qpolicy]
            }
            $i -delete
        }
        if {$typesList == {}} {
            # unknown attribute, so don't change type combobox
            return
        }
    } else {
        set typesList $Apol_Types::typelist
        # during policy load this list should already have been sorted
    }
    if {[lsearch -exact $typesList $vars($path:type)] == -1} {
        set vars($path:type) {}
    }
    $path.tb configure -values [lsort $typesList]
}

proc Apol_Widget::_sens_changed {path name1 name2 op} {
    variable vars
    # get a list of categories associated with this sensitivity
    [getScrolledListbox $path.cats] selection clear 0 end
    set vars($path:cats) {}
    set sens [Apol_MLS::isSensInPolicy $vars($path:sens)]
    if {$sens != {}} {
        # the given level exists within the given policy
        set qpol_level_datum [new_qpol_level_t $::ApolTop::qpolicy $sens]
        set i [$qpol_level_datum get_cat_iter $::ApolTop::qpolicy]
        while {![$i end]} {
            set qpol_cat_datum [new_qpol_cat_t [$i get_item]]
            lappend vars($path:cats) [$qpol_cat_datum get_name $::ApolTop::qpolicy]
            $i next
        }
        $i -delete
    }
}

proc Apol_Widget::_toggle_regexp_check_button {path name1 name2 op} {
    if {$Apol_Widget::vars($name2)} {
        $path configure -state normal -bg white
    } else {
        $path configure -state disabled -bg $ApolTop::default_bg_color
    }
}

proc Apol_Widget::_searchresults_popup {path x y} {
    if {[ApolTop::is_policy_open]} {
        focus $path
        # create a global popup menu widget if one does not already exist
        variable menuPopup
        if {![winfo exists $menuPopup]} {
            set menuPopup [menu .apol_widget_menu_popup -tearoff 0]
        }
        set callbacks {
            {"Copy" Apol_Widget::copySearchResults}
            {"Select All" Apol_Widget::selectAllSearchResults}
        }
        ApolTop::popup $path $x $y $menuPopup $callbacks $path
    }
}

proc Apol_Widget::_hyperlink {path x y} {
    set tb $path.tb
    set range [$tb tag prevrange linenum "@$x,$y + 1 char"]
    $tb tag add selected [lindex $range 0] [lindex $range 1]
    set line_num [$tb get [lindex $range 0] [lindex $range 1]]
    $ApolTop::notebook raise $ApolTop::policy_conf_tab
    Apol_PolicyConf::goto_line $line_num
}

proc Apol_Widget::_render_typeset {typeset} {
    if {[llength $typeset] > 1} {
        if {[lindex $typeset 0] == "~"} {
            set typeset "~\{[lrange $typeset 1 end]\}"
        } else {
            set typeset "\{$typeset\}"
        }
    } else {
        set typeset
    }
}
