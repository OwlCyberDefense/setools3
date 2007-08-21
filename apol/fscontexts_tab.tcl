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

namespace eval Apol_FSContexts {
    variable widgets
    variable vals
}

proc Apol_FSContexts::create {tab_name nb} {
    variable widgets
    variable vals

    _initializeVars

    # Layout frames
    set frame [$nb insert end $tab_name -text "FS Contexts"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    # build the left column, where one selects a particular type of
    # context; below it will be a scrolled listbox of keys for that
    # context
    set context_box [TitleFrame $leftf.context_f -text "Context Type"]
    set context_f [$context_box getframe]
    radiobutton $context_f.genfscon -text "genfscon" -value genfscon \
        -variable Apol_FSContexts::vals(context_type)
    radiobutton $context_f.fsuse -text "fs_use" -value fsuse \
        -variable Apol_FSContexts::vals(context_type)
    trace add variable Apol_FSContexts::vals(context_type) write \
        {Apol_FSContexts::_contextTypeChanged}
    pack $context_f.genfscon $context_f.fsuse \
        -anchor w -expand 0 -padx 4 -pady 5
    pack $context_box -expand 0 -fill x

    set widgets(items_tf) [TitleFrame $leftf.items_f -text "GenFS Contexts"]
    set widgets(items) [Apol_Widget::makeScrolledListbox [$widgets(items_tf) getframe].items \
                            -height 20 -width 20 -listvar Apol_FSContexts::vals(items)]
    Apol_Widget::setListboxCallbacks $widgets(items) \
        {{"Show Context Info" {Apol_FSContexts::_popupContextInfo}}}
    pack $widgets(items) -expand 1 -fill both
    pack $widgets(items_tf) -expand 1 -fill both

    # build the search options
    set optsbox [TitleFrame $rightf.optsbox -text "Search Options"]
    pack $optsbox -side top -expand 0 -fill both -padx 2
    set widgets(options_pm) [PagesManager [$optsbox getframe].pm]

    _genfscon_create [$widgets(options_pm) add genfscon]
    _fsuse_create [$widgets(options_pm) add fsuse]

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise genfscon

    set ok [button [$optsbox getframe].ok -text "OK" -width 6 \
                -command Apol_FSContexts::_runSearch]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # build the results box
    set resultsbox [TitleFrame $rightf.resultsbox -text "Search Results"]
    pack $resultsbox -expand yes -fill both -padx 2
    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}

proc Apol_FSContexts::open {ppath} {
    variable vals

    _genfscon_open
    _fsuse_open

    # force a flip to the genfscon page, via a trace on this variable
    set vals(context_type) genfscon
}

proc Apol_FSContexts::close {} {
    variable widgets

    _initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(genfscon:context)
    Apol_Widget::clearContextSelector $widgets(fsuse:context)
    $widgets(genfscon:fs) configure -values {}
    $widgets(fsuse:type) configure -values {}
    $widgets(fsuse:fs) configure -values {}
}

proc Apol_FSContexts::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

#### private functions below ####

proc Apol_FSContexts::_initializeVars {} {
    variable vals
    array set vals {
        genfscon:items {}
        genfscon:fs_enable 0     genfscon:fs {}
        genfscon:path_enable 0   genfscon:path {}

        fsuse:items {}
        fsuse:type_enable 0  fsuse:type {}
        fsuse:fs_enable 0    fsuse:fs {}

        items {}
        context_type genfscon
    }
}

proc Apol_FSContexts::_contextTypeChanged {name1 name2 op} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {$vals(context_type) == "genfscon"} {
        _genfscon_show
    } else {
        _fsuse_show
    }
}

proc Apol_FSContexts::_popupContextInfo {value} {
    variable vals
    if {$vals(context_type) == "genfscon"} {
        _genfscon_popup $value
    } else {
        _fsuse_popup $value
    }
}

proc Apol_FSContexts::_toggleCheckbutton {path name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $path configure -state normal
    } else {
        $path configure -state disabled
    }
}

proc Apol_FSContexts::_runSearch {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {$vals(context_type) == "genfscon"} {
        _genfscon_runSearch
    } else {
        _fsuse_runSearch
    }
}

#### genfscon private functions below ####

proc Apol_FSContexts::_genfscon_create {p_f} {
    variable widgets
    variable vals

    set fs [frame $p_f.fs]
    set fs_cb [checkbutton $fs.fs_enable -text "Filesystem" \
                   -variable Apol_FSContexts::vals(genfscon:fs_enable)]
    set widgets(genfscon:fs) [ComboBox $fs.fs -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(genfscon:fs) -autopost 1]
    trace add variable Apol_FSContexts::vals(genfscon:fs_enable) write \
        [list Apol_FSContexts::_toggleCheckbutton $widgets(genfscon:fs)]
    pack $fs_cb -side top -anchor w
    pack $widgets(genfscon:fs) -side top -expand 0 -fill x -padx 4

    set p [frame $p_f.p]
    set p_cb [checkbutton $p.p_enable -text "Path" \
                   -variable Apol_FSContexts::vals(genfscon:path_enable)]
    set widgets(genfscon:path) [entry $p.path -bg white -width 24 \
                                    -state disabled \
                                    -textvariable Apol_FSContexts::vals(genfscon:path)]
    trace add variable Apol_FSContexts::vals(genfscon:path_enable) write \
        [list Apol_FSContexts::_toggleCheckbutton $widgets(genfscon:path)]
    pack $p_cb -side top -anchor w
    pack $widgets(genfscon:path) -side top -expand 0 -fill x -padx 4

    frame $p_f.c
    set widgets(genfscon:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(genfscon:context)

    pack $fs $p $p_f.c -side left -anchor n -padx 4 -pady 2
}

proc Apol_FSContexts::_genfscon_open {} {
    variable vals

    set q [new_apol_genfscon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set genfscons [genfscon_vector_to_list $v]
    set vals(genfscon:items) {}
    foreach g $genfscons {
        lappend vals(genfscon:items) [$g get_name $::ApolTop::qpolicy]
    }
    set vals(genfscon:items) [lsort -unique $vals(genfscon:items)]

    # because qpol_policy_get_genfscon_iter() returns allocated items,
    # destroying the vector before using its items will segfault
    $v -acquire
    $v -delete
    
    variable widgets
    $widgets(genfscon:fs) configure -values $vals(genfscon:items)
}

proc Apol_FSContexts::_genfscon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "GenFS Contexts"
    $widgets(options_pm) raise genfscon
    set vals(items) $vals(genfscon:items)
}

proc Apol_FSContexts::_genfscon_popup {fstype} {
    set q [new_apol_genfscon_query_t]
    $q set_filesystem $::ApolTop::policy $fstype
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set genfscons [genfscon_vector_to_list $v]
    set text "genfs filesystem $fstype ([llength $genfscons] context"
    if {[llength $genfscons] != 1} {
        append text s
    }
    append text ")"
    foreach g [lsort -command _genfscon_sort $genfscons] {
        append text "\n    [_genfscon_render $g]"
    }
    Apol_Widget::showPopupText "filesystem $fstype" $text

    # because qpol_policy_get_genfscon_iter() returns allocated items,
    # destroying the vector before using its items will segfault
    $v -acquire
    $v -delete
}

proc Apol_FSContexts::_genfscon_runSearch {} {
    variable vals
    variable widgets

    if {$vals(genfscon:fs_enable)} {
        if {$vals(genfscon:fs) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No filesystem selected."
            return
        }
        set fstype $vals(genfscon:fs_enable)
    } else {
        set fstype {}
    }
    if {$vals(genfscon:path_enable)} {
        if {$vals(genfscon:path) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No path given."
            return
        }
        set path $vals(genfscon:path)
    } else {
        set path {}
    }

    set q [new_apol_genfscon_query_t]
    if {[Apol_Widget::getContextSelectorState $widgets(genfscon:context)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(genfscon:context)] {break}
        $q set_context $::ApolTop::policy $context $range_match
    }
    $q set_filesystem $::ApolTop::policy $fstype
    $q set_path $::ApolTop::policy $path

    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set genfscons [genfscon_vector_to_list $v]

    set results "GENFSCONS:"
    if {[llength $genfscons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach g [lsort -command _genfscon_sort $genfscons] {
            append results "\n[_genfscon_render $g]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results

    # because qpol_policy_get_genfscon_iter() returns allocated items,
    # destroying the vector before using its items will segfault
    $v -acquire
    $v -delete
}

proc Apol_FSContexts::_genfscon_render {qpol_genfscon_datum} {
    apol_genfscon_render $::ApolTop::policy $qpol_genfscon_datum
}

proc Apol_FSContexts::_genfscon_sort {a b} {
    set name_a [$a get_name $::ApolTop::qpolicy]
    set name_b [$b get_name $::ApolTop::qpolicy]
    if {[set z [string compare $name_a $name_b]] != 0} {
        return $z
    }
    set path_a [$a get_path $::ApolTop::qpolicy]
    set path_b [$b get_path $::ApolTop::qpolicy]
    if {[set z [string compare $path_a $path_b]] != 0} {
        return $z
    }
    return 0
}

#### fs_use private functions below ####

proc Apol_FSContexts::_fsuse_create {p_f} {
    variable widgets
    variable vals

    set t [frame $p_f.t]
    set type_cb [checkbutton $t.type_enable -text "Statement type" \
                   -variable Apol_FSContexts::vals(fsuse:type_enable)]
    set widgets(fsuse:type) [ComboBox $t.type -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(fsuse:type) -autopost 1]
    trace add variable Apol_FSContexts::vals(fsuse:type_enable) write \
        [list Apol_FSContexts::_toggleCheckbutton $widgets(fsuse:type)]
    pack $type_cb -side top -anchor w
    pack $widgets(fsuse:type) -side top -expand 0 -fill x -padx 4

    set fs [frame $p_f.fs]
    set fs_cb [checkbutton $fs.fs_enable -text "Filesystem" \
                   -variable Apol_FSContexts::vals(fsuse:fs_enable)]
    set widgets(fsuse:fs) [ComboBox $fs.fs -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(fsuse:fs) -autopost 1]
    trace add variable Apol_FSContexts::vals(fsuse:fs_enable) write \
        [list Apol_FSContexts::_toggleCheckbutton $widgets(fsuse:fs)]
    pack $fs_cb -side top -anchor w
    pack $widgets(fsuse:fs) -side top -expand 0 -fill x -padx 4

    frame $p_f.c
    set widgets(fsuse:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(fsuse:context)

    pack $t $fs $p_f.c -side left -anchor n -padx 4 -pady 2
}

proc Apol_FSContexts::_fsuse_open {} {
    variable vals

    set q [new_apol_fs_use_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set fs_uses [lsort -unique [fs_use_vector_to_list $v]]
    $v -acquire
    $v -delete

    # get a list of all behaviors present in this policy
    set vals(fsuse:items) {}
    set behavs {}
    foreach f $fs_uses {
        lappend vals(fsuse:items) [$f get_name $::ApolTop::qpolicy]
        lappend behavs [apol_fs_use_behavior_to_str [$f get_behavior $::ApolTop::qpolicy]]
    }

    variable widgets
    set vals(fsuse:items) [lsort -unique $vals(fsuse:items)]
    $widgets(fsuse:type) configure -values [lsort -unique $behavs]
    $widgets(fsuse:fs) configure -values $vals(fsuse:items)
}

proc Apol_FSContexts::_fsuse_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "fs_use Contexts"
    $widgets(options_pm) raise fsuse
    set vals(items) $vals(fsuse:items)
}

proc Apol_FSContexts::_fsuse_popup {fs} {
    set qpol_fs_use_datum [new_qpol_fs_use_t $::ApolTop::qpolicy $fs]
    set text "fs_use $fs\n    [_fsuse_render $qpol_fs_use_datum]"
    Apol_Widget::showPopupText $fs $text
}

proc Apol_FSContexts::_fsuse_runSearch {} {
    variable vals
    variable widgets

    if {$vals(fsuse:type_enable)} {
        if {$vals(fsuse:type) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No fs_use statement type selected."
            return
        }
        set behavior [apol_str_to_fs_use_behavior $vals(fsuse:type)]
        if {$behavior < 0} {
            tk_messageBox -icon error -type ok -title "Error" -message "$vals(fsuse:type) is not a valid fs_use statement type."
            return
        }
    } else {
        set behavior -1
    }
    if {$vals(fsuse:fs_enable)} {
        if {$vals(fsuse:fs) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No filesystem selected."
            return
        }
        set fstype $vals(fsuse:fs)
    } else {
        set fstype {}
    }

    set q [new_apol_fs_use_query_t]
    if {[Apol_Widget::getContextSelectorState $widgets(fsuse:context)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(fsuse:context)] {break}
        $q set_context $::ApolTop::policy $context $range_match
    }
    $q set_filesystem $::ApolTop::policy $fstype
    $q set_behavior $::ApolTop::policy $behavior

    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    set fsuses [fs_use_vector_to_list $v]
    $v -acquire
    $v -delete

    set results "FS_USES:"
    if {[llength $fsuses] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach u [lsort -command _fsuse_sort $fsuses] {
            append results "\n[_fsuse_render $u]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_FSContexts::_fsuse_render {qpol_fs_use_datum} {
    apol_fs_use_render $::ApolTop::policy $qpol_fs_use_datum
}

proc Apol_FSContexts::_fsuse_sort {a b} {
    set behav_a [apol_fs_use_behavior_to_str [$a get_behavior $::ApolTop::qpolicy]]
    set behav_b [apol_fs_use_behavior_to_str [$b get_behavior $::ApolTop::qpolicy]]
    if {[set z [string compare $behav_a $behav_b]] != 0} {
        return $z
    }
    set name_a [$a get_name $::ApolTop::qpolicy]
    set name_b [$b get_name $::ApolTop::qpolicy]
    if {[set z [string compare $name_a $name_b]] != 0} {
        return $z
    }
    return 0
}
