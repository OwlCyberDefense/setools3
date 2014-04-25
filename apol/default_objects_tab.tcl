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

namespace eval Apol_DefaultObjects {
    variable vals
    variable widgets
    variable mls_enabled {0}
    variable statement_count
}

proc Apol_DefaultObjects::create {tab_name nb} {
    variable vals
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "Default Object Rules"]
    set topf [frame $frame.top]
    set bottomf [frame $frame.bottom]
    pack $topf -expand 0 -fill both -pady 2
    pack $bottomf -expand 1 -fill both -pady 2

    set rsbox [TitleFrame $topf.rs -ipad 30 -text "Rule Selection"]
    set obox [TitleFrame $topf.opts -text "Search Options"]
    set dbox [TitleFrame $bottomf.results -text "Default Object Rules Display"]
    pack $rsbox -side left -expand 0 -fill both -padx 2
    pack $obox -side left -expand 1 -fill both -padx 2
    pack $dbox -expand 1 -fill both -padx 2

    # Rule selection subframe
    set rs [$rsbox getframe]
    checkbutton $rs.default_user -text "default_user" -onvalue 1 -offvalue 0 \
        -variable Apol_DefaultObjects::vals(default_user_enabled)
    trace add variable Apol_DefaultObjects::vals(default_user_enabled) write \
        [list Apol_DefaultObjects::_ruleChanged]
    checkbutton $rs.default_role -text "default_role" -onvalue 1 -offvalue 0 \
        -variable Apol_DefaultObjects::vals(default_role_enabled)
    trace add variable Apol_DefaultObjects::vals(default_role_enabled) write \
        [list Apol_DefaultObjects::_ruleChanged]
    checkbutton $rs.default_type -text "default_type" -onvalue 1 -offvalue 0 \
        -variable Apol_DefaultObjects::vals(default_type_enabled)
    trace add variable Apol_DefaultObjects::vals(default_type_enabled) write \
        [list Apol_DefaultObjects::_ruleChanged]
    checkbutton $rs.default_range -text "default_range" -onvalue 1 -offvalue 0 \
        -variable Apol_DefaultObjects::vals(default_range_enabled)
    trace add variable Apol_DefaultObjects::vals(default_range_enabled) write \
        [list Apol_DefaultObjects::_ruleChanged]
    pack $rs.default_user $rs.default_role $rs.default_type $rs.default_range -side top -anchor w

    set widgets(options_pm) [PagesManager [$obox getframe].opts]

    _defaultObjectCreate [$widgets(options_pm) add default_object]

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise default_object

    set ok [button [$obox getframe].ok -text OK -width 6 -command Apol_DefaultObjects::_searchDefaultObjects]
    pack $ok -side right -padx 5 -pady 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_DefaultObjects::open {ppath} {
    variable vals
    variable widgets
    variable mls_enabled

    if {[ApolTop::is_capable "mls"]} {
        set mls_enabled 1
    } else {
        set mls_enabled 0
    }

    $widgets(default_object:class) configure -values [Apol_Class_Perms::getClasses]
    $widgets(default_object:default) configure -values {"source" "target"}
    $widgets(default_object:range) configure -values {"low" "high" "low_high"}

    set vals(default_range_enabled) $mls_enabled
    set vals(default_type_enabled) [ApolTop::is_capable "default_type"]
}

proc Apol_DefaultObjects::close {} {
    variable widgets
    variable mls_enabled

    _initializeVars
    $widgets(default_object:class) configure -values {}
    $widgets(default_object:default) configure -values {}
    $widgets(default_object:range) configure -values {}
    set mls_enabled 0
}

proc Apol_DefaultObjects::getTextWidget {} {
    variable widgets
}

proc Apol_DefaultObjects::_initializeVars {} {
    variable vals

    array set vals {
        class:use 0
        class:sym {}
        default:sym {}
        default:use 0
        range:sym {}
        range:use 0

        default_user_enabled 1
        default_role_enabled 1
        default_type_enabled 1
        default_range_enabled 0
    }
}

proc Apol_DefaultObjects::_defaultObjectCreate {r_c} {
    variable vals
    variable widgets

    set class [frame $r_c.class]
    set class_cb [checkbutton $class.enable -text "Object class" \
                       -variable Apol_DefaultObjects::vals(class:use)]
    set widgets(default_object:class) [ComboBox $class.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_DefaultObjects::vals(class:sym)]

    trace add variable Apol_DefaultObjects::vals(class:use) write \
        [list Apol_DefaultObjects::_toggleCheckbutton $widgets(default_object:class) {}]
    pack $class_cb -side top -anchor w
    pack $widgets(default_object:class) -side top -expand 0 -fill x -padx 4
    pack $class -side left -padx 4 -pady 2 -expand 0 -anchor nw

    set default [frame $r_c.default]
    set widgets(default_object:default_cb) [checkbutton $default.enable -text "Default" \
                                      -variable Apol_DefaultObjects::vals(default:use)]
    set widgets(default_object:default) [ComboBox $default.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_DefaultObjects::vals(default:sym)]
    trace add variable Apol_DefaultObjects::vals(default:use) write \
        [list Apol_DefaultObjects::_toggleCheckbutton $widgets(default_object:default) {}]
    pack $widgets(default_object:default_cb) -side top -anchor w
    pack $widgets(default_object:default) -side top -expand 0 -fill x -padx 4
    pack $default -side left -padx 4 -pady 2 -expand 0 -fill y

    set range [frame $r_c.range]
    set widgets(default_object:range_cb) [checkbutton $range.enable -text "Range" \
                                      -variable Apol_DefaultObjects::vals(range:use)]
    set widgets(default_object:range) [ComboBox $range.cb -width 20 -state disabled \
                                   -entrybg $ApolTop::default_bg_color \
                                   -textvariable Apol_DefaultObjects::vals(range:sym)]
    trace add variable Apol_DefaultObjects::vals(range:use) write \
        [list Apol_DefaultObjects::_toggleCheckbutton $widgets(default_object:range) {}]
    pack $widgets(default_object:range_cb) -side top -anchor w
    pack $widgets(default_object:range) -side top -expand 0 -fill x -padx 4
    pack $range -side left -padx 4 -pady 2 -expand 0 -fill y
}

proc Apol_DefaultObjects::_toggleCheckbutton {cb w name1 name2 ops} {
    variable vals
    variable mls_enabled

    if {$name2 == "range:use" && $mls_enabled == 0 || $vals(default_range_enabled) == 0} {
        set vals(range:use) 0
        $cb configure -state disabled
    }

    if {$vals($name2)} {
        $cb configure -state normal -entrybg white
        foreach x $w {
            $x configure -state normal
        }
    } else {
        $cb configure -state disabled -entrybg $ApolTop::default_bg_color
        foreach x $w {
            $x configure -state disabled
        }
    }
}

proc Apol_DefaultObjects::_ruleChanged {name1 name2 ops} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)

    if {$vals(default_user_enabled) == 0} {
        set vals(user:use) 0
    }
    if {$vals(default_role_enabled) == 0} {
        set vals(role:use) 0
    }
    if {$vals(default_type_enabled) == 0} {
        set vals(type:use) 0
    }
    if {$vals(default_range_enabled) == 0} {
        set vals(range:use) 0
    }
}

proc Apol_DefaultObjects::_searchDefaultObjects {} {
    variable vals
    variable widgets
    variable statement_count

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
    }

    if {$vals(class:use) == 1 && $vals(class:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Default object Rule Search" -message "No class selected."
        return
    }
    if {$vals(default:use) == 1 && $vals(default:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Default object Rule Search" -message "No default selected."
        return
    }
    if {$vals(range:use) == 1 && $vals(range:sym) == {}} {
        tk_messageBox -icon error -type ok -title "Default object Rule Search" -message "No range selected."
        return
    }

    set results {}
    set header {}
    set print_results {}

    if {$vals(default_user_enabled) == 1} {
        append results [Apol_DefaultObjects::searchForDefault "user" get_user_default]
        append header "$statement_count default_user rules match the search criteria.\n"
    }
    if {$vals(default_role_enabled) == 1} {
         append results [Apol_DefaultObjects::searchForDefault "role" get_role_default]
        append header "$statement_count default_role rules match the search criteria.\n"
    }
    if {$vals(default_type_enabled) == 1} {
        append results [Apol_DefaultObjects::searchForDefault "type" get_type_default]
        append header "$statement_count default_type rules match the search criteria.\n"
    }
    if {$vals(default_range_enabled) == 1} {
        append results [Apol_DefaultObjects::searchDefaultRange "range" get_range_default]
        append header "$statement_count default_range rules match the search criteria.\n"
    }
    append print_results "$header\n$results"
    Apol_Widget::appendSearchResultText $widgets(results) $print_results
}

proc Apol_DefaultObjects::searchForDefault {type type_cmd} {
    variable vals
    variable widgets
    variable statement_count
    set results {}
    set printit 0
    set class_regexp 0
    set default_regexp 0
    set statement_count 0

    if {$vals(class:use)} {
        set class_regexp 1
    }
    if {$vals(default:use)} {
        set default_regexp 1
    }
 
    set q [new_apol_default_object_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
            set q [qpol_default_object_from_void [$v get_element $i]]
            set class [$q get_class $::ApolTop::qpolicy]
            set default [$q $type_cmd $::ApolTop::qpolicy]
            if {$default != ""} {
                if {$class_regexp == 1 && $class == $vals(class:sym) && $default_regexp == 1 && $default == $vals(default:sym)} {
                    set printit 1
                } elseif {$class_regexp == 1 && $class == $vals(class:sym) && $default_regexp == 0} {
                    set printit 1
                } elseif {$default_regexp == 1 && $default == $vals(default:sym) && $class_regexp == 0} {
                    set printit 1
                } elseif {$class_regexp == 0 && $default_regexp == 0} {
                    set printit 1
                }
                if {$printit == 1} {
                    append results "default_$type $class $default;\n"
                    set statement_count [expr $statement_count + 1]
               }
            }
            set printit 0
        }
    }
    return "$results\n"
}

proc Apol_DefaultObjects::searchDefaultRange {type type_cmd} {
    variable vals
    variable widgets
    variable statement_count
    set results {}
    set printit 0
    set class_regexp 0
    set default_regexp 0
    set range_regexp 0
    set statement_count 0

    if {$vals(class:use)} {
        set class_regexp 1
    }
    if {$vals(default:use)} {
        set default_regexp 1
    }
    if {$vals(range:use)} {
        set range_regexp 1
    }
 
    set q [new_apol_default_object_query_t]
    set v [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
            set q [qpol_default_object_from_void [$v get_element $i]]
            set class [$q get_class $::ApolTop::qpolicy]
            set default [$q $type_cmd $::ApolTop::qpolicy]
            if {$default != ""} {
                # split into the two components
                set entries [split $default " "]
                lassign $entries src_tgt range

                if {$class_regexp == 1 && $class == $vals(class:sym) && $default_regexp == 1 && \
                        $src_tgt== $vals(default:sym) && $range_regexp == 1 && $range == $vals(range:sym)} {
                    set printit 1
                } elseif {$class_regexp == 1 && $class == $vals(class:sym) && $default_regexp == 0 && $range_regexp == 0} {
                    set printit 1
                } elseif {$class_regexp == 0 && $default_regexp == 1 && $src_tgt == $vals(default:sym) && $range_regexp == 0} {
                    set printit 1
                } elseif {$class_regexp == 0 && $default_regexp == 0 && $range_regexp == 1 && $range == $vals(range:sym)} {
                    set printit 1
                } elseif {$class_regexp == 0 && $default_regexp == 1 && $src_tgt == $vals(default:sym) && \
                       $range_regexp == 1 && $range == $vals(range:sym)} {
                    set printit 1
                } elseif {$class_regexp == 1 && $class == $vals(class:sym) && $default_regexp == 0 && \
                        $range_regexp == 1 && $range == $vals(range:sym)} {
                    set printit 1
                } elseif {$class_regexp == 0 && $default_regexp == 0 && $range_regexp == 0} {
                    set printit 1
                }
                if {$printit == 1} {
                    append results "default_$type $class $default;\n"
                    set statement_count [expr $statement_count + 1]
               }
            }
            set printit 0
        }
    }
    return "$results\n"
}
