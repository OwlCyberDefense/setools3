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

# This file contains miscellaneous convenience routines to convert
# between Tcl and libapol/libqpol.

proc iter_to_list {iter} {
    set list {}
    while {![$iter end]} {
        lappend list [$iter get_item]
        $iter next
    }
    return $list
}

proc iter_to_str_list {iter} {
    set list {}
    while {![$iter end]} {
        lappend list [to_str [$iter get_item]]
        $iter next
    }
    return $list
}

proc list_to_vector {list} {
    set v [new_apol_vector_t]
    $v -acquire
    foreach x $list {
        $v append $x
    }
    return $v
}

proc list_to_str_vector {list} {
    set v [new_apol_string_vector_t]
    $v -acquire
    foreach x $list {
        $v append $x
    }
    return $v
}

proc str_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [$v get_element $i]
    }
    return $list
}

proc attr_vector_to_list {v} {
    type_vector_to_list $v
}

proc avrule_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_avrule_from_void [$v get_element $i]]
        lappend list $q
    }
    return $list
}

proc bool_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_bool_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc cat_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_cat_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc class_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_class_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc common_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_common_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

# Convert a vector a qpol_cond_t objects to a list of qpol_cond_t
# objects.
proc cond_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_cond_from_void [$v get_element $i]]
        lappend list $q
    }
    return $list
}

proc domain_trans_result_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set a [apol_domain_trans_result_from_void [$v get_element $i]]
        lappend list $a
    }
    return $list
}

# Convert a vector a qpol_fs_use_t objects to a list of qpol_fs_use_t
# objects.
proc fs_use_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_fs_use_from_void [$v get_element $i]]
        lappend list $q
    }
    return $list
}

# Convert a vector of qpol_genfscon_t objects to a list of
# qpol_genfscon_t objects.
proc genfscon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_genfscon_from_void [$v get_element $i]]
        lappend list $q
    }
    return $list
}

proc infoflow_result_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set a [apol_infoflow_result_from_void [$v get_element $i]]
        lappend list $a
    }
    return $list
}

proc isid_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_isid_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc level_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_level_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc netifcon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_netifcon_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

# Convert a vector of qpol_nodecon_t objects to a list of
# qpol_nodecon_t objects.
proc nodecon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_nodecon_from_void [$v get_element $i]]
        lappend list $q
    }
    return $list
}

# Convert a vector of qpol_portcon_t objects to a list of qpol_portcon_t.
proc portcon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [qpol_portcon_from_void [$v get_element $i]]
    }
    return $list
}

# Convert a vector of qpol_range_trans_t objects to a list of
# qpol_role_trans_t.
proc range_trans_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [qpol_range_trans_from_void [$v get_element $i]]
    }
    return $list
}

proc relabel_result_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [apol_relabel_result_from_void [$v get_element $i]]
    }
    return $list
}

proc relabel_result_pair_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [apol_relabel_result_pair_from_void [$v get_element $i]]
    }
    return $list
}

# Convert a vector of qpol_role_allow_t objects to a list of
# qpol_role_allow_t.
proc role_allow_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [qpol_role_allow_from_void [$v get_element $i]]
    }
    return $list
}

# Convert a vector of qpol_role_trans_t objects to a list of
# qpol_role_trans_t.
proc role_trans_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        lappend list [qpol_role_trans_from_void [$v get_element $i]]
    }
    return $list
}

proc role_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_role_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc terule_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_terule_from_void [$v get_element $i]]
        lappend list $q
    }
    return $list
}

proc type_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_type_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc user_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [qpol_user_from_void [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc list_to_policy_path {path_type primary modules} {
    if {$path_type == "monolithic"} {
        set path_type $::APOL_POLICY_PATH_TYPE_MONOLITHIC
    } else {
        set path_type $::APOL_POLICY_PATH_TYPE_MODULAR
    }
    set ppath [new_apol_policy_path_t $path_type $primary [list_to_str_vector $modules]]
    $ppath -acquire
    return $ppath
}

proc policy_path_to_list {ppath} {
    if {[$ppath get_type] == $::APOL_POLICY_PATH_TYPE_MONOLITHIC} {
        set path_type "monolithic"
    } else {
        set path_type "modular"
    }
    set primary [$ppath get_primary]
    set modules [str_vector_to_list [$ppath get_modules]]
    list $path_type $primary $modules
}
