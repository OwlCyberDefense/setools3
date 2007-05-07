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

# Convenience routines to convert between Tcl and libapol/libqpol.

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

proc bool_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_bool_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc cat_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_cat_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc class_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_class_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc common_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_common_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc fs_use_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_fs_use_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc genfscon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_genfscon_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc isid_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_isid_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc level_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_level_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc netifcon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_netifcon_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc nodecon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_nodecon_t [$v get_element $i]]
        set proto [$q get_protocol $::ApolTop::qpolicy]
        set addr [$q get_addr $::ApolTop::qpolicy]
        set mask [$q get_mask $::ApolTop::qpolicy]
        if {$proto == $::QPOL_IPV4} {
            set proto_str "ipv4"
            set addr [apol_ipv4_addr_render $::ApolTop::policy $addr]
            set mask [apol_ipv4_addr_render $::ApolTop::policy $mask]
        } elseif {$proto == $::QPOL_IPV6} {
            set proto_str "ipv6"
            set addr [apol_ipv6_addr_render $::ApolTop::policy $addr]
            set mask [apol_ipv6_addr_render $::ApolTop::policy $mask]
        } else {
            set proto_str "unknown"
        }
        lappend list [list $proto_str $addr $mask]
    }
    return $list
}

proc portcon_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_portcon_t [$v get_element $i]]
        set low [$q get_low_port $::ApolTop::qpolicy]
        set high [$q get_high_port $::ApolTop::qpolicy]
        set proto [$q get_protocol $::ApolTop::qpolicy]
        lappend list [list $low $high $proto]
    }
    return $list
}

proc role_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_role_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc type_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_type_t [$v get_element $i]]
        lappend list [$q get_name $::ApolTop::qpolicy]
    }
    return $list
}

proc user_vector_to_list {v} {
    set list {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set q [new_qpol_user_t [$v get_element $i]]
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
    set ppath [new_apol_policy_path_t $path_type $primary [list_to_str_vector modules]]
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
