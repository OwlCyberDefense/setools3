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

namespace eval Apol_NetContexts {
    variable widgets
    variable vals
}

proc Apol_NetContexts::create {tab_name nb} {
    variable widgets
    variable vals

    _initializeVars

    # Layout frames
    set frame [$nb insert end $tab_name -text "Net Contexts"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    # build the left column, where one selects a particular type of
    # context; below it will be a scrolled listbox of keys for that
    # context
    set context_box [TitleFrame $leftf.context_f -text "Context Type"]
    set context_f [$context_box getframe]
    radiobutton $context_f.portcon -text "portcon" -value portcon \
        -variable Apol_NetContexts::vals(context_type)
    radiobutton $context_f.netifcon -text "netifcon" -value netifcon \
        -variable Apol_NetContexts::vals(context_type)
    radiobutton $context_f.nodecon -text "nodecon" -value nodecon \
        -variable Apol_NetContexts::vals(context_type)
    trace add variable Apol_NetContexts::vals(context_type) write \
        {Apol_NetContexts::_contextTypeChanged}
    pack $context_f.portcon $context_f.netifcon $context_f.nodecon \
        -anchor w -expand 0 -padx 4 -pady 5
    pack $context_box -anchor nw -expand 0 -fill x

    set widgets(items_tf) [TitleFrame $leftf.items_f -text "Port Contexts"]
    set widgets(items) [Apol_Widget::makeScrolledListbox [$widgets(items_tf) getframe].items \
                            -height 20 -width 20 -listvar Apol_NetContexts::vals(items)]
    Apol_Widget::setListboxCallbacks $widgets(items) \
        {{"Show Context Info" {Apol_NetContexts::_popupContextInfo}}}
    pack $widgets(items) -expand 1 -fill both
    pack $widgets(items_tf) -expand 1 -fill both

    # build the search options
    set optsbox [TitleFrame $rightf.optsbox -text "Search Options"]
    pack $optsbox -side top -expand 0 -fill both -padx 2
    set widgets(options_pm) [PagesManager [$optsbox getframe].pm]

    _portcon_create [$widgets(options_pm) add portcon]
    _netifcon_create [$widgets(options_pm) add netifcon]
    _nodecon_create [$widgets(options_pm) add nodecon]

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise portcon

    set ok [button [$optsbox getframe].ok -text "OK" -width 6 \
                -command Apol_NetContexts::_runSearch]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    set resultsbox [TitleFrame $rightf.resultsbox -text "Search Results"]
    pack $resultsbox -expand yes -fill both -padx 2
    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}

proc Apol_NetContexts::open {ppath} {
    variable vals

    _portcon_open
    _netifcon_open
    _nodecon_open

    # force a flip to the portcon page
    set vals(context_type) portcon
}

proc Apol_NetContexts::close {} {
    variable widgets

    _initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(portcon:context)
    Apol_Widget::clearContextSelector $widgets(netifcon:ifcon)
    Apol_Widget::clearContextSelector $widgets(netifcon:msgcon)
    Apol_Widget::clearContextSelector $widgets(nodecon:context)
    $widgets(portcon:proto) configure -values {}
    $widgets(netifcon:dev) configure -values {}
}

proc Apol_NetContexts::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

#### private functions below ####

proc Apol_NetContexts::_initializeVars {} {
    variable vals
    array set vals {
        portcon:items {}
        portcon:proto_enable 0    portcon:proto {}
        portcon:port_enable 0     portcon:port 0
        portcon:hiport_enable 0   portcon:hiport 0

        netifcon:items {}
        netifcon:dev_enable 0     netifcon:dev {}

        nodecon:items {}
        nodecon:ip_type ipv4
        nodecon:ipv4_addr_enable 0
        nodecon:ipv4_addr0 0        nodecon:ipv4_addr1 0
        nodecon:ipv4_addr2 0        nodecon:ipv4_addr3 0
        nodecon:ipv4_mask_enable 0
        nodecon:ipv4_mask0 255      nodecon:ipv4_mask1 255
        nodecon:ipv4_mask2 255      nodecon:ipv4_mask3 255
        nodecon:ipv6_addr_enable 0  nodecon:ipv6_addr ::
        nodecon:ipv6_mask_enable 0  nodecon:ipv6_mask ::

        items {}
        context_type portcon
    }
}

proc Apol_NetContexts::_contextTypeChanged {name1 name2 op} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {$vals(context_type) == "portcon"} {
        _portcon_show
    } elseif {$vals(context_type) == "netifcon"} {
        _netifcon_show
    } else {
        _nodecon_show
    }
}

proc Apol_NetContexts::_popupContextInfo {value} {
    variable vals
    if {$vals(context_type) == "portcon"} {
        _portcon_popup $value
    } elseif {$vals(context_type) == "netifcon"} {
        _netifcon_popup $value
    } else {
        _nodecon_popup $value
    }
}

proc Apol_NetContexts::_toggleCheckbutton {path name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $path configure -state normal
    } else {
        $path configure -state disabled
    }
}

proc Apol_NetContexts::_runSearch {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {$vals(context_type) == "portcon"} {
        _portcon_runSearch
    } elseif {$vals(context_type) == "netifcon"} {
        _netifcon_runSearch
    } else {
        _nodecon_runSearch
    }
}

#### portcon private functions below ####

# create the portcon-specific options widgets
proc Apol_NetContexts::_portcon_create {p_f} {
    variable widgets
    variable vals

    frame $p_f.proto
    set proto_cb [checkbutton $p_f.proto.proto_enable -text "Protocol" \
                      -variable Apol_NetContexts::vals(portcon:proto_enable)]
    set widgets(portcon:proto) [ComboBox $p_f.proto.proto -entrybg white -width 8 -state disabled \
                                    -textvariable Apol_NetContexts::vals(portcon:proto) -autopost 1]
    trace add variable Apol_NetContexts::vals(portcon:proto_enable) write \
        [list Apol_NetContexts::_toggleCheckbutton $widgets(portcon:proto)]
    pack $proto_cb -side top -anchor w
    pack $widgets(portcon:proto) -side top -expand 0 -fill x -padx 4

    frame $p_f.port
    set low [frame $p_f.port.l]
    set port_cb [checkbutton $low.port_enable -text "Single Port" \
                     -variable Apol_NetContexts::vals(portcon:port_enable)]
    set widgets(portcon:port) [spinbox $low.port -bg white -width 8 \
                                   -justify right -state disabled \
                                   -from 0 -to 65535 \
                                   -validate all -vcmd [list Apol_NetContexts::_portcon_limitPort %W %V %P port] \
                                   -textvariable Apol_NetContexts::vals(portcon:port)]
    set high [frame $p_f.port.h]
    set hiport_cb [checkbutton $high.hiport_enable -text "High Port" \
                       -state disabled \
                       -variable Apol_NetContexts::vals(portcon:hiport_enable)]
    set widgets(portcon:hiport) [spinbox $high.hiport -bg white -width 8 \
                                     -justify right -state disabled \
                                     -from 0 -to 65535 \
                                     -validate all -vcmd [list Apol_NetContexts::_portcon_limitPort %W %V %P hiport] \
                                     -textvariable Apol_NetContexts::vals(portcon:hiport)]
    trace add variable Apol_NetContexts::vals(portcon:port_enable) write \
        [list Apol_NetContexts::_portcon_toggleCheckbutton_lowport \
             $widgets(portcon:port) $hiport_cb $widgets(portcon:hiport)]
    trace add variable Apol_NetContexts::vals(portcon:hiport_enable) write \
        [list Apol_NetContexts::_portcon_toggleCheckbutton_hiport $port_cb $widgets(portcon:hiport)]
    pack $port_cb -side top -anchor w -expand 0
    pack $widgets(portcon:port) -side top -expand 0 -fill x -padx 4
    pack $hiport_cb -side top -anchor w -expand 0
    pack $widgets(portcon:hiport) -side top -expand 0 -fill x -padx 4
    pack $low $high -side left -expand 0 -fill both

    frame $p_f.c
    set widgets(portcon:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(portcon:context)
    pack $p_f.proto $p_f.port $p_f.c -side left -padx 4 -pady 2 -anchor nw
}

proc Apol_NetContexts::_portcon_open {} {
    variable vals

    set q [new_apol_portcon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set portcons [portcon_vector_to_list $v]
    $v -delete
    set vals(portcon:items) {}
    set protos {}
    foreach p $portcons {
        set low [$p get_low_port $::ApolTop::qpolicy]
        set high [$p get_high_port $::ApolTop::qpolicy]
        set proto [$p get_protocol $::ApolTop::qpolicy]
        if {$low == $high} {
            lappend vals(portcon:items) $low
        } else {
            lappend vals(portcon:items) "$low-$high"
        }
        lappend protos [apol_protocol_to_str $proto]
    }

    variable widgets
    set vals(portcon:items) [lsort -unique -dictionary $vals(portcon:items)]
    $widgets(portcon:proto) configure -values [lsort -unique -dictionary $protos]
}

proc Apol_NetContexts::_portcon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "Port Contexts"
    $widgets(options_pm) raise portcon
    set vals(items) $vals(portcon:items)
}

proc Apol_NetContexts::_portcon_popup {port} {
    foreach {low high} [split $port "-"] {break}
    if {$high == {}} {
        set high $low
    }

    set q [new_apol_portcon_query_t]
    $q set_low $::ApolTop::policy $low
    $q set_high $::ApolTop::policy $high
    set v [$q run $::ApolTop::policy]
    $q -delete
    set portcons [portcon_vector_to_list $v]
    $v -delete

    set text "port $port ([llength $portcons] context"
    if {[llength $portcons] != 1} {
        append text s
    }
    append text ")"
    foreach p [lsort -command _portcon_sort $portcons] {
        append text "\n    [_portcon_render $p]"
    }
    Apol_Widget::showPopupText "port $port" $text
}

proc Apol_NetContexts::_portcon_limitPort {widget command new_port varname} {
    variable vals
    if {$command == "key"} {
        if {$new_port != "" &&
            (![string is integer $new_port] || $new_port < 0 || $new_port > 65535)} {
            return 0
        }
    } elseif {$command == "focusout"} {
        if {$new_port == ""} {
            set vals(portcon:$varname) 0
        } elseif {[string length $new_port] > 1} {
            set vals(portcon:$varname) [string trimleft $new_port " 0"]
        }

        # re-enable the validation command (it could have been
        # disabled because the variable changed)
        $widget config -validate all
    }
    return 1
}

proc Apol_NetContexts::_portcon_toggleCheckbutton_lowport {low high_cb high name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $low configure -state normal
        $high_cb configure -state normal
        if {$vals(portcon:hiport_enable)} {
            $high configure -state normal
        }
    } else {
        $low configure -state disabled
        $high_cb configure -state disabled
        $high configure -state disabled
    }
}

proc Apol_NetContexts::_portcon_toggleCheckbutton_hiport {low high name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $low configure -text "Low Port"
        $high configure -state normal
    } else {
        $low configure -text "Single Port"
        $high configure -state disabled
    }
}

proc Apol_NetContexts::_portcon_runSearch {} {
    variable vals
    variable widgets

    # explicitly validate the spinboxes (they could still have focus)
    _portcon_limitPort $widgets(portcon:port) focusout $vals(portcon:port) port
    _portcon_limitPort $widgets(portcon:hiport) focusout $vals(portcon:hiport) hiport

    if {$vals(portcon:port_enable)} {
        set low $vals(portcon:port)
        set high $low
        if {$vals(portcon:hiport_enable)} {
            set high $vals(portcon:hiport)
            if {$vals(portcon:port_enable) && $high < $low} {
                tk_messageBox -icon error -type ok -title "Error" -message "The second port is not greater than the first."
                return
            }
        }
    } else {
        set low -1
        set high -1
    }

    set q [new_apol_portcon_query_t]
    $q set_low $::ApolTop::policy $low
    $q set_high $::ApolTop::policy $high
    if {$vals(portcon:proto_enable)} {
        if {[set proto $vals(portcon:proto)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No protocol selected."
            return
        }
        $q set_protocol $::ApolTop::policy [apol_str_to_protocol $proto]
    }
    if {[Apol_Widget::getContextSelectorState $widgets(portcon:context)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(portcon:context)] {break}
        $q set_context $::ApolTop::policy $context $range_match
    }
    set v [$q run $::ApolTop::policy]
    $q -delete
    set portcons [portcon_vector_to_list $v]
    $v -delete

    set results "PORTCONS:"
    if {[llength $portcons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach p [lsort -command _portcon_sort $portcons] {
            append results "\n[_portcon_render $p]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_NetContexts::_portcon_render {qpol_portcon_datum} {
    set loport [$qpol_portcon_datum get_low_port $::ApolTop::qpolicy]
    set hiport [$qpol_portcon_datum get_high_port $::ApolTop::qpolicy]
    set proto [apol_protocol_to_str [$qpol_portcon_datum get_protocol $::ApolTop::qpolicy]]
    set qpol_context [$qpol_portcon_datum get_context $::ApolTop::qpolicy]
    if {$loport == $hiport} {
        set line "portcon $proto $loport "
    } else {
        set line "portcon $proto ${loport}-${hiport} "
    }
    concat $line [apol_qpol_context_render $::ApolTop::policy $qpol_context]
}

proc Apol_NetContexts::_portcon_sort {a b} {
    set loport1 [$a get_low_port $::ApolTop::qpolicy]
    set hiport1 [$a get_high_port $::ApolTop::qpolicy]
    set loport2 [$b get_low_port $::ApolTop::qpolicy]
    set hiport2 [$b get_high_port $::ApolTop::qpolicy]
    if {$loport1 == $hiport1} {
        set singleport1 1
    } else {
        set singleport1 0
    }
    if {$loport2 == $hiport2} {
        set singleport2 1
    } else {
        set singleport2 0
    }
    if {$singleport1 && !$singleport2} {
        return -1
    } elseif {!$singleport1 && $singleport2} {
        return 1
    }
    if {$loport1 < $loport2} {
        return -1
    } elseif {$loport1 > $loport2} {
        return 1
    }
    if {$hiport1 < $hiport2} {
        return -1
    } elseif {$hiport1 > $hiport2} {
        return 1
    }
    set proto1 [apol_protocol_to_str [$a get_protocol $::ApolTop::qpolicy]]
    set proto2 [apol_protocol_to_str [$b get_protocol $::ApolTop::qpolicy]]
    string compare $proto1 $proto2
}

#### netifcon private functions below ####

proc Apol_NetContexts::_netifcon_create {p_f} {
    variable vals
    variable widgets

    frame $p_f.dev
    set dev_cb [checkbutton $p_f.dev.dev_enable -text "Device" \
                    -variable Apol_NetContexts::vals(netifcon:dev_enable)]
    set widgets(netifcon:dev) [ComboBox $p_f.dev.dev -entrybg white -width 8 -state disabled \
                                   -textvariable Apol_NetContexts::vals(netifcon:dev) -autopost 1]
    trace add variable Apol_NetContexts::vals(netifcon:dev_enable) write \
        [list Apol_NetContexts::_toggleCheckbutton $widgets(netifcon:dev)]
    pack $dev_cb -side top -anchor w
    pack $widgets(netifcon:dev) -side top -expand 0 -fill x -padx 4

    frame $p_f.ifcon
    set widgets(netifcon:ifcon) [Apol_Widget::makeContextSelector $p_f.ifcon.context "Contexts" "Interface context" -width 18]
    pack $widgets(netifcon:ifcon)

    frame $p_f.msgcon
    set widgets(netifcon:msgcon) [Apol_Widget::makeContextSelector $p_f.msgcon.context "Contexts" "Message context" -width 18]
    pack $widgets(netifcon:msgcon)

    pack $p_f.dev $p_f.ifcon $p_f.msgcon -side left -padx 4 -pady 2 -anchor nw
}

proc Apol_NetContexts::_netifcon_open {} {
    variable vals

    set q [new_apol_netifcon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set vals(netifcon:items) [lsort [netifcon_vector_to_list $v]]
    $v -delete

    variable widgets
    $widgets(netifcon:dev) configure -values $vals(netifcon:items)
}

proc Apol_NetContexts::_netifcon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "NetIF Contexts"
    $widgets(options_pm) raise netifcon
    set vals(items) $vals(netifcon:items)
}

proc Apol_NetContexts::_netifcon_popup {netif} {
    set text "network interface $netif"
    append text "\n    [_netifcon_render $netif]"
    Apol_Widget::showPopupText "interface $netif" $text
}

proc Apol_NetContexts::_netifcon_runSearch {} {
    variable vals
    variable widgets

    if {$vals(netifcon:dev_enable)} {
        if {$vals(netifcon:dev) == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No device selected."
            return
        }
        set dev $vals(netifcon:dev)
    } else {
        set dev {}
    }

    set q [new_apol_netifcon_query_t]
    $q set_device $::ApolTop::policy $dev
    if {[Apol_Widget::getContextSelectorState $widgets(netifcon:ifcon)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(netifcon:ifcon)] {break}
        $q set_if_context $::ApolTop::policy $context $range_match
    }
    if {[Apol_Widget::getContextSelectorState $widgets(netifcon:msgcon)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(netifcon:msgcon)] {break}
        $q set_msg_context $::ApolTop::policy $context $range_match
    }
    set v [$q run $::ApolTop::policy]
    $q -delete
    set netifcons [netifcon_vector_to_list $v]
    $v -delete

    set results "NETIFCONS:"
    if {[llength $netifcons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach n [lsort $netifcons] {
            append results "\n[_netifcon_render $n]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_NetContexts::_netifcon_render {netifcon} {
    set qpol_netifcon_datum [new_qpol_netifcon_t $::ApolTop::qpolicy $netifcon]
    apol_netifcon_render $::ApolTop::policy $qpol_netifcon_datum
}

#### nodecon private functions below ####

proc Apol_NetContexts::_nodecon_create {p_f} {
    variable vals
    variable widgets

    frame $p_f.ip_type
    set ipv4_rb [radiobutton $p_f.ip_type.v4 -text "IPv4" -value ipv4 \
                     -variable Apol_NetContexts::vals(nodecon:ip_type)]
    set ipv6_rb [radiobutton $p_f.ip_type.v6 -text "IPv6" -value ipv6 \
                     -variable Apol_NetContexts::vals(nodecon:ip_type)]
    trace add variable Apol_NetContexts::vals(nodecon:ip_type) write \
        [list Apol_NetContexts::_nodecon_pageChanged]
    pack $ipv4_rb $ipv6_rb -side top -anchor nw -pady 5

    frame $p_f.opts
    set widgets(nodecon:ip_pm) [PagesManager $p_f.opts.pm]
    _nodecon_ipv4Create [$widgets(nodecon:ip_pm) add ipv4]
    _nodecon_ipv6Create [$widgets(nodecon:ip_pm) add ipv6]
    $widgets(nodecon:ip_pm) compute_size
    pack $widgets(nodecon:ip_pm)
    $widgets(nodecon:ip_pm) raise ipv4

    frame $p_f.con
    set widgets(nodecon:context) [Apol_Widget::makeContextSelector $p_f.con.context "Contexts"]
    pack $widgets(nodecon:context)

    pack $p_f.ip_type $p_f.opts $p_f.con -side left -padx 4 -pady 2 -anchor nw
}

proc Apol_NetContexts::_nodecon_open {} {
    set q [new_apol_nodecon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set nodecons [nodecon_vector_to_list $v]
    $v -delete

    variable vals
    variable widgets
    set vals(nodecon:items) {}
    foreach n [lsort -command _nodecon_sort $nodecons] {
        set proto [$n get_protocol $::ApolTop::qpolicy]
        set addr [$n get_addr $::ApolTop::qpolicy]
        if {$proto == $::QPOL_IPV4} {
            set addr [apol_ipv4_addr_render $::ApolTop::policy $addr]
        } elseif {$proto == $::QPOL_IPV6} {
            set addr [apol_ipv6_addr_render $::ApolTop::policy $addr]
        } else {
            puts stderr "Unknown protocol $proto"
            exit -1
        }
        lappend vals(nodecon:items) $addr
    }
    set vals(nodecon:items) [lsort -unique -dictionary $vals(nodecon:items)]
}

proc Apol_NetContexts::_nodecon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "Node Contexts"
    $widgets(options_pm) raise nodecon
    set vals(items) $vals(nodecon:items)
}

proc Apol_NetContexts::_nodecon_ipv4Create {fv4} {
    variable widgets
    set v4addrf [frame $fv4.addr]
    set ipv4_addr_cb [checkbutton $v4addrf.enable -text "IP address" \
                          -variable Apol_NetContexts::vals(nodecon:ipv4_addr_enable)]
    set widgets(nodecon:v4addrf2) [frame $v4addrf.a]
    for {set i 0} {$i < 4} {incr i} {
        set e [entry $widgets(nodecon:v4addrf2).e$i -bg white -justify center -width 4 \
                   -state disabled \
                   -validate all -vcmd [list Apol_NetContexts::_nodecon_limitAddr %W %V %P ipv4_addr$i] \
                   -textvariable Apol_NetContexts::vals(nodecon:ipv4_addr$i)]
        pack $e -side left -padx 1 -anchor center
        if {$i < 3} {
            pack [label $widgets(nodecon:v4addrf2).l$i -text "."] -side left -expand 0 -anchor s
        }
    }
    trace add variable Apol_NetContexts::vals(nodecon:ipv4_addr_enable) write \
        [list Apol_NetContexts::_nodecon_toggleV4button $widgets(nodecon:v4addrf2).e]
    pack $ipv4_addr_cb -anchor w
    pack $widgets(nodecon:v4addrf2) -padx 3 -expand 0 -fill x

    set v4maskf [frame $fv4.mask]
    set ipv4_mask_cb [checkbutton $v4maskf.enable -text "Mask" \
                          -variable Apol_NetContexts::vals(nodecon:ipv4_mask_enable)]
    set widgets(nodecon:v4maskf2) [frame $v4maskf.m]
    for {set i 0} {$i < 4} {incr i} {
        set e [entry $widgets(nodecon:v4maskf2).e$i -bg white -justify center -width 4 \
                   -state disabled \
                   -validate all -vcmd [list Apol_NetContexts::_nodecon_limitAddr %W %V %P ipv4_mask$i] \
                   -textvariable Apol_NetContexts::vals(nodecon:ipv4_mask$i)]
        pack $e -side left -padx 1 -anchor center
        if {$i < 3} {
            pack [label $widgets(nodecon:v4maskf2).l$i -text "."] -side left -expand 0 -anchor s
        }
    }
    trace add variable Apol_NetContexts::vals(nodecon:ipv4_mask_enable) write \
        [list Apol_NetContexts::_nodecon_toggleV4button $widgets(nodecon:v4maskf2).e]
    pack $ipv4_mask_cb -anchor w
    pack $widgets(nodecon:v4maskf2) -padx 3 -expand 0 -fill x

    pack $v4addrf $v4maskf -padx 4 -pady 2 -anchor nw
}

proc Apol_NetContexts::_nodecon_ipv6Create {fv6} {
    set v6addrf [frame $fv6.addr]
    set ipv4_addr_cb [checkbutton $v6addrf.enable -text "IP address" \
                          -variable Apol_NetContexts::vals(nodecon:ipv6_addr_enable)]
    set e [entry $v6addrf.addr -bg white -width 28 -state disabled \
               -textvariable Apol_NetContexts::vals(nodecon:ipv6_addr)]
    trace add variable Apol_NetContexts::vals(nodecon:ipv6_addr_enable) write \
        [list Apol_NetContexts::_toggleCheckbutton $e]
    pack $ipv4_addr_cb -anchor w
    pack $e -padx 4 -expand 0 -fill x

    set v6maskf [frame $fv6.mask]
    set ipv6_mask_cb [checkbutton $v6maskf.enable -text "Mask" \
                          -variable Apol_NetContexts::vals(nodecon:ipv6_mask_enable)]
    set e [entry $v6maskf.addr -bg white -width 28 -state disabled \
               -textvariable Apol_NetContexts::vals(nodecon:ipv6_mask)]
    trace add variable Apol_NetContexts::vals(nodecon:ipv6_mask_enable) write \
        [list Apol_NetContexts::_toggleCheckbutton $e]
    pack $ipv6_mask_cb -anchor w
    pack $e -padx 4 -expand 0 -fill x

    pack $v6addrf $v6maskf -padx 4 -pady 2 -anchor w
}

proc Apol_NetContexts::_nodecon_pageChanged {name1 name2 op} {
    variable vals
    variable widgets
    $widgets(nodecon:ip_pm) raise $vals(nodecon:ip_type)
}

proc Apol_NetContexts::_nodecon_limitAddr {widget command new_addr varname} {
    variable vals
    if {$command == "key"} {
        if {$new_addr != "" &&
            (![string is integer $new_addr] || $new_addr < 0 || $new_addr > 255)} {
            return 0
        }
    } elseif {$command == "focusout"} {
        if {$new_addr == ""} {
            set vals(nodecon:$varname) 0
        } elseif {[string length $new_addr] > 1} {
            set vals(nodecon:$varname) [string trimleft $new_addr " 0"]
        }

        # re-enable the validation command (it could have been
        # disabled because the variable changed)
        after idle [list $widget config -validate all]
    }
    return 1
}

proc Apol_NetContexts::_nodecon_toggleV4button {path name1 name2 op} {
    variable vals
    if {$vals($name2)} {
        for {set i 0} {$i < 4} {incr i} {
            ${path}${i} configure -state normal
        }
    } else {
        for {set i 0} {$i < 4} {incr i} {
            ${path}${i} configure -state disabled
        }
    }
}

proc Apol_NetContexts::_nodecon_popup {nodecon_addr} {
    set q [new_apol_nodecon_query_t]
    set ip [apol_str_to_internal_ip $nodecon_addr]
    $q set_addr $::ApolTop::policy $ip
    $ip -delete
    set v [$q run $::ApolTop::policy]
    $q -delete
    set nodecons [nodecon_vector_to_list $v]
    $v -delete

    set text "nodecon $nodecon_addr ([llength $nodecons] context"
    if {[llength $nodecons] != 1} {
        append text s
    }
    append text ")"
    foreach n [lsort -command _nodecon_sort $nodecons] {
        append text "\n    [_nodecon_render $n]"
    }
    Apol_Widget::showPopupText "address $nodecon_addr" $text
}

proc Apol_NetContexts::_nodecon_runSearch {} {
    variable vals
    variable widgets

    set addr {}
    set mask {}
    if {$vals(nodecon:ip_type) == "ipv4"} {
        # explicitly validate the entries (they could still have focus)
        foreach i {0 1 2 3} {
            _nodecon_limitAddr $widgets(nodecon:v4addrf2).e$i focusout $vals(nodecon:ipv4_addr$i) ipv4_addr$i
            _nodecon_limitAddr $widgets(nodecon:v4maskf2).e$i focusout $vals(nodecon:ipv4_mask$i) ipv4_mask$i
        }
        if {$vals(nodecon:ipv4_addr_enable)} {
            set addr [format "%d.%d.%d.%d" \
                          $vals(nodecon:ipv4_addr0) $vals(nodecon:ipv4_addr1) \
                          $vals(nodecon:ipv4_addr2) $vals(nodecon:ipv4_addr3)]
        }
        if {$vals(nodecon:ipv4_mask_enable)} {
            set mask [format "%d.%d.%d.%d" \
                          $vals(nodecon:ipv4_mask0) $vals(nodecon:ipv4_mask1) \
                          $vals(nodecon:ipv4_mask2) $vals(nodecon:ipv4_mask3)]
        }
        set proto $::QPOL_IPV4
    } else {
        if {$vals(nodecon:ipv6_addr_enable)} {
            if {[set addr $vals(nodecon:ipv6_addr)] == {}} {
                tk_messageBox -icon error -type ok -title "Error" -message "No IPV6 address provided."
                return
            }
        }
        if {$vals(nodecon:ipv6_mask_enable)} {
            if {[set mask $vals(nodecon:ipv6_mask)] == {}} {
                tk_messageBox -icon error -type ok -title "Error" -message "No IPV6 address provided."
                return
            }
        }
        set proto $::QPOL_IPV6
    }

    set q [new_apol_nodecon_query_t]
    $q set_protocol $::ApolTop::policy $proto
    if {$addr != {}} {
        if {[catch {apol_str_to_internal_ip $addr} u]} {
            tk_messageBox -icon error -type ok -title "Error" -message $u
            return
        }
        $q set_addr $::ApolTop::policy $u
    }
    if {$mask != {}} {
        if {[catch {apol_str_to_internal_ip $mask} u]} {
            tk_messageBox -icon error -type ok -title "Error" -message $u
            return
        }
        $q set_mask $::ApolTop::policy $u
    }
    if {[Apol_Widget::getContextSelectorState $widgets(nodecon:context)]} {
        foreach {context range_match attribute} [Apol_Widget::getContextSelectorValue $widgets(nodecon:context)] {break}
        $q set_context $::ApolTop::policy $context $range_match
    }

    set v [$q run $::ApolTop::policy]
    $q -delete
    set nodecons [nodecon_vector_to_list $v]
    $v -delete

    set results "NODECONS:"
    if {[llength $nodecons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach n [lsort -command _nodecon_sort $nodecons] {
            append results "\n[_nodecon_render $n]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_NetContexts::_nodecon_render {qpol_nodecon_datum} {
    apol_nodecon_render $::ApolTop::policy $qpol_nodecon_datum
}

# Sort nodecons, grouping ipv4 before ipv6.  Then sort by address and
# then mask.
proc Apol_NetContexts::_nodecon_sort {a b} {
    set proto1 [$a get_protocol $::ApolTop::qpolicy]
    set proto2 [$b get_protocol $::ApolTop::qpolicy]
    if {$proto1 == $::QPOL_IPV4 && $proto2 == $::QPOL_IPV6} {
        return -1
    } elseif {$proto1 == $::QPOL_IPV6 && $proto1 == $::QPOL_IPV4} {
        return 0
    }

    if {$proto1 == $::QPOL_IPV4} {
        set render apol_ipv4_addr_render
    } else {
        set render apol_ipv6_addr_render
    }
    set addr1 [$render $::ApolTop::policy [$a get_addr $::ApolTop::qpolicy]]
    set addr2 [$render $::ApolTop::policy [$b get_addr $::ApolTop::qpolicy]]
    if {[set x [string compare $addr1 $addr2]] != 0} {
        return $x
    }

    set mask1 [$render $::ApolTop::policy [$a get_mask $::ApolTop::qpolicy]]
    set mask2 [$render $::ApolTop::policy [$b get_mask $::ApolTop::qpolicy]]
    string compare $mask1 $mask2
}
