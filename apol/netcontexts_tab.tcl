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

proc Apol_NetContexts::open {ppath} {
    variable vals

    portcon_open
    netifcon_open
    nodecon_open

    # force a flip to the portcon page
    set vals(context_type) portcon
}

proc Apol_NetContexts::close {} {
    variable widgets

    initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(portcon:context)
    Apol_Widget::clearContextSelector $widgets(netifcon:ifcon)
    Apol_Widget::clearContextSelector $widgets(netifcon:msgcon)
    Apol_Widget::clearContextSelector $widgets(nodecon:context)
    $widgets(portcon:proto) configure -values {}
    $widgets(netifcon:dev) configure -values {}
}

proc Apol_NetContexts::initializeVars {} {
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

proc Apol_NetContexts::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

proc Apol_NetContexts::create {tab_name nb} {
    variable widgets
    variable vals

    initializeVars

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
        {Apol_NetContexts::contextTypeChanged}
    pack $context_f.portcon $context_f.netifcon $context_f.nodecon \
        -anchor w -expand 0 -padx 4 -pady 5
    pack $context_box -anchor nw -expand 0 -fill x

    set widgets(items_tf) [TitleFrame $leftf.items_f -text "Port Contexts"]
    set widgets(items) [Apol_Widget::makeScrolledListbox [$widgets(items_tf) getframe].items \
                            -height 20 -width 20 -listvar Apol_NetContexts::vals(items)]
    Apol_Widget::setListboxCallbacks $widgets(items) \
        {{"Show Context Info" {Apol_NetContexts::popupContextInfo}}}
    pack $widgets(items) -expand 1 -fill both
    pack $widgets(items_tf) -expand 1 -fill both

    # build the search options
    set optsbox [TitleFrame $rightf.optsbox -text "Search Options"]
    pack $optsbox -side top -expand 0 -fill both -padx 2
    set widgets(options_pm) [PagesManager [$optsbox getframe].pm]

    portcon_create [$widgets(options_pm) add portcon]
    netifcon_create [$widgets(options_pm) add netifcon]
    nodecon_create [$widgets(options_pm) add nodecon]

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise portcon

    # add okay button to the top-right corner
    set ok [button [$optsbox getframe].ok -text "OK" -width 6 \
                -command Apol_NetContexts::runSearch]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # build the results box
    set resultsbox [TitleFrame $rightf.resultsbox -text "Search Results"]
    pack $resultsbox -expand yes -fill both -padx 2
    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}

#### private functions below ####

proc Apol_NetContexts::popupContextInfo {value} {
    variable vals
    if {$vals(context_type) == "portcon"} {
        portcon_popup $value
    } elseif {$vals(context_type) == "netifcon"} {
        netifcon_popup $value
    } else {
        nodecon_popup $value
    }
}

proc Apol_NetContexts::contextTypeChanged {name1 name2 op} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {$vals(context_type) == "portcon"} {
        portcon_show
    } elseif {$vals(context_type) == "netifcon"} {
        netifcon_show
    } else {
        nodecon_show
    }
}

proc Apol_NetContexts::toggleCheckbutton {path name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $path configure -state normal
    } else {
        $path configure -state disabled
    }
}

proc Apol_NetContexts::runSearch {} {
    variable vals
    variable widgets
    
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {$vals(context_type) == "portcon"} {
        portcon_runSearch
    } elseif {$vals(context_type) == "netifcon"} {
        netifcon_runSearch
    } else {
        nodecon_runSearch
    }
}

#### portcon private functions below ####

proc Apol_NetContexts::portcon_open {} {
    set q [new_apol_portcon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set portcons [lsort [portcon_vector_to_list $v]]
    $v -delete

    variable vals
    variable widgets
    set vals(portcon:items) {}
    set protos {}
    foreach p $portcons {
        foreach {low high proto} $p {break}
        if {$low == $high} {
            lappend vals(portcon:items) $low
        } else {
            lappend vals(portcon:items) "$low-$high"
        }
        lappend protos [apol_protocol_to_str $proto]
    }

    set vals(portcon:items) [lsort -unique -dictionary $vals(portcon:items)]
    $widgets(portcon:proto) configure -values [lsort -unique -dictionary $protos]
}

proc Apol_NetContexts::portcon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "Port Contexts"
    $widgets(options_pm) raise portcon
    set vals(items) $vals(portcon:items)
}

# create the portcon-specific options widgets
proc Apol_NetContexts::portcon_create {p_f} {
    variable widgets
    variable vals

    frame $p_f.proto
    set proto_cb [checkbutton $p_f.proto.proto_enable -text "Protocol" \
                      -variable Apol_NetContexts::vals(portcon:proto_enable)]
    set widgets(portcon:proto) [ComboBox $p_f.proto.proto -entrybg white -width 8 -state disabled \
                                    -textvariable Apol_NetContexts::vals(portcon:proto) -autopost 1]
    trace add variable Apol_NetContexts::vals(portcon:proto_enable) write \
        [list Apol_NetContexts::toggleCheckbutton $widgets(portcon:proto)]
    pack $proto_cb -side top -anchor w
    pack $widgets(portcon:proto) -side top -expand 0 -fill x -padx 4

    frame $p_f.port
    set low [frame $p_f.port.l]
    set port_cb [checkbutton $low.port_enable -text "Single Port" \
                     -variable Apol_NetContexts::vals(portcon:port_enable)]
    set widgets(portcon:port) [spinbox $low.port -bg white -width 8 \
                                   -justify right -state disabled \
                                   -from 0 -to 65535 \
                                   -validate all -vcmd [list Apol_NetContexts::portcon_limitPort %W %V %P port] \
                                   -textvariable Apol_NetContexts::vals(portcon:port)]
    set high [frame $p_f.port.h]
    set hiport_cb [checkbutton $high.hiport_enable -text "High Port" \
                       -state disabled \
                       -variable Apol_NetContexts::vals(portcon:hiport_enable)]
    set widgets(portcon:hiport) [spinbox $high.hiport -bg white -width 8 \
                                     -justify right -state disabled \
                                     -from 0 -to 65535 \
                                     -validate all -vcmd [list Apol_NetContexts::portcon_limitPort %W %V %P hiport] \
                                     -textvariable Apol_NetContexts::vals(portcon:hiport)]
    trace add variable Apol_NetContexts::vals(portcon:port_enable) write \
        [list Apol_NetContexts::portcon_toggleCheckbutton_lowport \
             $widgets(portcon:port) $hiport_cb $widgets(portcon:hiport)]
    trace add variable Apol_NetContexts::vals(portcon:hiport_enable) write \
        [list Apol_NetContexts::portcon_toggleCheckbutton_hiport $port_cb $widgets(portcon:hiport)]
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

proc Apol_NetContexts::portcon_limitPort {widget command new_port varname} {
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

proc Apol_NetContexts::portcon_toggleCheckbutton_lowport {low high_cb high name1 name2 op} {
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

proc Apol_NetContexts::portcon_toggleCheckbutton_hiport {low high name1 name2 op} {
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

proc Apol_NetContexts::portcon_render {portcon} {
    foreach {loport hiport proto context} $portcon {break}
    if {$loport == $hiport} {
        set line "portcon $proto $loport "
    } else {
        set line "portcon $proto ${loport}-${hiport} "
    }
    concat $line [apol_RenderContext $context]
}

proc Apol_NetContexts::portcon_popup {port} { 
    foreach {low high} [split $port "-"] {break}
    if {$high == {}} {
        set high $low
    }
    set portcons [apol_GetPortcons $low $high]
    set text "port $port ([llength $portcons] context"
    if {[llength $portcons] != 1} {
        append text s
    }
    append text ")"
    foreach p [lsort -command portcon_sort $portcons] {
        append text "\n\t[portcon_render $p]"
    }
    Apol_Widget::showPopupText "port $port" $text
}

proc Apol_NetContexts::portcon_sort {a b} {
    foreach {loport1 hiport1 proto1 context1} $a {break}
    foreach {loport2 hiport2 proto2 context2} $b {break}
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
    string compare $proto1 $proto2
}

proc Apol_NetContexts::portcon_runSearch {} {
    variable vals
    variable widgets

    # explicitly validate the spinboxes (they could still have focus)
    portcon_limitPort $widgets(portcon:port) focusout $vals(portcon:port) port
    portcon_limitPort $widgets(portcon:hiport) focusout $vals(portcon:hiport) hiport

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
    if {$vals(portcon:proto_enable)} {
        if {[set proto $vals(portcon:proto)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No protocol selected."
            return
        }
    } else {
        set proto {}
    }
    if {[Apol_Widget::getContextSelectorState $widgets(portcon:context)]} {
        foreach {context range_match} [Apol_Widget::getContextSelectorValue $widgets(portcon:context)] {break}
    } else {
        set context {}
        set range_match 0
    }
    if {[catch {apol_GetPortcons $low $high $proto $context $range_match} portcons]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining portcons list:\n$portcons"
        return
    }

    # now display results
    set results "PORTCONS:"
    if {[llength $portcons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach p [lsort -command portcon_sort $portcons] {
            append results "\n[portcon_render $p]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}


#### netifcon private functions below ####

proc Apol_NetContexts::netifcon_open {} {
    variable vals

    set q [new_apol_netifcon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set vals(netifcon:items) [lsort [netifcon_vector_to_list $v]]
    $v -delete
    
    variable widgets
    $widgets(netifcon:dev) configure -values $vals(netifcon:items)
}

proc Apol_NetContexts::netifcon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "NetIF Contexts"
    $widgets(options_pm) raise netifcon
    set vals(items) $vals(netifcon:items)
}

proc Apol_NetContexts::netifcon_create {p_f} {
    variable vals
    variable widgets

    frame $p_f.dev
    set dev_cb [checkbutton $p_f.dev.dev_enable -text "Device" \
                    -variable Apol_NetContexts::vals(netifcon:dev_enable)]
    set widgets(netifcon:dev) [ComboBox $p_f.dev.dev -entrybg white -width 8 -state disabled \
                                   -textvariable Apol_NetContexts::vals(netifcon:dev) -autopost 1]
    trace add variable Apol_NetContexts::vals(netifcon:dev_enable) write \
        [list Apol_NetContexts::toggleCheckbutton $widgets(netifcon:dev)]
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

proc Apol_NetContexts::netifcon_render {netifcon_datum} {
    foreach {dev ifcon msgcon} $netifcon_datum {break}
    set line "netifcon $dev "
    append line "[apol_RenderContext $ifcon] [apol_RenderContext $msgcon]"
}

proc Apol_NetContexts::netifcon_popup {netif} {
    set netifcons [apol_GetNetifcons $netif]
    set text "network interface $netif ([llength $netifcons] context"
    if {[llength $netifcons] != 1} {
        append text s
    }
    append text ")"
    foreach n [lsort -index 0 $netifcons] {
        append text "\n\t[netifcon_render $n]"
    }
    Apol_Widget::showPopupText "interface $netif" $text
}

proc Apol_NetContexts::netifcon_runSearch {} {
    variable vals
    variable widgets
    if {$vals(netifcon:dev_enable)} {
        if {[set dev $vals(netifcon:dev)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No device selected."
            return
        }
    } else {
        set dev {}
    }
    if {[Apol_Widget::getContextSelectorState $widgets(netifcon:ifcon)]} {
        foreach {ifcon_context ifcon_range_match} [Apol_Widget::getContextSelectorValue $widgets(netifcon:ifcon)] {break}
    } else {
        set ifcon_context {}
        set ifcon_range_match 0
    }
    if {[Apol_Widget::getContextSelectorState $widgets(netifcon:msgcon)]} {
        foreach {msgcon_context msgcon_range_match} [Apol_Widget::getContextSelectorValue $widgets(netifcon:msgcon)] {break}
    } else {
        set msgcon_context {}
        set msgcon_range_match 0
    }
    if {[catch {apol_GetNetifcons $dev $ifcon_context $ifcon_range_match \
                    $msgcon_context $msgcon_range_match} netifcons]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining netifcons list:\n$netifcons"
        return
    }

    # now display results
    set results "NETIFCONS:"
    if {[llength $netifcons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach n [lsort -index 0 $netifcons] {
            append results "\n[netifcon_render $n]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}


#### nodecon private functions below ####

proc Apol_NetContexts::nodecon_open {} {
    set q [new_apol_nodecon_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    set nodecons [nodecon_vector_to_list $v]
    $v -delete

    variable vals
    variable widgets
    set vals(nodecon:items) {}
    foreach n [lsort -command nodecon_sort $nodecons] {
        set addr [lindex $n 1]
        if {[lsearch $vals(nodecon:items) $addr] == -1} {
            lappend vals(nodecon:items) $addr
        }
    }
}

proc Apol_NetContexts::nodecon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "Node Contexts"
    $widgets(options_pm) raise nodecon
    set vals(items) $vals(nodecon:items)
}

proc Apol_NetContexts::nodecon_create {p_f} {
    variable vals
    variable widgets

    frame $p_f.ip_type
    set ipv4_rb [radiobutton $p_f.ip_type.v4 -text "IPv4" -value ipv4 \
                     -variable Apol_NetContexts::vals(nodecon:ip_type)]
    set ipv6_rb [radiobutton $p_f.ip_type.v6 -text "IPv6" -value ipv6 \
                     -variable Apol_NetContexts::vals(nodecon:ip_type)]
    trace add variable Apol_NetContexts::vals(nodecon:ip_type) write \
        [list Apol_NetContexts::nodecon_pageChanged]
    pack $ipv4_rb $ipv6_rb -side top -anchor nw -pady 5
    
    frame $p_f.opts
    set widgets(nodecon:ip_pm) [PagesManager $p_f.opts.pm]
    nodecon_ipv4Create [$widgets(nodecon:ip_pm) add ipv4]
    nodecon_ipv6Create [$widgets(nodecon:ip_pm) add ipv6]
    $widgets(nodecon:ip_pm) compute_size
    pack $widgets(nodecon:ip_pm)
    $widgets(nodecon:ip_pm) raise ipv4

    frame $p_f.con
    set widgets(nodecon:context) [Apol_Widget::makeContextSelector $p_f.con.context "Contexts"]
    pack $widgets(nodecon:context)

    pack $p_f.ip_type $p_f.opts $p_f.con -side left -padx 4 -pady 2 -anchor nw
}
    
proc Apol_NetContexts::nodecon_ipv4Create {fv4} {
    variable widgets
    set v4addrf [frame $fv4.addr]
    set ipv4_addr_cb [checkbutton $v4addrf.enable -text "IP address" \
                          -variable Apol_NetContexts::vals(nodecon:ipv4_addr_enable)]
    set widgets(nodecon:v4addrf2) [frame $v4addrf.a]
    for {set i 0} {$i < 4} {incr i} {
        set e [entry $widgets(nodecon:v4addrf2).e$i -bg white -justify center -width 4 \
                   -state disabled \
                   -validate all -vcmd [list Apol_NetContexts::nodecon_limitAddr %W %V %P ipv4_addr$i] \
                   -textvariable Apol_NetContexts::vals(nodecon:ipv4_addr$i)]
        pack $e -side left -padx 1 -anchor center
        if {$i < 3} {
            pack [label $widgets(nodecon:v4addrf2).l$i -text "."] -side left -expand 0 -anchor s
        }
    }
    trace add variable Apol_NetContexts::vals(nodecon:ipv4_addr_enable) write \
        [list Apol_NetContexts::nodecon_toggleV4button $widgets(nodecon:v4addrf2).e]
    pack $ipv4_addr_cb -anchor w
    pack $widgets(nodecon:v4addrf2) -padx 3 -expand 0 -fill x

    set v4maskf [frame $fv4.mask]
    set ipv4_mask_cb [checkbutton $v4maskf.enable -text "Mask" \
                          -variable Apol_NetContexts::vals(nodecon:ipv4_mask_enable)]
    set widgets(nodecon:v4maskf2) [frame $v4maskf.m]
    for {set i 0} {$i < 4} {incr i} {
        set e [entry $widgets(nodecon:v4maskf2).e$i -bg white -justify center -width 4 \
                   -state disabled \
                   -validate all -vcmd [list Apol_NetContexts::nodecon_limitAddr %W %V %P ipv4_mask$i] \
                   -textvariable Apol_NetContexts::vals(nodecon:ipv4_mask$i)]
        pack $e -side left -padx 1 -anchor center
        if {$i < 3} {
            pack [label $widgets(nodecon:v4maskf2).l$i -text "."] -side left -expand 0 -anchor s
        }
    }
    trace add variable Apol_NetContexts::vals(nodecon:ipv4_mask_enable) write \
        [list Apol_NetContexts::nodecon_toggleV4button $widgets(nodecon:v4maskf2).e]
    pack $ipv4_mask_cb -anchor w
    pack $widgets(nodecon:v4maskf2) -padx 3 -expand 0 -fill x

    pack $v4addrf $v4maskf -padx 4 -pady 2 -anchor nw
}

proc Apol_NetContexts::nodecon_ipv6Create {fv6} {
    set v6addrf [frame $fv6.addr]
    set ipv4_addr_cb [checkbutton $v6addrf.enable -text "IP address" \
                          -variable Apol_NetContexts::vals(nodecon:ipv6_addr_enable)]
    set e [entry $v6addrf.addr -bg white -width 28 -state disabled \
               -textvariable Apol_NetContexts::vals(nodecon:ipv6_addr)]
    trace add variable Apol_NetContexts::vals(nodecon:ipv6_addr_enable) write \
        [list Apol_NetContexts::toggleCheckbutton $e]
    pack $ipv4_addr_cb -anchor w
    pack $e -padx 4 -expand 0 -fill x

    set v6maskf [frame $fv6.mask]
    set ipv6_mask_cb [checkbutton $v6maskf.enable -text "Mask" \
                          -variable Apol_NetContexts::vals(nodecon:ipv6_mask_enable)]
    set e [entry $v6maskf.addr -bg white -width 28 -state disabled \
               -textvariable Apol_NetContexts::vals(nodecon:ipv6_mask)]
    trace add variable Apol_NetContexts::vals(nodecon:ipv6_mask_enable) write \
        [list Apol_NetContexts::toggleCheckbutton $e]
    pack $ipv6_mask_cb -anchor w
    pack $e -padx 4 -expand 0 -fill x

    pack $v6addrf $v6maskf -padx 4 -pady 2 -anchor w
}

proc Apol_NetContexts::nodecon_pageChanged {name1 name2 op} {
    variable vals
    variable widgets
    $widgets(nodecon:ip_pm) raise $vals(nodecon:ip_type)
}

proc Apol_NetContexts::nodecon_limitAddr {widget command new_addr varname} {
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

proc Apol_NetContexts::nodecon_toggleV4button {path name1 name2 op} {
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

proc Apol_NetContexts::nodecon_render {nodecon} {
    foreach {iptype addr mask context} $nodecon {break}
    return "nodecon $addr $mask [apol_RenderContext $context]"
}

proc Apol_NetContexts::nodecon_popup {nodecon} {
    if {[catch {apol_GetNodecons $nodecon} nodecons]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining nodecons list:\n$nodecons"
        return
    }
    set text "nodecon $nodecon ([llength $nodecons] context"
    if {[llength $nodecons] != 1} {
        append text s
    }
    append text ")"
    foreach n [lsort -index 0 $nodecons] {
        append text "\n\t[nodecon_render $n]"
    }
    Apol_Widget::showPopupText "address $nodecon" $text
}

# Sort nodecons, grouping ipv4 before ipv6.  Then sort by address and
# then mask.
proc Apol_NetContexts::nodecon_sort {a b} {
    foreach {t1 a1 m1 c1} $a {break}
    foreach {t2 a2 m2 c2} $b {break}
    if {$t1 == "ipv4" && $t2 == "ipv6"} {
        return -1
    } elseif {$t1 == "ipv6" && $t1 == "ipv4"} {
        return 0
    }
    if {[set x [string compare $a1 $a2]] != 0} {
        return $x
    }
    string compare $m1 $m2
}

proc Apol_NetContexts::nodecon_runSearch {} {
    variable vals
    variable widgets
    set addr {}
    set mask {}
    set context {}
    set range_match 0
    if {$vals(nodecon:ip_type) == "ipv4"} {
        # explicitly validate the entries (they could still have focus)
        foreach i {0 1 2 3} {
            nodecon_limitAddr $widgets(nodecon:v4addrf2).e$i focusout $vals(nodecon:ipv4_addr$i) ipv4_addr$i
            nodecon_limitAddr $widgets(nodecon:v4maskf2).e$i focusout $vals(nodecon:ipv4_mask$i) ipv4_mask$i
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
    }
    if {[Apol_Widget::getContextSelectorState $widgets(nodecon:context)]} {
        foreach {context range_match} [Apol_Widget::getContextSelectorValue $widgets(nodecon:context)] {break}
    }
    if {[catch {apol_GetNodecons $addr $mask $vals(nodecon:ip_type) $context $range_match} nodecons]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining nodecons list:\n$nodecons"
        return
    }

    # now display results
    set results "NODECONS:"
    if {[llength $nodecons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach n [lsort -command nodecon_sort $nodecons] {
            append results "\n[nodecon_render $n]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results    
}
