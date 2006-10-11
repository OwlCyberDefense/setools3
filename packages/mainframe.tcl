# this fragment was taken from BWidget 1.8 release, slightly modified
proc MainFrame::_create_menubar { path descmenu } {
    variable _widget
    global    tcl_platform

    set top $_widget($path,top)

    foreach {v x} {mbfnt -menubarfont mefnt -menuentryfont} {
	if {[string length [Widget::getoption $path $x]]} {
	    set $v [list -font [Widget::getoption $path $x]]
	} else {
	    set $v ""
	}
    }

    if {$tcl_platform(platform) == "unix"} {
	set menuopts [list -background [Widget::getoption $path -background] \
			  -borderwidth 1]
    } else {
	set menuopts [list]
    }
    set menubar [eval [list menu $top.menubar -tearoff 0] $menuopts $mbfnt]
    $top configure -menu $menubar

    set count 0
    foreach {name tags menuid tearoff entries} $descmenu {
        set opt  [_parse_name $name]
        if {[string length $menuid]
	    && ![info exists _widget($path,menuid,$menuid)] } {
            # menu has identifier
	    # we use it for its pathname, to enable special menu entries
	    # (help, system, ...)
	    set menu $menubar.$menuid
        } else {
	    set menu $menubar.menu$count
	}
        eval [list $menubar add cascade] $opt [list -menu $menu]
        eval [list menu $menu -tearoff $tearoff] $menuopts $mefnt
        foreach tag $tags {
            lappend _widget($path,tags,$tag) $menubar $count
	    # ericm@scriptics:  Add a tagstate tracker
	    if { ![info exists _widget($path,tagstate,$tag)] } {
		set _widget($path,tagstate,$tag) 1
	    }
        }
	# ericm@scriptics:  Add mapping from menu items to tags
	set _widget($path,menutags,[list $menubar $count]) $tags

        if { [string length $menuid] } {
            # menu has identifier
            set _widget($path,menuid,$menuid) $menu
        }
        _create_entries $path $menu $menuopts $entries
        incr count
    }
}


# ----------------------------------------------------------------------------
#  Command MainFrame::_create_entries
# ----------------------------------------------------------------------------
proc MainFrame::_create_entries { path menu menuopts entries } {
    variable _widget

    set count      [$menu cget -tearoff]
    set registered 0
    foreach entry $entries {
        set len  [llength $entry]
        set type [lindex $entry 0]

        if { [string equal $type "separator"] } {
            $menu add separator
            incr count
            continue
        }

        # entry name and tags
        set opt  [_parse_name [lindex $entry 1]]
        set tags [lindex $entry 2]
        foreach tag $tags {
            lappend _widget($path,tags,$tag) $menu $count
	    # ericm@scriptics:  Add a tagstate tracker
	    if { ![info exists _widget($path,tagstate,$tag)] } {
		set _widget($path,tagstate,$tag) 1
	    }
        }
	# ericm@scriptics:  Add mapping from menu items to tags
	set _widget($path,menutags,[list $menu $count]) $tags

        if {[string equal $type "cascade"] || [string equal $type "cascad"]} {
            set menuid  [lindex $entry 3]
            set tearoff [lindex $entry 4]
            set submenu $menu.menu$count
            eval [list $menu add cascade] $opt [list -menu $submenu]
            eval [list menu $submenu -tearoff $tearoff] $menuopts
            if { [string length $menuid] } {
                # menu has identifier
                set _widget($path,menuid,$menuid) $submenu
            }
            _create_entries $path $submenu $menuopts [lindex $entry 5]
            incr count
            continue
        }

        # entry help description
        set desc [lindex $entry 3]
        if { [string length $desc] } {
            if { !$registered } {
                DynamicHelp::register $menu menu [Widget::getoption $path -textvariable]
                set registered 1
            }
            DynamicHelp::register $menu menuentry $count $desc
        }

        # entry accelerator
        set accel [_parse_accelerator [lindex $entry 4]]
        if { [llength $accel] } {
            lappend opt -accelerator [lindex $accel 0]
            bind $_widget($path,top) [lindex $accel 1] [list $menu invoke $count]
        }

        # user options
        set useropt [lrange $entry 5 end]
        if { [string equal $type "command"] ||
             [string equal $type "radiobutton"] ||
             [string equal $type "checkbutton"] } {
            eval [list $menu add $type] $opt $useropt
        } else {
            return -code error "invalid menu type \"$type\""
        }
        incr count
    }
}
