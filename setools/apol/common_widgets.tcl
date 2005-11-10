# Copyright (C) 2001-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets 1.7+

namespace eval Apol_Widget {
    variable popup ""
}

proc Apol_Widget::makeScrolledListbox {path args} {
    set sw [ScrolledWindow $path -scrollbar both -auto both]
    set lb [eval listbox $sw.lb $args -bg white -highlightthickness 0]
    $sw setwidget $lb

    bind $lb <<ListboxSelect>> [list focus -force $lb]

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

    # enable right-clicks on listbox to popup a menu; that menu has a lets
    # the user see more info
    
    # first create a global popup menu widget if one does not already exist
    variable popup
    if {$popup == "" || ![winfo exists $popup]} {
        set popup [menu .apol_widget_popup]
    }

    set lb [getScrolledListbox $path]
    bind $lb <Button-3> [list ApolTop::popup_listbox_Menu %W %x %y $popup $callback_list $lb]
}

proc Apol_Widget::getScrolledListbox {path} {
    return $path.lb
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
    }
}

proc Apol_Widget::_listbox_double_click {listbox callback_func args} {
    eval $callback_func $args [$listbox get active]
}
