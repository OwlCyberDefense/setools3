#############################################################
#  relabel_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <jtang@tresys.com>
# -----------------------------------------------------------
#
# This is the implementation of the interface for File
# Relabeling Analysis
##############################################################
# ::Apol_Analysis_relabel module namespace
##############################################################

namespace eval Apol_Analysis_relabel {
    variable info_button_text "Foxy nymphs grab quick-lived waltz."

    # name of widget holding most recently executed assertion
    variable most_recent_results ""

    # Within the namespace command for the module, you must call
    # Apol_Analysis::register_analysis_modules, the first argument is
    # the namespace name of the module, and the second is the
    # descriptive display name you want to be displayed in the GUI
    # selection box.
    Apol_Analysis::register_analysis_modules "Apol_Analysis_relabel" \
        "File Relabeling Analysis"
}

# Apol_Analysis_relabel::initialize is called when the tool first
# starts up.  The analysis has the opportunity to do any additional
# initialization it must do that wasn't done in the initial namespace
# eval command.
proc Apol_Analysis_relabel::initialize { } {
    catch {console show}
    return 0
}

# Returns the text to display whenever the user hits the 'Info'
# button.
proc Apol_Analysis_relabel::get_analysis_info {} {
    return $Apol_Analysis_relabel::info_button_text
}

# Returns the name of the widget that contains the results for the
# currently selected results tab.  This widget should have been
# created by [do_analysis] below.  The module knows which result tab
# is raised due to the most recent call
# [set_display_to_results_state].
proc Apol_Analysis_relabel::get_results_raised_tab {} {
    variable most_recent_results
    return $most_recent_results
}

# The GUI will call Apol_Analysis_relabel::do_analysis when the
# module is to perform its analysis.  The module should know how to
# get its own option information.  The options are displayed via
# Apol_Analysis_relabel::display_mod_options.
proc Apol_Analysis_relabel::do_analysis {results_frame} {  
    tk_messageBox -icon error -type ok -title "File Relabeling Error" \
        -message "Not done yet."
    return -code error
}


# Apol_Analysis_relabel::close must exist; it is called when a
# policy is closed.  Typically you should reset any context or option
# variables you have.
proc Apol_Analysis_relabel::close { } {
    populate_lists 0
}

# Apol_Analysis_relabel::open must exist; it is called when a
# policy is opened.
proc Apol_Analysis_relabel::open { } {
    populate_lists 1
}

# Called whenever a user loads a query file.  Clear away the old
# contents of the assertion file and replace it with the remainder
# from $file_channel.
proc Apol_Analysis_relabel::load_query_options {file_channel parentDlg} {
    return 0
}

# Called whenever a user saves a query
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
proc Apol_Analysis_relabel::save_query_options {module_name file_channel file_name} {
    return 0
}

# Captures the current set of options, which is then later restored by
# [set_display_to_results_tab].
proc Apol_Analysis_relabel::get_current_results_state { } {
}

# Apol_Analysis_relabel::set_display_to_results_state is called to
# reset the options or any other context that analysis needs when the
# GUI switches back to an existing analysis.  options is a list that
# we created in a previous get_current_results_state() call.
proc Apol_Analysis_relabel::set_display_to_results_state { query_options } {
}

# Apol_Analysis_relabel::free_results_data is called to handle any
# cleanup of module options prior to [destroy]ing its parent frame.
# There are three times this function is called: when using the
# 'Update' button, when closing its result tab, and when closing all
# tabs.  query_options is a list that we created in a previous
# get_current_results_state() call, from which we extract the
# subwidget pathnames for the results frame.
proc Apol_Analysis_relabel::free_results_data {query_options} {  
}

# Apol_Analysis_dirflow::display_mod_options is called by the GUI to
# display the analysis options interface the analysis needs.  Each
# module must know how to display their own options, as well bind
# appropriate commands and variables with the options GUI.  opts_frame
# is the name of a frame in which the options GUI interface is to be
# packed.
proc Apol_Analysis_relabel::display_mod_options { opts_frame } {
    variable widgets
    array unset widgets
    variable widget_vars
    array unset widget_vars

    set option_f [frame $opts_frame.option_f]

    set widget_vars(mode) "relabelto"
    set mode_tf [TitleFrame $option_f.mode_tf -text "Mode"]
    set relabelto_rb [radiobutton [$mode_tf getframe].relabelto_rb \
                          -text "relabelto" -value "relabelto" \
                          -variable Apol_Analysis_relabel::widget_vars(mode) \
                          -command [namespace code set_mode_relabelto]]
    set relabelfrom_rb [radiobutton [$mode_tf getframe].relabelfrom_rb \
                            -text "relabelfrom" -value "relabelfrom" \
                            -variable Apol_Analysis_relabel::widget_vars(mode)\
                            -command [namespace code set_mode_relabelfrom]]
    set domain_rb [radiobutton [$mode_tf getframe].domain_rb \
                       -text "domain" -value "domain" \
                       -variable Apol_Analysis_relabel::widget_vars(mode) \
                       -command [namespace code set_mode_domain]]
    pack $relabelto_rb $relabelfrom_rb $domain_rb -anchor w -side top

    set req_tf [TitleFrame $option_f.req_tf -text "Required parameters"]
    set start_f [frame [$req_tf getframe].start_f]
    set attrib_f [frame [$req_tf getframe].attrib_frame]
    set widgets(start_l) [label $start_f.start_l -text "Starting type:"]
    set widgets(start_cb) [ComboBox $start_f.start_cb -editable 1 \
                               -entrybg white -width 16 \
                               -textvariable Apol_Analysis_relabel::widget_vars(start_type)]
    bindtags $widgets(start_cb).e [linsert [bindtags $widgets(start_cb).e] 3 start_cb_tag]
    bind start_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_cb) %W %K]
    pack $widgets(start_l) -side top -anchor nw -expand 0 -fill none
    pack $widgets(start_cb) -side top -anchor nw -expand 0 -fill x

    set widgets(start_attrib_ch) \
        [checkbutton $attrib_f.start_attrib_ch \
             -text "Select starting type using attrib:" \
             -variable Apol_Analysis_relabel::widget_vars(start_attrib_ch) \
             -command [namespace code toggle_attributes]]
    set widgets(start_attrib_cb) [ComboBox $attrib_f.start_attrib_cb \
                -editable 1 -entrybg white -width 16 \
                -modifycmd [namespace code [list set_types_list ""]] \
                -vcmd [namespace code [list set_types_list %P]] -validate key \
                -textvariable Apol_Analysis_relabel::widget_vars(start_attrib)]
    bindtags $widgets(start_attrib_cb).e [linsert [bindtags $widgets(start_attrib_cb).e] 3 start_attrib_cb_tag]
    bind start_attrib_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_attrib_cb) %W %K]
    pack $widgets(start_attrib_ch) -anchor nw -expand 0 -fill none
    pack $widgets(start_attrib_cb) -anchor nw -padx 15 -expand 0 -fill x
    pack $start_f -expand 0 -expand 0 -fill x
    pack $attrib_f -expand 0 -pady 20 -expand 0 -fill x
    
    set opt_tf [TitleFrame $option_f.opt_tf -text "Optional result filters"]
    
    set widgets(enable_filter_ch) \
        [checkbutton [$opt_tf getframe].enable_filter_ch \
             -text "Filter using permissions" \
             -command [namespace code toggle_permissions] \
             -variable Apol_Analysis_relabel::widget_vars(enable_filter_ch)]
    pack $widgets(enable_filter_ch) -side top -anchor w -expand 0 -fill none
    set filter_f [frame [$opt_tf getframe].filter_f]
    set filter_l_f [frame $filter_f.filter_l_f]
    set widgets(objs_l) [label $filter_l_f.objs_l -text "Object"]
    pack $widgets(objs_l) -side top -anchor w -expand 0
    set widgets(objs_cb) [ComboBox $filter_l_f.objs_cb -editable 1 \
                       -entrybg white -width 16 \
                       -modifycmd [namespace code [list set_perms_list ""]] \
                       -vcmd [namespace code [list set_perms_list %P]] \
                       -validate key \
                       -textvariable Apol_Analysis_relabel::widget_vars(objs)]
    bindtags $widgets(objs_cb).e [linsert [bindtags $widgets(objs_cb).e] 3 objs_cb_tag]
    bind objs_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(objs_cb) %W %K]
    pack $widgets(objs_cb) -side top -expand 0 -fill x
    set widgets(perms_l) [label $filter_l_f.perms_l -text "Permission"]
    pack $widgets(perms_l) -side top -anchor w -expand 0
    set widgets(perms_cb) [ComboBox $filter_l_f.perms_cb -editable 1 \
                       -entrybg white -width 16 \
                       -modifycmd [namespace code [list select_perms ""]] \
                       -vcmd [namespace code [list select_perms %P]] \
                       -validate key \
                       -textvariable Apol_Analysis_relabel::widget_vars(perms)]
    bindtags $widgets(perms_cb).e [linsert [bindtags $widgets(perms_cb).e] 3 perms_cb_tag]
    bind perms_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(perms_cb) %W %K]
    pack $widgets(perms_cb) -side top -expand 0 -fill x
    pack $filter_l_f -side left -expand 1 -fill x -padx 10
    set widgets(opts_bb) [ButtonBox $filter_f.filter_bb -homogeneous 1 \
                              -spacing 10 -orient vertical]
    $widgets(opts_bb) add -text "Add" -command [namespace code add_permission]
    $widgets(opts_bb) add -text "Remove" -command [namespace code remove_permission]
    pack $widgets(opts_bb) -side right -expand 0 -fill none
    pack $filter_f -side top -expand 0 -fill x -pady 10
    
    set objs_sw [ScrolledWindow [$opt_tf getframe].objs_sw -auto horizontal]
    set widgets(objs_lb) [listbox [$objs_sw getframe].objs_lb \
                              -selectmode single -height 5 -exportselection 0 \
                              -listvariable Apol_Analysis_relabel::widget_vars(objs_list) \
                              -background white]
    bind $widgets(objs_lb) <<ListboxSelect>> [namespace code select_perm_item]
    $objs_sw setwidget $widgets(objs_lb)
    pack $objs_sw -side top -expand 1 -fill both

    pack $option_f -fill both -anchor nw -side left -padx 5 -expand 1
    pack $mode_tf $req_tf $opt_tf -side left -anchor nw -padx 5 -expand 1 -fill both

    # set initial widget states
    set_mode_relabelto
    populate_lists 1
    toggle_attributes
    toggle_permissions
}


##########################################################################
##########################################################################
## The rest of these procs are not interface procedures, but rather
## internal functions to this analysis.
##########################################################################
##########################################################################

proc Apol_Analysis_relabel::set_mode_relabelto {} {
    variable widgets
    $widgets(start_l) configure -text "Starting type:"
    $widgets(start_attrib_ch) configure -text "Select starting type using attrib:"
}

proc Apol_Analysis_relabel::set_mode_relabelfrom {} {
    variable widgets
    $widgets(start_l) configure -text "Ending type:"
    $widgets(start_attrib_ch) configure -text "Select starting type using attrib:"
}

proc Apol_Analysis_relabel::set_mode_domain {} {
    variable widgets
    $widgets(start_l) configure -text "Starting domain:"
    $widgets(start_attrib_ch) configure -text "Select starting domain using attrib:"
}

proc Apol_Analysis_relabel::toggle_attributes {} {
    variable widgets
    variable widget_vars
    if $widget_vars(start_attrib_ch) {
        $widgets(start_attrib_cb) configure -state normal
        set_types_list ""
    } else {
        $widgets(start_attrib_cb) configure -state disabled
        $widgets(start_cb) configure -values $Apol_Types::typelist
    }
}

# Called whenever the user enters an attribute name (either by typing
# it or selecting from a list).  Modify the list of available types if
# the attribute is legal
proc Apol_Analysis_relabel::set_types_list {start_attrib} {
    variable widgets
    variable widget_vars
    if {$start_attrib == ""} {
        set start_attrib $widget_vars(start_attrib)
    }

    if [catch {apol_GetAttribTypesList $start_attrib} types_list] {
        set types_list ""
    }
    $widgets(start_cb) configure -values [lsort -uniq $types_list]
    # check if the starting type is within the list of legal types; if
    # not then remove the entry.
    if {[lsearch $types_list $widget_vars(start_type)] == -1} {
        set widget_vars(start_type) {}
    }
    return 1
}


# Called whenever the user selects/deselects the 'Filter using
# permissions' checkbox.
proc Apol_Analysis_relabel::toggle_permissions {} {
    variable widgets
    variable widget_vars
    if $widget_vars(enable_filter_ch) {
        set newstate "normal"
    } else {
        set newstate "disabled"
    }
    foreach w {objs_l objs_cb perms_l perms_cb opts_bb objs_lb} {
        $widgets($w) configure -state $newstate
    }
    $widgets(objs_lb) selection clear 0 end
    select_perms ""
    select_perm_item
}

# Called whenever the object class selected changed.  If the object
# class is legal, obtain its permissions and fill the permission list
# and clear the entry.  Otherwise disable the permission list.  For
# both cases diable the 'Add' button.
proc Apol_Analysis_relabel::set_perms_list {obj_name} {
    variable widgets
    variable widget_vars

    if {$obj_name == ""} {
        set obj_name $widget_vars(objs)
    }
    if {![catch {apol_GetClassPermList $obj_name} perm_list] && \
            [llength $perm_list] == 3} {
        foreach {uniq_perms class_name class_perms} $perm_list {}
        foreach perm $uniq_perms {
            foreach {name id} $perm {}
            lappend permissions $name
        }
        foreach perm $class_perms {
            foreach {name id} $perm {}
            lappend permissions $name
        }
        set widget_vars(perm_list) [concat [lindex $perm_list 0] \
                                        [lindex $perm_list 2]]
        $widgets(perms_cb) configure -state normal -values [lsort -uniq $permissions]
        $widgets(perms_l) configure -state normal
        set widget_vars(perms) {}
    } else {
        $widgets(perms_cb) configure -values {} -state disabled
        $widgets(perms_l) configure -state disabled
    }
    $widgets(opts_bb) itemconfigure 0 -state disabled    
    return 1
}

# Only allow the 'Add' button to be enabled when: permission combobox
# is active, it has a value, /and/ that value is within the list of
# valid permissions.  Otherwise disable it.
proc Apol_Analysis_relabel::select_perms {perm_name} {
    variable widgets
    variable widget_vars

    if {$perm_name == ""} {
        set perm_name $widget_vars(perms)
    }
    if {[$widgets(perms_cb) cget -state] == "normal" && \
            $perm_name != "" && \
            [info exists widget_vars(perm_list)] && \
            [lsearch $widget_vars(perm_list) "$perm_name *"] >= 0} {
                $widgets(opts_bb) itemconfigure 0 -state normal
    } else {
        # otherwise disable the 'Add' button
        $widgets(opts_bb) itemconfigure 0 -state disabled
    }
    return 1
}

# Called whenever the object permission listbox selection changes.
# Enable the 'Remove' button if and only if something is selected and
# the box itself is active.
proc Apol_Analysis_relabel::select_perm_item {} {
    variable widgets
    if {[$widgets(objs_lb) cget -state] == "normal" && \
            [$widgets(objs_lb) curselection] != {}} {
        $widgets(opts_bb) itemconfigure 1 -state normal
    } else {
        $widgets(opts_bb) itemconfigure 1 -state disabled
    }
}

# Called when the user clicks on the 'Add' button.  Transfer the
# current object class and permission over to the permissions listbox.
proc Apol_Analysis_relabel::add_permission {} {
    variable widgets
    variable widget_vars

    set perm_item "${widget_vars(objs)}:${widget_vars(perms)}"
    lappend widget_vars(objs_list) $perm_item
    set widget_vars(perms) ""
    set widget_vars(objs) ""
    $widgets(opts_bb) itemconfigure 0 -state disabled
}

# Called when the user clicks on the 'Remove' button.  Delete the
# permission item currently selected in the listbox.
proc Apol_Analysis_relabel::remove_permission {} {
    variable widgets
    variable widget_vars
    set old_selection [$widgets(objs_lb) curselection]
    $widgets(objs_lb) delete $old_selection
    # reset selection to the next one, but only if that index still exists
    if {$old_selection < [llength $widget_vars(objs_list)]} {
        $widgets(objs_lb) selection set $old_selection
    } else {
        $widgets(objs_lb) selection clear 0 end
        $widgets(opts_bb) itemconfigure 1 -state disabled
    }
}


# Called to populate the ComboBox/ComboBox/listbox holding the type
# names/attributes/object classes.  This is done in one of three
# places: upon wizard dialog creation, when opening a policy, and when
# closing a policy.
proc Apol_Analysis_relabel::populate_lists {add_items} {
    variable widgets
    variable widget_vars
    if $add_items {
        $widgets(start_cb) configure -values $Apol_Types::typelist
        $widgets(start_attrib_cb) configure -values $Apol_Types::attriblist
        $widgets(objs_cb) configure -values $Apol_Class_Perms::class_list
        if {[lsearch -exact $Apol_Types::typelist $widget_vars(start_type)] == -1} {
            set widget_vars(start_type) {}
        }
        if {[lsearch -exact $Apol_Types::attriblist $widget_vars(start_attrib)] == -1} {
            set widget_vars(start_attrib) {}
        }
        if {[lsearch -exact $Apol_Class_Perms::class_list $widget_vars(objs)] == -1} {
            set widget_vars(objs) {}
            set widget_vars(perms) {}
        } else {
            set_perms_list ""
        }
    } else {
        $widgets(start_cb) configure -values {}
        $widgets(start_attrib_cb) configure -values {}
        $widgets(objs_cb) configure -values {}
        set widget_vars(start_type) {}
        set widget_vars(start_attrib) {}
    }
}
