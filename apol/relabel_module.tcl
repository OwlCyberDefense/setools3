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
    variable VERSION 1
    
    variable info_button_text {This analysis checks the possible ways to relabel objects allowed by a policy.  The permissions relabelto
and relabelfrom are special in a type enforcement environment as they provide a method of changing type.
Relable analysis is designed to fascilitate queries about the possible changes for a given type.

There are three modes for a query, each presenting a differnt perspective.

relabelto mode -
        from starting type lists the types to which relabeling is possible for each domain with apropriate
        permissions and the associated rules granting this permission*.
        
relabelfrom mode -
        lists types from which each domain with the apropriate permissions can relabel to the selected end
        type and the associated rules*.  This mode can be considered the same as perfroming a query under
        relabelto mode in the opposite direction.
        
domain mode -
        given a starting domain lists all types to and from which that domain can relabel and the associated
        rules*.

Optionally results may be filtered by object class and permission (select * for permissions to filter by
object class only). When selected any number of lines may be added to the filter (each line displayed has
the format class:permission).  The filter shows only those results which have at least one of the specified
classes and if specified at least one of the permissions for that class.

*A note on rules display and filtering:

Rules are stored for each type found to have relabeling permission, therefore it is possible to specify a
permission in a filter and still see a rule that does not contain that specific permission.  This is not an
error rather it means that multiple rules grant permissions for that specific source-target-object triplet.
To see all rules governing a particular triplet use the Policy Rules tab.}

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
    variable most_recent_results_pw
    return $most_recent_results_pw
}

# The GUI will call Apol_Analysis_relabel::do_analysis when the
# module is to perform its analysis.  The module should know how to
# get its own option information.  The options are displayed via
# Apol_Analysis_relabel::display_mod_options.
proc Apol_Analysis_relabel::do_analysis {results_frame} {
    # collate user options into a single relabel analysis query    
    variable widget_vars
    variable most_recent_results

    # convert the object permissions list into Tcl lists
    set objs_list ""
    if $widget_vars(enable_filter_ch) {
        foreach objs $widget_vars(objs_list) {
            foreach {obj class} [split $objs ':'] {}
            lappend objs_list [list $obj $class]
        }
    }
    if [catch {apol_RelabelAnalysis $widget_vars(start_type) $widget_vars(mode) $objs_list} results] {
        tk_messageBox -icon error -type ok \
            -title "Relabel Analysis Error" -message $results
        return -code error
    }
    set most_recent_results $results

    # create widgets to display results
    variable most_recent_results_pw
    catch {destroy $results_frame.pw}
    set pw [PanedWindow $results_frame.pw -side top]
    set most_recent_results_pw $pw
    set lf [$pw add]
    set dtf [TitleFrame $lf.dtf]
    switch -- $widget_vars(mode) {
        to     {set text "Domains relabeling to $widget_vars(start_type)"}
        from   {set text "Domains relabeling from $widget_vars(start_type)"}
        domain {set text "Domain relabeling for $widget_vars(start_type)"}
    }
    $dtf configure -text $text
    set dsw [ScrolledWindow [$dtf getframe].dsw -auto horizontal]
    set dtree [Tree [$dsw getframe].dtree -relief flat -width 15 \
                   -borderwidth 0  -highlightthickness 0 -redraw 1 \
                   -bg white -showlines 1 -padx 0 \
                  ]
    $dsw setwidget $dtree
    set widget_vars(current_dtree) $dtree
    pack $dsw -expand 1 -fill both

    set widget_vars(show) {}
    set doptsf [frame $lf.doptsf]
    set show0_rb [radiobutton $doptsf.show0_rb -value {0 t} \
                      -variable Apol_Analysis_relabel::widget_vars(show) \
                      -command [namespace code set_show_type]]
    set show1_rb [radiobutton $doptsf.show1_rb \
                      -variable Apol_Analysis_relabel::widget_vars(show) \
                      -command [namespace code set_show_type]]
    pack $show0_rb $show1_rb -anchor w
    switch $widget_vars(mode) {
        to -
        from   {
            $show0_rb configure -text "show types"
            $show1_rb configure -text "show rules" -value {1 r}
        }
        domain {
            $show0_rb configure -text "show from types"
            $show1_rb configure -text "show to types" -value {1 t}
            set show2_rb [radiobutton $doptsf.show2_rb -value {2 r} \
                              -variable Apol_Analysis_relabel::widget_vars(show) \
                              -command [namespace code set_show_type] \
                              -text "show rules"]
            pack $show2_rb -anchor w
        }
    }
    pack $doptsf -expand 0 -fill none -side right
    pack $dtf -expand 1 -fill both -side left

    set rf [$pw add]
    set rtf [TitleFrame $rf.rtf -text "File Relabeling Results"]
    set rsw [ScrolledWindow [$rtf getframe].rsw -auto horizontal]
    set rtext [text $rsw.rtext -wrap none -bg white -font $ApolTop::text_font]
    $rsw setwidget $rtext
    Apol_PolicyConf::configure_HyperLinks $rtext
    set widget_vars(current_rtext) $rtext
    pack $rsw -expand 1 -fill both
    pack $rtf -expand 1 -fill both
    
    pack $pw -expand 1 -fill both

#    puts "results is $results"
    # now fill the domain tree with results info
    if {$results == ""} {
        $dtree configure -state disabled
        $show0_rb configure -state disabled
        $show1_rb configure -state disabled
        set text "$widget_vars(start_type) does not "
        switch -- $widget_vars(mode) {
            to     {append text "relabel to anything."}
            from   {append text "relabel from anything."}
            domain {
                append text "relabel to or from any types."
                $show2_rb configure -state disabled
            }
        }
        $rtext insert end $text
    } else {
        $rtext insert end "This tab provides the results of a file relabeling analysis."
        foreach result_elem $results {
            set domain [lindex $result_elem 0]
            $dtree insert end root $domain -text $domain -open 1 \
                -drawcross auto -data [lrange $result_elem 1 end]
        }
        $dtree configure -selectcommand [namespace code tree_select]
    }
    $rtext configure -state disabled
}

# Apol_Analysis_relabel::close must exist; it is called when a
# policy is closed.  Typically you should reset any context or option
# variables you have.
proc Apol_Analysis_relabel::close { } {
    populate_lists 0
    # flush the relabel sets cache
    apol_RelabelFlushSets
}

# Apol_Analysis_relabel::open must exist; it is called when a
# policy is opened.
proc Apol_Analysis_relabel::open { } {
    populate_lists 1
    # flush the relabel sets cache
    apol_RelabelFlushSets
}

# Called whenever a user loads a query file.  Clear away the old
# contents of the assertion file and replace it with the remainder
# from $file_channel.
proc Apol_Analysis_relabel::load_query_options {file_channel parentDlg} {
    variable VERSION widget_vars
    if {[gets $file_channel] > $VERSION} {
        return -code error "The specified query version is not allowed."
    }
    array set widget_vars [read $file_channel]
    toggle_attributes 0
    toggle_permissions
    return 0
}

# Called whenever a user saves a query
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
proc Apol_Analysis_relabel::save_query_options {module_name file_channel file_name} {
    variable VERSION widget_vars
    puts $file_channel $module_name
    puts $file_channel $VERSION
    puts $file_channel [array get widget_vars]
    return 0
}

# Captures the current set of options, which is then later restored by
# [set_display_to_results_tab].
proc Apol_Analysis_relabel::get_current_results_state { } {
    variable widget_vars
    return [array get widget_vars]
}

# Apol_Analysis_relabel::set_display_to_results_state is called to
# reset the options or any other context that analysis needs when the
# GUI switches back to an existing analysis.  options is a list that
# we created in a previous get_current_results_state() call.
proc Apol_Analysis_relabel::set_display_to_results_state { query_options } {
    variable widget_vars
    array set widget_vars $query_options
    toggle_attributes 0
    toggle_permissions
    set_show_type
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

    set widget_vars(mode) "to"
    set mode_tf [TitleFrame $option_f.mode_tf -text "Mode"]
    set relabelto_rb [radiobutton [$mode_tf getframe].relabelto_rb \
                          -text "relabelto" -value "to" \
                          -variable Apol_Analysis_relabel::widget_vars(mode) \
                          -command [namespace code set_mode_relabelto]]
    set relabelfrom_rb [radiobutton [$mode_tf getframe].relabelfrom_rb \
                            -text "relabelfrom" -value "from" \
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
    set widgets(start_l) [label $start_f.start_l -anchor w]
    set widgets(start_cb) [ComboBox $start_f.start_cb -editable 1 \
                               -entrybg white -width 16 \
                               -textvariable Apol_Analysis_relabel::widget_vars(start_type)]
    bindtags $widgets(start_cb).e [linsert [bindtags $widgets(start_cb).e] 3 start_cb_tag]
    bind start_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_cb) %W %K]
    pack $widgets(start_l) $widgets(start_cb) -side top -expand 0 -fill x

    set widgets(start_attrib_ch) \
        [checkbutton $attrib_f.start_attrib_ch -anchor w -width 36 \
             -variable Apol_Analysis_relabel::widget_vars(start_attrib_ch) \
             -command [namespace code [list toggle_attributes 1]]]
    set widgets(start_attrib_cb) [ComboBox $attrib_f.start_attrib_cb \
                -editable 1 -entrybg white -width 16 \
                -modifycmd [namespace code [list set_types_list ""]] \
                -vcmd [namespace code [list set_types_list %P]] -validate key \
                -textvariable Apol_Analysis_relabel::widget_vars(start_attrib)]
    bindtags $widgets(start_attrib_cb).e [linsert [bindtags $widgets(start_attrib_cb).e] 3 start_attrib_cb_tag]
    bind start_attrib_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_attrib_cb) %W %K]
    pack $widgets(start_attrib_ch) -expand 0 -fill x
    pack $widgets(start_attrib_cb) -padx 15 -expand 0 -fill x
    pack $start_f -expand 0 -fill x
    pack $attrib_f -pady 20 -expand 0 -fill x
    
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
    toggle_attributes 1
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

proc Apol_Analysis_relabel::toggle_attributes {clear_types_list} {
    variable widgets
    variable widget_vars
    if $widget_vars(start_attrib_ch) {
        $widgets(start_attrib_cb) configure -state normal
        if $clear_types_list {
            set_types_list ""
        }
    } else {
        $widgets(start_attrib_cb) configure -state disabled
        $widgets(start_cb) configure -values $Apol_Types::typelist
    }
}

# Called whenever the user enters an attribute name (either by typing
# it or selecting from a list).  Modify the list of available types if
# the attribute is legal.
proc Apol_Analysis_relabel::set_types_list {start_attrib} {
    variable widgets
    variable widget_vars
    if {$start_attrib == ""} {
        set start_attrib $widget_vars(start_attrib)
    }
    if [catch {apol_GetAttribTypesList $start_attrib} types_list] {
        set types_list ""
    }
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
    foreach w {objs_l objs_cb objs_lb} {
        $widgets($w) configure -state $newstate
    }
    $widgets(objs_lb) selection clear 0 end
    $widgets(perms_l) configure -state disabled
    $widgets(perms_cb) configure -state disabled
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
        set permissions [concat {{*}} [lsort -uniq $permissions]]
        $widgets(perms_cb) configure -state normal -values $permissions
        $widgets(perms_l) configure -state normal
        set widget_vars(perms) {}
    } else {
        $widgets(perms_l) configure -state disabled
        $widgets(perms_cb) configure -values {} -state disabled
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
            [lsearch [$widgets(perms_cb) cget -values] $perm_name] >= 0} {
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
    $widgets(opts_bb) itemconfigure 1 -state disabled
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

# Update the File Relabeling Results display with whatever the user
# selected
proc Apol_Analysis_relabel::tree_select {widget node} {
    variable widget_vars
    if {$node == ""} {
        return
    }
    # auto select the first radio button if none selected
    if {$widget_vars(show) == ""} {
        set widget_vars(show) {0 t}
    }
    foreach {index type} $widget_vars(show) {}
    set data [lindex [$widget itemcget $node -data] $index]
    $widget_vars(current_rtext) configure -state normal
    $widget_vars(current_rtext) delete 1.0 end
    if {$type == "t"} {
        foreach datum $data {
            $widget_vars(current_rtext) insert end "$datum\n"
        }
    } else {
        set policy_tags_list ""
        set line ""
        foreach datum $data {
            foreach {rule rule_num} $datum {}
            set start_index [expr {[string length $line] + 1}]
            append line "($rule_num"
            set end_index [string length $line]
            append line ") $rule\n"
            lappend policy_tags_list $start_index $end_index
        }
        $widget_vars(current_rtext) insert end $line
        foreach {start_index end_index} $policy_tags_list {
            Apol_PolicyConf::insertHyperLink $widget_vars(current_rtext) \
                "1.0 + $start_index c" "1.0 + $end_index c"
        }
    }
    $widget_vars(current_rtext) configure -state disabled    
}

# Change the File Relabeling Results to the radiobutton selected
proc Apol_Analysis_relabel::set_show_type {} {
    variable widget_vars
    # auto select the first node if nothing has yet been selected
    if {[$widget_vars(current_dtree) selection get] == ""} {
        set first_node [$widget_vars(current_dtree) nodes root 0]
        $widget_vars(current_dtree) selection set $first_node
    }
    tree_select $widget_vars(current_dtree) \
        [$widget_vars(current_dtree) selection get]
}
