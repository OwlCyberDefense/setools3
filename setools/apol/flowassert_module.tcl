#############################################################
#  flowassert_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2004 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <jtang@tresys.com>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Information
# Flow Assertion.
##############################################################
# ::Apol_Analysis_flowassert module namespace
##############################################################

namespace eval Apol_Analysis_flowassert {

    # widget variables
    variable assertfile_t    
    variable assert_wizard_dlg ""

    # these three are lists of valid type names, attributes, and
    # object classes, which are used to see the
    # ComboBox/ComboBox/listbox in the assertion rule wizard
    variable assert_wizard_types ""
    variable assert_wizard_attribs ""
    variable assert_wizard_objclasses ""

    # name of widget holding most recently executed assertion
    variable most_recent_results ""

    # name and path of most recently saved/loaded assertion files
    variable last_filename ""
    variable last_pathname ""
    
    variable info_button_text \
"Information flow in access control policy refers to the ability for
information to flow from a process or object into another process or
object. This can be done directly or transitively through several
intermediate types. When analyzing an access control policy the need
to see information flow from one type to another is very important and
while direct flow is fairly obvious transitive flows are not.\n

There are to be three type of assertions.  The first one is noflow,
which asserts there is no flow between two different types.  The
second is mustflow, which instead states that there must exist one.
The third type is onlyflow, which says that there must be a flow, and
that flow be through a particular intermediary type.  All three modes
must allow for any number of source, destination, and exception types.
Types may be limited by optional object classes; they may also be
specified through attributes.  Finally, each assertion can have a
minimum weight to limiting searches.\n

To facilitate automated validation and regression testing of policies
the user creates a series of information flow assertions using a batch
language that represents transitive flows.  A module for apol,
\"Information Flow Assertion\", easily allows the user to generate and
execute assertion statements.  Results from the analysis are presented
in new window.  Assertions found to be correctly are labelled as
\"Passed\"; invalid ones are hyperlinked to the line within
policy.conf that caused the conflict."

    # Within the namespace command for the module, you must call
    # Apol_Analysis::register_analysis_modules, the first argument is
    # the namespace name of the module, and the second is the
    # descriptive display name you want to be displayed in the GUI
    # selection box.
    Apol_Analysis::register_analysis_modules "Apol_Analysis_flowassert" \
        "Information Flow Assertion"
}

# Apol_Analysis_flowassert::initialize is called when the tool first
# starts up.  The analysis has the opportunity to do any additional
# initialization it must do that wasn't done in the initial namespace
# eval command.
proc Apol_Analysis_flowassert::initialize { } {
    catch {console show}
    return 0
}

# Returns the text to display whenever the user hits the 'Info'
# button.
proc Apol_Analysis_flowassert::get_analysis_info {} {
    return $Apol_Analysis_flowassert::info_button_text
}

# Returns the name of the widget that contains the results for the
# currently selected results tab.  This widget should have been
# created by [do_analysis] below.  The module knows which result tab
# is raised due to the most recent call
# [set_display_to_results_state].
proc Apol_Analysis_flowassert::get_results_raised_tab {} {
    variable most_recent_results
    return $most_recent_results
}

# The GUI will call Apol_Analysis_flowassert::do_analysis when the
# module is to perform its analysis.  The module should know how to
# get its own option information.  The options are displayed via
# Apol_Analysis_flowassert::display_mod_options.
proc Apol_Analysis_flowassert::do_analysis {results_frame} {  
    # if a permission map is not loaded then load the default one
    # if an error occurs on open then skip analysis
    if {[catch {Apol_Perms_Map::is_pmap_loaded} err] || $err == 0} {
        if {[set rt [catch {Apol_Perms_Map::load_default_perm_map} err]] != 0} {
            if {$rt == $Apol_Perms_Map::warning_return_val} {
                tk_messageBox -icon warning -type ok \
                    -title "Warning" -message $err
            } else {
                tk_messageBox -icon error -type ok \
                    -title "Error" -message $err
                return -code error
            }
        }
    }

    set sw [ScrolledWindow $results_frame.sw -auto horizontal]
    set t [text $sw.t -wrap none -bg white -font $ApolTop::text_font]
    Apol_PolicyConf::configure_HyperLinks $t
    $t tag configure assert_file_tag -underline 1
    $t tag bind assert_file_tag <Button-1> [namespace code [list highlight_assert_line  %W %x %y]]
    $t tag bind assert_file_tag <Enter> { set Apol_PolicyConf::orig_cursor [%W cget -cursor]; %W configure -cursor hand2 }
    $t tag bind assert_file_tag <Leave> { %W configure -cursor $Apol_PolicyConf::orig_cursor }

    $sw setwidget $t
    pack $sw -expand 1 -fill both
    variable most_recent_results
    set most_recent_results $sw
    
    variable assertfile_t
    set assert_contents [string trim [$assertfile_t get 1.0 end]]
    $t insert end "-- Executing --\n$assert_contents"
    update idletasks

    if [catch {apol_FlowAssertExecute $assert_contents 0} assert_results] {
        set retval -1
    } else {
        $t delete 1.0 end
        $t insert end "--- Results ---\n"
        set typeslist [apol_GetNames types]
        foreach result $assert_results {
            foreach {mode lineno result rules_list} $result {}
            set line "line $lineno: "
            set line_end_index [expr {[string length $line] - 2}]
            set policy_tags_list ""
            switch -- $result {
                0 { append line "Passed.\n" }
                1 {
                    set s ""
                    if {[llength $rules_list] > 1} {
                        set s "s"
                    }
                    append line "Assertion failed, conflict$s found:\n"
                    foreach rules $rules_list {
                        foreach {start_type end_type via_type rule_num rule} $rules {}
                        if {[set from [lindex $typeslist $start_type]] == ""} {
                            set from "<unknown type>"
                        }
                        if {[set to [lindex $typeslist $end_type]] == ""} {
                            set to "<unknown type>"
                        }
                        if {$rule_num >= 0} {
                            if {$ApolTop::policy_type != $ApolTop::binary_policy_type} {
                                append line "  $from to $to via \"$rule\" \["
                                set start_index [string length $line]
                                append line "$rule_num]\n"
                                set end_index [expr {[string length $line] - 2}]
                                lappend policy_tags_list $start_index $end_index
                            } else {
                                append line "  $from to $to\n"
                            }
                        } elseif {$via_type >= 0} {
                            if {[set via [lindex $Apol_Types::typelist $via_type]] == ""} {
                                set via "<unknown type>"
                            }
                            append line "  no rule from $from to $to via $via\n"
                        } else {
                            append line "  no rule from $from to $to\n"
                        }
                    }
                }
                2 { append line "Assertion has illegal mix of options.\n" }
                3 { append line "Unknown type or attribute specified.\n" }
                4 { append line "Unknown class specified.\n" }
                5 { append line "Variable undeclared.\n" }
                6 { append line "Syntax error.\n" }
                -1 { append line "Out of memory\n" }
                default {
                    append line "Invalid return value from execute_flow_execute(): $result"
                }
            }

            set offset [$t index "end - 1c"]
            $t insert end $line
            $t tag add assert_file_tag $offset "$offset + $line_end_index c"
            foreach {start_index end_index} $policy_tags_list {
                Apol_PolicyConf::insertHyperLink $t \
                    "$offset + $start_index c" "$offset + $end_index c"
            }
        }
        set retval 0
    }
    if {$assert_results == ""} {
        $t insert end "<success>"
    }
    $t configure -state disabled
    if {$retval == -1} {
        tk_messageBox -icon error -type ok -title "Flow Assertion Error" \
            -message $assert_results
    }        
    return $retval
}


# Apol_Analysis_flowassert::close must exist; it is called when a
# policy is closed.  Typically you should reset any context or option
# variables you have.
proc Apol_Analysis_flowassert::close { } {
    variable assert_wizard_dlg
    if [winfo exists $assert_wizard_dlg] {
        # update the dialog display to match this policy's declared
        # types and attributes
        populate_lists 0
    }
    return
}

# Apol_Analysis_flowassert::open must exist; it is called when a
# policy is opened.
proc Apol_Analysis_flowassert::open { } {
    variable assert_wizard_dlg
    if [winfo exists $assert_wizard_dlg] {
        # update the dialog display to match this policy's declared
        # types and attributes
        populate_lists 1
    }
}

# Called whenever a user loads a query file.  Clear away the old
# contents of the assertion file and replace it with the remainder
# from $file_channel.
proc Apol_Analysis_flowassert::load_query_options {file_channel parentDlg} {
    variable assertfile_t
    $assertfile_t delete 1.0 end
    $assertfile_t insert end "[string trim [read $file_channel]]\n"
    return 0
}

# Called whenever a user saves a query
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
proc Apol_Analysis_flowassert::save_query_options {module_name file_channel file_name} {
    puts $file_channel $module_name
    variable assertfile_t
    puts -nonewline $file_channel [$assertfile_t get 1.0 end]
    return 0
}

# Captures the current set of options, which is then later restored by
# [set_display_to_results_tab].
proc Apol_Analysis_flowassert::get_current_results_state { } {
    variable assertfile_t
    return [list $assertfile_t [$assertfile_t get 1.0 end]]
}

# Apol_Analysis_flowassert::set_display_to_results_state is called to
# reset the options or any other context that analysis needs when the
# GUI switches back to an existing analysis.  options is a list that
# we created in a previous get_current_results_state() call.
proc Apol_Analysis_flowassert::set_display_to_results_state { query_options } {
    variable most_recent_results
    foreach {assertfile_t assertcontents} $query_options {}
    $assertfile_t delete 1.0 end
    $assertfile_t insert 1.0 $assertcontents
    set most_recent_results $assertfile_t
}

# Apol_Analysis_flowassert::free_results_data is called to handle any
# cleanup of module options prior to [destroy]ing its parent frame.
# There are three times this function is called: when using the
# 'Update' button, when closing its result tab, and when closing all
# tabs.  query_options is a list that we created in a previous
# get_current_results_state() call, from which we extract the
# subwidget pathnames for the results frame.
proc Apol_Analysis_flowassert::free_results_data {query_options} {  
    return
}

# Apol_Analysis_dirflow::display_mod_options is called by the GUI to
# display the analysis options interface the analysis needs.  Each
# module must know how to display their own options, as well bind
# appropriate commands and variables with the options GUI.  opts_frame
# is the name of a frame in which the options GUI interface is to be
# packed.
proc Apol_Analysis_flowassert::display_mod_options { opts_frame } {
    variable assertfile_t
    set tf [TitleFrame $opts_frame.assertfile -text "Assertion File"]
    set sw [ScrolledWindow [$tf getframe].sw -auto horizontal]
    set assertfile_t [text $sw.assertfile_t -wrap none -state normal \
                          -bg white -font $ApolTop::text_font]
    $sw setwidget $assertfile_t
    $assertfile_t insert end "\# Place your assertion statements here\n"
    pack $sw -expand 1 -fill both
    set bb [ButtonBox $opts_frame.bb -homogeneous 1 -spacing 30]
    $bb add -text "Add..." -command [namespace code create_assert_wizard_dlg]
    $bb add -text "Clear File" -command [namespace code clear_assert_file]
    $bb add -text "Save..." -command [namespace code save_assert_file]
    $bb add -text "Load..." -command [namespace code load_assert_file]
    grid $tf -padx 10 -sticky nsew
    grid $bb -sticky {}
    grid rowconfigure $opts_frame 0 -weight 1
    grid rowconfigure $opts_frame 1 -weight 0 -pad 20
    grid columnconfigure $opts_frame 0 -weight 1
}


##########################################################################
##########################################################################
## The rest of these procs are not interface procedures, but rather
## internal functions to this analysis.
##########################################################################
##########################################################################

# Deletes the contents of the assertion file text box, and thus
# consequently clearing the file.
proc Apol_Analysis_flowassert::clear_assert_file {} {
    variable assertfile_t
    $assertfile_t delete 1.0 end
}

# Prompts the user for a file name, then saves the contents of the
# assertion buffer to it.
proc Apol_Analysis_flowassert::save_assert_file {} {
    variable assertfile_t
    variable last_filename
    variable last_pathname
    set filename [tk_getSaveFile -title "Save Assertion File" \
                      -parent $assertfile_t -initialdir $last_pathname \
                      -initialfile $last_filename]
    if {$filename == ""} {
        return
    }
    if [catch {::open $filename w} f] {
        tk_messageBox -icon error -type ok -title "Save Assertion File" \
            -message "Error saving to $filename" -parent $assertfile_t
        return
    }
    puts -nonewline $f [$assertfile_t get 1.0 end]
    ::close $f
    set last_filename [file tail $filename]
    set last_pathname [file dirname $filename]
}

# Prompts the user for a file name, then loads the contents of the
# file into the assertion buffer.
proc Apol_Analysis_flowassert::load_assert_file {} {
    variable assertfile_t
    variable last_filename
    variable last_pathname
    set filename [tk_getOpenFile -title "Load Assertion File" \
                      -parent $assertfile_t -initialdir $last_pathname \
                      -initialfile $last_filename]
    if {$filename == ""} {
        return
    }
    if [catch {::open $filename r} f] {
        tk_messageBox -icon error -type ok -title "Load Assertion File" \
            -message "Error loading from $filename" -parent $assertfile_t
        return
    }
    $assertfile_t delete 1.0 end
    $assertfile_t insert end [read $f]
    ::close $f
    set last_filename [file tail $filename]
    set last_pathname [file dirname $filename]
}

# Creates the "assertion statement wizard" that allows a user to
# easily add assertions lines to the current file.  The wizard is a
# non-modal dialog that presents all available types / attributes /
# options.  It does not validate entries for syntactical correctness.
proc Apol_Analysis_flowassert::create_assert_wizard_dlg {} {
    variable assertfile_t
    variable assert_wizard_dlg
    
    if [winfo exists $assert_wizard_dlg] {
        raise $assert_wizard_dlg
        return
    }

    variable assert_wiz_mode
    variable assert_wiz_line
    variable assert_wiz_weight
    
    set assert_wizard_dlg [toplevel .assertfile_wizard_dlg]
    wm title $assert_wizard_dlg "Add Assertion Statements"
    wm protocol $assert_wizard_dlg WM_DELETE_WINDOW \
        [list destroy $assert_wizard_dlg]

    set f [frame $assert_wizard_dlg.f]

    variable assert_wiz_type_cbs ""
    variable assert_wiz_attrib_cbs ""
    variable assert_wiz_objclass_lbs ""
    set start_tf [TitleFrame $f.start_tf -text "Starting Types"]
    create_type_panel [$start_tf getframe] start assert_wiz_start_type
    set end_tf [TitleFrame $f.end_tf -text "Ending Types"]
    create_type_panel [$end_tf getframe] end assert_wiz_end_type
    set via_tf [TitleFrame $f.via_tf -text "Exceptions Type"]
    create_type_panel [$via_tf getframe] via assert_wiz_via_type
    
    set f0 [frame $f.f0]
    set mode_tf [TitleFrame $f0.tf -text "Assertion Mode"]
    set noflow_rb [radiobutton [$mode_tf getframe].noflow_rb \
                  -text "noflow" -value "noflow" \
                  -variable Apol_Analysis_flowassert::assert_wiz_mode \
                  -command [namespace code [list set_mode "noflow" $via_tf]]]
    set mustflow_rb [radiobutton [$mode_tf getframe].mustflow_rb \
                  -text "mustflow" -value "mustflow" \
                  -variable Apol_Analysis_flowassert::assert_wiz_mode \
                  -command [namespace code [list set_mode "mustflow" $via_tf]]]
    set onlyflow_rb [radiobutton [$mode_tf getframe].onlyflow_rb \
                  -text "onlyflow" -value "onlyflow" \
                  -variable Apol_Analysis_flowassert::assert_wiz_mode \
                  -command [namespace code [list set_mode "onlyflow" $via_tf]]]
    pack $noflow_rb $mustflow_rb $onlyflow_rb -anchor w -side top
    set lf [LabelFrame $f0.lf -text "Minimum Weight: " -side left]
    set weight_sb [SpinBox [$lf getframe].weight_sb -font $ApolTop::text_font \
                    -width 3 -entrybg white -range [list 1 10 1] \
                    -editable 0 -justify right \
                    -textvariable Apol_Analysis_flowassert::assert_wiz_weight \
                    -modifycmd [namespace code set_weight]]
    pack $weight_sb -expand 1 -fill both
    pack $mode_tf -expand 1 -fill both -pady 20
    pack $lf -expand 1 -fill x -pady 20
    pack $f0 -expand 0 -side left -padx 10
    pack $via_tf $end_tf $start_tf -expand 1 -fill both -padx 10 -side right
    grid $f -sticky nsew
    
    set rule_e [LabelEntry $assert_wizard_dlg.rule_e -width 80 \
                   -font $ApolTop::text_font -entrybg white \
                    -label "Assertion Line: " \
                    -textvariable Apol_Analysis_flowassert::assert_wiz_line]
    grid $rule_e -sticky ew -padx 10

    set bb [ButtonBox $assert_wizard_dlg.bb -homogeneous 1 -spacing 30]
    $bb add -text "Reset Line" \
        -command [namespace code [list reset_wizard $via_tf]]
    $bb add -text "Add Line" \
        -command [namespace code add_line]
    $bb add -text "Close" \
        -command [list destroy $Apol_Analysis_flowassert::assert_wizard_dlg]
    grid $bb -sticky {}

    grid rowconfigure $assert_wizard_dlg 0 -weight 1 -pad 10
    grid rowconfigure $assert_wizard_dlg 1 -weight 0 -pad 20
    grid rowconfigure $assert_wizard_dlg 2 -weight 0 -pad 20
    grid columnconfigure $assert_wizard_dlg 0 -weight 1 -pad 5

    reset_wizard $via_tf
    
    wm deiconify $assert_wizard_dlg
}

# Creates an individual panel {starting, ending, via/exceptions} for
# the assertion wizard.
proc Apol_Analysis_flowassert::create_type_panel {type_panel type_name type_var} {
    # add the type selection radiobutton + two ComboBoxes
    set type_star_rb [radiobutton $type_panel.star_cb -value "*" \
                          -text "Any Type" \
                          -variable Apol_Analysis_flowassert::assert_wiz_${type_name}_type_rb]
    pack $type_star_rb -anchor w -side top
    
    variable assert_wizard_types
    set type_names_f [frame $type_panel.type_names_f]
    set type_names_l [label $type_names_f.names_l -text "Type Names:"]
    set type_names_cb [ComboBox $type_names_f.names_cb -width 24 \
                           -editable 1 -entrybg white -exportselection 0 \
                           -textvariable Apol_Analysis_flowassert::assert_wiz_${type_name}_type_name]
    bindtags $type_names_cb.e [linsert [bindtags $type_names_cb.e] 3 ${type_name}_names_tags]
    bind ${type_name}_names_tags <KeyPress> [list ApolTop::_create_popup $type_names_cb %W %K]
    pack $type_names_l -expand 0 -side top
    pack $type_names_cb -expand 1 -fill both -side top
    pack $type_names_f -expand 1 -fill both -side top -pady 2

    variable assert_wizard_attribs
    set type_attribs_f [frame $type_panel.type_attribs_f]
    set type_attribs_l [label $type_attribs_f.attribs_l \
                            -text "Type Attributes:"]
    set type_attribs_cb [ComboBox $type_attribs_f.attribs_cb -width 24 \
                             -editable 1 -entrybg white -exportselection 0 \
                             -textvariable Apol_Analysis_flowassert::assert_wiz_${type_name}_type_attrib]
    bindtags $type_attribs_cb.e [linsert [bindtags $type_attribs_cb.e] 3 ${type_name}_attribs_tags]
    bind ${type_name}_attribs_tags <KeyPress> [list ApolTop::_create_popup $type_attribs_cb %W %K]
    pack $type_attribs_l -expand 0 -side top
    pack $type_attribs_cb -expand 1 -fill both -side top
    pack $type_attribs_f -expand 1 -fill both -side top -pady 2

    # add bindings between these so that modifying one clears the other two
    set bindcmd [namespace code [list set_type $type_star_rb $type_names_cb $type_attribs_cb $type_var star ""]]
    $type_star_rb configure -command $bindcmd
    set bindcmd [namespace code [list set_type $type_star_rb $type_names_cb $type_attribs_cb $type_var name %P]]
    $type_names_cb configure -modifycmd $bindcmd -vcmd $bindcmd -validate key
    set bindcmd [namespace code [list set_type $type_star_rb $type_names_cb $type_attribs_cb $type_var attrib %P]]
    $type_attribs_cb configure -modifycmd $bindcmd -vcmd $bindcmd -validate key

    pack [Separator $type_panel.strut0 -orient horizontal] \
        -expand 1 -fill x -side top -pady 10

    # add the object selection listbox + Entry
    set class_var assert_wiz_${type_name}_class
    pack [label $type_panel.objs_l -text "Object Classes:"] -expand 0
    set objs_sw [ScrolledWindow $type_panel.objs_sw -auto horizontal]
    set objs_lb [listbox [$objs_sw getframe].objs_lb -selectmode multiple \
                     -height 5 -highlightthickness 0 -exportselection 0 \
                     -setgrid 1 -background white \
                     -listvariable Apol_Analysis_flowassert::assert_wizard_objclasses]
    $objs_sw setwidget $objs_lb
#    pack $objs_sw -expand 1 -fill both
    set objs_e [Entry $type_panel.objs_e -background white -validate key \
                    -textvariable Apol_Analysis_flowassert::${class_var}]
    $objs_e configure -vcmd [namespace code [list select_class $objs_lb $class_var $objs_e %P]]
#    pack $objs_e -expand 1 -fill x -pady 2
    bind $objs_lb <<ListboxSelect>> [namespace code [list select_class $objs_lb $class_var $objs_lb ""]]
    
#    pack [Separator $type_panel.strut1 -orient horizontal] \
        -expand 1 -fill x -side top -pady 10

    # add the include / exclude radio buttons
    set include_var assert_wiz_${type_name}_include
    set include_rb [radiobutton $type_panel.include_rb -value "include" \
                        -text "Include Type/Object" \
                        -variable Apol_Analysis_flowassert::$include_var]
    set exclude_rb [radiobutton $type_panel.exclude_rb -value "exclude" \
                        -text "Exclude Type/Object" \
                        -variable Apol_Analysis_flowassert::$include_var]
#    pack $include_rb $exclude_rb -anchor w -side top

    # FIX ME: temporary patch for now for lack of object classes
    pack [label $type_panel.nobj -text "Object classes are\ncurrently disabled." -bd 1 -relief sunken -padx 5 -pady 5] -pady 5
    
    pack [button $type_panel.add_b -text "Add" \
              -command [namespace code [list add_type $type_var $type_name $class_var $include_var]]] \
        -expand 0 -pady 10 -side bottom
    
    # add the widgets' paths list
    variable assert_wiz_type_cbs
    lappend assert_wiz_type_cbs $type_names_cb
    variable assert_wiz_attrib_cbs
    lappend assert_wiz_attrib_cbs $type_attribs_cb
    variable assert_wiz_objclass_lbs
    lappend assert_wiz_objclass_lbs $objs_lb
    populate_lists 1
}

# Called to populate the ComboBox/ComboBox/listbox holding the type
# names/attributes/object classes.  This is done in one of three
# places: upon wizard dialog creation, when opening a policy, and when
# closing a policy.
proc Apol_Analysis_flowassert::populate_lists {add_items} {
    variable assert_wiz_type_cbs
    variable assert_wiz_attrib_cbs
    variable assert_wiz_objclass_lbs
    if $add_items {
        foreach type_cb $assert_wiz_type_cbs {
            $type_cb configure -values $Apol_Types::typelist
        }
        foreach attrib_cb $assert_wiz_attrib_cbs {
            $attrib_cb configure -values $Apol_Types::attriblist
        }
        foreach objclass_lb $assert_wiz_objclass_lbs {
            set var [$objclass_lb cget -listvariable]
            set $var $Apol_Class_Perms::class_list
        }
    } else {
        foreach type_cb $assert_wiz_type_cbs {
            $type_cb configure -values {}
        }
        foreach attrib_cb $assert_wiz_attrib_cbs {
            $attrib_cb configure -values {}
        }
        foreach objclass_lb $assert_wiz_objclass_lbs {
            set var [$objclass_lb cget -listvariable]
            set $var {}
        }
    }
}

# Callback when a user clicks on a mode radiobutton {noflow, mustflow,
# onlyflow}.  Updates the title of the via_tf frame.  Updates the mode
# listed in the current assertion line.
proc Apol_Analysis_flowassert::set_mode {newmode via_tf} {
    variable assert_wiz_line
    if {$newmode == "noflow"} {
        $via_tf configure -text "Exception Types (optional)"
    } elseif {$newmode == "mustflow"} {
        $via_tf configure -text "Via Types (optional)"
    } else {
        $via_tf configure -text "Via Types (required)"
    }
    set assert_wiz_line [concat $newmode [lrange $assert_wiz_line 1 end]]
}

# Callback whenever a user selects a new weight from the spinner.
# Updates the weighting value in the current assertion line.
proc Apol_Analysis_flowassert::set_weight {} {
    variable assert_wiz_line
    variable assert_wiz_weight
    if {[llength $assert_wiz_line] >= 5} {
        set assert_wiz_line [lrange $assert_wiz_line 0 end-1]
        lappend assert_wiz_line $assert_wiz_weight
    } elseif {[llength $assert_wiz_line] == 4} {
        lappend assert_wiz_line $assert_wiz_weight
    }
}

# Callback whenever the user selects a type.  Disables the other two
# widgets.  Sets the internal variable to be equal to the name of the
# type.
proc Apol_Analysis_flowassert::set_type {star_rb names_cb attribs_cb type_var which newvalue} {
    variable $type_var
    switch -- $which {
        star {
            $names_cb configure -text ""
            $attribs_cb configure -text ""
            $star_rb select
            set $type_var "*"
        }
        name {
            $star_rb deselect
            $attribs_cb configure -text ""
            if {$newvalue == "%P"} {
                set newvalue [$names_cb cget -text]
            }
            set $type_var $newvalue
        }
        attrib {
            $star_rb deselect
            $names_cb configure -text ""
            if {$newvalue == "%P"} {
                set newvalue [$attribs_cb cget -text]
            }
            set $type_var $newvalue
        }
    }
    return 1
}

# Callback whenever the user modifies object classes selection, either
# by clicking on an item in the listbox or manually typing in a new
# one.  If clicking on the listbox, update the entry by
# appending/removing classes.  If manually editing the entry,
# select/deslect items from the listbox.
proc Apol_Analysis_flowassert::select_class {objs_lb class_var widget newvalue} {
    variable $class_var
    set objs_list [$objs_lb get 0 end]
    if {[string range $widget end-2 end] == "_lb"} {
        # user selected/deselected something from the listbox.
        # synchronize the widgets giving precedence to the listbox.
        # check that all selected in the listbox is in class_var and
        # that all /not/ selected are not in class_var
        set selected_list [$objs_lb curselection]
        set new_class_val [set $class_var]
        for {set i 0} {$i < [llength $objs_list]} {incr i} {
            set item [lindex $objs_list $i]
            if {[lsearch -exact -sorted -integer $selected_list $i] >= 0} {
                # item selected; add it to the entry line if not already there
                if {[lsearch -exact $new_class_val $item] == -1} {
                    lappend new_class_val $item
                }
            } else {
                # item deselected; if in entry line remove it
                if {[set x [lsearch -exact $new_class_val $item]] >= 0} {
                    set new_class_val [lreplace $new_class_val $x $x]
                }                
            }
        }
        set $class_var $new_class_val
    } else {
        # entry widget changed.  synchronize the widgets giving
        # precedence to the entry box.  auto-select in the listbox
        # anything new.  deselect those that are not in class_var.
        $objs_lb selection clear 0 end
        foreach class $newvalue {
            if {[set index [lsearch -exact $objs_list $class]] >= 0} {
                $objs_lb selection set $index
                $objs_lb see $index
            }
        }
    }
    return 1
}

# Add a type to either the starting, ending, or via list.  Do it
# smartly -- e.g., adding a '*' to a via list clears it.
proc Apol_Analysis_flowassert::add_type {type_var pos class_var include_var} {
    variable $type_var
    if {[set type [set $type_var]] == ""} {
        return
    }

    switch -- $pos {
        start { set old_pos 1 }
        end   { set old_pos 2 }
        via   { set old_pos 3 }
    }
    variable assert_wiz_line
    set old_list [lindex $assert_wiz_line $old_pos]
    
    variable $include_var
    variable $class_var
    set objclasses [set $class_var]
    if {[llength $objclasses] > 1} {
        set objclasses [list $objclasses]
    }
    if {$objclasses != ""} {
        set typeid "$type:$objclasses"
    } else {
        set typeid $type
    }
    if {[set $include_var] == "include"} {
        if {$old_list == "*"} {
            set new_list $typeid
        } elseif {$typeid == "*"} {
            if {$pos == "via"} {
                set new_list {}
            } else {
                set new_list "*"
            }
        } else {
            set new_list [concat $old_list $typeid]
        }
    } else {
        set typeid "-$typeid"
        if {$typeid == "-*"} {
            if {$pos == "via"} {
                set new_list {}
            } else {
                set new_list "*"
            }
        } else {
            set new_list [concat $old_list $typeid]
        }
    }

    set assert_wiz_line [lreplace $assert_wiz_line $old_pos $old_pos $new_list]
    reset_type $pos
}

# Takes the current assertion line and appends to to the end of the
# current assertion file.  Resets the type panels to their original
# positions, but does not modify the current assertion mode nor
# weight.
proc Apol_Analysis_flowassert::add_line {} {
    variable assertfile_t
    # add the line if and only if the widget is still visible (which
    # might not be the case if the user has clicked on a different
    # analysis module since this wizard was created)
    if [winfo exists $assertfile_t] {
        variable assert_wiz_line
        variable assert_wiz_mode
        variable assert_wiz_weight
        # check if line has an empty list for its fourth element; if
        # so don't copy it over
        if {[lindex $assert_wiz_line 3] == {}} {
            set assert_wiz_line "[lrange $assert_wiz_line 0 2] [lrange $assert_wiz_line 4 end]"
        }
        $assertfile_t insert end "$assert_wiz_line;\n"
        foreach name {start end via} {
            reset_type $name
        }
        set assert_wiz_line [list $assert_wiz_mode * * {} $assert_wiz_weight]
    }
}

# Resets all widgets in the assertion wizard to their original
# positions.  Clears the assertion line.
proc Apol_Analysis_flowassert::reset_wizard {via_tf} {
    variable assert_wiz_mode "noflow"
    variable assert_wiz_line [list noflow * * {} 1]
    variable assert_wiz_weight 1
    set_mode "noflow" $via_tf
    foreach name {start end via} {
        reset_type $name
    }
}

# Clears the values within a single wizard type panel.  This has the
# side effect of clearing the widget view as well.
proc Apol_Analysis_flowassert::reset_type {name} {
    # because the next three variables are all bounded to event
    # handlers, do the radiobutton last so that its display dominates
    # the other two
    variable assert_wiz_${name}_type_name ""
    variable assert_wiz_${name}_type_attrib ""
    variable assert_wiz_${name}_type_rb "*"
    variable assert_wiz_${name}_type "*"
    variable assert_wiz_${name}_class ""
    variable assert_wiz_${name}_include "include"
}

# Whenever the user clicks on the assertion "line xxx" hyperlink from
# the results textbox, highlight the line within the assertion file
# textbox.  Highlighting is done by changing the selection.  This
# assumes that the assertion file contents have not changed since
# executing the file.
proc Apol_Analysis_flowassert::highlight_assert_line {widget x y} {
    set line [eval $widget get [$widget tag prevrange assert_file_tag "@$x,$y + 1 char"]]
    foreach {foo linenum} [split $line] {}
    variable assertfile_t
    $assertfile_t tag remove sel 1.0 end
    $assertfile_t tag add sel $linenum.0 [expr {$linenum + 1}].0
    $assertfile_t see $linenum.0
}
