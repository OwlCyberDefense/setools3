#############################################################
#  flowassert_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2004-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: Jason Tang <jtang@tresys.com>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Information
# Flow Assertion.
##############################################################
# ::Apol_Analysis_flowassert module namespace
##############################################################

namespace eval Apol_Analysis_flowassert {
    variable VERSION 1

    # internal representation of assertions (model)
    variable asserts ""

    # widget variables (view)
    variable assertfile_t
    variable assert_wizard_dlg ""
    variable progressDlg .progress

    # name of widget holding most recently executed assertion
    variable most_recent_results ""

    # name and path of most recently saved/loaded assertion files
    variable last_filename ""
    variable last_pathname ""
    
    # Progress Dialog variables
    variable progressmsg		""
    variable progress_indicator		-1
    variable progressDlg
    set progressDlg .progress
		
    variable info_button_text \
"Information flow in an access control policy refers to the ability for
information to flow from one process or object into another process or
object. This can be done directly or transitively through several
intermediate types. When analyzing an access control policy, the need
to see information flow from one type to another is very important and
while direct flow is fairly obvious, transitive flows are not.\n

To facilitate automated validation and regression testing of policies
the user creates a series of information flow assertions using a batch
language that represents transitive flows. The \"Information Flow 
Assertion\" analysis module for apol easily allows the user to generate 
and execute assertion statements.  Results from the analysis are presented
in a new window.  Assertions found to be correct are labeled as \"Passed\"; 
invalid ones are hyperlinked to the line within policy.conf that caused 
the conflict.\n

Currently, there are three type of assertions. The first one is noflow,
which asserts that there is no flow between two different types.  The
second is mustflow, which instead states that there must exist one flow
between two different types. The third type is onlyflow, which says that 
there must be a flow AND that flow must be through specific intermediary 
type(s). All three modes allow for any number of source, destination, 
and exception types. Types may be specified through the use of attributes.
Finally, each assertion can have a minimum weight to limiting searches."

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
                    -title "Flow Assertion Analysis Warning" -message $err
            } else {
                tk_messageBox -icon error -type ok \
                    -title "Flow Assertion Analysis Error" -message $err
                Apol_Analysis_flowassert::destroy_progressDlg
                return -code error
            }
        }
    }

    set sw [ScrolledWindow $results_frame.sw -auto horizontal]
    set t [text $sw.t -wrap none -bg white -font $ApolTop::text_font \
              -exportselection 1]
    Apol_PolicyConf::configure_HyperLinks $t
    $t tag configure assert_file_tag -underline 1 -foreground blue
    $t tag configure title_tag -font {Helvetica 14 bold}
    $t tag configure title_num_tag -font {Helvetica 14 bold} -foreground blue
    $t tag configure subtitle_tag -font {Helvetica 11 bold}
    $t tag bind assert_file_tag <Button-1> [namespace code [list highlight_assert_line  %W %x %y]]
    $t tag bind assert_file_tag <Enter> { set Apol_PolicyConf::orig_cursor [%W cget -cursor]; %W configure -cursor hand2 }
    $t tag bind assert_file_tag <Leave> { %W configure -cursor $Apol_PolicyConf::orig_cursor }

    $sw setwidget $t
    pack $sw -expand 1 -fill both
    variable most_recent_results
    set most_recent_results $sw
    
    variable assertfile_t
    set assert_contents [string trim [$assertfile_t get 1.0 end]]
    $t insert end "Executing:\n\n$assert_contents"
    $t tag add title_tag 1.0 "1.0 lineend"
    display_progressDlg
    update idletasks

    if [catch {apol_FlowAssertExecute $assert_contents 0} assert_results] {
        set retval -1
    } else {
        $t delete 1.0 end
        if {$ApolTop::policy_type == $ApolTop::binary_policy_type} {
            set bin_policy 1
        } else {
            set bin_policy 0
        }
        
        # build summary statement
        set num_passed 0
        set num_failed 0
        set num_illegal 0
        foreach result $assert_results {
            switch -- [lindex $result 2] {
                0 { incr num_passed }
                1 { incr num_failed }
                default { incr num_illegal }
            }
        }
        set summary "Results: "
        set i [string length $summary]
        if {$num_passed == 1} {
            append summary "1 assertion passed"
        } else {
            append summary "$num_passed assertions passed"
        }
        set j [string length $summary]
        append summary ", $num_failed failed"
        set k [string length $summary]
        if {$num_illegal == 1} {
            append summary ", and 1 statement could not be evaluated."
        } elseif {$num_illegal > 1} {
            append summary ", and $num_illegal statements could not be evaluated."
        } else {
            append summary "."
        }
        $t insert end "$summary\n\n"
        $t tag add title_tag 1.0 "1.0 lineend"
        $t tag add title_num_tag "1.0 + $i c" "1.0 + $i c + [string length $num_passed] c"
        $t tag add title_num_tag "1.0 + $j c + 2 c" "1.0 + $j c + 2 c + [string length $num_failed] c"
        if {$num_illegal >= 1} {
            $t tag add title_num_tag "1.0 + $k c + 6 c" "1.0 + $k c + 6 c + [string length $num_illegal] c"
        }
        set typeslist [apol_GetNames types]
        foreach result $assert_results {
            foreach {mode lineno result rules_list} $result {}
            set orig_line [$assertfile_t get $lineno.0 "$lineno.0 lineend - 1c"]
            set line "$orig_line"
            set line_end_index [string length $line]
            append line ": "
            set policy_tags_list ""
            set i [string length $line]
            set j {}
            switch -- $result {
                0 { append line "Passed.\n" }
                1 {
                    append line "Failed.\n"
                    foreach rules $rules_list {
                        foreach {start_type end_type via_type rule_list} $rules {}
                        if {[set from [lindex $typeslist $start_type]] == ""} {
                            set from "<unknown type>"
                        }
                        if {[set to [lindex $typeslist $end_type]] == ""} {
                            set to "<unknown type>"
                        }
                        if {$rule_list != {}} {
                            lappend j [string length $line]
                            append line "  $from to $to:\n"
                            foreach rule $rule_list {
                                set rule_num [lindex $rule 0]
                                set rule_str [lindex $rule 1]
                                append line "    "
                                if {$bin_policy == 0} {
                                    append line "\["
                                    set start_index [string length $line]
                                    append line $rule_num
                                    set end_index [string length $line]
                                    append line "\] "
                                    lappend policy_tags_list $start_index $end_index
                                }
                                append line "$rule_str\n"
                            }
                        } elseif {$via_type >= 0} {
                            if {[set via [lindex $typeslist $via_type]] == ""} {
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
            $t insert end "$line\n"
            $t tag add assert_file_tag $offset "$offset + $line_end_index c"
            $t tag add subtitle_tag "$offset + $i c" "$offset lineend"
            foreach k $j {
                $t tag add subtitle_tag "$offset + $k c" "$offset + $k c lineend"
            }
            $t tag add l$lineno $offset "$offset + $line_end_index c"
            
            # hyperlink to policy.conf if policy is not binary
            if {$bin_policy == 0} {
                foreach {start_index end_index} $policy_tags_list {
                    Apol_PolicyConf::insertHyperLink $t \
                        "$offset + $start_index c" "$offset + $end_index c"
                }
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
    $assertfile_t tag remove assert_file_sel_tag 1.0 end
    destroy_progressDlg
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
    variable VERSION
    variable asserts
    if {[gets $file_channel] > $VERSION} {
        return -code error "The specified query version is not allowed."
    }
    set asserts [read $file_channel]
    sync_asserts_to_text
    return 0
}

# Called whenever a user saves a query
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
proc Apol_Analysis_flowassert::save_query_options {module_name file_channel file_name} {
    variable VERSION
    variable asserts
    puts $file_channel $module_name
    puts $file_channel $VERSION
    puts -nonewline $file_channel $asserts
    return 0
}

# Captures the current set of options, which is then later restored by
# [set_display_to_results_tab].
proc Apol_Analysis_flowassert::get_current_results_state { } {
    variable asserts
    variable assertfile_t
    return [list $assertfile_t $asserts]
}

# Apol_Analysis_flowassert::set_display_to_results_state is called to
# reset the options or any other context that analysis needs when the
# GUI switches back to an existing analysis.  options is a list that
# we created in a previous get_current_results_state() call.
proc Apol_Analysis_flowassert::set_display_to_results_state {query_options} {
    variable most_recent_results
    foreach {assertfile_t assertcontents} $query_options {}
    variable asserts $assertcontents
    sync_asserts_to_text
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
    variable asserts ""
    variable assertfile_t
    set tf [TitleFrame $opts_frame.assertfile -text "Assertions"]
    set sw [ScrolledWindow [$tf getframe].sw -auto horizontal]
    set assertfile_t [text $sw.assertfile_t -wrap none -state normal \
                          -fg black -bg white -font $ApolTop::text_font \
                          -cursor arrow \
                          -exportselection 0 -selectbackground white \
                          -selectforeground black -selectborderwidth 0]
    $assertfile_t tag configure assert_file_t_tag
    $assertfile_t tag configure assert_file_sel_tag -background gray
    $assertfile_t tag bind assert_file_t_tag <Button-1> [namespace code [list assertfile_click %W %x %y]]
    $assertfile_t tag bind assert_file_t_tag <Double-Button-1> [namespace code edit_line]
    $sw setwidget $assertfile_t
    grid $tf -row 0 -column 0 -padx 10 -sticky nsew
    pack $sw -expand 1 -fill both
    set bb1 [ButtonBox $opts_frame.bb1 -homogeneous 1 -spacing 10]
    $bb1 add -text "Insert Assertion..." -command [namespace code create_assert_wizard_dlg]
    $bb1 add -text "Insert Comment..." -command [namespace code add_comment_dlg]
    $bb1 add -text "Edit..." -command [namespace code edit_line]
    $bb1 add -text "Delete" -command [namespace code delete_line]
    grid $bb1 -sticky {}
    set bb2 [ButtonBox $opts_frame.bb2 -homogeneous 1 -spacing 10 -orient vertical]
    $bb2 add -text "Clear All" -command [namespace code clear_assert_file]
    $bb2 add -text "Export Assertions..." -command [namespace code export_assert_file]
    $bb2 add -text "Import Assertions..." -command [namespace code import_assert_file]
    grid $bb2 -row 0 -column 1 -padx 5 -sticky ns
    grid rowconfigure $opts_frame 0 -weight 1
    grid rowconfigure $opts_frame 1 -weight 0 -pad 20
    grid columnconfigure $opts_frame 0 -weight 1
    variable line_editing_buttons [list $bb1 2 3]
    sync_asserts_to_text
}


##########################################################################
##########################################################################
## The rest of these procs are not interface procedures, but rather
## internal functions to this analysis.
##########################################################################
##########################################################################

# Called whenever the user clicks on the assertion file text field.
# Select the line clicked and enable the line editing buttons.  If the
# click was on an already selected line, deselect it and disable the
# buttons.
proc Apol_Analysis_flowassert::assertfile_click {widget x y} {
    variable asserts
    set newline [lindex [split [$widget index @$x,$y] .] 0]
    set selection [lindex [$widget tag ranges assert_file_sel_tag] 0]
    set oldline [lindex [split [lindex $selection 0] .] 0]
    # remove old selection
    if {$oldline != ""} {
        $widget tag remove assert_file_sel_tag $oldline.0 [expr {$oldline + 1}].0
    }
    if {$newline >= 1 && $newline <= [llength $asserts] && $newline != $oldline} {
        # add a selection
        $widget tag add assert_file_sel_tag $newline.0 [expr {$newline + 1}].0
    }
    enable_line_editing
}

# Enable/disable the line editing buttons (edit line and delete line),
# but only if something is selected.
proc Apol_Analysis_flowassert::enable_line_editing {} {
    variable assertfile_t    
    if {[$assertfile_t tag ranges assert_file_sel_tag] != ""} {
        set newstate normal
    } else {
        set newstate disabled
    }
    variable line_editing_buttons
    set parent [lindex $line_editing_buttons 0]
    foreach button [lrange $line_editing_buttons 1 end] {
        $parent itemconfigure $button -state $newstate
    }
}

# Deletes the contents of the assertion file text box, and thus
# consequently clears the file.
proc Apol_Analysis_flowassert::clear_assert_file {} {
    variable asserts ""
    sync_asserts_to_text
}

# Prompts the user for a file name, then saves the contents of the
# assertion buffer to it.
proc Apol_Analysis_flowassert::export_assert_file {} {
    variable assertfile_t
    variable last_filename
    variable last_pathname
    set filename [tk_getSaveFile -title "Export Flow Assertion File" \
                      -parent $assertfile_t -initialdir $last_pathname \
                      -initialfile $last_filename]
    if {$filename == ""} {
        return
    }
    if [catch {::open $filename w} f] {
        tk_messageBox -icon error -type ok -title "Export Flow Assertion File" \
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
proc Apol_Analysis_flowassert::import_assert_file {} {
    variable assertfile_t
    variable last_filename
    variable last_pathname
    set filename [tk_getOpenFile -title "Import Flow Assertion File" \
                      -parent $assertfile_t -initialdir $last_pathname \
                      -initialfile $last_filename]
    if {$filename == ""} {
        return
    }
    if [catch {::open $filename r} f] {
        tk_messageBox -icon error -type ok -title "Import Flow Assertion File" \
            -message "Error loading from $filename" -parent $assertfile_t
        return
    }
    variable asserts ""
    set errors_found 0
    foreach line [split [read $f] \n] {
        if {[string index [string trimleft $line] 0] == "\#"} {
            lappend asserts $line
        } else {
            foreach a [split $line ";"] {
                if {$a == ""} {
                    continue
                } elseif {[llength $a] < 3 || [llength $a] > 5} {
                    set errors_found 1
                } else {
                    foreach {mode start to via weight} $a {}
                    if {$mode != "noflow" && $mode != "onlyflow" && $mode != "mustflow"} {
                        set errors_found 1
                    } else {
                        if {[llength $a] == 3} {
                            set weight 1
                        } elseif {[llength $a] == 4} {
                            set weight $via
                            set via {}
                        }
                        if {[string is integer -strict $weight] == 0 || \
                                $weight < 1 || $weight > 10} {
                            set errors_found 1
                        } else {
                            lappend asserts [list $mode $start $to $via $weight]
                        }
                    }
                }
            }
        }
    }
    ::close $f
    set last_filename [file tail $filename]
    set last_pathname [file dirname $filename]
    if {$errors_found == 1} {
        tk_messageBox -icon warning -type ok \
            -title "Import Flow Assertion Warning" \
            -message "Some lines in $filename could not be safely imported into apol."
    }
    sync_asserts_to_text
}

# Creates the "assertion statement wizard" that allows a user to
# easily add assertions lines to the current file.  The wizard is a
# non-modal dialog that presents all available types + attributes /
# options.  It does not validate entries for syntactical correctness.
proc Apol_Analysis_flowassert::create_assert_wizard_dlg {{origline {}}} {
    # destroy old wizard items
    destroy .assertfile_wizard_dlg
    variable wiz
    array unset wiz
    variable wiz_var
    array unset wiz_var

    if {$origline == ""} {
        set title "Insert Flow Assertion"
    } else {
        set title "Edit Flow Assertion"
    }
    # create a dialog to hold the wizard
    variable assertfile_t
    variable assert_wizard_dlg [Dialog .assertfile_wizard_dlg -homogeneous 1 \
                                    -spacing 20 -anchor c -cancel 2 \
                                    -modal local -parent $assertfile_t \
                                    -separator 0 -side bottom -title $title]
    set f [$assert_wizard_dlg getframe]
    set topf [frame $f.topf]

    set start_tf [TitleFrame $topf.start_tf -text "Starting Types"]
    create_type_panel [$start_tf getframe] start
    set end_tf [TitleFrame $topf.end_tf -text "Ending Types"]
    create_type_panel [$end_tf getframe] to
    set wiz(via_tf) [TitleFrame $topf.via_tf -text "Exceptions Type"]
    create_type_panel [$wiz(via_tf) getframe] via
    
    set f0 [frame $topf.f0]
    set mode_tf [TitleFrame $f0.tf -text "Assertion Mode"]
    set noflow_rb [radiobutton [$mode_tf getframe].noflow_rb \
                  -text "noflow" -value "noflow" \
                  -variable Apol_Analysis_flowassert::wiz_var(mode) \
                  -command [namespace code [list set_mode "noflow"]]]
    set mustflow_rb [radiobutton [$mode_tf getframe].mustflow_rb \
                  -text "mustflow" -value "mustflow" \
                  -variable Apol_Analysis_flowassert::wiz_var(mode) \
                  -command [namespace code [list set_mode "mustflow"]]]
    set onlyflow_rb [radiobutton [$mode_tf getframe].onlyflow_rb \
                  -text "onlyflow" -value "onlyflow" \
                  -variable Apol_Analysis_flowassert::wiz_var(mode) \
                  -command [namespace code [list set_mode "onlyflow"]]]
    pack $noflow_rb $mustflow_rb $onlyflow_rb -anchor w -side top
    set lf [LabelFrame $f0.lf -text "Minimum Weight: " -side left]
    set weight_sb [SpinBox [$lf getframe].weight_sb -font $ApolTop::text_font \
                    -width 3 -entrybg white -range [list 1 10 1] \
                    -editable 0 -justify right \
                    -textvariable Apol_Analysis_flowassert::wiz_var(weight) \
                    -modifycmd [namespace code sync_wiz_lbs_to_line]]
    pack $weight_sb -expand 1 -fill both
    pack $mode_tf -expand 1 -fill both -pady 20
    pack $lf -expand 1 -fill x -pady 20
    pack $f0 -expand 0 -fill none -side left -padx 10
    pack $start_tf $end_tf $wiz(via_tf) -expand 1 -fill both -side left
    pack $topf -side top -expand 1 -fill both
    
    $assert_wizard_dlg add -text "Reset" \
        -command [namespace code [list reset_wizard $origline]]
    $assert_wizard_dlg add -text "OK" -command [namespace code add_assertion]
    $assert_wizard_dlg add -text "Cancel"
    
    populate_lists 1
    reset_wizard $origline

    set result [$assert_wizard_dlg draw]
    destroy $assert_wizard_dlg
    if {$result == 1} {
        # user clicked on add line
        return 1
    } else {
        # user canceled dialog
        return 0
    }
}

# Creates an individual panel {starting, ending, via/exceptions} for
# the assertion wizard.
proc Apol_Analysis_flowassert::create_type_panel {type_panel type_name} {
    variable wiz
    variable wiz_var
    
    # add the type selection radiobutton + ComboBox
    set type_star_rb [radiobutton $type_panel.star_cb -value "*" \
                          -text "Any Type" \
                          -variable Apol_Analysis_flowassert::wiz_var($type_name,type,rb)]
    pack $type_star_rb -anchor w -side top
    set type_names_f [frame $type_panel.type_names_f]
    set type_names_l [label $type_names_f.names_l -text "Type/Attribute Names:"]
    set type_names_cb [ComboBox $type_names_f.names_cb -width 24 \
                           -editable 1 -entrybg white -exportselection 0 \
                           -textvariable Apol_Analysis_flowassert::wiz_var($type_name,type,name)]
    bindtags $type_names_cb.e [linsert [bindtags $type_names_cb.e] 3 ${type_name}_names_tags]
    bind ${type_name}_names_tags <KeyPress> [list ApolTop::_create_popup $type_names_cb %W %K]
    pack $type_names_l -expand 0 -side top
    pack $type_names_cb -expand 0 -fill both -side top
    pack $type_names_f -expand 0 -fill none -side top -pady 2

    # add bindings between these so that modifying one clears the other
    set bindcmd [namespace code [list set_type $type_star_rb $type_names_cb $type_name star ""]]
    $type_star_rb configure -command $bindcmd
    set bindcmd [namespace code [list set_type $type_star_rb $type_names_cb $type_name name %P]]
    $type_names_cb configure -modifycmd $bindcmd -vcmd $bindcmd -validate key

#    pack [Separator $type_panel.strut0 -orient horizontal] \
#        -expand 0 -fill x -side top -pady 10

    # add the object selection listbox + Entry
#    pack [label $type_panel.objs_l -text "Object Classes:"] -expand 0
    set objs_sw [ScrolledWindow $type_panel.objs_sw -auto horizontal]
    set wiz($type_name,objs_lb) [listbox [$objs_sw getframe].objs_lb -selectmode multiple \
                     -height 5 -highlightthickness 0 -exportselection 0 \
                     -setgrid 0 -background white \
                     -listvariable Apol_Analysis_flowassert::assert_wizard_objclasses]
    $objs_sw setwidget $wiz($type_name,objs_lb)
#    pack $objs_sw -expand 0 -fill both
    set objs_e [Entry $type_panel.objs_e -background white -validate key \
                    -textvariable Apol_Analysis_flowassert::wiz_var($type_name,class)]
    $objs_e configure -vcmd [namespace code [list select_class $type_name $objs_e %P]]
#    pack $objs_e -expand 0 -fill x -pady 2
    bind $wiz($type_name,objs_lb) <<ListboxSelect>> [namespace code [list select_class $type_name $wiz($type_name,objs_lb) ""]]
    
#    pack [Separator $type_panel.strut1 -orient horizontal] \
# -expand 0 -fill x -side top -pady 10

    # add the include / exclude radio buttons
    set include_rb [radiobutton $type_panel.include_rb -value "include" \
                        -text "Include Type" \
                        -variable Apol_Analysis_flowassert::wiz_var($type_name,include)]
    set exclude_rb [radiobutton $type_panel.exclude_rb -value "exclude" \
                        -text "Exclude Type" \
                        -variable Apol_Analysis_flowassert::wiz_var($type_name,include)]
    pack $include_rb $exclude_rb -anchor w -side top

    set add_replace_f [frame $type_panel.add_replace_f]
    set add_b [button $add_replace_f.add_b -text "Add"]
    set wiz($type_name,replace_b) [button $add_replace_f.replace_b -text "Replace"]
    grid $add_b $wiz($type_name,replace_b) -padx 5 -sticky ew
    grid columnconfigure $add_replace_f 0 -weight 1
    grid columnconfigure $add_replace_f 1 -weight 1
    pack $add_replace_f -expand 0 -fill x -pady 5 -side top
    
    pack [Separator $type_panel.strut2 -orient horizontal] \
        -expand 0 -fill x -side top -pady 10

    set id_list_sw [ScrolledWindow $type_panel.id_list_sw -auto horizontal]
    set id_list_lb [listbox [$id_list_sw getframe].id_list_lb \
                        -selectmode browse -height 4 -exportselection 0 \
                        -listvariable Apol_Analysis_flowassert::wiz_var($type_name) \
                        -background white]
    set wiz($type_name,id_lb) $id_list_lb
    $id_list_sw setwidget $id_list_lb
    pack $id_list_sw -side top -expand 1 -fill both
    set wiz($type_name,remove_b) [button $type_panel.remove_b -text "Remove"]
    $wiz($type_name,remove_b) configure -command [namespace code [list remove_type $id_list_lb $type_name]]
    pack $wiz($type_name,remove_b) -expand 0 -pady 5 -side top

    $add_b configure -command [namespace code [list add_replace_type $id_list_lb $type_name 0]]
    $wiz($type_name,replace_b) configure -command [namespace code [list add_replace_type $id_list_lb $type_name 1]]
    bind $id_list_lb <<ListboxSelect>> [namespace code [list select_id_item $id_list_lb $type_name]]
    bind $id_list_lb <Button-1> [namespace code [list id_list_lb_click %W $type_name %y]]
    select_id_item $id_list_lb $type_name
    
    # add the widgets' paths to a list, to be read by [populate_lists]
    lappend wiz(type_cbs) $type_names_cb
    lappend wiz(objclass_lbs) $wiz($type_name,objs_lb)
}

# Called to populate the ComboBox/listbox holding the type names +
# attributes/object classes.  This is done in one of three places:
# upon wizard dialog creation, when opening a policy, and when closing
# a policy.
proc Apol_Analysis_flowassert::populate_lists {add_items} {
    variable wiz
    
    if $add_items {
        foreach type_cb $wiz(type_cbs) {
            $type_cb configure -values [lsort [concat $Apol_Types::typelist $Apol_Types::attriblist]]
        }
        foreach objclass_lb $wiz(objclass_lbs) {
            set var [$objclass_lb cget -listvariable]
            set $var $Apol_Class_Perms::class_list
        }
    } else {
        foreach type_cb $wiz(type_cbs) {
            $type_cb configure -values {}
        }
        foreach objclass_lb $wiz(objclass_lbs) {
            set var [$objclass_lb cget -listvariable]
            set $var {}
        }
    }
}

# Callback when a user clicks on a mode radiobutton {noflow, mustflow,
# onlyflow}.  Updates the title of the via_tf frame.  Updates the mode
# listed in the current assertion line.
proc Apol_Analysis_flowassert::set_mode {newmode} {
    variable wiz
    if {$newmode == "noflow"} {
        $wiz(via_tf) configure -text "Exception Types (optional)"
    } elseif {$newmode == "mustflow"} {
        $wiz(via_tf) configure -text "Via Types (optional)"
    } else {
        $wiz(via_tf) configure -text "Via Types (required)"
    }
    sync_wiz_lbs_to_line
}

# Callback whenever the user selects a type.  Disables the other
# widgets.  Sets the internal variable to be equal to the name of the
# type.
proc Apol_Analysis_flowassert::set_type {star_rb names_cb type_name which newvalue} {
    variable wiz_var
    switch -- $which {
        star {
            $star_rb select
            $names_cb configure -text ""
            set wiz_var($type_name,type) "*"
        }
        name {
            if {$newvalue != ""} {
                $star_rb deselect
                if {$newvalue == "%P"} {
                    set newvalue [$names_cb cget -text]
                }
                set wiz_var($type_name,type) $newvalue
            }
        }
    }
    return 1
}

# Callback whenever the user modifies object classes selection, either
# by clicking on an item in the listbox or manually typing in a new
# one.  If clicking on the listbox, update the entry by
# appending/removing classes.  If manually editing the entry,
# select/deslect items from the listbox.
proc Apol_Analysis_flowassert::select_class {type_name widget newvalue} {
    variable wiz
    variable wiz_var
    set objs_lb $wiz($type_name,objs_lb)
    set class_var wiz_var($type_name,class)
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

# Callback when the user clicks on the 'add' or 'replace' button
# within the wizard.  For the add button ($replace_clicked == 0), if
# an item is already selected insert the new type_id prior to
# selection; otherwise append to bottom.  For replace, replace the
# currently selected item.  Either way remove the selection
# afterwards.
proc Apol_Analysis_flowassert::add_replace_type {id_lb type_name
                                                 replace_clicked} {
    variable wiz_var
    set class $wiz_var($type_name,class)
    if {$wiz_var($type_name,include) == "include"} {
        set sign ""
    } else {
        set sign "-"
    }
    set type $wiz_var($type_name,type)
    if {$class != ""} {
        if {[llength $class] > 1} {
            set class ":\{$class\}"
        } else {
            set class ":$class"
        }
    }
    set type_id "$sign$type$class"
    if {[set selected [$id_lb curselection]] == {}} {
        lappend wiz_var($type_name) $type_id
    } else {
        set selected [lindex $selected 0]
        if {$replace_clicked == 0} {
            set wiz_var($type_name) [linsert $wiz_var($type_name) $selected $type_id]
        } else {
            set wiz_var($type_name) [lreplace $wiz_var($type_name) $selected $selected $type_id]
        }
    }
    $id_lb selection clear 0 end
    select_id_item $id_lb $type_name
    sync_wiz_lbs_to_line
    reset_type $type_name
}

# Take the three type_id list boxes and re-render the current
# assertion line.
proc Apol_Analysis_flowassert::sync_wiz_lbs_to_line {} {
    variable wiz_var
    foreach var {mode start to via weight} {
        set $var $wiz_var($var)
    }
    set wiz_var(line) [render_assertion [list $mode $start $to $via $weight]]
}

# Callback whenever the selection changes in the assert id listbox.
# If an item is highlighted, fill in the type rb/lb and object class
# entry; also enable the replace and remove buttons.  If no items are
# selected then disable replace and remove buttons.
proc Apol_Analysis_flowassert::select_id_item {id_lb type_name} {
    variable wiz
    variable wiz_var
    if {[set selected [$id_lb curselection]] != {}} {
        $wiz($type_name,remove_b) configure -state normal
        $wiz($type_name,replace_b) configure -state normal
        # fill in the other fields given the currently selected one
        set type_id [lindex $wiz_var($type_name) [lindex $selected 0]]
        foreach {type class} [split $type_id ":"] {}
        set wiz_var($type_name,type) $type
        if {[string index $type 0] == "-"} {
            set wiz_var($type_name,include) "exclude"
            set type [string range $type 1 end]
        } else {
            set wiz_var($type_name,include) "include"
        }
        if {$type == "*"} {
            set wiz_var($type_name,type,name) ""
            set wiz_var($type_name,type,rb) "*"
        } else {
            set wiz_var($type_name,type,rb) ""
            set wiz_var($type_name,type,name) $type
        }
        set wiz_var($type_name,class) $class
    } else {
        $wiz($type_name,replace_b) configure -state disabled
        $wiz($type_name,remove_b) configure -state disabled
    }
}

# Callback whenever the user clicks on the remove button. Remove the
# currently selected item from the assert id listbox.
proc Apol_Analysis_flowassert::remove_type {id_lb type_name} {
    if {[set selected [$id_lb curselection]] == {}} {
        return
    }
    set selected [lindex $selected 0]
    variable wiz_var
    set wiz_var($type_name) [lreplace $wiz_var($type_name) $selected $selected]
    $id_lb selection clear 0 end
    select_id_item $id_lb $type_name
    reset_type $type_name
    sync_wiz_lbs_to_line
}

# Callback whenever the user clicks on the assert id list box.  If
# user clicks on the already selected item deselect it.
proc Apol_Analysis_flowassert::id_list_lb_click {id_lb type_name y} {
    if {[set clicked [$id_lb index @1,$y]] != -1} {
        if {[$id_lb selection includes $clicked]} {
            # deselect the item
            $id_lb selection clear $clicked
            select_id_item $id_lb $type_name
            return -code break
        }
        select_id_item $id_lb $type_name
    }
}

# Takes the current assertion line and adds it to the current
# assertion file, but only if the required list boxes have been
# selected.  Then closes the assertion dialog.
proc Apol_Analysis_flowassert::add_assertion {} {
    variable assertfile_t
    # add the line if and only if the widget is still visible (which
    # might not be the case if the user has clicked on a different
    # analysis module since this wizard was created)
    if [winfo exists $assertfile_t] {
        variable wiz_var
        foreach var {mode start to via weight} {
            set $var $wiz_var($var)
        }
        if {$start == {} || $to == {} || ($mode == "onlyflow" && $via == {})} {
            tk_messageBox -icon error -type ok \
                -title "Flow Assertion Wizard Error" \
                -message "A required type has not been added."
        } else {
            add_line [list $mode $start $to $via $weight]
            variable assert_wizard_dlg
            $assert_wizard_dlg enddialog 1
        }
    }
}

# Resets all widgets in the assertion wizard to theimdr original
# positions.  Clears the assertion line and type_id list boxes.
proc Apol_Analysis_flowassert::reset_wizard {origline} {
    variable wiz
    variable wiz_var
    if {$origline == ""} {
        set mode "noflow"
        set start {}
        set to {}
        set via {}
        set weight 1
    } else {
        foreach {mode start to via weight} $origline {}
    }
    foreach var {mode start to via weight} {
        set wiz_var($var) [set $var]
    }
    foreach type_name {start to via} {
        reset_type $type_name
        $wiz($type_name,id_lb) selection set 0
        select_id_item $wiz($type_name,id_lb) $type_name
    }
    set_mode $mode
}

# Clears the values within a single wizard type panel.
proc Apol_Analysis_flowassert::reset_type {type_name} {
    variable wiz_var
    set wiz_var($type_name,type) "*"
    set wiz_var($type_name,class) ""
    set wiz_var($type_name,include) "include"
    # do these in reverse order so that the radiobutton change event
    # fires last
    set wiz_var($type_name,type,name) ""
    set wiz_var($type_name,type,rb) "*"
}

# Whenever the user clicks on the assertion "line xxx" hyperlink from
# the results textbox, highlight the line within the assertion file
# textbox.  Highlighting is done by changing the selection.  This
# assumes that the assertion file contents have not changed since
# executing the file.
proc Apol_Analysis_flowassert::highlight_assert_line {widget x y} {
    foreach tag [$widget tag names "@$x,$y"] {
        if {[string index $tag 0] == "l"} {
            set linenum [string range $tag 1 end]
        }
    }
    variable assertfile_t
    $assertfile_t tag remove assert_file_sel_tag 1.0 end
    $assertfile_t tag add assert_file_sel_tag $linenum.0 [expr {$linenum + 1}].0
    $assertfile_t see $linenum.0
    enable_line_editing
}

# Given an assertion (either a comment or a 4-tuple/5-tuple) return a
# string that represents the line.
proc Apol_Analysis_flowassert::render_assertion {assertion} {
    if {[string index [string trimleft $assertion] 0] == "\#"} {
        return $assertion
    } else {
        foreach {mode start to via weight} $assertion {}
        if {[llength $start] == 0} {
            set start "*"
        }
        if {$to == {}} {
            set to "*"
        }
        if {$via == {}} {
            return "[list $mode $start $to $weight];"
        } else {
            return "[list $mode $start $to $via $weight];"
        }
    }
}

# Resynchronize the assertions (model) to its view (assertfile_t text
# field).
proc Apol_Analysis_flowassert::sync_asserts_to_text {} {
    variable asserts
    variable assertfile_t
    $assertfile_t configure -state normal
    $assertfile_t delete 1.0 end
    foreach line $asserts {
        $assertfile_t insert end "[render_assertion $line]\n"
    }
    $assertfile_t tag add assert_file_t_tag 1.0 end
    $assertfile_t configure -state disabled
    enable_line_editing
}

# Displays a dialog box to allow user to add a comment to the
# assertion file.  Returns 1 if something was added, 0 otherwise.
proc Apol_Analysis_flowassert::add_comment_dlg {{origcomment ""}} {
    if [winfo exists .assertfile_comment_dlg] {
        raise .assertfile_comment_dlg
        return
    }
    if {$origcomment == ""} {
        set title "Insert Flow Assertion Comment"
    } else {
        set title "Edit Flow Assertion Comment"
    }
    variable assertfile_t
    set d [Dialog .assertfile_comment_dlg -homogeneous 1 -spacing 10 \
               -anchor e -cancel 1 -default 0 -modal local \
               -parent $assertfile_t -separator 0 -side bottom \
               -title $title]
    $d add -text "OK"
    $d add -text "Cancel"
    set f [$d getframe]
    set l [label $f.l -text "Comment: "]
    set e [entry $f.e -width 80 -font $ApolTop::text_font -bg white]
    $e insert end $origcomment
    pack $l -side left
    pack $e -side right -fill x -expand 0
    if {[$d draw $e] == 0} {
        # user either clicked on okay or hit the enter key
        add_line "\#[$e get]"
        destroy $d
        return 1
    }
    destroy $d
    return 0
}

# Edit the currently selected line.  If the line is a comment then pop
# up the comment dialog, else pop up the assertion wizard.
proc Apol_Analysis_flowassert::edit_line {} {
    variable assertfile_t
    set selection [lindex [$assertfile_t tag ranges assert_file_sel_tag] 0]
    if {[llength $selection] == 0} {
        return
    }
    set oldline [lindex [split [lindex $selection 0] .] 0]
    variable asserts
    set line [lindex $asserts [expr {$oldline - 1}]]
    if {[string index [string trimleft $line] 0] == "\#"} {
        set result [add_comment_dlg [string range $line 1 end]]
    } else {
        set result [create_assert_wizard_dlg $line]
    }
    if $result {
        # delete the previous line and select the newly edited one
        set asserts [lreplace $asserts $oldline $oldline]
        sync_asserts_to_text
        $assertfile_t tag add assert_file_sel_tag $oldline.0 [expr {$oldline + 1}].0
        enable_line_editing
    }
}

# Delete the currently selected line.  Re-render the text field and
# select the next line.
proc Apol_Analysis_flowassert::delete_line {} {
    variable assertfile_t
    set selection [lindex [$assertfile_t tag ranges assert_file_sel_tag] 0]
    if {[llength $selection] == 0} {
        return
    }
    set oldline [lindex [split [lindex $selection 0] .] 0]
    incr oldline -1
    variable asserts
    set asserts [lreplace $asserts $oldline $oldline]
    sync_asserts_to_text
    # select the next line
    incr oldline
    $assertfile_t tag add assert_file_sel_tag $oldline.0 [expr {$oldline + 1}].0
    enable_line_editing
}

# Adds a line (either comment or assertion) to the assertions list.
# If a line is selected, add the new line prior to the selection.
# Otherwise append it to the end.
proc Apol_Analysis_flowassert::add_line {line} {
    variable asserts
    variable assertfile_t
    set selection [lindex [$assertfile_t tag ranges assert_file_sel_tag] 0]
    set oldline [lindex [split [lindex $selection 0] .] 0]
    if {$oldline != ""} {
        set asserts [linsert $asserts [expr {$oldline - 1}] $line]
    } else {
        lappend asserts $line
    }
    sync_asserts_to_text
    if {$oldline != ""} {
        # reselect the previous line
        incr oldline
        $assertfile_t tag add assert_file_sel_tag $oldline.0 [expr {$oldline + 1}].0
    }
    enable_line_editing
}

proc Apol_Analysis_flowassert::destroy_progressDlg {} {
    variable progressDlg
    
    if {[winfo exists $progressDlg]} {
        destroy $progressDlg
    }
    return 0
} 

proc Apol_Analysis_flowassert::display_progressDlg {} {
    variable progressDlg   
    variable progressMsg "Executing assertion statements..."
    variable progress_indicator -1
    destroy $progressDlg
    set progressBar [ProgressDlg $progressDlg \
                         -parent $ApolTop::mainframe \
                         -textvariable Apol_Analysis_flowassert::progressMsg \
                         -variable Apol_Analysis_flowassert::progress_indicator \
                         -maximum 3 \
                         -width 45]
    update
    bind $progressBar <<AnalysisStarted>> {
        set Apol_Analysis_fulflow::progress_indicator \
            [expr {Apol_Analysis_fulflow::progress_indicator + 1}]
    }
    return 0
}
