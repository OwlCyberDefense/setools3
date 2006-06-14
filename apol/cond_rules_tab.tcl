# Copyright (C) 2004-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_Cond_Rules
#
# The Conditional Booleans tab namespace
##############################################################
namespace eval Apol_Cond_Rules {
    variable vals
    variable widgets
}

###############################################################
#  ::cond_rules_render_rules
#
proc Apol_Cond_Rules::cond_rules_render_rules {resultsbox results num_rules list_idx_1} {
	upvar 1 $list_idx_1 list_idx

	for {set j 0} {$j < $num_rules} {incr j} {
		incr list_idx
		$resultsbox insert end "   "
		# Only display line number hyperlink if this is not a binary policy.
		if {![ApolTop::is_binary_policy]} {
			set lineno [lindex $results $list_idx]
			$resultsbox insert end "\["
			set start_idx [$resultsbox index insert]
			$resultsbox insert end "$lineno"
			set end_idx [$resultsbox index insert]
			Apol_PolicyConf::insertHyperLink $resultsbox $start_idx $end_idx
			$resultsbox insert end "\]"
		}
		incr list_idx
		set rule [lindex $results $list_idx]
		$resultsbox insert end " $rule "

		incr list_idx
		if {[lindex $results $list_idx]} {
			$resultsbox insert end "\[enabled\]"
		} else {
			$resultsbox insert end "\[disabled\]"
		}
		$resultsbox insert end "\n"
	}
}


###############################################################
#  ::cond_rules_search
#
proc Apol_Cond_Rules::cond_rules_search {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }

    # check search options
    set rule_selection {}
    foreach {key value} [array get vals rs:*] {
        if {$value} {
            lappend rule_selection [string range $key 3 end]
        }
    }
    if {$rule_selection == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "At least one rule must be selected."
            return
    }
    set other_opts {}
    if {$vals(use_regexp)} {
        lappend other_opts regexp
    }
    set bool_name {}
    if {$vals(enable_bool)} {
        if {[set bool_name $vals(name)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No booleean selected."
            return
        }
    }

    if {[catch {apol_SearchConditionalRules $rule_selection $other_opts $bool_name} results]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error searching conditionals:\n$results"
        return
    } else {
		$resultsbox insert end "Found the following expressions in Reverse Polish Notation:\n"
		set rule_selected [expr ($search_opts(incl_teallow) || \
					 $search_opts(incl_teaudit) || \
					 $search_opts(incl_ttrans))]
		set len [llength $results]
		if {$len > 0} {
			set counter 1
			# List should look like {expr1 num_av_rules avrule1_lineno avrule1_string avrule1_status num_audit_rules ... }
			for {set list_idx 0} {$list_idx < $len} {incr list_idx} {
				set cond_expr [lindex $results $list_idx]
				$resultsbox insert end "\nconditional expression $counter: \[ $cond_expr \]\n\n"

				if {$rule_selected} {
					$resultsbox insert end "TRUE list:\n"
				}
				incr list_idx
				set num_av_access [lindex $results $list_idx]

				if {$search_opts(incl_teallow)} {
					Apol_Cond_Rules::cond_rules_render_rules \
						$resultsbox $results $num_av_access list_idx
				}
				incr list_idx
				set num_av_audit [lindex $results $list_idx]
				if {$search_opts(incl_teaudit)} {
					Apol_Cond_Rules::cond_rules_render_rules \
						$resultsbox $results $num_av_audit list_idx
				}
				incr list_idx
				set num_ttrans [lindex $results $list_idx]
				if {$search_opts(incl_ttrans)} {
					Apol_Cond_Rules::cond_rules_render_rules \
						$resultsbox $results $num_ttrans list_idx
				}

				if {$rule_selected} {
					$resultsbox insert end "\n\nFALSE list:\n"
				}
				incr list_idx
				set num_av_access [lindex $results $list_idx]
				if {$search_opts(incl_teallow)} {
					Apol_Cond_Rules::cond_rules_render_rules \
						$resultsbox $results $num_av_access list_idx
				}
				incr list_idx
				set num_av_audit [lindex $results $list_idx]
				if {$search_opts(incl_teaudit)} {
					Apol_Cond_Rules::cond_rules_render_rules \
						$resultsbox $results $num_av_audit list_idx
				}
				incr list_idx
				set num_ttrans [lindex $results $list_idx]
				if {$search_opts(incl_ttrans)} {
					Apol_Cond_Rules::cond_rules_render_rules \
						$resultsbox $results $num_ttrans list_idx
				}
				$resultsbox insert end "\n"
				incr counter
			}
			Apol_PolicyConf::configure_HyperLinks $resultsbox
		} else {
			$resultsbox insert end "\nNo conditional expressions found."
		}
		ApolTop::makeTextBoxReadOnly $resultsbox
	}

	return 0
}

################################################################
# ::search
#	- Search text widget for a string
#
proc Apol_Cond_Rules::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results) $str $case_Insensitive $regExpr $srch_Direction
}

################################################################
# ::goto_line
#	- goes to indicated line in text box
#
proc Apol_Cond_Rules::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

################################################################
# ::set_Focus_to_Text
#
proc Apol_Cond_Rules::set_Focus_to_Text {} {
    focus $Apol_RBAC::widgets(results)
}

################################################################
#  ::open
#
proc Apol_Cond_Rules::open { } {
    variable widgets
    $widgets(combo_box) configure -values $Apol_Cond_Bools::cond_bools_list
}

################################################################
#  ::close
#
proc Apol_Cond_Rules::close { } {
    variable widgets

    initializeVars
    $widgets(combo_box) configure -values {}
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_Cond_Rules::initializeVars {} {
    variable vals
    array set vals {
        rs:allow 1       rs:type_transition 1
        rs:neverallow 1  rs:type_member 1
        rs:auditallow 1  rs:type_change 1
        rs:dontaudit 1

        enable_bool 0
        name {}
        use_regexp 0
    }
}

################################################################
#  ::free_call_back_procs
#
proc Apol_Cond_Rules::free_call_back_procs { } {
}


################################################################
#  ::create
#
proc Apol_Cond_Rules::create {nb} {
    variable vals
    variable widgets

    initializeVars

    # Layout frames
    set frame [$nb insert end $ApolTop::cond_rules_tab -text "Conditional Expressions"]
    set topf [frame $frame.top]
    set bottomf [frame $frame.bottom]
    pack $topf -expand 0 -fill both -pady 2
    pack $bottomf -expand 1 -fill both -pady 2

    # Major subframes
    set rules_box [TitleFrame $topf.rules_box -text "Rule Selection"]
    set obox [TitleFrame $topf.obox -text "Search Options"]
    set dbox [TitleFrame $bottomf.dbox -text "Conditional Expressions Display"]
    pack $rules_box -side left -expand 0 -fill both -padx 2
    pack $obox -side left -expand 1 -fill both -padx 2
    pack $dbox -expand 1 -fill both -padx 2

    # Rule selection subframe
    set fm_rules [$rules_box getframe]
    set allow [checkbutton $fm_rules.allow -text "allow" \
                   -variable Apol_Cond_Rules::vals(rs:allow)]
    set auditallow [checkbutton $fm_rules.auditallow -text "auditallow" \
                        -variable Apol_Cond_Rules::vals(rs:auditallow)]
    set dontaudit [checkbutton $fm_rules.dontaudit -text "dontaudit" \
                       -variable Apol_Cond_Rules::vals(rs:dontaudit)]
    set type_transition [checkbutton $fm_rules.type_transition -text "type_trans" \
                             -variable Apol_Cond_Rules::vals(rs:type_transition)]
    set type_member [checkbutton $fm_rules.type_member -text "type_member" \
                         -variable Apol_Cond_Rules::vals(rs:type_member)]
    set type_change [checkbutton $fm_rules.type_change -text "type_change" \
                         -variable Apol_Cond_Rules::vals(rs:type_change)]
    grid $allow $type_transition -sticky w -padx 2
    grid $auditallow $type_member -sticky w -padx 2
    grid $dontaudit $type_change -sticky w -padx 2

    # Search options subframes
    set ofm [$obox getframe]
    set bool_frame [frame $ofm.bool]
    pack $bool_frame -side left -padx 4 -pady 2 -anchor nw
    set enable [checkbutton $bool_frame.enable \
                    -variable Apol_Cond_Rules::vals(enable_bool) \
                    -text "Boolean"]
    set widgets(combo_box) [ComboBox $bool_frame.combo_box \
                                -textvariable Apol_Cond_Rules::vals(name) \
                                -helptext "Type or select a boolean variable" \
                                -state disabled -entrybg white]
    set widgets(regexp) [checkbutton $bool_frame.regexp \
                             -text "Search using regular expression" \
                             -state disabled \
                             -variable Apol_Cond_Rules::vals(use_regexp)]
    bind $widgets(combo_box).e <KeyPress> \
        [list ApolTop::_create_popup $widgets(combo_box) %W %K]
    trace add variable Apol_Cond_Rules::vals(enable_bool) write \
        [list Apol_Cond_Rules::toggleSearchBools]
    pack $enable -anchor w
    pack $widgets(combo_box) $widgets(regexp) -padx 4 -anchor nw -expand 0 -fill x

    # Action Buttons
    set ok_button [button $ofm.ok -text OK -width 6 \
                       -command Apol_Cond_Rules::cond_rules_search]
    pack $ok_button -side right -anchor ne -padx 5 -pady 5

    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$dbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Cond_Rules::toggleSearchBools {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(enable_bool)} {
        $widgets(combo_box) configure -state normal
        $widgets(regexp) configure -state normal
    } else {
        $widgets(combo_box) configure -state disabled
        $widgets(regexp) configure -state disabled
    }
}
