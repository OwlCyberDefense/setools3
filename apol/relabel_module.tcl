#############################################################
#  relabel_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <jtang@tresys.com>
# -----------------------------------------------------------
#
# This is the implementation of the interface for
# Relabeling Analysis

namespace eval Apol_Analysis_relabel {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_relabel" "Direct Relabel"
}

proc Apol_Analysis_relabel::open {} {
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(type)
}

proc Apol_Analysis_relabel::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(type)
}

proc Apol_Analysis_relabel::getInfo {} {
    return "Direct relabel analysis is designed to facilitate querying a policy
for both potential changes to object labels and relabel privileges
granted to a subject. These two modes are respectively called Object
Mode and Subject Mode.

\nOBJECT MODE
In object mode the user specifies a starting or ending type and either
To, From, or Both. When To is selected all types to which the starting
type can be relabeled will be displayed. When From is selected all
types from which the ending type can be relabeled will be
displayed. Both will, obviously, do both analyses.

\nSUBJECT MODE
In subject mode the user specifies only a subject type. Two lists of
types will be displayed corresponding to all of the types To which the
subject can relabel and From which the subject can relabel.

\nOPTIONAL RESULT FILTERS
Results may be filtered in several ways. The end types resulting from
a query may be filtered by regular expression. The Advanced Filters
provide the option of selecting which object classes to include in the
analysis and which types to include as subjects of relabeling
operations. Note, excluded subjects are ignored in subject mode
because only the selected subject type is used as a subject."
}

proc Apol_Analysis_relabel::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

    set mode_tf [TitleFrame $options_frame.mode -text "Mode"]
    pack $mode_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set object_mode [radiobutton [$mode_tf getframe].object \
                         -text "Object mode" -value "object" \
                         -variable Apol_Analysis_relabel::vals(mode)]
    pack $object_mode -anchor w
    set widgets(mode:to) [checkbutton [$mode_tf getframe].to \
                                -text "To" \
                                -variable Apol_Analysis_relabel::vals(mode:to)]
    $widgets(mode:to) configure -command \
        [list Apol_Analysis_relabel::toggleToFromPushed $widgets(mode:to)]
    set widgets(mode:from) [checkbutton [$mode_tf getframe].from \
                                -text "From" \
                                -variable Apol_Analysis_relabel::vals(mode:from)]
    $widgets(mode:from) configure -command \
        [list Apol_Analysis_relabel::toggleToFromPushed $widgets(mode:from)]
    pack $widgets(mode:to) $widgets(mode:from) -anchor w -padx 8
    set subject_mode [radiobutton [$mode_tf getframe].subject \
                          -text "Subject Mode" -value "subject" \
                          -variable Apol_Analysis_relabel::vals(mode)]
    pack $subject_mode -anchor w -pady 4
    trace add variable Apol_Analysis_relabel::vals(mode) write \
        Apol_Analysis_relabel::toggleModeSelected

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set l [label [$req_tf getframe].l -textvariable Apol_Analysis_relabel::vals(type:label)]
    pack $l -anchor w
    set widgets(type) [Apol_Widget::makeTypeCombobox [$req_tf getframe].type]
    pack $widgets(type)

    set filter_tf [TitleFrame $options_frame.filter -text "Optional Result Filters:"]
    pack $filter_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    set widgets(regexp) [Apol_Widget::makeRegexpEntry [$filter_tf getframe].end]
    $widgets(regexp).cb configure -text "Filter result types using regular expression"
    pack $widgets(regexp) -anchor nw
    set advanced [button [$filter_tf getframe].adv -text "Advanced Filters"]
    pack $advanced -pady 4 -anchor w
}

proc Apol_Analysis_relabel::newAnalysis {} {
    if {[set rt [checkParams]] != {}} {
        return $rt
    }
    if {[catch {analyze} results]} {
        return $results
    }
    set f [createResultsDisplay]
    if {[catch {renderResults $f $results} rt]} {
        Apol_Analysis::deleteCurrentResults
        return $rt
    }
    return {}
}

proc Apol_Analysis_relabel::updateAnalysis {f} {
    if {[set rt [checkParams]] != {}} {
        return $rt
    }
    if {[catch {analyze} results]} {
        return $results
    }
    clearResultsDisplay $f
    if {[catch {renderResults $f $results} rt]} {
        return $rt
    }
    return {}
}

proc Apol_Analysis_relabel::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_relabel::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
}

proc Apol_Analysis_relabel::saveQuery {channel} {
    variable vals
    foreach {key value} [array get vals] {
        puts $channel "$key $value"
    }
}

proc Apol_Analysis_relabel::loadQuery {channel} {
    variable vals
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        set vals($key) $value
    }
}

proc Apol_Analysis_foo::gotoLine {tab line_num} {
}

proc Apol_Analysis_foo::search {tab str case_Insensitive regExpr srch_Direction } {
}


#################### private functions below ####################

proc Apol_Analysis_relabel::reinitializeVals {} {
    variable vals

    array set vals {
        mode object
        mode:to 1
        mode:from 0

        type:label "Starting type"
        type {}

        regexp:enable 0
        regexp {}
    }
}

proc Apol_Analysis_relabel::reinitializeWidgets {} {
    variable vals
    variable widgets

    Apol_Widget::setTypeComboboxValue $widgets(type) $vals(type)
    Apol_Widget::setRegexpEntryValue $widgets(regexp) $vals(regexp:enable) $vals(regexp)
    updateTypeLabel
}

proc Apol_Analysis_relabel::toggleModeSelected {name1 name2 op} {
    variable vals
    variable widgets
    if {$vals(mode) == "object"} {
        $widgets(mode:to) configure -state normal
        $widgets(mode:from) configure -state normal
    } else {
        $widgets(mode:to) configure -state disabled
        $widgets(mode:from) configure -state disabled
    }
    updateTypeLabel
}

# disallow both to and from to be deselected
proc Apol_Analysis_relabel::toggleToFromPushed {cb} {
    variable vals
    if {!$vals(mode:to) && !$vals(mode:from)} {
        $cb select
    }
    updateTypeLabel
}

proc Apol_Analysis_relabel::updateTypeLabel {} {
    variable vals
    if {$vals(mode) == "subject"} {
        set vals(type:label) "Subject"
    } elseif {$vals(mode:to) && $vals(mode:from)} {
        set vals(type:label) "Starting/ending type"
    } elseif {$vals(mode:from)} {
        set vals(type:label) "Ending type"
    } else {
        set vals(type:label) "Starting type"
    }
}


#################### functions that do analyses ####################

proc Apol_Analysis_relabel::checkParams {} {
    variable vals
    variable widgets
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened!"
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(type)]
    if {[lindex $type 0] == {}} {
        return "No type was selected."
    }
    set vals(type) $type
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    if {$use_regexp && $regexp == {}} {
            return "No regular expression provided."
    }
    set vals(regexp:enable) $use_regexp
    set vals(regexp) $regexp
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_relabel::analyze {} {
    variable vals
    if {$vals(mode) == "object"} {
        if {$vals(mode:to) && $vals(mode:from)} {
            set mode "both"
        } elseif {$vals(mode:to)} {
            set mode "to"
        } else {
            set mode "from"
        }
    } else {
        set mode "subject"
    }
    if {$vals(regexp:enable)} {
        set regexp $vals(regexp)
    } else {
        set regexp {}
    }
    apol_RelabelAnalysis $mode $vals(type) $regexp
}

################# functions that control analysis output #################

proc Apol_Analysis_relabel::createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Relabel" [array get vals]]

    if {$vals(mode) == "object"} {
        if {$vals(mode:to) && $vals(mode:from)} {
            set tree_title "Type $vals(type) can be relabeled to/from:"
        } elseif {$vals(mode:to)} {
            set tree_title "Type $vals(type) can be relabeled to:"
        } else {
            set tree_title "Type $vals(type) can be relabeled from:"
        }
    } else {
        set tree_title "Subject $vals(type) can relabel:"
    }
    set tree_tf [TitleFrame $f.left -text $tree_title]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto horizontal]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg white]
    $sw setwidget $tree
    pack $sw -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Relabeling Results"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure num -font {Helvetica 12 bold}
    $res.tb tag configure type_tag -foreground blue -font {Helvetica 12 bold}
    pack $res -expand 1 -fill both

    $tree configure -selectcommand [list Apol_Analysis_relabel::treeSelect $res]
    return $f
}

proc Apol_Analysis_relabel::treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        if {[string index $node 0] == "x"} {
            # a rules node, so treat its data as a set of rule identifiers
            foreach {mode data} [$tree itemcget $node -data] {break}
            if {$mode == "object"} {
                renderResultsRuleObject $res $tree $node $data
            } else {
                renderResultsRuleSubject $res $tree $node $data
            }
        } else {
            # an informational node, whose data has already been rendered
            eval $res.tb insert end [$tree itemcget $node -data]
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_relabel::clearResultsDisplay {f} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_relabel::renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res

    $tree insert end root top -text $vals(type) -open 1 -drawcross auto
    if {$vals(mode) == "object"} {
        set top_text [list foo {}]
    } else {  ;# subject mode
        set top_text [renderResultsSubject $results $res $tree]
    }
    $tree itemconfigure top -data $top_text
    $tree selection set top
    $tree opentree top
    $tree see top
}

proc Apol_Analysis_relabel::renderResultsSubject {results res tree} {
    variable vals
    foreach {to from both} $results {}
    set to_count 0
    set from_count 0

    if {[llength $to] + [llength $both]} {
        $tree insert end top to -text "To" -drawcross auto
        foreach rule [concat $to $both] {
            foreach t [expandTypeSet $rule 2] {
                lappend to_types($t) $rule
            }
        }
        set to_count [llength [array names to_types]]
        foreach type [lsort -index 0 [array names to_types]] {
            $tree insert end to x\#auto -text $type -data [list subject [list to $to_types($type)]]
        }
        set to_text [list $vals(type) title_type " can relabel to " {} ]
        lappend to_text $to_count num \
            " type(s). Open the subtree of this item to view the list of types." {}
        $tree itemconfigure to -data $to_text
    }
    
    if {[llength $from] + [llength $both]} {
        $tree insert end top from -text "From" -drawcross auto
        foreach rule [concat $from $both] {
            foreach t [expandTypeSet $rule 2] {
                lappend from_types($t) $rule
            }
        }
        set from_count [llength [array names from_types]]
        foreach type [lsort -index 0 [array names from_types]] {
            $tree insert end from x\#auto -text $type -data [list subject [list from $from_types($type)]]
        }
        set from_text [list $vals(type) title_type " can relabel from " {} ]
        lappend from_text $from_count num \
            " type(s). Open the subtree of this item to view the list of types." {}
        $tree itemconfigure from -data $from_text
    }

    set top_text [list "Direct Relabel Analysis: Subject: " title]
    lappend top_text $vals(type) title_type \
        "\n\n" title \
        $vals(type) type_tag
    if {$to_count + $from_count} {
        lappend top_text " can relabel to " {} \
            $to_count num \
            " type(s) and relabel from " {} \
            $from_count num \
            " type(s).\n\n" {} \
            "This tab provides the results of a Direct Relabel Analysis for the\n" {} \
            "subject above. The results of the analysis are presented in tree form\n" {} \
            "with the root of the tree (this node) being the starting point for the\n" {} \
            "analysis.\n\n" {} \
            "Each child node in the To and From subtrees represents a type in the\n" {} \
            "current policy which the chosen subject can relabel." {}
    } else {
        lappend top_text " does not relabel to or from any type as a subject." {}
    }
}

proc Apol_Analysis_relabel::renderResultsRuleSubject {res tree node data} {
    foreach {dir rules} $data {break}
    set header [list [$tree itemcget top -text] title_type]
    lappend header " can relabel $dir " {} \
        [$tree itemcget $node -text] type_tag \
        "\n\n" {}
    eval $res.tb insert end $header
    foreach rule $rules {
        foreach {rule_type source_set target_set class perm_default line_num cond_info} [apol_RenderAVRule $rule] {break}
        Apol_Widget::appendSearchResultLine $res 0 $line_num {} $rule_type  "\{ $source_set \}" "\{ $target_set \}" : $class "\{ $perm_default \}"
    }
}

proc Apol_Analysis_relabel::expandTypeSet {rule_num pos} {
    set orig_type_set [lindex [apol_RenderAVRule $rule_num] $pos]
    set exp_type_set {}
    foreach t $orig_type_set {
        set exp_type_set [concat $exp_type_set [lindex [apol_GetAttribs $t] 0 1]]
    }
    if {$exp_type_set != {}} {
        return [lsort -unique $exp_type_set]
    } else {
        return $orig_type_set
    }
}

proc Apol_Analysis_relabel::old_analysis {} {
 
    # collate user options into a single relabel analysis query    
	variable widget_vars
	variable most_recent_results
	
	# If the advanced options object doesn't exist, then create it.
	if {![array exists widget_vars] || [array names widget_vars "$advanced_filter_Dlg,name"] == ""} {
		Apol_Analysis_relabel::adv_options_create_object $advanced_filter_Dlg
	} 
		
	foreach class $widget_vars($advanced_filter_Dlg,incl_class_list) {
		lappend objs_list $class 
	}
	foreach subj $widget_vars($advanced_filter_Dlg,master_excl_subj_list) {
		lappend subj_list $subj
	}

	if {$objs_list == ""} {
		tk_messageBox -icon error -type ok \
		    -title "Relabel Analysis Error" \
		    -message "You cannot exclude all object classes in the filter!"
		return -code error
	}

	if {[llength $widget_vars($advanced_filter_Dlg,master_incl_subj_list)] == 0} {
		tk_messageBox -icon error -type ok \
		    -title "Relabel Analysis Error" \
		    -message "You cannot exclude all subject types in the filter!"
		return -code error
	}
	
	
	if [catch {apol_RelabelAnalysis $widget_vars(start_type) $mode $objs_list \
		$subj_list $widget_vars(endtype_sel) $widget_vars(end_type)} results] {
		tk_messageBox -icon error -type ok \
		    -title "Relabel Analysis Error" -message $results
		return -code error
	}
	set most_recent_results $results
	Apol_Analysis_relabel::create_widgets_to_display_results $results $results_frame
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_destroy_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_destroy_dialog {path_name} {

    	if {[winfo exists $path_name]} {	
    		destroy $path_name	 
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_refresh_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_refresh_dialog {path_name} {  
	if {[array exists widget_vars] && \
	    [array names widget_vars "$path_name,name"] != ""} { 
		Apol_Analysis_relabel::adv_options_destroy_object $path_name	
		Apol_Analysis_relabel::adv_options_create_object $path_name	
		Apol_Analysis_relabel::adv_options_update_dialog $path_name
	}
	
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_update_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_update_dialog {path_name} {
	variable widget_vars
			
	# If the advanced filters dialog is displayed, then we need to update its' state.
	if {[array exists widget_vars] && \
	    [array names widget_vars "$path_name,name"] != "" &&
	    [winfo exists $widget_vars($path_name,name)]} {
		set rt [catch {Apol_Analysis_relabel::adv_options_set_widgets_to_default_state \
			$path_name} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
		raise $widget_vars($path_name,name)
		focus -force $widget_vars($path_name,name)
	} 

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select
#`	-  This proc also searches a class string for the sequence " (Excluded)"
# 	   in order to process the class name only. 
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select {path_name} {
	variable widget_vars 
	variable widgets 
	
	set num_excluded 0	
	# There may be multiple selected items, but we need the object class that is 
	# currently displayed in the text box. We have this index stored in our global 
	# class_selected_idx variable.
	if {$widget_vars($path_name,class_selected_idx) != "-1"} {
		set class_sel [$widgets($path_name,class_incl_lb) get \
			$widget_vars($path_name,class_selected_idx)]
		set idx [string first $Apol_Analysis_relabel::excluded_tag $class_sel]
		if {$idx != -1} {
			set class_sel [string range $class_sel 0 [expr $idx - 1]]
		}
		set class_elements [array get widget_vars "$path_name,perm_status_array,$class_sel,*"]
		if {$class_elements != ""} {
			set num_perms_for_class [expr {[llength $class_elements] / 2}]
			for {set i 0} {$i < [llength $class_elements]} {incr i} {
				incr i
				if {[string equal [lindex $class_elements $i] "exclude"]} {
					incr num_excluded	
				}
			}
			set items [$widgets($path_name,class_incl_lb) get 0 end]
			# If the total all permissions for the object have been 
			# excluded then inform the user. 
			if {$num_excluded == $num_perms_for_class} {
				$widgets($path_name,class_incl_lb) itemconfigure \
					$widget_vars($path_name,class_selected_idx) \
					-foreground gray
				set [$widgets($path_name,class_incl_lb) cget -listvar] \
					[lreplace $items $widget_vars($path_name,class_selected_idx) \
					$widget_vars($path_name,class_selected_idx) \
					"$class_sel$Apol_Analysis_relabel::excluded_tag"]
			} else {
				$widgets($path_name,class_incl_lb) itemconfigure \
					$widget_vars($path_name,class_selected_idx) \
					-foreground $widget_vars($path_name,select_fg_orig)
				set [$widgets($path_name,class_incl_lb) cget -listvar] \
					[lreplace $items $widget_vars($path_name,class_selected_idx) \
					$widget_vars($path_name,class_selected_idx) \
					"$class_sel"]
			}
  			$widget_vars($path_name,permissions_title_frame) configure \
  				-text "Permissions for [$widgets($path_name,class_incl_lb) get \
  					$widget_vars($path_name,class_selected_idx)]:"
		}
	}
	
	return 0	
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_relabel::adv_options_embed_perm_buttons 
#	- Embeds include/exclude radiobuttons in the permissions textbox next to
#	  each permission label.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_embed_perm_buttons {list_b class perm path_name} {
	variable widget_vars
	
 	# Frames
	set frame [frame $list_b.f:$class:$perm -bd 0 -bg white]
	set lbl_frame [frame $frame.lbl_frame:$class:$perm -width 20 -bd 1 -bg white]
	set cb_frame [frame $frame.cb_frame:$class:$perm -width 10 -bd 0 -bg white]
	
	# Label
	set lbl1 [label $lbl_frame.lbl1:$class:$perm -bg white -justify left -width 20  \
			-anchor nw -text $perm] 
	set lbl2 [label $lbl_frame.lbl2:$class:$perm -bg white -justify left -width 5 -text "--->"]
	
	# Radiobuttons. Here we are embedding selinux and mls permissions into the pathname 
	# in order to make them unique radiobuttons.
	set cb_include [radiobutton $cb_frame.cb_include:$class:$perm -bg white \
		-value include -text "Include" \
		-highlightthickness 0 \
		-variable Apol_Analysis_relabel::widget_vars($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select \
			$path_name"]	
	set cb_exclude [radiobutton $cb_frame.cb_exclude:$class:$perm -bg white \
		-value exclude -text "Exclude" \
		-highlightthickness 0 \
		-variable Apol_Analysis_relabel::widget_vars($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select \
			$path_name"]
	
	# Placing widgets
	pack $frame -side left -anchor nw -expand yes -pady 10
	pack $lbl_frame $cb_frame -side left -anchor nw -expand yes
	pack $lbl1 $lbl2 -side left -anchor nw
	pack $cb_include $cb_exclude -side left -anchor nw
	
	# Return the pathname of the frame to embed.
 	return $frame
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_relabel::adv_options_clear_perms_text 
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_clear_perms_text {path_name} {
	variable widget_vars
	
	# Enable the text widget. 
	$widget_vars($path_name,perms_box) configure -state normal
	# Clear the text widget and any embedded windows
	set names [$widget_vars($path_name,perms_box) window names]
	foreach emb_win $names {
		if { [winfo exists $emb_win] } {
			set rt [catch {destroy $emb_win} err]
			if {$rt != 0} {
				tk_messageBox \
					-icon error \
					-type ok \
					-title "Error" \
					-message "$err"
				return -1
			}
		}
	}
	$widget_vars($path_name,perms_box) delete 1.0 end
	return 0
}

proc Apol_Analysis_relabel::render_permissions {path_name} {
	variable widget_vars
	variable widgets 
	
	set class_idx [$widgets($path_name,class_incl_lb) curselection]
	if {$class_idx == ""} {
		# Something was simply deselected.
		return 0
	} 
	focus -force $widgets($path_name,class_incl_lb)
	set class_name [$widgets($path_name,class_incl_lb) get $class_idx]
	$widget_vars($path_name,permissions_title_frame) configure -text "Permissions for $class_name:"
	Apol_Analysis_relabel::adv_options_clear_perms_text $path_name
	update
	# Make sure to strip out just the class name, as this may be an excluded class.
	set idx [string first $Apol_Analysis_relabel::excluded_tag $class_name]
	if {$idx != -1} {
		set class_name [string range $class_name 0 [expr $idx - 1]]
	}
	# Get all valid permissions for the selected class from the policy database.
	set rt [catch {set perms_list [apol_GetPermsByClass $class_name 1]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return -1
	}
	set perms_list [lsort $perms_list]

	foreach perm $perms_list { 
		# If this permission does not exist in our perm status array, this means
		# that a saved query was loaded and the permefined in the policy
		# is not defined in the saved query. So we default this to be included.
		if {[array names widget_vars "$path_name,perm_status_array,$class_name,$perm"] == ""} {
			set widget_vars($path_name,perm_status_array,$class_name,$perm) include
		}
		$widget_vars($path_name,perms_box) window create end -window \
			[Apol_Analysis_relabel::adv_options_embed_perm_buttons \
			$widget_vars($path_name,perms_box) $class_name $perm $path_name] 
		$widget_vars($path_name,perms_box) insert end "\n"
	}
	# Disable the text widget. 
	$widget_vars($path_name,perms_box) configure -state disabled
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_relabel::adv_options_display_permissions 
# 	- Displays permissions for the selected object class in the permissions 
#	  text box.
#	- Takes the selected object class index as the only argument. 
#	  This proc also searches the class string for the sequence " (Excluded)"
# 	  in order to process the class name only. This is because a Tk listbox
# 	  is being used and does not provide a -text option for items in the 
# 	  listbox.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_display_permissions {path_name} {
	variable widget_vars
	variable widgets 
	
	if {[$widgets($path_name,class_incl_lb) get 0 end] == "" || \
		[llength [$widgets($path_name,class_incl_lb) curselection]] > 1} {
		# Nothing in the listbox; return
		return 0
	}
	bind $widgets($path_name,class_incl_lb) <<ListboxSelect>> ""
	set widget_vars($path_name,class_selected_idx) [$widgets($path_name,class_incl_lb) curselection]]
	Apol_Analysis_relabel::render_permissions $path_name
	update idletasks
	bind $widgets($path_name,class_incl_lb) <<ListboxSelect>> "Apol_Analysis_dta::forward_options_display_permissions $path_name"
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_set_widgets_to_default_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_set_widgets_to_default_state {path_name} {
	variable widget_vars
	variable widgets
	
	$widgets($path_name,incl_cmb) configure -values $Apol_Types::attriblist
	$widgets($path_name,excl_cmb) configure -values $Apol_Types::attriblist
	$widgets($path_name,incl_cmb) configure -text $Apol_Analysis_relabel::widget_vars($path_name,incl_attrib)
	$widgets($path_name,excl_cmb) configure -text $Apol_Analysis_relabel::widget_vars($path_name,excl_attrib)
	set widget_vars($path_name,select_fg_orig) [$widgets($path_name,class_incl_lb) cget -foreground]
        set class_lbox_idx 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_initialize_objs_and_perm_filters
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_initialize_objs_and_perm_filters {path_name} {
	variable widget_vars
	 
	set Apol_Analysis_relabel::widget_vars($path_name,excl_class_list) ""
	set tmp_list ""
	# Initialization for object classes section
	foreach class $Apol_Class_Perms::class_list {
		set rt [catch {set perms_list [apol_GetPermsByClass $class 1]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
		# Filter out object classes that do not have relabelto/relabelfrom permission
		set idx1 [lsearch -exact $perms_list $Apol_Analysis_relabel::relabelto_perm]
		set idx2 [lsearch -exact $perms_list $Apol_Analysis_relabel::relabelfrom_perm]
		if {$idx1 == -1 && $idx2 == -1} {
			continue
		}
#		foreach perm $perms_list {
#			set widget_vars($path_name,perm_status_array,$class,$perm) include
#		}
		set tmp_list [lappend tmp_list $class]
	}

	set Apol_Analysis_relabel::widget_vars($path_name,filter_incl_subj) 0
	set Apol_Analysis_relabel::widget_vars($path_name,filter_excl_subj) 0
	set Apol_Analysis_relabel::widget_vars($path_name,incl_class_list) $tmp_list
	set Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) ""
	set Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) ""
	set Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) ""
	set Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) ""
	foreach type_id $Apol_Types::typelist {
		if {$type_id != "self"} {
			lappend Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) $type_id
			lappend Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) $type_id
		}
	}
	set Apol_Analysis_relabel::widget_vars($path_name,incl_attrib) ""
	set Apol_Analysis_relabel::widget_vars($path_name,excl_attrib) ""

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_create_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_create_object {path_name} {
	variable widget_vars
	variable widgets
	
	set widget_vars($path_name,name) 			$path_name
	set widget_vars($path_name,class_selected_idx) 	-1
	set widget_vars($path_name,filter_vars_init) 1
	# Initialize all object classes/permissions and related information to default values
	Apol_Analysis_relabel::adv_options_initialize_objs_and_perm_filters $path_name

}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_copy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_copy_object {path_name new_object} {
	variable widget_vars
	upvar 1 $new_object object 
	
	if {![array exists widget_vars] || [array names widget_vars "$path_name,name"] == ""} {
		Apol_Analysis_relabel::adv_options_create_object $path_name
	}
	array set object [array get widget_vars "$path_name,*"]
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_destroy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_destroy_object {path_name} { 
	variable widget_vars
	
	if {[array exists widget_vars] && [array names widget_vars "$path_name,name"] != ""} {
		array unset widget_vars "$path_name,*"
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_incl_excl_classes
#	- path_name - name of the object
#	- remove_list - the list displayed inside the listbox from which the 
#			type is being removed.
#	- add_list - the list displayed inside the listbox to which the type 
#		     being added. 
#	- remove_lbox - listbox widget from which the type is being removed.
#	- add_lbox - listbox widget to which the type is being added.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_incl_excl_classes {path_name remove_list_1 \
							    	add_list_1 \
							    	remove_lbox \
							    	add_lbox } {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	
	set obj_indices [$remove_lbox curselection]		
	if {$obj_indices != ""} {
		set tmp_list ""
		foreach idx $obj_indices {
			set tmp_list [lappend tmp_list [$remove_lbox get $idx]]	
		}
		foreach class $tmp_list {
			set idx  [lsearch -exact $remove_list $class]
			if {$idx != -1} {
				set remove_list [lreplace $remove_list $idx $idx]
				# put in add list
				set add_list [lappend add_list $class]
				set add_list [lsort $add_list]
			} 
		} 
		$remove_lbox selection clear 0 end
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_incl_excl_types
#	- path_name - name of the object
#	- remove_list - the list displayed inside the listbox from which the 
#			type is being removed.
#	- add_list - the list displayed inside the listbox to which the type 
#		     being added. 
#	- remove_lbox - listbox widget from which the type is being removed.
#	- add_lbox - listbox widget to which the type is being added.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_incl_excl_types {path_name remove_list_1 \
							    	add_list_1 \
							    	remove_lbox \
							    	add_lbox \
								master_remove_list_1\
								master_add_list_1} {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	upvar #0 $master_remove_list_1 master_remove_list
	upvar #0 $master_add_list_1 master_add_list
	
	set subj_indices [$remove_lbox curselection]		
	if {$subj_indices != ""} {
		set tmp_list ""
		foreach idx $subj_indices {
			set tmp_list [lappend tmp_list [$remove_lbox get $idx]]	
		}
		foreach type $tmp_list {
			set idx  [lsearch -exact $remove_list $type]
			if {$idx != -1} {
				set remove_list [lreplace $remove_list $idx $idx]
				# put in add list
				set add_list [lappend add_list $type]
				set add_list [lsort $add_list]
			} 
			# set master list as well
			set idx  [lsearch -exact $master_remove_list $type]
			if {$idx != -1} {
				set master_remove_list [lreplace $master_remove_list $idx $idx]
				# put in add list
				set master_add_list [lappend master_add_list $type]
				set master_add_list [lsort $master_add_list]
			} 
		} 
		$remove_lbox selection clear 0 end
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_filter_list_by_attrib
#	filter_list_1 - list to be filtered
#	master_list_1 - master (unfiltered) list
#	attrib_1 - attribute to filter by
#	lbox - the list box to change
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_filter_list_by_attrib {filter_list_1 master_list_1 attrib_1 lbox} {
	upvar #0 $filter_list_1 filter_list
	if {$master_list_1 != ""} {
		upvar #0 $master_list_1 master_list
	} else { 
		set master_list ""
	}
	if {$attrib_1 != ""} {
		upvar $attrib_1 attrib
	} else {
		set attrib ""
	}

	if {$attrib != ""} {
            set attrib_types [lindex [apol_GetAttribs] 0 1]
		if {$master_list != ""} {
			$lbox delete 0 end
			foreach subj $master_list {
				set idx [lsearch -exact $attrib_types $subj]
				if {$idx != -1} {
					$lbox insert end $subj
				}
			}
		}
	} else {
		if {$master_list != ""} {
			$lbox delete 0 end
			foreach subj $master_list {
				$lbox insert end $subj
			}
		}
	}

}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_objtions_config_combo
#
#
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_objtions_config_combo {combo_box checkboxval which_list path_name} {
	upvar #0 $checkboxval checkbox_val
	set empty_attrib ""
	if {$checkbox_val} {
		$combo_box configure -state normal -entrybg white
		if {$which_list == "incl"} {
			Apol_Analysis_relabel::adv_options_filter_list_by_attrib \
				Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) \
				Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) \
				Apol_Analysis_relabel::widget_vars($path_name,incl_attrib) \
				$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb) 
		} else {
			Apol_Analysis_relabel::adv_options_filter_list_by_attrib \
				Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) \
				Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) \
				Apol_Analysis_relabel::widget_vars($path_name,excl_attrib) \
				$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb) 
		}
	} else {
		$combo_box configure -state disabled -entrybg $ApolTop::default_bg_color
		if {$which_list == "incl"} {
			if {$Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) != ""} {
				$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb) delete 0 end
				foreach subj \
				$Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) {
					$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb) \
						insert end $subj
				}
			}
		} else {
			if {$Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) != ""} {
				$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb) delete 0 end
				foreach subj \
				$Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) {
					$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb) \
						insert end $subj
				}
			}
		}
	}
}



# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_create_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_create_dialog {path_name title_txt} {
	variable widget_vars 
	variable widgets
	
	if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -1
        } 
       	
	# Check to see if object already exists.
	if {[array exists widget_vars] && \
	    [array names widget_vars "$path_name,name"] != ""} {
	    	# Check to see if the dialog already exists.
	    	if {[winfo exists $widget_vars($path_name,name)]} {
		    	raise $widget_vars($path_name,name)
		    	focus $widget_vars($path_name,name)
	    		return 0
	    	} 
	    	# else we need to display the dialog with the correct object settings
    	} else {
	    	# Create a new options dialog object
    		Apol_Analysis_relabel::adv_options_create_object $path_name
    	}	
   	
    	# Create the top-level dialog and subordinate widgets
    	toplevel $widget_vars($path_name,name) 
     	wm withdraw $widget_vars($path_name,name)	
    	wm title $widget_vars($path_name,name) $title_txt 
	wm protocol $widget_vars($path_name,name) WM_DELETE_WINDOW  " "
    	    	   	
   	set close_frame [frame $widget_vars($path_name,name).close_frame -relief sunken -bd 1]
   	set topf  [frame $widget_vars($path_name,name).topf]
        pack $close_frame -side bottom -anchor center -pady 2
        pack $topf -fill both -expand yes -padx 10 -pady 10
        
   	# Main Titleframe
   	set label_frame [frame $topf.label_frame]
   	set objs_frame  [TitleFrame $topf.objs_frame -text "Filter by object classes:"]
	set subj_frame  [TitleFrame $topf.subj_frame -text "Filter by subject type:"]
        
        set top_lbl [Label $label_frame.top_lbl -justify left -font $ApolTop::dialog_font \
        	-text "NOTE: The following list of object classes has been filtered to include \
        	only object classes which have both 'relabelto' and 'relabelfrom' permission."]
        # Widgets for object classes frame
        set search_pane [frame [$objs_frame getframe].search_pane]
        set button_f [frame [$objs_frame getframe].button_f]
        set class_pane 	[frame [$objs_frame getframe].class_pane]
	set subj_pane [frame [$subj_frame getframe].subj_pane]
	set search_pane2 [frame [$subj_frame getframe].search_pane2]
	set button_f2 [frame [$subj_frame getframe].button_f2]
	set obj_incl_butn_f [frame [$objs_frame getframe].obj_incl_butn_f]
	set obj_excl_butn_f [frame [$objs_frame getframe].obj_excl_butn_f]
	set subj_incl_butn_f [frame [$subj_frame getframe].subj_incl_butn_f]
	set subj_excl_butn_f [frame [$subj_frame getframe].subj_excl_butn_f]
	set attrib_incl_f [frame [$subj_frame getframe].attrib_incl_f]
	set attrib_excl_f [frame [$subj_frame getframe].attrib_excl_f]

        set incl_classes_box [TitleFrame $class_pane.tbox \
        	-text "Included Object Classes:" -bd 0]
        set excl_classes_box [TitleFrame $search_pane.rbox \
        	-text "Excluded Object Classes:" -bd 0]
	set incl_subj_box [TitleFrame $subj_pane.tbox2 \
		-text "Included Subject Types:" -bd 0]
	set excl_subj_box [TitleFrame $search_pane2.rbox2 \
		-text "Excluded Subject Types:" -bd 0]
        
        set sw_incl_class [ScrolledWindow [$incl_classes_box getframe].sw_incl_class -auto none]
        set widgets($path_name,class_incl_lb) [listbox [$sw_incl_class getframe].lb1 \
        	-height 10 -highlightthickness 0 \
        	-bg white -selectmode extended \
        	-listvar Apol_Analysis_relabel::widget_vars($path_name,incl_class_list) \
        	-exportselection 0]
        $sw_incl_class setwidget $widgets($path_name,class_incl_lb)  
      	     	
	set sw_excl_class [ScrolledWindow [$excl_classes_box getframe].sw_excl_class  -auto none]
	set widgets($path_name,class_excl_lb) [listbox [$sw_excl_class getframe].lb2 \
        	-height 10 -highlightthickness 0 \
        	-bg white -selectmode extended \
        	-listvar Apol_Analysis_relabel::widget_vars($path_name,excl_class_list) \
        	-exportselection 0]
	$sw_excl_class setwidget $widgets($path_name,class_excl_lb)

	set sw_incl_subj [ScrolledWindow [$incl_subj_box getframe].sw_incl_subj -auto none]
	set widgets($path_name,subj_incl_lb) [listbox [$sw_incl_subj getframe].lb3 \
		-height 10 -highlightthickness 0 \
		-bg white -selectmode extended \
		-listvar Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) \
		-exportselection 0]
	if {$widget_vars(mode) == "subject"} {
		$widgets($path_name,subj_incl_lb) configure -state disabled
	}
	$sw_incl_subj setwidget $widgets($path_name,subj_incl_lb)

	set sw_excl_subj [ScrolledWindow [$excl_subj_box getframe].sw_excl_subj -auto none]
	set widgets($path_name,subj_excl_lb) [listbox [$sw_excl_subj getframe].lb4 \
		-height 10 -highlightthickness 0 \
		-bg white -selectmode extended \
		-listvar Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) \
		-exportselection 0]
	if {$widget_vars(mode) == "subject"} {
		$widgets($path_name,subj_excl_lb) configure -state disabled
	}
	$sw_excl_subj setwidget $widgets($path_name,subj_excl_lb)

	set attrib_incl_cbox [ComboBox $attrib_incl_f.attrib_incl_cbox -editable 1 \
		-entrybg white -width 16 -state disabled -autopost 1 \
		-textvariable Apol_Analysis_relabel::widget_vars($path_name,incl_attrib) \
		-modifycmd "Apol_Analysis_relabel::adv_options_filter_list_by_attrib \
			Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,incl_attrib) \
			$widgets($path_name,subj_incl_lb)"]
	if {$Apol_Analysis_relabel::widget_vars($path_name,filter_incl_subj)} {
		$attrib_incl_cbox configure -state normal
	}

	set attrib_excl_cbox [ComboBox $attrib_excl_f.attrib_excl_cbox -editable 1 \
		-entrybg white -width 16 -state disabled -autopost 1 \
		-textvariable Apol_Analysis_relabel::widget_vars($path_name,excl_attrib) \
		-modifycmd "Apol_Analysis_relabel::adv_options_filter_list_by_attrib \
			Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,excl_attrib) \
			$widgets($path_name,subj_excl_lb)"]

	if {$Apol_Analysis_relabel::widget_vars($path_name,filter_excl_subj)} {
		$attrib_excl_cbox configure -state normal
	}

	set cb_incl_attrib_filter [checkbutton $attrib_incl_f.cb_incl_attrib_filter  \
		-text "Filter included subject types by attribute" -offvalue 0 -onvalue 1 \
		-variable Apol_Analysis_relabel::widget_vars($path_name,filter_incl_subj) \
		-command "Apol_Analysis_relabel::adv_objtions_config_combo \
			$attrib_incl_cbox \
			Apol_Analysis_relabel::widget_vars($path_name,filter_incl_subj) \
			incl $path_name"]
	set cb_excl_attrib_filter [checkbutton $attrib_excl_f.cb_excl_attrib_filter  \
		-text "Filter excluded subject types by attribute" -offvalue 0 -onvalue 1 \
		-variable Apol_Analysis_relabel::widget_vars($path_name,filter_excl_subj) \
		-command "Apol_Analysis_relabel::adv_objtions_config_combo \
			$attrib_excl_cbox \
			Apol_Analysis_relabel::widget_vars($path_name,filter_excl_subj) \
			excl $path_name"]
	set widgets($path_name,incl_cmb) $attrib_incl_cbox
	set widgets($path_name,excl_cmb) $attrib_excl_cbox

	set b_incl_classes [Button $button_f.b_incl_classes -text "<--"  \
		-helptext "Include the selected object classes in the results." \
		-command "Apol_Analysis_relabel::adv_options_incl_excl_classes \
			$path_name \
			Apol_Analysis_relabel::widget_vars($path_name,excl_class_list) \
			Apol_Analysis_relabel::widget_vars($path_name,incl_class_list) \
			$Apol_Analysis_relabel::widgets($path_name,class_excl_lb) \
			$Apol_Analysis_relabel::widgets($path_name,class_incl_lb)"]
	set b_excl_classes [Button $button_f.b_excl_classes -text "-->" \
		-helptext "Exclude the selected object classes from the results." \
		-command "Apol_Analysis_relabel::adv_options_incl_excl_classes \
			$path_name \
			Apol_Analysis_relabel::widget_vars($path_name,incl_class_list)  \
			Apol_Analysis_relabel::widget_vars($path_name,excl_class_list) \
			$Apol_Analysis_relabel::widgets($path_name,class_incl_lb) \
			$Apol_Analysis_relabel::widgets($path_name,class_excl_lb)"]
	set b_incl_subj [Button $button_f2.b_incl_subj -text "<--" \
		-helptext "Include the selected subject types in the results." \
		-command "Apol_Analysis_relabel::adv_options_incl_excl_types \
			$path_name \
			Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) \
			$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb) \
			$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb) \
			Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list)"]
	set b_excl_subj [Button $button_f2.b_excl_subj -text "-->" \
		-helptext "Exclude the selected subject types from the results." \
		-command "Apol_Analysis_relabel::adv_options_incl_excl_types \
			$path_name \
			Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list)  \
			Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) \
			$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb) \
			$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb) \
			Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list)  \
			Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list)"]
	set b_incl_subj_sel_all [Button $subj_incl_butn_f.b_incl_subj_sel_all \
		 -text "Select All" \
		-command "Apol_Analysis_relabel::select_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb)"]
	set b_excl_subj_sel_all [Button $subj_excl_butn_f.b_excl_subj_sel_all \
		-text "Select All" \
		-command "Apol_Analysis_relabel::select_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb)"]
	set b_incl_obj_sel_all [Button $obj_incl_butn_f.b_incl_obj_sel_all \
		-text "Select All" \
		-command "Apol_Analysis_relabel::select_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,class_incl_lb)"]
	set b_excl_obj_sel_all [Button $obj_excl_butn_f.b_excl_obj_sel_all \
		-text "Select All" \
		-command "Apol_Analysis_relabel::select_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,class_excl_lb)"]
	set b_incl_subj_clear_all [Button $subj_incl_butn_f.b_incl_subj_clear_all \
		-text "Unselect" \
		-command "Apol_Analysis_relabel::clear_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,subj_incl_lb)"]
	set b_excl_subj_clear_all [Button $subj_excl_butn_f.b_excl_subj_clear_all \
		-text "Unselect" \
		-command "Apol_Analysis_relabel::clear_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,subj_excl_lb)"]
	set b_incl_obj_clear_all [Button $obj_incl_butn_f.b_incl_obj_clear_all \
		-text "Unselect" \
		-command "Apol_Analysis_relabel::clear_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,class_incl_lb)"]
	set b_excl_obj_clear_all [Button $obj_excl_butn_f.b_excl_obj_clear_all \
		-text "Unselect" \
		-command "Apol_Analysis_relabel::clear_all_lbox_items \
			$Apol_Analysis_relabel::widgets($path_name,class_excl_lb)"]

	if {$widget_vars(mode) == "subject"} {
		$subj_frame configure -state disabled
		$b_incl_subj_clear_all configure -state disabled
		$b_excl_subj_clear_all configure -state disabled
		$b_incl_subj_sel_all configure -state disabled
		$b_excl_subj_sel_all configure -state disabled
		$cb_incl_attrib_filter configure -state disabled
		$cb_excl_attrib_filter configure -state disabled
		$attrib_incl_cbox configure -state disabled
		$attrib_excl_cbox configure -state disabled
		$b_incl_subj configure -state disabled
		$b_excl_subj configure -state disabled
		$incl_subj_box configure -state disabled
		$excl_subj_box configure -state disabled
	}
	
        pack $b_excl_classes $b_incl_classes -side top -anchor nw -pady 2 -fill x
	pack $b_excl_subj $b_incl_subj -side top -anchor nw -pady 2 -fill x
	pack $b_incl_subj_sel_all $b_incl_subj_clear_all -side left -anchor nw -padx 4 -fill x 
	pack $b_excl_subj_sel_all $b_excl_subj_clear_all -side left -anchor nw -pady 2 -fill x
	pack $b_incl_obj_sel_all $b_incl_obj_clear_all -side left -anchor nw -pady 2 -fill x
	pack $b_excl_obj_sel_all $b_excl_obj_clear_all -side left -anchor nw -pady 2 -fill x
	pack $cb_incl_attrib_filter $attrib_incl_cbox -side top -padx 2 -pady 2 -anchor nw -fill x
	pack $cb_excl_attrib_filter $attrib_excl_cbox -side top -padx 2 -pady 2 -anchor nw -fill x
	pack $obj_incl_butn_f -in $class_pane -side bottom -padx 5 -pady 2 -expand 0
	pack $obj_excl_butn_f -in $search_pane -side bottom -padx 5 -pady 2 -expand 0
	pack $subj_incl_butn_f -in $subj_pane -side bottom -padx 5 -pady 2 -expand 0
	pack $subj_excl_butn_f -in $search_pane2 -side bottom -padx 5 -pady 2 -expand 0
	pack $attrib_incl_f -in $subj_pane -side bottom -padx 5 -pady 2 -expand 0
	pack $attrib_excl_f -in $search_pane2 -side bottom -padx 5 -pady 2 -expand 0
        pack $class_pane -fill both -expand yes -side left -anchor nw
        pack $subj_pane -fill both -expand yes -side left -anchor nw
        pack $button_f -anchor center -fill x -expand yes -side left -pady 20
	pack $button_f2 -anchor center -fill x -expand yes -side left -pady 20
        pack $sw_incl_class $sw_excl_class -fill both -expand yes -side left -anchor nw 
        pack $sw_incl_subj $sw_excl_subj -fill both -expand yes -side left -anchor nw 
        pack $search_pane -fill both -expand yes -side left -anchor nw
        pack $search_pane2 -fill both -expand yes -side left -anchor nw
        pack $incl_classes_box $excl_classes_box -side left -pady 2 -padx 2 -fill both -expand yes
        pack $incl_subj_box $excl_subj_box -side left -pady 2 -padx 2 -fill both -expand yes
        pack $subj_frame -side bottom -anchor nw -padx 5 -pady 2 -expand yes -fill both 	  
        pack $objs_frame -side bottom -anchor nw -padx 5 -pady 2 -expand yes -fill both 	  
        pack $label_frame -side top -anchor center
        pack $top_lbl -side left -anchor nw -fill x -pady 2 -padx 2
	# Create and pack close button for the dialog
  	set close_bttn [Button $close_frame.close_bttn -text "Close" -width 8 \
		-command "Apol_Analysis_relabel::adv_options_destroy_dialog $path_name"]
	pack $close_bttn -side left -anchor center
					  
        # Configure top-level dialog specifications
        set width 780
	set height 750
	wm geom $widget_vars($path_name,name) ${width}x${height}
	wm deiconify $widget_vars($path_name,name)
	focus $widget_vars($path_name,name)
	
	Apol_Analysis_relabel::adv_options_set_widgets_to_default_state $path_name
	wm protocol $widget_vars($path_name,name) WM_DELETE_WINDOW \
		"Apol_Analysis_relabel::adv_options_destroy_dialog $path_name"
}

