#############################################################
#  relabel_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <jtang@tresys.com>
# -----------------------------------------------------------
#
# This is the implementation of the interface for 
# Relabeling Analysis
##############################################################
# ::Apol_Analysis_relabel module namespace
##############################################################

namespace eval Apol_Analysis_relabel {
    variable VERSION 1
    
    variable info_button_text \
	"Direct relabel analysis is designed to facilitate querying a \
	policy for both potential changes to object labels and relabel \
	privileges granted to a subject. These two modes are respectively \
	called Object Mode and Subject Mode.\n\n \
	OBJECT MODE\n \
	In object mode the user specifies a starting or ending type and \
	either To, From, or Both. When To is selected all types to which \
	the starting type can be relabeled will be displayed. When From \
	is selected all types from which the ending type can be relabeled \
	will be displayed. Both will, obviously, do both analyses.\n\n \
	SUBJECT MODE\n \
	In subject mode the user specifies only a subject type. Two lists \
	of types will be displayed corresponding to all of the types To \
	which the subject can relabel and From which the subject can \
	relabel.\n\n \
	OPTIONAL RESULT FILTERS\n \
	Results may be filtered in several ways. The end types resulting \
	from a query may be filtered by regular expression. The Advanced \
	Filters provide the option of selecting which object classes to \
	include in the analysis and which types to include as subjects \
	of relabeling operations. Note, excluded subjects are ignored in \
	subject mode because only the selected subject type is used as \
	a subject."
    
	variable widget_vars 
	variable widgets
	# name of widget holding most recently executed assertion
	variable most_recent_results 	""
	# Advanced filter dialog widget
	variable advanced_filter_Dlg
	set advanced_filter_Dlg .apol_relabel_advanced_filter_Dlg
	
	variable excluded_tag		" (Excluded)"	

	# defined tag names for output 
	variable title_tag		TITLE
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	variable type_tag		TYPE
	
	# Tree nodes
	variable top_node		TOP_NODE
	
	variable relabelto_perm		"relabelto"
	variable relabelfrom_perm	"relabelfrom"
	
	# Within the namespace command for the module, you must call
	# Apol_Analysis::register_analysis_modules, the first argument is
	# the namespace name of the module, and the second is the
	# descriptive display name you want to be displayed in the GUI
	# selection box.
	Apol_Analysis::register_analysis_modules "Apol_Analysis_relabel" "Direct Relabel"
}

# Apol_Analysis_relabel::initialize is called when the tool first
# starts up.  The analysis has the opportunity to do any additional
# initialization it must do that wasn't done in the initial namespace
# eval command.
proc Apol_Analysis_relabel::initialize { } {
	set widget_vars(mode) "to"
	set widget_vars(to_mode) 1
	set widget_vars(from_mode) 1
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

proc Apol_Analysis_relabel::create_widgets_to_display_results {results results_frame} {
	variable widget_vars
	variable most_recent_results_pw
	
	catch {destroy $results_frame.pw}
	set pw [PanedWindow $results_frame.pw -side top -weights available]
	set most_recent_results_pw $pw
	set lf [$pw add -minsize 150 -weight 1]
	set dtf [TitleFrame $lf.dtf]
	
	if {$widget_vars(mode) == "object"} {
		if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
			set text "Type $widget_vars(start_type) can be relabeled to/from:"
		} elseif {$widget_vars(to_mode)} {
			set text "Type $widget_vars(start_type) can be relabeled to:"
		} else {
			set text "Type $widget_vars(start_type) can be relabeled from:"
		}
	} else {
		set text "Subject $widget_vars(start_type) can relabel:"
	}
	$dtf configure -text $text
	set dsw [ScrolledWindow [$dtf getframe].dsw -auto horizontal]
	set dtree [Tree [$dsw getframe].dtree -relief flat -width 15 \
	           -borderwidth 0  -highlightthickness 0 -redraw 1 \
	           -bg white -showlines 1 -padx 0]
	$dsw setwidget $dtree
	set widget_vars(current_dtree) $dtree
	pack $dsw -expand 1 -fill both
	pack $dtf -expand 1 -fill both -side left
	
	set rf [$pw add -weight 3]
	set rtf [TitleFrame $rf.rtf -text "Relabeling Results"]
	set rsw [ScrolledWindow [$rtf getframe].rsw -auto horizontal]
	set rtext [text $rsw.rtext -wrap none -bg white -font $ApolTop::text_font]
	$rsw setwidget $rtext
	Apol_PolicyConf::configure_HyperLinks $rtext
	set widget_vars(current_rtext) $rtext
	pack $rsw -expand 1 -fill both
	pack $rtf -expand 1 -fill both
	pack $pw -expand 1 -fill both
	
	$dtree insert end root $Apol_Analysis_relabel::top_node \
		-text $widget_vars(start_type) -open 1 \
		-drawcross auto 
				
	# now fill the domain tree with results info
	if {$results == ""} {
		$dtree configure -state disabled
		set start_index 0
		set text_s ""
		$widget_vars(current_rtext) configure -wrap word
		set start_index [string length $text_s]
		append text_s "Direct Relabel Analysis: "
		if {$widget_vars(mode) == "object"} {
			if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append text_s "Starting/Ending Type: "
			} elseif {$widget_vars(to_mode) && !$widget_vars(from_mode)} {
				append text_s "Starting Type: "
			} elseif {!$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append text_s "Ending Type: "
			} else {
				puts "Direction must be to, from, or both for object mode."
				return
			}
		} else {
			append text_s "Subject: "
		}
		set end_index [string length $text_s]
		lappend title_tags $start_index $end_index
		set start_index [string length $text_s]
		append text_s "$widget_vars(start_type)"
		set end_index [string length $text_s]
		lappend title_type_tags $start_index $end_index
		append text_s "\n\n"

		append text_s "$widget_vars(start_type)"
		set end_index [string length $text_s]
		lappend title_type_tags $start_index $end_index
		if {$widget_vars(mode) == "object"} {
			append text_s " cannot be relabeled "
			set start_index [string length $text_s]
			if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append text_s "to/from"
			} elseif {$widget_vars(to_mode)} {
				append text_s "to"
			} else {
				append text_s "from"
			}
			set end_index [string length $text_s]
			lappend subtitle_type_tags $start_index $end_index
			append text_s " any type."
		} else {
			append text_s " does not relabel "
			set start_index [string length $text_s]
			append text_s "to or from"
			set end_index [string length $text_s]
			lappend subtitle_type_tags $start_index $end_index
			append text_s " any type as a subject."
		}
		$rtext insert end $text_s
		foreach {start_index end_index} $title_type_tags {
			$rtext tag add $Apol_Analysis_relabel::title_type_tag \
				"1.0 + $start_index c" "1.0 + $end_index c"
		}
		foreach {start_index end_index} $subtitle_type_tags {
			$rtext tag add $Apol_Analysis_relabel::subtitle_tag \
				"1.0 + $start_index c" "1.0 + $end_index c"
		}
		foreach {start_index end_index} $title_tags {
			$rtext tag add $Apol_Analysis_relabel::title_tag \
				"1.0 + $start_index c" "1.0 + $end_index c"
		}
		Apol_Analysis_relabel::formatInfoText $rtext
	} else {
		$rtext insert end "This tab provides the results of a relabeling analysis."
		if {$widget_vars(mode) == "subject"} {
			$dtree insert end $Apol_Analysis_relabel::top_node TO_LIST \
				-text "To" -open 1 \
				-drawcross auto 
		        $dtree insert end $Apol_Analysis_relabel::top_node FROM_LIST \
		        	-text "From" -open 1 \
				-drawcross auto 
				
			set from_list [lindex $results 0]
			set to_list [lindex $results 1]

			# From list
			foreach datum $from_list {
		            set domain [lindex $datum 0]
		            $dtree insert end FROM_LIST from_list:$domain \
		            	-text $domain -open 1 \
		                -drawcross auto -data [lindex $datum 1]
		        }
			set from_items [lsort -dictionary [$dtree nodes FROM_LIST]]
			$dtree reorder FROM_LIST $from_items
		        # To list
		        foreach datum $to_list {
		        	set domain [lindex $datum 0]
				$dtree insert end TO_LIST to_list:$domain \
					-text $domain -open 1 \
					-drawcross auto -data [lindex $datum 1]
		        }
		        set to_items [lsort -dictionary [$dtree nodes TO_LIST]]
			$dtree reorder TO_LIST $to_items
		        
		        $dtree itemconfigure $Apol_Analysis_relabel::top_node \
				-data [list [llength $from_items] [llength $to_items]]
			$dtree itemconfigure TO_LIST \
				-data [llength $to_items]
			$dtree itemconfigure FROM_LIST \
				-data [llength $from_items]
		} else {
		        foreach result_elem $results {
		            set domain [lindex $result_elem 0]
		            $dtree insert end $Apol_Analysis_relabel::top_node $domain \
		            	-text $domain -open 1 \
		                -drawcross auto -data [lrange $result_elem 1 end]
		        }
		        # Sort types list
		        set items [lsort -dictionary [$dtree nodes $Apol_Analysis_relabel::top_node]]
		        $dtree reorder $Apol_Analysis_relabel::top_node $items
		        $dtree itemconfigure $Apol_Analysis_relabel::top_node \
				-data [llength $items]
		}
        	$dtree configure -selectcommand [namespace code tree_select]
	}
	$dtree selection set $Apol_Analysis_relabel::top_node
	$rtext configure -state disabled
}

# The GUI will call Apol_Analysis_relabel::do_analysis when the
# module is to perform its analysis.  The module should know how to
# get its own option information.  The options are displayed via
# Apol_Analysis_relabel::do_analysis.
proc Apol_Analysis_relabel::do_analysis {results_frame} {
	# collate user options into a single relabel analysis query    
	variable widget_vars
	variable most_recent_results
	variable advanced_filter_Dlg
	
	if {![ApolTop::is_policy_open]} {
		tk_messageBox -icon error -type ok \
		    -title "Relabel Analysis Error" \
		    -message "No current policy file is opened!"
		return -code error
	}
	# convert the object permissions list into Tcl lists
	set objs_list ""
	set subj_list ""
	
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
	
	if {$widget_vars(mode) == "object"} {
		if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
			set mode "both"
		} elseif {$widget_vars(to_mode)} {
			set mode "to"
		} else {
			set mode "from"
		}
	} else {
		set mode "subject"
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

# Apol_Analysis_relabel::close must exist; it is called when a
# policy is closed.  Typically you should reset any context or option
# variables you have.
proc Apol_Analysis_relabel::close { } {
    Apol_Analysis_relabel::set_widgets_to_initial_open_state
}

proc Apol_Analysis_relabel::set_widgets_to_initial_open_state { } {
    Apol_Analysis_relabel::adv_options_destroy_dialog $Apol_Analysis_relabel::advanced_filter_Dlg
    Apol_Analysis_relabel::init_widget_vars
    Apol_Analysis_relabel::init_widget_state
}

# Apol_Analysis_relabel::open must exist; it is called when a
# policy is opened.
proc Apol_Analysis_relabel::open { } {
    Apol_Analysis_relabel::set_widgets_to_initial_open_state
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
    Apol_Analysis_relabel::init_widget_state
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
    Apol_Analysis_relabel::init_widget_state
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
proc Apol_Analysis_relabel::adv_options_copy_object {path_name new_object} {		set rt [catch {set attrib_types [apol_GetAttribTypesList $attribute]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}

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
#  Command Apol_Analysis_relabel::select_all_lbox_items
#	- Takes a Tk listbox widget as an argument.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::select_all_lbox_items {lbox} {
        $lbox selection set 0 end
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::clear_all_lbox_items
#	- Takes a Tk listbox widget as an argument.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::clear_all_lbox_items {lbox} {
        $lbox selection clear 0 end
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

		set rt [catch {set attrib_types [apol_GetAttribTypesList $attrib]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
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
		-entrybg white -width 16 -state disabled -autocomplete 1 \
		-textvariable Apol_Analysis_relabel::widget_vars($path_name,incl_attrib) \
		-modifycmd "Apol_Analysis_relabel::adv_options_filter_list_by_attrib \
			Apol_Analysis_relabel::widget_vars($path_name,incl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,master_incl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,incl_attrib) \
			$widgets($path_name,subj_incl_lb)"]
	bindtags $attrib_incl_cbox.e [linsert [bindtags $attrib_incl_cbox.e] 3 incl_attrib_cb_tag]
	bind incl_attrib_cb_tag <KeyPress> [list ApolTop::_create_popup $attrib_incl_cbox %W %K]

	if {$Apol_Analysis_relabel::widget_vars($path_name,filter_incl_subj)} {
		$attrib_incl_cbox configure -state normal
	}

	set attrib_excl_cbox [ComboBox $attrib_excl_f.attrib_excl_cbox -editable 1 \
		-entrybg white -width 16 -state disabled -autocomplete 1 \
		-textvariable Apol_Analysis_relabel::widget_vars($path_name,excl_attrib) \
		-modifycmd "Apol_Analysis_relabel::adv_options_filter_list_by_attrib \
			Apol_Analysis_relabel::widget_vars($path_name,excl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,master_excl_subj_list) \
			Apol_Analysis_relabel::widget_vars($path_name,excl_attrib) \
			$widgets($path_name,subj_excl_lb)"]
	bindtags $attrib_excl_cbox.e [linsert [bindtags $attrib_excl_cbox.e] 3 excl_attrib_cb_tag]
	bind excl_attrib_cb_tag <KeyPress> [list ApolTop::_create_popup $attrib_excl_cbox %W %K]

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


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::change_types_list {type_cmbox attrib_cmbox clear_type} { 
	upvar #0 [$attrib_cmbox cget -textvariable] attrib
	
	if {$attrib != ""} {
		if {$clear_type} {
			$type_cmbox configure -text ""		   
		}
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $attrib]} err]	
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return
		} 
		set attrib_typesList [lsort $attrib_typesList]
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
		$type_cmbox configure -values $attrib_typesList
        } else {
        	set attrib_typesList $Apol_Types::typelist
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$type_cmbox configure -values $attrib_typesList
        }
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::config_attrib_comboBox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::config_attrib_comboBox_state {checkbttn attrib_cbox type_cbox change_list} { 
	upvar #0 [$checkbttn cget -variable] cb_val
	upvar #0 [$attrib_cbox cget -textvariable] attrib_val
	upvar #0 [$type_cbox cget -textvariable] type_val
	
	if {$cb_val} {
		$attrib_cbox configure -state normal -entrybg white
		if {$change_list} {
			Apol_Analysis_tra::change_types_list $type_cbox $attrib_cbox 1
		}
	} else {
		$attrib_cbox configure -state disabled -entrybg $ApolTop::default_bg_color
		set attrib_typesList $Apol_Types::typelist
        	set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$type_cbox configure -values $attrib_typesList
	}
	
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::config_endtype_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::config_endtype_state {} {
	variable widgets
	variable widget_vars
	
        if {$widget_vars(endtype_sel)} {
	        $widgets(entry_end) configure -state normal -background white
	} else {
	        $widgets(entry_end) configure -state disabled -background $ApolTop::default_bg_color
	}
        return 0
}

proc Apol_Analysis_relabel::init_widget_state { } {
	variable widgets
	variable widget_vars
	
	# set initial widget states
	populate_lists 
	toggle_attributes
	Apol_Analysis_relabel::config_endtype_state
	if {$widget_vars(mode) ==  "object"} {
		set_mode_object
	} else {
		set_mode_subject
	}
}

proc Apol_Analysis_relabel::init_widget_vars { } {
	variable widget_vars
	array unset widget_vars
	
	set widget_vars(mode) 		"object"
	set widget_vars(to_mode) 	1
	set widget_vars(from_mode) 	1
	set widget_vars(endtype_sel) 	0
	set widget_vars(end_type) 	""
	set widget_vars(start_attrib_ch) 0
	set widget_vars(start_attrib)	""
	set widget_vars(start_type)	""
}

# Apol_Analysis_relabel::display_mod_options is called by the GUI to
# display the analysis options interface the analysis needs.  Each
# module must know how to display their own options, as well bind
# appropriate commands and variables with the options GUI.  opts_frame
# is the name of a frame in which the options GUI interface is to be
# packed.
proc Apol_Analysis_relabel::display_mod_options { opts_frame } {    
    variable widgets

    array unset widgets
    Apol_Analysis_relabel::init_widget_vars
    set option_f [frame $opts_frame.option_f]
    set mode_tf [TitleFrame $option_f.mode_tf -text "Mode"]
    set mode_obj_f [frame [$mode_tf getframe].mode_obj_f]
    set mode_subj_f [frame [$mode_tf getframe].mode_subj_f]
    set widgets(objectMode_cb)  [radiobutton $mode_obj_f.objectMode_cb \
                            -text "Object Mode" -value "object" \
                            -variable Apol_Analysis_relabel::widget_vars(mode) \
                            -command [namespace code set_mode_object]]
    set widgets(subjectMode_cb) [radiobutton $mode_subj_f.subjectMode_cb \
                       -text "Subject Mode" -value "subject" \
                       -variable Apol_Analysis_relabel::widget_vars(mode) \
                       -command [namespace code set_mode_subject]]
    set widgets(relabelto_rb) [checkbutton $mode_obj_f.relabelto_rb \
                          -text "To" \
                          -variable Apol_Analysis_relabel::widget_vars(to_mode) \
                          -command [namespace code set_mode_relabelto]]
    set widgets(relabelfrom_rb) [checkbutton $mode_obj_f.relabelfrom_rb \
                            -text "From"  \
                            -variable Apol_Analysis_relabel::widget_vars(from_mode)\
                            -command [namespace code set_mode_relabelfrom]]
   
    set req_tf [TitleFrame $option_f.req_tf -text "Required parameters"]
    set start_f [frame [$req_tf getframe].start_f]
    set attrib_f [frame [$req_tf getframe].attrib_frame]
    set widgets(start_l) [label $start_f.start_l -anchor w]
    set widgets(start_cb) [ComboBox $start_f.start_cb -editable 1 \
                               -entrybg white -width 16 \
                               -textvariable Apol_Analysis_relabel::widget_vars(start_type)]
    bindtags $widgets(start_cb).e [linsert [bindtags $widgets(start_cb).e] 3 start_cb_tag]
    bind start_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_cb) %W %K]
    	
    set widgets(start_attrib_cb) [ComboBox $attrib_f.start_attrib_cb \
                -editable 1 -entrybg white -width 16 -state disabled \
                -vcmd [namespace code [list set_types_list %P]] -validate key \
                -textvariable Apol_Analysis_relabel::widget_vars(start_attrib)]
    $widgets(start_attrib_cb) configure -modifycmd {Apol_Analysis_tra::change_types_list \
			$Apol_Analysis_relabel::widgets(start_cb) $Apol_Analysis_relabel::widgets(start_attrib_cb) 1}  
			
    set widgets(start_attrib_ch) \
        [checkbutton $attrib_f.start_attrib_ch -anchor w -width 36 \
             -variable Apol_Analysis_relabel::widget_vars(start_attrib_ch)]
    $widgets(start_attrib_ch) configure \
		-command "Apol_Analysis_relabel::config_attrib_comboBox_state \
			$widgets(start_attrib_ch) $widgets(start_attrib_cb) $widgets(start_cb) 1"
 
    bindtags $widgets(start_attrib_cb).e [linsert [bindtags $widgets(start_attrib_cb).e] 3 start_attrib_cb_tag]
    bind start_attrib_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_attrib_cb) %W %K]
    
    set filter_f [TitleFrame $option_f.filter_f -text "Optional result filters:"]
    set endtype_frame [frame [$filter_f getframe].endtype_frame]
    set adv_frame [frame [$filter_f getframe].adv_frame]
    set widgets(entry_end) [Entry $endtype_frame.entry_end \
	-helptext "You may enter a regular expression" \
	-editable 1 -state disabled \
	-textvariable Apol_Analysis_relabel::widget_vars(end_type)] 
    set widgets(cb_endtype) [checkbutton $endtype_frame.cb_endtype \
    	-text "Filter end types using regular expression:" \
	-variable Apol_Analysis_relabel::widget_vars(endtype_sel) \
	-command {Apol_Analysis_relabel::config_endtype_state}]
    set widgets(b_adv_options) [button $adv_frame.b_adv_options -text "Advanced Filters" \
		-command {Apol_Analysis_relabel::adv_options_create_dialog \
			$Apol_Analysis_relabel::advanced_filter_Dlg \
			"Direct Relabel Advanced Filters"}]
    
    pack $widgets(objectMode_cb) -anchor w -side top
    pack $widgets(relabelto_rb) $widgets(relabelfrom_rb) -side top -padx 10 -pady 3 -anchor nw
    pack $widgets(subjectMode_cb) -anchor w -side top
    pack $widgets(start_l) $widgets(start_cb) -side top -expand 0 -fill x
    pack $widgets(start_attrib_ch) -expand 0 -fill x
    pack $widgets(start_attrib_cb) -padx 15 -expand 0 -fill x
    pack $widgets(cb_endtype) -side top -anchor nw
    pack $widgets(entry_end) -anchor nw -fill x -expand yes 
    pack $widgets(b_adv_options) -anchor nw 
    pack $start_f -expand 0 -fill x
    pack $attrib_f -pady 20 -expand 0 -fill x
    pack $option_f -fill both -anchor nw -side left -padx 5 -expand 1
    pack $mode_tf $req_tf $filter_f -side left -anchor nw -padx 5 -expand 1 -fill both
    pack $mode_obj_f $mode_subj_f -side top -anchor nw -fill both 
    pack $endtype_frame $adv_frame -side top -anchor nw -fill both -pady 4
    
    Apol_Analysis_relabel::init_widget_state
}


##########################################################################
##########################################################################
## The rest of these procs are not interface procedures, but rather
## internal functions to this analysis.
##########################################################################
##########################################################################

proc Apol_Analysis_relabel::set_mode_relabelto {} {
    variable widgets
    variable widget_vars
  
    if {!$widget_vars(to_mode) && !$widget_vars(from_mode)} {
    	set widget_vars(to_mode) 1
    	return
    } 
    if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
	Apol_Analysis_relabel::set_mode_relabelboth
    } elseif {$widget_vars(to_mode)} {
	$widgets(start_l) configure -text "Starting type:"
	$widgets(start_attrib_ch) configure -text "Filter starting types to select using attribute:"
    } else {
    	Apol_Analysis_relabel::set_mode_relabelfrom
    }
}

proc Apol_Analysis_relabel::set_mode_relabelfrom {} {
    variable widgets
    variable widget_vars
    
    if {!$widget_vars(to_mode) && !$widget_vars(from_mode)} {
    	set widget_vars(from_mode) 1
    	return
    } 
    if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
	Apol_Analysis_relabel::set_mode_relabelboth
    } elseif {$widget_vars(from_mode)} {
	$widgets(start_l) configure -text "Ending type:"
	$widgets(start_attrib_ch) configure -text "Filter ending types to select using attribute:"
    } else {
	Apol_Analysis_relabel::set_mode_relabelto
    }
}

proc Apol_Analysis_relabel::set_mode_relabelboth {} {
    variable widgets
    $widgets(start_l) configure -text "Starting/ending type:"
    $widgets(start_attrib_ch) configure -text "Filter starting/ending types to select using attribute:"
}

proc Apol_Analysis_relabel::set_mode_subject {} {
    variable widgets
    $widgets(start_l) configure -text "Subject:"
    $widgets(start_attrib_ch) configure -text "Filter subjects to select using attribute:"
    $widgets(relabelto_rb) configure -state disabled
    $widgets(relabelfrom_rb) configure -state disabled
}

proc Apol_Analysis_relabel::set_mode_object {} {
    variable widgets
    variable widget_vars
    	  
    $widgets(relabelto_rb) configure -state normal
    $widgets(relabelfrom_rb) configure -state normal
    if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
    	Apol_Analysis_relabel::set_mode_relabelboth
    } elseif {$widget_vars(to_mode) && !$widget_vars(from_mode)} {
    	Apol_Analysis_relabel::set_mode_relabelto
    } else {
    	Apol_Analysis_relabel::set_mode_relabelfrom
    }
}

proc Apol_Analysis_relabel::toggle_attributes {} {
    variable widgets
    variable widget_vars
    if $widget_vars(start_attrib_ch) {
        $widgets(start_attrib_cb) configure -state normal -entrybg white
    } else {
        $widgets(start_attrib_cb) configure -state disabled -entrybg  $ApolTop::default_bg_color
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

# Called to populate the ComboBox/ComboBox/listbox holding the type
# names/attributes/object classes.  This is done in one of three
# places: upon wizard dialog creation, when opening a policy, and when
# closing a policy.
proc Apol_Analysis_relabel::populate_lists {} {
	variable widgets
	variable widget_vars
  
	$widgets(start_cb) configure -values $Apol_Types::typelist
	$widgets(start_attrib_cb) configure -values $Apol_Types::attriblist
	if {[lsearch -exact $Apol_Types::typelist $widget_vars(start_type)] == -1} {
	    set widget_vars(start_type) {}
	}
	if {[lsearch -exact $Apol_Types::attriblist $widget_vars(start_attrib)] == -1} {
	    set widget_vars(start_attrib) {}
	}
}

##########################################################################
# ::formatInfoText
#
proc Apol_Analysis_relabel::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_relabel::title_tag -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_relabel::title_type_tag -foreground blue -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_relabel::subtitle_tag -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_relabel::type_tag -foreground blue -font {Helvetica 12 bold}
}

# Update the Relabeling Results display with whatever the user
# selected
proc Apol_Analysis_relabel::tree_select {widget node} {
	variable widget_vars
	
	if {$node == ""} {
		return
	}
	set data [$widget itemcget $node -data]
	$widget_vars(current_rtext) configure -state normal
	$widget_vars(current_rtext) delete 1.0 end
	
	set title_tags ""
	set subtitle_type_tags ""
	set title_type_tags ""
	set policy_tags_list ""
	set type_tags ""
	set line ""
	set start_index 0
	
	if {$node == $Apol_Analysis_relabel::top_node} {
		$widget_vars(current_rtext) configure -wrap word
		set start_index [string length $line]
		append line "Direct Relabel Analysis: "
		if {$widget_vars(mode) == "object"} {
			if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append line "Starting/Ending Type: "
			} elseif {$widget_vars(to_mode) && !$widget_vars(from_mode)} {
				append line "Starting Type: "
			} elseif {!$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append line "Ending Type: "
			} else {
				puts "Direction must be to, from, or both for object mode."
				return
			}
		} else {
			append line "Subject: "
		}
		set end_index [string length $line]
		lappend title_tags $start_index $end_index
		set start_index [string length $line]
		append line "$widget_vars(start_type)"
		set end_index [string length $line]
		lappend title_type_tags $start_index $end_index
		append line "\n\n"
		set start_index [string length $line]
		append line "$widget_vars(start_type) "
		set end_index [string length $line]
		lappend type_tags $start_index $end_index
		
		if {$widget_vars(mode) == "object"} {
			append line "can be relabeled "
			if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append line "to and from "
			} elseif {$widget_vars(to_mode) && !$widget_vars(from_mode)} {
				append line "to "
			} elseif {!$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append line "from "
			} else {
				puts "Direction must be to, from or both for object mode."
				return
			}
			set start_index [string length $line]
			append line "$data "
			set end_index [string length $line]
			lappend subtitle_type_tags $start_index $end_index
			append line "types.\n\n"
		} else {
			append line "can relabel "
			set start_index [string length $line]
			append line "to [lindex $data 1] "
			set end_index [string length $line]
			lappend subtitle_type_tags $start_index $end_index
			
			append line "type(s) and relabel "
			set start_index [string length $line]
			append line "from [lindex $data 0] "
			set end_index [string length $line]
			lappend subtitle_type_tags $start_index $end_index
			append line "type(s).\n\n"
		}
		append line "This tab provides the results of a Direct Relabel Analysis "
		if {$widget_vars(mode) == "object"} {
			append line "beginning with the "
			if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append line "starting/ending type above. "
			} elseif {$widget_vars(to_mode) && !$widget_vars(from_mode)} {
				append line "starting type above. "
			} elseif {!$widget_vars(to_mode) && $widget_vars(from_mode)} {
				append line "ending type above. "
			} else {
				puts "Direction must be to, from, or both for object mode."
				return
			}
		} else {
			append line "for the subject above. "
		}
		append line "The results of the analysis are presented in tree form with the "
		append line "root of the tree (this node) being the starting point for the analysis.\n\n"
		if {$widget_vars(mode) == "object"} {
			append line "Each child node in the tree represents a type in the current "
			append line "policy to/from which relabeling is allowed "
			append line "(depending on you selection above)."
		} else {
			append line "Each child node in the To and From subtrees represents a type "
			append line "in th current policy which the chosen subject can relabel. "
		}
	} elseif {$widget_vars(mode) == "subject"} {
		$widget_vars(current_rtext) configure -wrap none
		append line "$widget_vars(start_type)"
		set end_index [string length $line]
		lappend title_type_tags $start_index $end_index
		
		append line " can relabel "
		set start_index [string length $line]	
		if {$node == "TO_LIST"} {
			append line "to $data"
			set end_index [string length $line]
			lappend subtitle_type_tags $start_index $end_index
			append line " type(s). Open the subtree of this item to view the list of types."
		} elseif {$node == "FROM_LIST"} {
			append line "from $data"
			set end_index [string length $line]
			lappend subtitle_type_tags $start_index $end_index
			append line " type(s). Open the subtree of this item to view the list of types."
		} else {
			set parent [$widget parent $node]
			if {$parent == "TO_LIST"} {
				append line "to"
				set id_end [string length "to_list:"]
			} else {
				append line "from"
				set id_end [string length "from_list:"]
			}
			set node_str [string range $node $id_end end]
			set end_index [string length $line]
			lappend subtitle_type_tags $start_index $end_index
				
			set start_index [string length $line]
			append line " $node_str"
			set end_index [string length $line]
			lappend type_tags $start_index $end_index
			append line "\n\n"
			
			set rlist ""

			foreach item $data {
				if {![ApolTop::is_binary_policy]} {
				    set check [lsearch $rlist [expr [lindex $item 0]]]
				    if {$check > -1} continue
				    append line "("
				    set start_index [expr {[string length $line]}]
				    append line "[lindex $item 0]"
				    lappend rlist "[lindex $item 0]"
				    set end_index [string length $line]
				    append line ") "
				    lappend policy_tags_list $start_index $end_index
				}
				append line "[lindex $item 1]\n"
			}
		}
		append line "\n"
	} else {	
		$widget_vars(current_rtext) configure -wrap none
		set start_index [string length $line]
		append line "$widget_vars(start_type)"
		set end_index [string length $line]
		lappend title_type_tags $start_index $end_index
		append line " can be relabeled:\n\n"
		foreach datum $data {
			foreach layer $datum {
				foreach {obj obj_info} $layer {
					set start_index [string length $line]
					append line "$obj:\n"
					set end_index [string length $line]
					lappend title_tags $start_index $end_index
					append line "\n"
					foreach thing $obj_info {
						foreach {direction subject rule_proof} $thing { 				
							set start_index [string length $line]
							if {$widget_vars(to_mode) && $widget_vars(from_mode)} {
								if {$direction == "both"} {
									append line "    to and from "
								} elseif {$direction == "to"} {
									append line "    to "
								} else {
									append line "    from "
								}
							} elseif {$widget_vars(to_mode)} {
								append line "    to "
							} else {
								append line "    from "
							}
							set end_index [string length $line]
							lappend subtitle_type_tags $start_index $end_index
						
							set start_index [string length $line]
							append line "$node "
							set end_index [string length $line]
							lappend type_tags $start_index $end_index
						
							append line "by "
						
							set start_index [string length $line]
							append line "$subject\n"
							set end_index [string length $line]
							lappend type_tags $start_index $end_index
					
							foreach rule_set $rule_proof {
								foreach {rule_num rule} $rule_set {
									append line "        "
									if {![ApolTop::is_binary_policy]} {
										append line "("
										set start_index [expr {[string length $line]}]
										append line "$rule_num"
										set end_index [string length $line]
										append line ") "
										lappend policy_tags_list $start_index $end_index
									}
									append line "$rule\n"
								}
							}
							append line "\n"
						}
					}
				}
			}
		}
	}
	$widget_vars(current_rtext) insert end $line
	if {![ApolTop::is_binary_policy]} {
		foreach {start_index end_index} $policy_tags_list {
			Apol_PolicyConf::insertHyperLink $widget_vars(current_rtext) \
				"1.0 + $start_index c" "1.0 + $end_index c"
		}
	}
	foreach {start_index end_index} $title_tags {
		$widget_vars(current_rtext) tag add $Apol_Analysis_relabel::title_tag \
			"1.0 + $start_index c" "1.0 + $end_index c"
	}
	foreach {start_index end_index} $type_tags {
		$widget_vars(current_rtext) tag add $Apol_Analysis_relabel::type_tag \
			"1.0 + $start_index c" "1.0 + $end_index c"
	}
	foreach {start_index end_index} $subtitle_type_tags {
		$widget_vars(current_rtext) tag add $Apol_Analysis_relabel::subtitle_tag \
			"1.0 + $start_index c" "1.0 + $end_index c"
	}
	foreach {start_index end_index} $title_type_tags {
		$widget_vars(current_rtext) tag add $Apol_Analysis_relabel::title_type_tag \
			"1.0 + $start_index c" "1.0 + $end_index c"
	}
	Apol_Analysis_relabel::formatInfoText $widget_vars(current_rtext)
	$widget_vars(current_rtext) configure -state disabled    
}
