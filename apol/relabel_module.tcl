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
    
    variable info_button_text \
	"This analysis checks the possible ways to relabel objects allowed by a policy. \
    	The permissions relabelto and relabelfrom are special in a type enforcement environment as they \
    	provide a method of changing type.  Relabel analysis is designed to fascilitate queries about \
    	the possible changes for a given type.\n\n\There are four modes for a query, each presenting a \
    	differnt perspective:\n\n\To mode - beginning at starting type lists all types to which relabeling \
    	is possible and the associated rules*. \n\From mode - beginning at starting type lists all types \
    	from which relabeling is possible and the associated rules*.\n\Both mode - beginning at starting \
    	type lists all types to or from which relabeling is possible and the associated rules*.\n\Subject mode - \
    	given a starting subject lists all types to and from which that subject can relabel and the \
    	associated rules*.\n\n\Optionally results may be filtered by object class and permission using the \
    	Advanced Filters button. Permissions may be enabled or disabled for each object class. \n\n\*A note \
    	on rules display and filtering: Rules are stored for each type found to have relabeling permission, \
    	therefore it is possible to specify a permission in a filter and still see a rule that does not contain \
    	that specific permission.  This is not an error rather it means that multiple rules grant permissions \
    	for that specific source-target-object triplet. To see all rules governing a particular triplet use the \
    	Policy Rules tab."

	variable f_opts 
	# name of widget holding most recently executed assertion
	variable most_recent_results 	""
	# Advanced filter dialog widget
	variable advanced_filter_Dlg
	set advanced_filter_Dlg .advanced_filter_Dlg
	
	variable excluded_tag		" (Excluded)"	
	# Provided to tkwait to prevent multiple clicks on an object in the Advanced Search options dialog.
	variable rendering_finished	0
	
	# defined tag names for output 
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	
	# Within the namespace command for the module, you must call
	# Apol_Analysis::register_analysis_modules, the first argument is
	# the namespace name of the module, and the second is the
	# descriptive display name you want to be displayed in the GUI
	# selection box.
	Apol_Analysis::register_analysis_modules "Apol_Analysis_relabel" "Direct File Relabel"
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
	variable advanced_filter_Dlg
	variable f_opts
	
	# convert the object permissions list into Tcl lists
	set objs_list ""
	
	# If the advanced options object doesn't exist, then create it.
	if {![array exists f_opts] || [array names f_opts "$advanced_filter_Dlg,name"] == ""} {
		Apol_Analysis_relabel::adv_options_create_object $advanced_filter_Dlg
	} 
		
	foreach class $f_opts($advanced_filter_Dlg,class_list) {
		set perms_list ""
		# Determine if entire class is to be included, which is indicated by
		# the " (Excluded)" tag appended to its' name.
		set idx [string first $Apol_Analysis_relabel::excluded_tag $class]
		if {$idx == -1} {
			set class_elements [array names f_opts "$advanced_filter_Dlg,perm_status_array,$class,*"]
			foreach element $class_elements {
				set perm [lindex [split $element ","] 3]
				# These are manually set to be included, so skip.
				if {[string equal $f_opts($element) "exclude"]} {
					continue
				}
				set perms_list [lappend perms_list $perm]
			}
			if {$perms_list != ""} {
				set objs_list [lappend objs_list [list $class $perms_list]]
			}	
		} 
	}
	
	if {$objs_list == ""} {
		tk_messageBox -icon error -type ok \
		    -title "Relabel Analysis Error" \
		    -message "You cannot exclude all object classes and permissions in the filter!"
		return -code error
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
	set pw [PanedWindow $results_frame.pw -side top -weights available]
	set most_recent_results_pw $pw
	set lf [$pw add -minsize 150 -weight 1]
	set dtf [TitleFrame $lf.dtf]
	switch -- $widget_vars(mode) {
		to     {set text "Type $widget_vars(start_type) can be relabeled to:"}
		from   {set text "Type $widget_vars(start_type) can be relabeled from:"}
		both   {set text "Type $widget_vars(start_type) can be relabeled to/from:"}
		domain {set text "Subject $widget_vars(start_type) can relabel:"}
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
	pack $dtf -expand 1 -fill both -side left
	
	set rf [$pw add -weight 3]
	set rtf [TitleFrame $rf.rtf -text "File Relabeling Results"]
	set rsw [ScrolledWindow [$rtf getframe].rsw -auto horizontal]
	set rtext [text $rsw.rtext -wrap none -bg white -font $ApolTop::text_font]
	$rsw setwidget $rtext
	Apol_PolicyConf::configure_HyperLinks $rtext
	set widget_vars(current_rtext) $rtext
	pack $rsw -expand 1 -fill both
	pack $rtf -expand 1 -fill both
	pack $pw -expand 1 -fill both

	# now fill the domain tree with results info
	if {$results == ""} {
		$dtree configure -state disabled
		set text "$widget_vars(start_type) does not "
		switch -- $widget_vars(mode) {
		    to     {append text "relabel to anything."}
		    from   {append text "relabel from anything."}
		    both   {append text "relabel to/from anything."}
		    domain {append text "relabel to or from any subject."}
		}
		$rtext insert end $text
	} else {
		$rtext insert end "This tab provides the results of a file relabeling analysis."
		if {$widget_vars(mode) == "domain"} {
			$dtree insert end root TO_LIST -text "To" -open 0 \
				-drawcross auto 
		        $dtree insert end root FROM_LIST -text "From" -open 0 \
				-drawcross auto 
				
			set to_list [lindex $results 0]
			set from_list [lindex $results 1]

			# From list
			foreach datum $from_list {
		            set domain [lindex $datum 0]
		            $dtree insert end FROM_LIST from_list:$domain -text $domain -open 1 \
		                -drawcross auto -data [lindex $datum 1]
		        }

		        # To list
		        foreach datum $to_list {
		        	set domain [lindex $datum 0]
				$dtree insert end TO_LIST to_list:$domain -text $domain -open 1 \
					-drawcross auto -data [lindex $datum 1]
		        }
		} else {
		        foreach result_elem $results {
		            set domain [lindex $result_elem 0]
		            $dtree insert end root $domain -text $domain -open 1 \
		                -drawcross auto -data [lrange $result_elem 1 end]
		        }
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

proc Apol_Analysis_relabel::set_widgets_to_initial_open_state { } {
    variable widgets
    
    toggle_attributes 0
}

# Apol_Analysis_relabel::open must exist; it is called when a
# policy is opened.
proc Apol_Analysis_relabel::open { } {
    populate_lists 1
    # flush the relabel sets cache
    apol_RelabelFlushSets
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
    toggle_attributes 0
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
#  Command Apol_Analysis_relabel::adv_options_destroy_all_dialogs_on_open
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_destroy_all_dialogs_on_open {} {
	variable f_opts
	
	set dlgs [array names f_opts "*,name"]
	set length [llength $dlgs]

	for {set i 0} {$i < $length} {incr i} {
		# Skip the name of the element to the actual value of the element
		incr i
		Apol_Analysis_relabel::adv_options_destroy_dialog [lindex $dlgs $i]
		Apol_Analysis_relabel::adv_options_destroy_object [lindex $dlgs $i]
	}
	array unset f_opts
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_destroy_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_destroy_dialog {path_name} {
	variable f_opts
	
    	if {[winfo exists $path_name]} {	
    		destroy $path_name	 		
		unset f_opts($path_name,class_listbox) 
		unset f_opts($path_name,perms_box) 
		unset f_opts($path_name,permissions_title_frame) 
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_refresh_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_refresh_dialog {path_name} {  
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != ""} { 
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
	variable f_opts
			
	# If the advanced filters dialog is displayed, then we need to update its' state.
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != "" &&
	    [winfo exists $f_opts($path_name,name)]} {
		set rt [catch {Apol_Analysis_relabel::adv_options_set_widgets_to_default_state \
			$path_name} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
		raise $f_opts($path_name,name)
		focus -force $f_opts($path_name,name)
		
		# Reset the selection in the listbox
		if {$f_opts($path_name,class_selected_idx) != "-1"} {
			$f_opts($path_name,class_listbox) selection set \
				[$f_opts($path_name,class_listbox) index \
				$f_opts($path_name,class_selected_idx)]
			Apol_Analysis_relabel::adv_options_display_permissions $path_name
		}
	} 

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_include_exclude_permissions
#	- perms_box - the specified attribute
#	- which - include or exclude
#
#	- This proc will change a list item in the class listbox. When all perms 
#	  are excluded, the object class is grayed out in the listbox and the 
# 	  class label is changed to "object_class (Exluded)". This is a visual 
# 	  representation to the user that the object class itself is being  
# 	  implicitly excluded from the query as a result of all of its' 
#	  permissions being excluded. When any or all permissions are included, 
#	  the class label is reset to the class name itself and is then un-grayed.
#	  Any other functions that then take a selected listbox element as an 
#	  argument MUST first search the class string for the sequence " (Excluded)"
# 	  before processing the class name.
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_include_exclude_permissions {which path_name} {	
	variable f_opts
	
	if {[ApolTop::is_policy_open]} {
		if {[string equal $which "include"] == 0 && [string equal $which "exclude"] == 0} {
			puts "Tcl error: wrong 'which' argument sent to Apol_Analysis_relabel::adv_options_include_exclude_permissions. Must be either 'include' or 'exclude'."	
			return -1
		}
		set objs [$f_opts($path_name,class_listbox) curselection]
 		foreach object_class_idx $objs {
 			set object_class [$f_opts($path_name,class_listbox) get $object_class_idx]
 			set idx [string first $Apol_Analysis_relabel::excluded_tag $object_class]
 			if {$idx != -1} {
 				set object_class [string range $object_class 0 [expr $idx - 1]]
 			}
 			set rt [catch {set perms_list [apol_GetPermsByClass $object_class 1]} err]
 			if {$rt != 0} {
 				tk_messageBox -icon error -type ok -title "Error" -message "$err"
 				return -1
 			}
 			foreach perm $perms_list {
 				set f_opts($path_name,perm_status_array,$object_class,$perm) $which
 			}
 			if {$object_class_idx != ""} {
 				set items [$f_opts($path_name,class_listbox) get 0 end]
				if {[string equal $which "exclude"]} {
					$f_opts($path_name,class_listbox) itemconfigure $object_class_idx \
						-foreground gray
					set [$f_opts($path_name,class_listbox) cget -listvar] \
						[lreplace $items $object_class_idx $object_class_idx \
						"$object_class$Apol_Analysis_relabel::excluded_tag"]
				} else {
					$f_opts($path_name,class_listbox) itemconfigure $object_class_idx \
						-foreground $f_opts($path_name,select_fg_orig)
					set [$f_opts($path_name,class_listbox) cget -listvar] \
						[lreplace $items $object_class_idx $object_class_idx \
						"$object_class"]
				}
  			}
  			if {$f_opts($path_name,class_selected_idx) == $object_class_idx} {
  				$f_opts($path_name,permissions_title_frame) configure \
  					-text "Permissions for [$f_opts($path_name,class_listbox) get \
  						$object_class_idx]:"
  			}
  		}
	}
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select
#`	-  This proc also searches a class string for the sequence " (Excluded)"
# 	   in order to process the class name only. 
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select {path_name} {
	variable f_opts 
	
	set num_excluded 0	
	# There may be multiple selected items, but we need the object class that is 
	# currently displayed in the text box. We have this index stored in our global 
	# class_selected_idx variable.
	if {$f_opts($path_name,class_selected_idx) != "-1"} {
		set class_sel [$f_opts($path_name,class_listbox) get \
			$f_opts($path_name,class_selected_idx)]
		set idx [string first $Apol_Analysis_relabel::excluded_tag $class_sel]
		if {$idx != -1} {
			set class_sel [string range $class_sel 0 [expr $idx - 1]]
		}
		set class_elements [array get f_opts "$path_name,perm_status_array,$class_sel,*"]
		if {$class_elements != ""} {
			set num_perms_for_class [expr {[llength $class_elements] / 2}]
			for {set i 0} {$i < [llength $class_elements]} {incr i} {
				incr i
				if {[string equal [lindex $class_elements $i] "exclude"]} {
					incr num_excluded	
				}
			}
			set items [$f_opts($path_name,class_listbox) get 0 end]
			# If the total all permissions for the object have been 
			# excluded then inform the user. 
			if {$num_excluded == $num_perms_for_class} {
				$f_opts($path_name,class_listbox) itemconfigure \
					$f_opts($path_name,class_selected_idx) \
					-foreground gray
				set [$f_opts($path_name,class_listbox) cget -listvar] \
					[lreplace $items $f_opts($path_name,class_selected_idx) \
					$f_opts($path_name,class_selected_idx) \
					"$class_sel$Apol_Analysis_relabel::excluded_tag"]
			} else {
				$f_opts($path_name,class_listbox) itemconfigure \
					$f_opts($path_name,class_selected_idx) \
					-foreground $f_opts($path_name,select_fg_orig)
				set [$f_opts($path_name,class_listbox) cget -listvar] \
					[lreplace $items $f_opts($path_name,class_selected_idx) \
					$f_opts($path_name,class_selected_idx) \
					"$class_sel"]
			}
  			$f_opts($path_name,permissions_title_frame) configure \
  				-text "Permissions for [$f_opts($path_name,class_listbox) get \
  					$f_opts($path_name,class_selected_idx)]:"
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
	variable f_opts
	variable rendering_finished
	
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
		-variable Apol_Analysis_relabel::f_opts($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select \
			$path_name"]	
	set cb_exclude [radiobutton $cb_frame.cb_exclude:$class:$perm -bg white \
		-value exclude -text "Exclude" \
		-highlightthickness 0 \
		-variable Apol_Analysis_relabel::f_opts($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_relabel::adv_options_change_obj_state_on_perm_select \
			$path_name"]
	
	# Placing widgets
	pack $frame -side left -anchor nw -expand yes -pady 10
	pack $lbl_frame $cb_frame -side left -anchor nw -expand yes
	pack $lbl1 $lbl2 -side left -anchor nw
	pack $cb_include $cb_exclude -side left -anchor nw
	
	set rendering_finished 1
	# Return the pathname of the frame to embed.
 	return $frame
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_relabel::adv_options_clear_perms_text 
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_clear_perms_text {path_name} {
	variable f_opts
	
	# Enable the text widget. 
	$f_opts($path_name,perms_box) configure -state normal
	# Clear the text widget and any embedded windows
	set names [$f_opts($path_name,perms_box) window names]
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
	$f_opts($path_name,perms_box) delete 1.0 end
	return 0
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
	variable f_opts
	
	if {[$f_opts($path_name,class_listbox) get 0 end] == "" || \
		[llength [$f_opts($path_name,class_listbox) curselection]] > 1} {
		# Nothing in the listbox; return
		return 0
	}
	
	set class_idx [$f_opts($path_name,class_listbox) curselection]
	if {$class_idx == ""} {
		# Something was simply deselected.
		return 0
	} 
	focus -force $f_opts($path_name,class_listbox)
	set class_name [$f_opts($path_name,class_listbox) get $class_idx]
	$f_opts($path_name,permissions_title_frame) configure -text "Permissions for $class_name:"
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
		if {[array names f_opts "$path_name,perm_status_array,$class_name,$perm"] == ""} {
			set f_opts($path_name,perm_status_array,$class_name,$perm) include
		}
		$f_opts($path_name,perms_box) window create end -window \
			[Apol_Analysis_relabel::adv_options_embed_perm_buttons \
			$f_opts($path_name,perms_box) $class_name $perm $path_name] 
		$f_opts($path_name,perms_box) insert end "\n"
	}
	tkwait variable Apol_Analysis_relabel::rendering_finished
	set rendering_finished 0
	update 
	
	# Disable the text widget. 
	$f_opts($path_name,perms_box) configure -state disabled
	set f_opts($path_name,class_selected_idx) $class_idx
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_set_widgets_to_default_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_set_widgets_to_default_state {path_name} {
	variable f_opts
	
	set f_opts($path_name,select_fg_orig) [$f_opts($path_name,class_listbox) cget -foreground]
	
	# Configure the class listbox items to indicate excluded/included object classes.
        set class_lbox_idx 0
        foreach class $f_opts($path_name,class_list) {
        	# Make sure to strip out just the class name, as this may be an excluded class.
		set idx [string first $Apol_Analysis_relabel::excluded_tag $class]
		if {$idx != -1} {
			set class [string range $class 0 [expr $idx - 1]]
		}	
		set num_excluded 0
		set class_perms [array names f_opts "$path_name,perm_status_array,$class,*"]
		foreach element $class_perms {
			if {[string equal $f_opts($element) "exclude"]} {
				incr num_excluded
			}
		}
		if {$num_excluded == [llength $class_perms]} {
			set [$f_opts($path_name,class_listbox) cget -listvar] \
				[lreplace $f_opts($path_name,class_list) $class_lbox_idx \
				$class_lbox_idx "$class$Apol_Analysis_relabel::excluded_tag"]
			$f_opts($path_name,class_listbox) itemconfigure $class_lbox_idx \
				-foreground gray
		} else {
			set [$f_opts($path_name,class_listbox) cget -listvar] \
				[lreplace $f_opts($path_name,class_list) $class_lbox_idx \
				$class_lbox_idx "$class"]
			$f_opts($path_name,class_listbox) itemconfigure $class_lbox_idx \
				-foreground $f_opts($path_name,select_fg_orig)
		}
		incr class_lbox_idx
	}

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_initialize_objs_and_perm_filters
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_initialize_objs_and_perm_filters {path_name} {
	variable f_opts
	
	set f_opts($path_name,class_list) $Apol_Class_Perms::class_list
	# Initialization for object classes section
	foreach class $f_opts($path_name,class_list) {
		set rt [catch {set perms_list [apol_GetPermsByClass $class 1]} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		}
		foreach perm $perms_list {
			set f_opts($path_name,perm_status_array,$class,$perm) include
		}
	}

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_create_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_create_object {path_name} {
	variable f_opts
	
	set f_opts($path_name,name) 			$path_name
	set f_opts($path_name,threshhold_cb_value) 	0
	set f_opts($path_name,threshhold_value) 	1
	set f_opts($path_name,class_selected_idx) 	-1
	
	# Initialize all object classes/permissions and related information to default values
	Apol_Analysis_relabel::adv_options_initialize_objs_and_perm_filters $path_name
        set f_opts($path_name,filter_vars_init) 1
 
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_copy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_copy_object {path_name new_object} {
	variable f_opts
	upvar 1 $new_object object 
	
	if {![array exists f_opts] || [array names f_opts "$path_name,name"] == ""} {
		Apol_Analysis_relabel::adv_options_create_object $path_name
	}
	array set object [array get f_opts "$path_name,*"]
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_destroy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_destroy_object {path_name} { 
	variable f_opts
	
	if {[array exists f_opts] && [array names f_opts "$path_name,name"] != ""} {
		array unset f_opts "$path_name,perm_status_array,*"
		unset f_opts($path_name,threshhold_cb_value)
		unset f_opts($path_name,threshhold_value)
		unset f_opts($path_name,filter_vars_init) 	
		unset f_opts($path_name,class_selected_idx) 
		unset f_opts($path_name,name) 
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_relabel::adv_options_create_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_relabel::adv_options_create_dialog {path_name title_txt} {
	variable f_opts 

	if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -1
        } 
       	
	# Check to see if object already exists.
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != ""} {
	    	# Check to see if the dialog already exists.
	    	if {[winfo exists $f_opts($path_name,name)]} {
		    	raise $f_opts($path_name,name)
		    	focus $f_opts($path_name,name)
	    		return 0
	    	} 
	    	# else we need to display the dialog with the correct object settings
    	} else {
	    	# Create a new options dialog object
    		Apol_Analysis_relabel::adv_options_create_object $path_name
    	}	
   	
    	# Create the top-level dialog and subordinate widgets
    	toplevel $f_opts($path_name,name) 
     	wm withdraw $f_opts($path_name,name) 	
    	wm title $f_opts($path_name,name) $title_txt 
    	   	
   	set close_frame [frame $f_opts($path_name,name).close_frame -relief sunken -bd 1]
   	set topf  [frame $f_opts($path_name,name).topf]
        #set pw1 [PanedWindow $topf.pw1 -side left -weights available]
        #$pw1 add -weight 2 -minsize 225
        #$pw1 add -weight 2 -minsize 225
        pack $close_frame -side bottom -anchor center -pady 2
        #pack $pw1 -fill both -expand yes	
        pack $topf -fill both -expand yes -padx 10 -pady 10
        
   	# Main Titleframe
   	set objs_frame  [TitleFrame $topf.objs_frame -text "Filter by object class permissions:"]
        
        # Widgets for object classes frame
        set pw1   [PanedWindow [$objs_frame getframe].pw -side top -weights available]
        set pane  [$pw1 add]
        set search_pane [$pw1 add]
        set pw2   [PanedWindow $pane.pw -side left -weights available]
        set class_pane 	[$pw2 add]
        set f_opts($path_name,classes_box) [TitleFrame $class_pane.tbox -text "Object Classes:" -bd 0]
        set f_opts($path_name,permissions_title_frame) [TitleFrame $search_pane.rbox \
        	-text "Permissions:" -bd 0]
          
        set sw_class [ScrolledWindow [$f_opts($path_name,classes_box) getframe].sw -auto none]
        set f_opts($path_name,class_listbox) [listbox [$sw_class getframe].lb \
        	-height 10 -highlightthickness 0 \
        	-bg white -selectmode extended \
        	-listvar Apol_Analysis_relabel::f_opts($path_name,class_list) \
        	-exportselection 0]
        $sw_class setwidget $f_opts($path_name,class_listbox)  
      	     	
	set sw_list [ScrolledWindow [$f_opts($path_name,permissions_title_frame) getframe].sw_c -auto none]
	set f_opts($path_name,perms_box) [text [$f_opts($path_name,permissions_title_frame) getframe].perms_box \
		-cursor $ApolTop::prevCursor \
		-bg white -font $ApolTop::text_font]
	$sw_list setwidget $f_opts($path_name,perms_box)
	
	set bframe [frame [$f_opts($path_name,classes_box) getframe].bframe]
	set b_incl_all_perms [Button $bframe.b_incl_all_perms -text "Include All Perms" \
		-helptext "Select this to include all permissions for the selected object in the query." \
		-command "Apol_Analysis_relabel::adv_options_include_exclude_permissions \
			include $path_name"]
	set b_excl_all_perms [Button $bframe.b_excl_all_perms -text "Exclude All Perms" \
		-helptext "Select this to exclude all permissions for the selected object from the query." \
		-command "Apol_Analysis_relabel::adv_options_include_exclude_permissions \
			exclude $path_name"]
		
	# Bindings
	set bind_tag_id [string trim $path_name "."]
	bindtags $f_opts($path_name,class_listbox) \
		[linsert [bindtags $f_opts($path_name,class_listbox)] 3 \
		${bind_tag_id}_f_relabel_object_list_Tag]  
        bind ${bind_tag_id}_f_relabel_object_list_Tag \
        	<<ListboxSelect>> "Apol_Analysis_relabel::adv_options_display_permissions $path_name"
        
        pack $b_excl_all_perms -side right -anchor nw -pady 2 -expand yes -fill x -ipadx 1
        pack $b_incl_all_perms -side left -anchor nw -pady 2 -expand yes -fill x -ipadx 2
        pack $bframe -side bottom -fill both -anchor sw -pady 2
        pack $f_opts($path_name,permissions_title_frame) -pady 2 -padx 2 -fill both -expand yes
	pack $f_opts($path_name,classes_box) -padx 2 -side left -fill both -expand yes	   
        pack $sw_class -fill both -expand yes -side top
	pack $sw_list -fill both -expand yes -side top
	pack $pw2 -fill both -expand yes
        pack $pw1 -fill both -expand yes
        pack $objs_frame -side top -anchor nw -padx 5 -pady 2 -expand yes -fill both 	  
        
	# Create and pack close button for the dialog
  	set close_bttn [Button $close_frame.close_bttn -text "Close" -width 8 \
		-command "Apol_Analysis_relabel::adv_options_destroy_dialog $path_name"]
	pack $close_bttn -side left -anchor center
					  
	wm protocol $f_opts($path_name,name) WM_DELETE_WINDOW \
		"Apol_Analysis_relabel::adv_options_destroy_dialog $path_name"
    	
        # Configure top-level dialog specifications
        set width 780
	set height 750
	wm geom $f_opts($path_name,name) ${width}x${height}
	wm deiconify $f_opts($path_name,name)
	focus $f_opts($path_name,name)
	
	Apol_Analysis_relabel::adv_options_set_widgets_to_default_state $path_name
	return 0
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
                          -text "To" -value "to" \
                          -variable Apol_Analysis_relabel::widget_vars(mode) \
                          -command [namespace code set_mode_relabelto]]
    set relabelfrom_rb [radiobutton [$mode_tf getframe].relabelfrom_rb \
                            -text "From" -value "from" \
                            -variable Apol_Analysis_relabel::widget_vars(mode)\
                            -command [namespace code set_mode_relabelfrom]]
    set domain_rb [radiobutton [$mode_tf getframe].domain_rb \
                       -text "Subject" -value "domain" \
                       -variable Apol_Analysis_relabel::widget_vars(mode) \
                       -command [namespace code set_mode_domain]]
    set both_rb [radiobutton [$mode_tf getframe].both_rb \
                       -text "Both" -value "both" \
                       -variable Apol_Analysis_relabel::widget_vars(mode) \
                       -command [namespace code set_mode_relabelboth]]
    pack $relabelto_rb $relabelfrom_rb $both_rb $domain_rb -anchor w -side top

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
                -editable 1 -entrybg white -width 16 -state disabled \
                -modifycmd [namespace code [list set_types_list ""]] \
                -vcmd [namespace code [list set_types_list %P]] -validate key \
                -textvariable Apol_Analysis_relabel::widget_vars(start_attrib)]
    bindtags $widgets(start_attrib_cb).e [linsert [bindtags $widgets(start_attrib_cb).e] 3 start_attrib_cb_tag]
    bind start_attrib_cb_tag <KeyPress> [list ApolTop::_create_popup $widgets(start_attrib_cb) %W %K]
    
    set filter_f [frame $option_f.filter_f]
    set widgets(b_adv_options) [button $filter_f.b_adv_options -text "Advanced Filters" \
		-command {Apol_Analysis_relabel::adv_options_create_dialog \
			$Apol_Analysis_relabel::advanced_filter_Dlg \
			"Direct File Relabel Advanced Filters"}]
    
    pack $widgets(start_attrib_ch) -expand 0 -fill x
    pack $widgets(start_attrib_cb) -padx 15 -expand 0 -fill x
    pack $widgets(b_adv_options) -anchor nw 
    pack $start_f -expand 0 -fill x
    pack $attrib_f -pady 20 -expand 0 -fill x
    
    pack $option_f -fill both -anchor nw -side left -padx 5 -expand 1
    pack $mode_tf $req_tf $filter_f -side left -anchor nw -padx 5 -expand 1 -fill both

    # set initial widget states
    set_mode_relabelto
    populate_lists 1
    toggle_attributes 1
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

proc Apol_Analysis_relabel::set_mode_relabelboth {} {
    variable widgets
  $widgets(start_l) configure -text "Starting type:"
    $widgets(start_attrib_ch) configure -text "Select starting type using attrib:"
}

proc Apol_Analysis_relabel::set_mode_domain {} {
    variable widgets
    $widgets(start_l) configure -text "Subject:"
    $widgets(start_attrib_ch) configure -text "Select subject using attrib:"
}

proc Apol_Analysis_relabel::toggle_attributes {clear_types_list} {
    variable widgets
    variable widget_vars
    if $widget_vars(start_attrib_ch) {
        $widgets(start_attrib_cb) configure -state normal -entrybg white
        if $clear_types_list {
            set_types_list ""
        }
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
proc Apol_Analysis_relabel::populate_lists {add_items} {
    variable widgets
    variable widget_vars
    if $add_items {
        $widgets(start_cb) configure -values $Apol_Types::typelist
        $widgets(start_attrib_cb) configure -values $Apol_Types::attriblist
        if {[lsearch -exact $Apol_Types::typelist $widget_vars(start_type)] == -1} {
            set widget_vars(start_type) {}
        }
        if {[lsearch -exact $Apol_Types::attriblist $widget_vars(start_attrib)] == -1} {
            set widget_vars(start_attrib) {}
        }
    } else {
        $widgets(start_cb) configure -values {}
        $widgets(start_attrib_cb) configure -values {}
        set widget_vars(start_type) {}
        set widget_vars(start_attrib) {}
    }
}

##########################################################################
# ::formatInfoText
#
proc Apol_Analysis_relabel::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_relabel::title_type_tag -foreground blue -font {Helvetica 12 bold}
	$tb tag configure $Apol_Analysis_relabel::subtitle_tag -font {Helvetica 11 bold}
}

# Update the File Relabeling Results display with whatever the user
# selected
proc Apol_Analysis_relabel::tree_select {widget node} {
	variable widget_vars
	
	if {$node == ""} {
		return
	}
	set data [$widget itemcget $node -data]
	$widget_vars(current_rtext) configure -state normal
	$widget_vars(current_rtext) delete 1.0 end
	
	set subtitle_type_tags ""
	set title_type_tags ""
	set policy_tags_list ""
	set line ""
	set start_index 0
	append line "$widget_vars(start_type)"
	set end_index [string length $line]
	lappend title_type_tags $start_index $end_index
	append line " can "
	
	switch -- $widget_vars(mode) {
	    to     {append line "relabel to "}
	    from   {append line "relabel from "}
	    both   {append line "both relabel to and from "}
	    domain {append line "relabel to or from "}
	} 
	
	if {$widget_vars(mode) == "domain"} {
		if {$node == "TO_LIST" || $node == "FROM_LIST"} {
			return
		}
		
		if {[$widget_vars(current_dtree) parent $node] == "TO_LIST"} {
			set node [string trimleft $node "to_list:"]
		} else {
			set node [string trim $node "from_list:"]
		}
		set start_index [string length $line]
		append line "$node"
		set end_index [string length $line]
		lappend title_type_tags $start_index $end_index
		append line "\n\n"
		
		foreach item $data {
		    set start_index [expr {[string length $line] + 1}]
		    append line "([lindex $item 0]"
		    set end_index [string length $line]
		    append line ") [lindex $item 1]\n"
		    lappend policy_tags_list $start_index $end_index
		}
		append line "\n"
	} else {
		set start_index [string length $line]
		append line "$node"
		set end_index [string length $line]
		lappend title_type_tags $start_index $end_index
		append line " by:\n\n"
		foreach datum $data {
			foreach {subject rule_proof} $datum {
				set start_index [string length $line]
				append line "$subject\n"
				set end_index [string length $line]
				lappend subtitle_type_tags $start_index $end_index
				append line "\n"
				foreach {rule_num rule} $rule_proof {
				    append line "    "
				    set start_index [expr {[string length $line] + 1}]
				    append line "($rule_num"
				    set end_index [string length $line]
				    append line ") $rule\n"
				    lappend policy_tags_list $start_index $end_index
				}
				append line "\n"
			}
		}
	}
	$widget_vars(current_rtext) insert end $line
	foreach {start_index end_index} $policy_tags_list {
		Apol_PolicyConf::insertHyperLink $widget_vars(current_rtext) \
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
