#############################################################
#  dta_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com, mayerf@tresys.com>
# -----------------------------------------------------------
#
# This module implements the domain transition analysis interface.

##############################################################
# ::Apol_Analysis_dta module namespace
##############################################################
namespace eval Apol_Analysis_dta {
	# Options widgets 
	variable combo_domain
	variable combo_attribute
	variable cb_attrib
	variable entry_frame
	# Forward transition advanced options search widgets
	variable forward_options_Dlg
	set forward_options_Dlg .forward_options_Dlg
	variable adv_frame
	variable b_forward_options
	variable cb_filters
	variable progressDlg
	set progressDlg .progress
	variable progressmsg		""
	variable progress_indicator	-1
							
    	# Options Display Variables
	variable display_type			""
	variable display_attribute		""
	variable display_attrib_sel		0
	variable display_direction		"forward"
	variable endtype_sel			0
	variable end_type			""
	variable use_filters			0
	
	# Options State Variables
	variable type_state			""
	variable attribute_state		""
	variable attrib_selected_state 		0
	variable direction_state		"forward"
	variable endtype_sel_state		0
	variable end_type_state			""
	variable use_filters_state		0
	
	# Current results display
	variable dta_tree		""	
	variable dta_info_text		""
	
	# Array to hold multiple instances of the forward DTA advanced options dialog
	variable f_opts
	# Result type filters dialog widgets
	variable b_incl_all_perms
	variable b_excl_all_perms
	
    	# Defined Tag Names
	variable title_tag		TITLE
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	variable rules_tag		RULES
	variable counters_tag		COUNTERS
	variable types_tag		TYPE
	variable disabled_rule_tag     	DISABLE_RULE
	variable excluded_tag		" (Excluded)"
	
    	# Register ourselves
    	Apol_Analysis::register_analysis_modules "Apol_Analysis_dta" "Domain Transition"
    	
    	variable descriptive_text	"\n\nA forward domain transition analysis will determine all (target) \
    		domains to which a given (source) domain may transition.  For a forward domain \
    		transition to be allowed, three forms of access must be granted:\n\n\ \
    		\t(1) source domain must have process transition permission for target domain,\n\
    		\t(2) source domain must have file execute permission for some entrypoint type, and\n\
    		\t(3) target domain must have file entrypoint permission for the same entrypoint type.\n\nA \
    		reverse domain transition analysis will determine all (source) domains that can transition to \
    		a given (target) domain.  For a reverse domain transition to be allowed, three forms of access must be granted:\n\n\
    		\t(1) target domain must have process transition permission from the source domain,\n\
    		\t(2) target domain must have file entrypoint permission to some entrypoint type, and\n\
    		\t(3) source domain must have file execute permission to the same entrypoint type.\n\n\The \
    		results are presented in tree form.  You can open target children domains to \
    		perform another domain transition analysis on that domain.\n\nFor additional \
    		help on this topic select \"Domain Transition Analysis\" from the help menu."
	
	# root text for forward dta results
	variable dta_root_text_f 	"\n\nThis tab provides the results of a forward domain transition analysis\
		starting from the source domain type above.  The results of this analysis are presented in tree form with the root\
		of the tree (this node) being the start point for the analysis.\n\nEach child node in the tree represents\
		a TARGET DOMAIN TYPE.  A target domain type is a domain to which the source domain may transition.  You can\
		follow the domain transition tree by opening each subsequent generation of children in the tree.\n\nNOTE: For any\
		given generation, if the parent and the child are the same, you cannot open the child. This avoids cyclic analyses.\n\nThe\
		criteria that defines an allowed domain transition are:\n\n1) There must be at least one rule that allows TRANSITION\
		access for PROCESS objects between the SOURCE and TARGET domain types.\n\n2) There must be at least one FILE TYPE that\
		allows the TARGET type ENTRYPOINT access for FILE objects.\n\n3) There must be at least one FILE TYPE that meets\
		criterion 2) above and allows the SOURCE type EXECUTE access for FILE objects.\n\nThe information window shows\
		all the rules and file types that meet these criteria for each target domain type.\n\nFUTURE NOTE: In the future\
		we also plan to show the type_transition rules that provide for a default domain transitions.  While such rules\
		cause a domain transition to occur by default, they do not allow it.  Thus, associated type_transition rules\
		are not truly part of the definition of allowed domain transitions."
	
	# root text for reverse dta results
	variable dta_root_text_r 	"\n\nThis tab provides the results of a reverse domain transition analysis\
		given the target domain type above.  The results of this analysis are presented in tree form with the root\
		of the tree (this node) being the target point of the analysis.\n\nEach child node in the tree represents\
		a source DOMAIN TYPE.  A source domain type is a domain that can transition to the target domain.  You can\
		follow the domain transition tree by opening each subsequent generation of children in the tree.\n\nNOTE: For any\
		given generation, if the parent and the child are the same, you cannot open the child. This avoids cyclic analyses.\n\nThe\
		criteria that defines an allowed domain transition are:\n\n1) There must be at least one rule that allows TRANSITION\
		access for PROCESS objects between the SOURCE and TARGET domain types.\n\n2) There must be at least one FILE TYPE that\
		allows the TARGET type ENTRYPOINT access for FILE objects.\n\n3) There must be at least one FILE TYPE that meets\
		criterion 2) above and allows the SOURCE type EXECUTE access for FILE objects.\n\nThe information window shows\
		all the rules and file types that meet these criteria for each source domain type.\n\nFUTURE NOTE: In the future\
		we also plan to show the type_transition rules that provide for a default domain transitions.  While such rules\
		cause a domain transition to occur by default, they do not allow it.  Thus, associated type_transition rules\
		are not truly part of the definition of allowed domain transitions."
}

# The following are procs related to creating/modifying/destroying a forward 
# DTA advanced options dialog object. These procs provide a generic interface 
# which can be used by other namespaces, such as the types relationship analysis
# namespace, which uses an advanced options dialog for fine-tuning a search for
# domain transitions between two types. The following procedure is the main for
# creating the object:
#	- Apol_Analysis_dta::forward_options_create_dialog path_name dialog_title
#
#	

proc Apol_Analysis_dta::get_short_name {} {
    return "Domain Trans"
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_update_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_update_dialog {path_name} {
	variable f_opts
	
	# If the advanced filters dialog is displayed, then we need to update its' state.
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != "" &&
	    [winfo exists $f_opts($path_name,name)]} {
		Apol_Analysis_dta::forward_options_set_widgets_to_default_state $path_name
		raise $f_opts($path_name,name)
		focus -force $f_opts($path_name,name)
		
		# Reset the selection in the listbox
		if {$f_opts($path_name,class_selected_idx) != "-1"} {
			$f_opts($path_name,class_listbox) selection set \
				 [$f_opts($path_name,class_listbox) index \
				 $f_opts($path_name,class_selected_idx)]
			Apol_Analysis_dta::forward_options_display_permissions $path_name
		}
	}
}

proc Apol_Analysis_dta::forward_options_disable_perms_textbox {path_name} {
	variable f_opts
	Apol_Analysis_dta::forward_options_clear_perms_text $path_name
	$f_opts($path_name,perms_box) configure -state disabled
}

proc Apol_Analysis_dta::forward_options_configure_class_perms_section {path_name} {
	variable f_opts
	variable b_incl_all_perms
	variable b_excl_all_perms
	
	if {[$f_opts($path_name,lbox_incl) get 0 end] == ""} {
		$f_opts($path_name,class_listbox) selection clear 0 end
		ApolTop::disable_tkListbox $f_opts($path_name,class_listbox) 
	 	bind $f_opts($path_name,class_listbox) <<ListboxSelect>> ""
		Apol_Analysis_dta::forward_options_disable_perms_textbox $path_name
		$b_incl_all_perms configure -state disabled
		$b_excl_all_perms configure -state disabled
	} else {
		ApolTop::enable_tkListbox $f_opts($path_name,class_listbox) 
	 	bind $f_opts($path_name,class_listbox) <<ListboxSelect>> "Apol_Analysis_dta::forward_options_display_permissions $path_name"
		$b_incl_all_perms configure -state normal
		$b_excl_all_perms configure -state normal
		# Select the top most item by default
		$f_opts($path_name,class_listbox) selection set 0
		Apol_Analysis_dta::forward_options_display_permissions $path_name
	}
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_include_types
#	- type_indices - the indexes of selected types to include
#	- add_list - the list displayed inside the listbox to which the type 
#		     being added. 
#	- remove_lbox - listbox widget from which the type is being removed.
#	- add_lbox - listbox widget to which the type is being added.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_include_types {remove_list_1 \
						       add_list_1 \
						       remove_lbox \
						       add_lbox \
						       master_incl_types_list_1 \
						       master_excl_types_list_1 \
						       path_name} {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	upvar #0 $master_incl_types_list_1 master_incl_types_list
	upvar #0 $master_excl_types_list_1 master_excl_types_list
	
	set type_indices [$remove_lbox curselection]
	if {$type_indices != ""} {
		set tmp_list ""
		foreach idx $type_indices {
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
			# Update the non-filtered list variables (i.e. types not filtered by attribute)
			set master_incl_types_list [lappend master_incl_types_list $type]
			set idx  [lsearch -exact $master_excl_types_list $type]
			if {$idx != -1} {
				set master_excl_types_list [lreplace $master_excl_types_list $idx $idx]
			}
		    }
		$remove_lbox selection clear 0 end
	}  	
	Apol_Analysis_dta::forward_options_configure_class_perms_section $path_name
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_exclude_types
#	- type_indices - the indexes of selected types to include
#	- add_list - the list displayed inside the listbox to which the type 
#		     being added. 
#	- remove_lbox - listbox widget from which the type is being removed.
#	- add_lbox - listbox widget to which the type is being added.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_exclude_types {remove_list_1 \
						       add_list_1 \
						       remove_lbox \
						       add_lbox \
						       master_incl_types_list_1 \
						       master_excl_types_list_1 \
						       path_name} {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	upvar #0 $master_incl_types_list_1 master_incl_types_list
	upvar #0 $master_excl_types_list_1 master_excl_types_list

	set type_indices [$remove_lbox curselection]
	if {$type_indices != ""} {
		set tmp_list ""
		foreach idx $type_indices {
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
			# Update the non-filtered list variables (i.e. types not filtered by attribute)
			set master_excl_types_list [lappend master_excl_types_list $type]
			set idx  [lsearch -exact $master_incl_types_list $type]
			if {$idx != -1} {
				set master_incl_types_list [lreplace $master_incl_types_list $idx $idx]
			}
		    }
		    $remove_lbox selection clear 0 end
	}  
	Apol_Analysis_dta::forward_options_configure_class_perms_section $path_name	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_configure_combo_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_configure_combo_state {cb_selected_1 combo_box lbox which_list path_name} {
	variable f_opts

	upvar #0 $cb_selected_1 cb_selected
	if {$cb_selected} {
		$combo_box configure -state normal -entrybg white
		if {$which_list == "incl"} {
			Apol_Analysis_dta::forward_options_filter_types_using_attrib \
				Apol_Analysis_dta::f_opts($path_name,incl_attrib_combo_value) \
				$lbox \
				Apol_Analysis_dta::f_opts($path_name,master_incl_types_list)
		} else {
			Apol_Analysis_dta::forward_options_filter_types_using_attrib \
				Apol_Analysis_dta::f_opts($path_name,excl_attrib_combo_value) \
				$lbox \
				Apol_Analysis_dta::f_opts($path_name,master_excl_types_list)
		}
	} else {
		$combo_box configure -state disabled -entrybg $ApolTop::default_bg_color
		if {$which_list == "incl"} {
			set [$lbox cget -listvar] \
				[lsort $Apol_Analysis_dta::f_opts($path_name,master_incl_types_list)]
		} elseif {$which_list == "excl"} {
			set [$lbox cget -listvar] \
				[lsort $Apol_Analysis_dta::f_opts($path_name,master_excl_types_list)]
		} else {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "Invalid paremeter ($which_list) \
				to Apol_Analysis_dta::forward_options_configure_combo_state. \
				Must be either 'incl' or 'excl'"
	    		return -1
		}
	}
		
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_filter_types_using_attrib
#	- attribute - the specified attribute
#	- lbox - the listbox in which to perform the selection
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_filter_types_using_attrib {attribute_1 lbox non_filtered_types_1} {	
	upvar #0 $attribute_1 attribute
	upvar #0 $non_filtered_types_1 non_filtered_types
	
	if {$attribute != ""} {
		$lbox delete 0 end
		# Get a list of types for the specified attribute
            set attrib_types [lindex [apol_GetAttribs $attribute] 0 1]
		if {$non_filtered_types != ""} {
			for {set i 0} {$i < [llength $non_filtered_types]} {incr i} { 
				# Check if this is a filtered type
				set idx [lsearch -exact $attrib_types [lindex $non_filtered_types $i]]
				if {$idx != -1} {
					$lbox insert end [lindex $non_filtered_types $i]
				}
			}
		}
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_include_exclude_permissions
#	- which - include or exclude
#	- path_name - the DTA options dialog object pathname
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
proc Apol_Analysis_dta::forward_options_include_exclude_permissions {which path_name} {	
	variable f_opts
	
	if {[ApolTop::is_policy_open]} {
		if {[string equal $which "include"] == 0 && [string equal $which "exclude"] == 0} {
			puts "Tcl error: wrong 'which' argument sent to \
				Apol_Analysis_dta::forward_options_include_exclude_permissions. \
				Must be either 'include' or 'exclude'."	
			return -1
		}
		set objs [$f_opts($path_name,class_listbox) curselection]
 		foreach object_class_idx $objs {
 			set object_class [$f_opts($path_name,class_listbox) get $object_class_idx]
 			set idx [string first $Apol_Analysis_dta::excluded_tag $object_class]
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
					$f_opts($path_name,class_listbox) itemconfigure \
						$object_class_idx -foreground gray
					set [$f_opts($path_name,class_listbox) cget -listvar] \
						[lreplace $items $object_class_idx \
						$object_class_idx \
						"$object_class$Apol_Analysis_dta::excluded_tag"]
				} else {
					$f_opts($path_name,class_listbox) itemconfigure \
						$object_class_idx \
						-foreground $f_opts($path_name,select_fg_orig)
					set [$f_opts($path_name,class_listbox) cget -listvar] \
						[lreplace $items $object_class_idx \
						$object_class_idx "$object_class"]
				}
  			}
  			if {$f_opts($path_name,class_selected_idx)  == $object_class_idx} {
  				set obj [$f_opts($path_name,class_listbox) get $object_class_idx]
  				$f_opts($path_name,permissions_title_frame) configure \
  					-text "Permissions for $obj:"
  			}
  		}
	}
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_change_obj_state_on_perm_select
#`	-  This proc also searches a class string for the sequence " (Excluded)"
# 	   in order to process the class name only. 
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_change_obj_state_on_perm_select {path_name} {
	variable f_opts

	set num_excluded 0	
	# There may be multiple selected items, but we need the object class that is currently displayed in
	# the text box. We have this index stored in our global class_selected_idx variable.
	if {$f_opts($path_name,class_selected_idx) != "-1"} {
		# Get the selected class string from the listbox
		set class_sel [$f_opts($path_name,class_listbox) get $f_opts($path_name,class_selected_idx)]
		# Check the string to see if it contains the special excluded tag
		set idx [string first $Apol_Analysis_dta::excluded_tag $class_sel]
		if {$idx != -1} {
			# If the excluded tag was found, extract just the class name portion from the string
			set class_sel [string range $class_sel 0 [expr $idx - 1]]
		}

		# Extract the class/value pairs from the array
		set class_elements [array get f_opts "$path_name,perm_status_array,$class_sel,*"]

		if {$class_elements != ""} {
			# The number of permissions for the class is equal to the number of pairs of elements
			set num_perms_for_class [expr [llength $class_elements] / 2]
			set len [llength $class_elements]
			for {set i 0} {$i < $len} {incr i} {
				# Skip the class string element
				incr i
				if {[string equal [lindex $class_elements $i] "exclude"]} {
					incr num_excluded	
				}
			}

			# Get a copy of the list class items from the listbox
			set items [$f_opts($path_name,class_listbox) get 0 end]
			# If the total all permissions for the object have been excluded then inform the user. 
			if {$num_excluded == $num_perms_for_class} {
				$f_opts($path_name,class_listbox) itemconfigure \
					$f_opts($path_name,class_selected_idx) -foreground gray
				set [$f_opts($path_name,class_listbox) cget -listvar] \
					[lreplace $items $f_opts($path_name,class_selected_idx) \
					$f_opts($path_name,class_selected_idx) \
					"$class_sel$Apol_Analysis_dta::excluded_tag"]
			} else {
				$f_opts($path_name,class_listbox) itemconfigure \
					$f_opts($path_name,class_selected_idx) \
					-foreground $f_opts($path_name,select_fg_orig)
				set [$f_opts($path_name,class_listbox) cget -listvar] \
					[lreplace $items $f_opts($path_name,class_selected_idx) \
					$f_opts($path_name,class_selected_idx) "$class_sel"]
			}
			$f_opts($path_name,permissions_title_frame) configure \
				-text "Permissions for [$f_opts($path_name,class_listbox) get \
					$f_opts($path_name,class_selected_idx)]:"
		}
	}
	
	return 0	
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_dta::forward_options_embed_perm_buttons 
#	- Embeds include/exclude radiobuttons in the permissions textbox next to
#	  each permission label.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_embed_perm_buttons {list_b class perm path_name} {
	variable f_opts
	
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
		-variable Apol_Analysis_dta::f_opts($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_dta::forward_options_change_obj_state_on_perm_select \
			$path_name"]	
	set cb_exclude [radiobutton $cb_frame.cb_exclude:$class:$perm -bg white \
		-value exclude -text "Exclude" \
		-highlightthickness 0 \
		-variable Apol_Analysis_dta::f_opts($path_name,perm_status_array,$class,$perm) \
		-command "Apol_Analysis_dta::forward_options_change_obj_state_on_perm_select \
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
# Command Apol_Analysis_dta::forward_options_clear_perms_text 
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_clear_perms_text {path_name} {
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
	$f_opts($path_name,perms_box) configure -state disabled
	return 0
}

proc Apol_Analysis_dta::render_permissions {path_name} {
	variable f_opts
	
	set class_idx [$f_opts($path_name,class_listbox) curselection]
	if {$class_idx == ""} {
		# Something was simply deselected.
		return 0
	} 
	focus -force $f_opts($path_name,class_listbox)
	set class_name [$f_opts($path_name,class_listbox) get $class_idx]
	$f_opts($path_name,permissions_title_frame) configure -text "Permissions for $class_name:"
	Apol_Analysis_dta::forward_options_clear_perms_text $path_name
	update 
	# Make sure to strip out just the class name, as this may be an excluded class.
	set idx [string first $Apol_Analysis_dta::excluded_tag $class_name]
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
	$f_opts($path_name,perms_box) configure -state normal
	foreach perm $perms_list { 
		# If this permission does not exist in our perm status array, this means
		# that a saved query was loaded and the permission defined in the policy
		# is not defined in the saved query. So we default this to be included.
		if {[array names f_opts "$path_name,perm_status_array,$class_name,$perm"] == ""} {
			set f_opts($path_name,perm_status_array,$class_name,$perm) include
		}
		$f_opts($path_name,perms_box) window create end -window \
			[Apol_Analysis_dta::forward_options_embed_perm_buttons \
			$f_opts($path_name,perms_box) $class_name $perm $path_name] 
		$f_opts($path_name,perms_box) insert end "\n"
	}
	# Disable the text widget. 
	$f_opts($path_name,perms_box) configure -state disabled
}

# ------------------------------------------------------------------------------
# Command Apol_Analysis_dta::forward_options_display_permissions 
# 	- Displays permissions for the selected object class in the permissions 
#	  text box.
#	- Takes the selected object class index as the only argument. 
#	  This proc also searches the class string for the sequence " (Excluded)"
# 	  in order to process the class name only. This is because a Tk listbox
# 	  is being used and does not provide a -text option for items in the 
# 	  listbox.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_display_permissions {path_name} {
	variable f_opts
	
	if {[$f_opts($path_name,class_listbox) get 0 end] == "" || \
	    [llength [$f_opts($path_name,class_listbox) curselection]] > 1} {
		# Nothing in the listbox; return
		return 
	}
	bind $f_opts($path_name,class_listbox) <<ListboxSelect>> ""
	set f_opts($path_name,class_selected_idx) [$f_opts($path_name,class_listbox) curselection]
	event generate $f_opts($path_name,perms_box) <<Rendering>> -when now 
	update idletasks
	bind $f_opts($path_name,class_listbox) <<ListboxSelect>> "Apol_Analysis_dta::forward_options_display_permissions $path_name"
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_initialize_objs_and_perm_filters
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_initialize_objs_and_perm_filters {path_name} {
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
#  Command Apol_Analysis_dta::forward_options_initialize_vars
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_initialize_vars {path_name} {
	variable f_opts
	
	if {$f_opts($path_name,filter_vars_init) == 0} {
		# Initialize all object classes/permissions and related information to default values
		Apol_Analysis_dta::forward_options_initialize_objs_and_perm_filters $path_name
		
  	        # Initialize included/excluded intermediate types section to default values
 		set f_opts($path_name,master_excl_types_list) $Apol_Types::typelist 
 		set idx [lsearch -exact $f_opts($path_name,master_excl_types_list) "self"]
  		if {$idx != -1} {
 			set f_opts($path_name,master_excl_types_list) \
 				 [lreplace $f_opts($path_name,master_excl_types_list) \
 				  $idx $idx]
  		}   
 	        set f_opts($path_name,master_incl_types_list) ""
 	        set f_opts($path_name,filtered_incl_types) $f_opts($path_name,master_incl_types_list)
 	        set f_opts($path_name,filtered_excl_types) $f_opts($path_name,master_excl_types_list)
  	        set f_opts($path_name,filter_vars_init) 1
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_set_widgets_to_default_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_set_widgets_to_default_state {path_name} {
	variable f_opts
	
	$f_opts($path_name,combo_incl) configure -values $Apol_Types::attriblist
     	$f_opts($path_name,combo_excl) configure -values $Apol_Types::attriblist
     	$f_opts($path_name,combo_excl) configure -text $f_opts($path_name,excl_attrib_combo_value)
	$f_opts($path_name,combo_incl) configure -text $f_opts($path_name,incl_attrib_combo_value)	
	
	set f_opts($path_name,select_fg_orig) [$f_opts($path_name,class_listbox) cget -foreground]

	# Configure the class listbox items to indicate excluded/included object classes.
        set class_lbox_idx 0
	# Configure the class listbox items to indicate excluded/included object classes.
        foreach class $f_opts($path_name,class_list) {
        	# Make sure to strip out just the class name, as this may be an excluded class.
		set idx [string first $Apol_Analysis_dta::excluded_tag $class]
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
				[lreplace $f_opts($path_name,class_list) $class_lbox_idx $class_lbox_idx \
				"$class$Apol_Analysis_dta::excluded_tag"]
			$f_opts($path_name,class_listbox) itemconfigure $class_lbox_idx -foreground gray
		} else {
			set [$f_opts($path_name,class_listbox) cget -listvar] \
			[lreplace $f_opts($path_name,class_list) $class_lbox_idx $class_lbox_idx "$class"]
			$f_opts($path_name,class_listbox) itemconfigure $class_lbox_idx \
				-foreground $f_opts($path_name,select_fg_orig)
		}
		incr class_lbox_idx
	}
	update
	Apol_Analysis_dta::forward_options_configure_combo_state \
		Apol_Analysis_dta::f_opts($path_name,incl_attrib_cb_sel) \
		$f_opts($path_name,combo_incl) \
		$f_opts($path_name,lbox_incl) \
		incl \
		$path_name
	Apol_Analysis_dta::forward_options_configure_combo_state \
		Apol_Analysis_dta::f_opts($path_name,excl_attrib_cb_sel) \
		$f_opts($path_name,combo_excl) \
		$f_opts($path_name,lbox_excl) \
		excl \
		$path_name
	Apol_Analysis_dta::forward_options_configure_class_perms_section $path_name
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_destroy_all_dialogs_on_open
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_destroy_all_dialogs_on_open {} {
	variable f_opts
	
	set dlgs [array get f_opts "*,name"]
	set length [llength $dlgs]
	for {set i 0} {$i < $length} {incr i} {
		# Skip the name of the element to the actual value of the element
		incr i
		Apol_Analysis_dta::forward_options_destroy_dialog [lindex $dlgs $i]
		Apol_Analysis_dta::forward_options_destroy_object [lindex $dlgs $i]
	}
	array unset f_opts
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_destroy_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_destroy_dialog {path_name} {
	variable f_opts
		
	if {[winfo exists $path_name]} {	
    		destroy $path_name
	 	unset f_opts($path_name,lbox_incl) 	
	 	unset f_opts($path_name,lbox_excl) 	
	 	unset f_opts($path_name,combo_incl) 	
	 	unset f_opts($path_name,combo_excl) 	 		
		unset f_opts($path_name,class_listbox) 
		unset f_opts($path_name,perms_box) 
		unset f_opts($path_name,permissions_title_frame) 
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_create_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_create_object {path_name} {
	variable f_opts
	
	set f_opts($path_name,name) 			$path_name
 	set f_opts($path_name,filtered_incl_types) 	""
 	set f_opts($path_name,filtered_excl_types) 	"" 
 	set f_opts($path_name,master_incl_types_list) 	""
 	set f_opts($path_name,master_excl_types_list) 	"" 
	set f_opts($path_name,class_list) 		""
	set f_opts($path_name,incl_attrib_combo_value)  ""
	set f_opts($path_name,excl_attrib_combo_value)  ""
	set f_opts($path_name,incl_attrib_cb_sel) 	0
	set f_opts($path_name,excl_attrib_cb_sel) 	0
	set f_opts($path_name,filter_vars_init) 	0
	set f_opts($path_name,class_selected_idx) 	-1
	
	# Initialize list and permission mapping data
	set rt [catch {Apol_Analysis_dta::forward_options_initialize_vars $path_name} err]
	if {$rt != 0} {
		puts "Error: $err"
		return -1
	}
 
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_copy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_copy_object {path_name new_object} {
	variable f_opts
	upvar 1 $new_object object 
	
	if {![array exists f_opts] || [array names f_opts "$path_name,name"] == ""} {
		Apol_Analysis_dta::forward_options_create_object $path_name
	}
	array set object [array get f_opts "$path_name,*"]
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_destroy_object
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_destroy_object {path_name} { 
	variable f_opts
	
	if {[array exists f_opts] && [array names f_opts "$path_name,name"] != ""} {
		array unset f_opts "$path_name,perm_status_array,*"
	 	unset f_opts($path_name,filtered_incl_types) 	
	 	unset f_opts($path_name,filtered_excl_types) 	
	 	unset f_opts($path_name,master_incl_types_list) 	
	 	unset f_opts($path_name,master_excl_types_list) 	 
		unset f_opts($path_name,class_list) 		
		unset f_opts($path_name,incl_attrib_combo_value) 
		unset f_opts($path_name,excl_attrib_combo_value) 
		unset f_opts($path_name,incl_attrib_cb_sel) 	
		unset f_opts($path_name,excl_attrib_cb_sel) 	
		unset f_opts($path_name,filter_vars_init) 	
		unset f_opts($path_name,class_selected_idx)
		unset f_opts($path_name,name)
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_refresh_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_refresh_dialog {path_name} { 
	if {[array exists f_opts] && \
	    [array names f_opts "$path_name,name"] != ""} {  
		Apol_Analysis_dta::forward_options_destroy_object $path_name	
		Apol_Analysis_dta::forward_options_create_object $path_name	
		Apol_Analysis_dta::forward_options_update_dialog $path_name
	}
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_select_all_lbox_items
#	- Takes a Tk listbox widget as an argument.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_select_all_lbox_items {lbox} {
        $lbox selection set 0 end
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_clear_all_lbox_items
#	- Takes a Tk listbox widget as an argument.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_clear_all_lbox_items {lbox} {
        $lbox selection clear 0 end
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::forward_options_create_dialog
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::forward_options_create_dialog {path_name title_txt} {
	variable f_opts 
	variable b_incl_all_perms
	variable b_excl_all_perms
	
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
    	} else {
	    	# Create a new options dialog object
    		Apol_Analysis_dta::forward_options_create_object $path_name
    	}
	
    	# Create the top-level dialog and subordinate widgets
    	toplevel $f_opts($path_name,name)
     	wm withdraw $f_opts($path_name,name)	
    	wm title $f_opts($path_name,name) $title_txt
   	wm protocol $f_opts($path_name,name) WM_DELETE_WINDOW " "
			
   	set close_frame [frame $f_opts($path_name,name).close_frame -relief sunken -bd 1]
   	set topf  [frame $f_opts($path_name,name).topf]
        set pw1 [PanedWindow $topf.pw1 -side left -weights available]
        $pw1 add -weight 2
        $pw1 add -weight 2
        pack $close_frame -side bottom -anchor center -pady 2
        pack $pw1 -fill both -expand yes	
        pack $topf -fill both -expand yes -padx 10 -pady 10
      
   	# Main Titleframes
   	set objs_frame  [TitleFrame [$pw1 getframe 1].objs_frame -text "Filter target domains by object class access:"]
        set types_frame [TitleFrame [$pw1 getframe 0].types_frame -text "Filter target domains by object type(s) access:"]
        
        set top_lbl [Label [$objs_frame getframe].top_lbl -justify left -font $ApolTop::dialog_font \
        	-text "Configure the query to search for transitions to domains with access to specific object classes:"]
       	
       	set bot_lbl [Label [$types_frame getframe].bot_lbl -justify left -font $ApolTop::dialog_font \
        	-text "Configure the query to search for transitions to domains with access to specific object types:"]
        pack $top_lbl $bot_lbl -side top -anchor nw -pady 3
   	
        # Widgets for object classes frame
        set pw1   [PanedWindow [$objs_frame getframe].pw -side top -weights available]
        set pane  [$pw1 add]
        set search_pane [$pw1 add]
        set pw2   [PanedWindow $pane.pw -side left -weights available]
        set class_pane 	[$pw2 add]
        set classes_box [TitleFrame $class_pane.tbox -text "Object Classes:" -bd 0]
        set f_opts($path_name,permissions_title_frame) [TitleFrame $search_pane.rbox -text "Permissions:" -bd 0]
        
        set sw_class [ScrolledWindow [$classes_box getframe].sw -auto none]
        set f_opts($path_name,class_listbox) [listbox [$sw_class getframe].lb \
        	-height 10 -highlightthickness 0 \
        	-bg white -selectmode extended \
        	-listvar Apol_Analysis_dta::f_opts($path_name,class_list) \
        	-exportselection 0]
        $sw_class setwidget $f_opts($path_name,class_listbox)  
   
	set sw_list [ScrolledWindow [$f_opts($path_name,permissions_title_frame) getframe].sw_c -auto none]
	set f_opts($path_name,perms_box) [text [$f_opts($path_name,permissions_title_frame) getframe].perms_box \
		-cursor $ApolTop::prevCursor \
		-bg white -font $ApolTop::text_font]
	$sw_list setwidget $f_opts($path_name,perms_box)
	bind $f_opts($path_name,perms_box) <<Rendering>> \
		"Apol_Analysis_dta::render_permissions $path_name"
		
	set bframe [frame [$f_opts($path_name,permissions_title_frame) getframe].bframe]
	set b_incl_all_perms [Button $bframe.b_incl_all_perms -text "Include All Perms" \
		-helptext "Select this to include all permissions for the selected object in the query." \
		-command "Apol_Analysis_dta::forward_options_include_exclude_permissions \
				include $path_name"]
	set b_excl_all_perms [Button $bframe.b_excl_all_perms -text "Exclude All Perms" \
		-helptext "Select this to exclude all permissions for the selected object from the query." \
		-command "Apol_Analysis_dta::forward_options_include_exclude_permissions \
				exclude $path_name"]
		
	# Bindings
	bind $f_opts($path_name,class_listbox) <<ListboxSelect>> \
        	"Apol_Analysis_dta::forward_options_display_permissions $path_name"
	bind $f_opts($path_name,class_listbox) <Double-Button-1> ""
	bind $f_opts($path_name,class_listbox) <Triple-Button-1> ""
	bind $f_opts($path_name,class_listbox) <Quadruple-Button-1> ""	
        		           
	pack $classes_box -padx 2 -side left -fill both -expand yes
        pack $f_opts($path_name,permissions_title_frame) -pady 2 -padx 2 -fill both -expand yes
        pack $pw1 -fill both -expand yes
        pack $pw2 -fill both -expand yes
       	pack $b_excl_all_perms -side right -anchor nw -pady 2 -expand yes -fill x	
       	pack $b_incl_all_perms -side left -anchor nw -pady 2 -expand yes -fill x
        pack $topf -fill both -expand yes -padx 10 -pady 10   
        pack $sw_class -fill both -expand yes -side top
        pack $bframe -side bottom -fill both -anchor sw -pady 2
	pack $sw_list -fill both -expand yes -side top
        	
        # Widgets for types frame
        set include_f [TitleFrame [$types_frame getframe].include_f -text "Include these types:" -bd 0]
        set middle_f  [frame [$types_frame getframe].middle_f]
        set exclude_f [TitleFrame [$types_frame getframe].exclude_f -text "Exclude these types:" -bd 0]
        set b_incl_f  [frame [$include_f getframe].b_incl_f]
        set b_excl_f  [frame [$exclude_f getframe].b_excl_f]
        set buttons_incl_f [frame $b_incl_f.buttons_incl_f]
        set buttons_excl_f [frame $b_excl_f.buttons_excl_f]
        
        set sw_incl [ScrolledWindow [$include_f getframe].sw_incl]
  	set sw_excl [ScrolledWindow [$exclude_f getframe].sw_excl]	
	set f_opts($path_name,lbox_incl) [listbox [$sw_incl getframe].lbox_incl -height 6 \
		-highlightthickness 0 -listvar Apol_Analysis_dta::f_opts($path_name,filtered_incl_types) \
		-selectmode extended -bg white -exportselection 0]
	set f_opts($path_name,lbox_excl) [listbox [$sw_excl getframe].lbox_excl -height 6 \
		-highlightthickness 0 -listvar Apol_Analysis_dta::f_opts($path_name,filtered_excl_types) \
		-selectmode extended -bg white -exportselection 0]
	$sw_incl setwidget $f_opts($path_name,lbox_incl)
	$sw_excl setwidget $f_opts($path_name,lbox_excl)
	
	bind $f_opts($path_name,lbox_incl) <<ListboxSelect>> "focus -force $f_opts($path_name,lbox_incl)"
	bind $f_opts($path_name,lbox_excl) <<ListboxSelect>> "focus -force $f_opts($path_name,lbox_excl)"
	
	bind $f_opts($path_name,lbox_incl) <KeyPress> "ApolTop::tklistbox_select_on_key_callback \
			$Apol_Analysis_dta::f_opts($path_name,lbox_incl) \
			Apol_Analysis_dta::f_opts($path_name,filtered_incl_types) \
			%K"
	bind $f_opts($path_name,lbox_excl) <KeyPress> "ApolTop::tklistbox_select_on_key_callback \
			$Apol_Analysis_dta::f_opts($path_name,lbox_excl) \
			Apol_Analysis_dta::f_opts($path_name,filtered_excl_types) \
			%K"
			
        set include_bttn [Button $middle_f.include_bttn -text "<--" \
        	-helptext "Include this type in the query" -width 8 \
		-command "Apol_Analysis_dta::forward_options_include_types \
			Apol_Analysis_dta::f_opts($path_name,filtered_excl_types) \
			Apol_Analysis_dta::f_opts($path_name,filtered_incl_types) \
			$Apol_Analysis_dta::f_opts($path_name,lbox_excl) \
			$Apol_Analysis_dta::f_opts($path_name,lbox_incl) \
			Apol_Analysis_dta::f_opts($path_name,master_incl_types_list) \
			Apol_Analysis_dta::f_opts($path_name,master_excl_types_list) \
			$path_name"]
	set exclude_bttn [Button $middle_f.exclude_bttn -text "-->" \
		-helptext "Exclude this type from the query" -width 8 \
		-command "Apol_Analysis_dta::forward_options_exclude_types \
			Apol_Analysis_dta::f_opts($path_name,filtered_incl_types) \
			Apol_Analysis_dta::f_opts($path_name,filtered_excl_types) \
			$Apol_Analysis_dta::f_opts($path_name,lbox_incl) \
			$Apol_Analysis_dta::f_opts($path_name,lbox_excl) \
			Apol_Analysis_dta::f_opts($path_name,master_incl_types_list) \
			Apol_Analysis_dta::f_opts($path_name,master_excl_types_list) \
			$path_name"]
	set b_incl_all_sel [Button $buttons_incl_f.b_incl_all_sel -text "Select All" \
		-command "Apol_Analysis_dta::forward_options_select_all_lbox_items \
			$Apol_Analysis_dta::f_opts($path_name,lbox_incl)"]
	set b_incl_all_clear [Button $buttons_incl_f.b_incl_all_clear -text "Unselect" \
		-command "Apol_Analysis_dta::forward_options_clear_all_lbox_items \
			$Apol_Analysis_dta::f_opts($path_name,lbox_incl)"]
	set b_excl_all_sel [Button $buttons_excl_f.b_excl_all_sel -text "Select All" \
		-command "Apol_Analysis_dta::forward_options_select_all_lbox_items \
			$Apol_Analysis_dta::f_opts($path_name,lbox_excl)"]
	set b_excl_all_clear [Button $buttons_excl_f.b_excl_all_clear -text "Unselect" \
		-command "Apol_Analysis_dta::forward_options_clear_all_lbox_items \
			$Apol_Analysis_dta::f_opts($path_name,lbox_excl)"]
	
	set f_opts($path_name,combo_incl) [ComboBox $b_incl_f.combo_incl \
		-editable 0 -autopost 1 \
    		-textvariable Apol_Analysis_dta::f_opts($path_name,incl_attrib_combo_value) \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd "Apol_Analysis_dta::forward_options_filter_types_using_attrib \
  				Apol_Analysis_dta::f_opts($path_name,incl_attrib_combo_value) \
  				$Apol_Analysis_dta::f_opts($path_name,lbox_incl) \
 				Apol_Analysis_dta::f_opts($path_name,master_incl_types_list)"] 
  	
  	set f_opts($path_name,combo_excl) [ComboBox [$exclude_f getframe].combo_excl \
		-editable 0 -autopost 1 \
    		-textvariable Apol_Analysis_dta::f_opts($path_name,excl_attrib_combo_value) \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd "Apol_Analysis_dta::forward_options_filter_types_using_attrib \
				Apol_Analysis_dta::f_opts($path_name,excl_attrib_combo_value) \
				$Apol_Analysis_dta::f_opts($path_name,lbox_excl) \
				Apol_Analysis_dta::f_opts($path_name,master_excl_types_list)"] 
				
	set cb_incl_attrib [checkbutton $b_incl_f.cb_incl_attrib \
		-text "Filter included type(s) by attribute:" \
		-variable Apol_Analysis_dta::f_opts($path_name,incl_attrib_cb_sel) \
		-offvalue 0 -onvalue 1 \
		-command "Apol_Analysis_dta::forward_options_configure_combo_state \
			Apol_Analysis_dta::f_opts($path_name,incl_attrib_cb_sel) \
			$Apol_Analysis_dta::f_opts($path_name,combo_incl) \
			$Apol_Analysis_dta::f_opts($path_name,lbox_incl) \
			incl \
			$path_name"]
	set cb_excl_attrib [checkbutton [$exclude_f getframe].cb_excl_attrib \
		-text "Filter excluded type(s) by attribute:" \
		-variable Apol_Analysis_dta::f_opts($path_name,excl_attrib_cb_sel) \
		-offvalue 0 -onvalue 1 \
		-command "Apol_Analysis_dta::forward_options_configure_combo_state \
			Apol_Analysis_dta::f_opts($path_name,excl_attrib_cb_sel) \
			$Apol_Analysis_dta::f_opts($path_name,combo_excl) \
			$Apol_Analysis_dta::f_opts($path_name,lbox_excl) \
			excl \
			$path_name"]
			    
	# Create and pack close button for the dialog
  	set close_bttn [Button $close_frame.close_bttn -text "Close" -width 8 \
		-command "Apol_Analysis_dta::forward_options_destroy_dialog $f_opts($path_name,name)"]
	pack $close_bttn -side left -anchor center
					  	
	# pack all subframes and widgets for the types frame
	pack $b_excl_f -side bottom -anchor center -pady 2 
	pack $buttons_excl_f -side bottom -anchor center -pady 2
	pack $b_excl_all_sel $b_excl_all_clear -side left -anchor center -expand yes -pady 2
	pack $sw_excl -side top -anchor nw -fill both -expand yes -pady 2 -padx 6
	pack $cb_excl_attrib -side top -anchor center -padx 6
	pack $f_opts($path_name,combo_excl) -side top -anchor center -pady 2 -padx 15 
	
	pack $b_incl_f -side bottom -anchor center -pady 2 
	pack $buttons_incl_f -side bottom -anchor center -pady 2
	pack $b_incl_all_sel $b_incl_all_clear -side left -anchor center -expand yes -pady 2
	pack $sw_incl -side top -anchor nw -fill both -expand yes -pady 2 -padx 6
	pack $cb_incl_attrib -side top -anchor center -padx 6
	pack $f_opts($path_name,combo_incl) -side top -anchor center -pady 2 -padx 15 
	
	pack $include_bttn $exclude_bttn -side top -pady 2 -anchor center
	pack $include_f $exclude_f -side left -anchor nw -fill both -expand yes
	pack $middle_f -side left -anchor center -after $include_f -padx 5 -expand yes
	pack $objs_frame $types_frame -side top -anchor nw -padx 5 -pady 2 -expand yes -fill both
    	
        # Configure top-level dialog specifications
	set width 780
	set height 750
        wm geom $f_opts($path_name,name) ${width}x${height}
	wm deiconify $f_opts($path_name,name)
	focus $f_opts($path_name,name)

	Apol_Analysis_dta::forward_options_set_widgets_to_default_state $path_name
	wm protocol $f_opts($path_name,name) WM_DELETE_WINDOW \
		"Apol_Analysis_dta::forward_options_destroy_dialog $path_name"
	return 0
}

####################################################################
# The following procedures are for the main tab of the dta analysis.
#

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::close { } {   
	Apol_Analysis_dta::reset_variables
	
     	$Apol_Analysis_dta::combo_attribute configure -values ""
     	$Apol_Analysis_dta::combo_domain configure -values ""
	$Apol_Analysis_dta::combo_attribute configure -state disabled -entrybg $ApolTop::default_bg_color
	
	Apol_Analysis_dta::configure_widgets_for_dta_direction
        Apol_Analysis_dta::config_attrib_comboBox_state
	Apol_Analysis_dta::config_endtype_state
	
	Apol_Analysis_dta::forward_options_destroy_all_dialogs_on_open
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::open { } {  
	Apol_Analysis_dta::populate_ta_list	
	Apol_Analysis_dta::change_types_list	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::initialize { } { 	
	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_analysis_info { } {   
	return $Apol_Analysis_dta::descriptive_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_results_raised_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_results_raised_tab {} {
     	return $Apol_Analysis_dta::dta_info_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::display_mod_options { opts_frame } {
	variable f_opts
	
	# Selecting a new module will reset current values
	Apol_Analysis_dta::reset_variables
	Apol_Analysis_dta::forward_options_refresh_dialog \
		$Apol_Analysis_dta::forward_options_Dlg	
     	
     	Apol_Analysis_dta::create_options $opts_frame
     	Apol_Analysis_dta::configure_widgets_for_dta_direction
     	Apol_Analysis_dta::populate_ta_list
     	Apol_Analysis_dta::config_endtype_state
     	
     	if {[ApolTop::is_policy_open]} {
	     	# Have the attributes checkbutton OFF by default
		set Apol_Analysis_dta::display_attrib_sel	0
		Apol_Analysis_dta::config_attrib_comboBox_state
		Apol_Analysis_dta::change_types_list	
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::load_dta_advanced_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::load_dta_advanced_query_options {query_options curr_idx path_name parentDlg} {
	variable f_opts

	# Destroy the current forward DTA options object    	
	Apol_Analysis_dta::forward_options_destroy_object $path_name
	# Create a new forward DTA options object
	Apol_Analysis_dta::forward_options_create_object $path_name
	# Clear our list
	set f_opts($path_name,master_excl_types_list) ""
	# Now we begin our gory parsing! Hold onto your seat!
        # Set our counter variable to the next element in the query options list, which is now the 8th element 
        # We need a counter variable at this point because we start to parse list elements.
	set i $curr_idx
        # ignore an empty list, which is indicated by '{}'
        if {[lindex $query_options $i] != "\{\}"} {
        	# we have to pretend to parse a list here since this is a string and not a TCL list.
        	# First, filter out the open bracket
	        set split_list [split [lindex $query_options $i] "\{"]
	        # An empty list element will be generated because the first character '{' of string 
	        # is in splitChars, so we ignore the first element of the split list.

	        set perm_status_list [lappend perm_status_list [lindex $split_list 1]]
	        # Update our counter variable to the next element in the query options list
	        set i [expr $i + 1]
	        # Loop through the query list, trying to split each element by a close bracket, in order to see
	        # if this is the last element of the permission status list. If the '}' delimter is found in the
	        # element, then the length of the list returned by the TCL split command is greater than 1. At
	        # this point, we then break out of the while loop and then parse this last element of the query 
	        # options list.
	        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
	        	set perm_status_list [lappend perm_status_list [lindex $query_options $i]]
	        	# Increment to the next element in the query options list
	        	incr i
	        }
	        # This is the end of the list, so grab the first element of the split list, since the last 
	        # element of split list is an empty list element because the last char of the element is a '}'.
	        set perm_status_list [lappend perm_status_list [lindex [split [lindex $query_options $i] "\}"] 0]]
					        
      		# OK, now that we have list of class,permission and perm status, 
      		# filter out permissions that do not exist in the policy. 
      		for {set j 0} {$j < [llength $perm_status_list]} {incr j} {
      			set elements [split [lindex $perm_status_list $j] ","]
      			# We skip index 0 and 1 because this holds the path name #
      			# and the key string "perm_status_array"
      			set class_name [lindex $elements 0]
      			if {[lsearch -exact $f_opts($path_name,class_list) "$class_name"] == -1} {
      				puts "Invalid class: $class_name.....ignoring."
      				continue
      			}
      			set perm [lindex $elements 1]	
      			set rt [catch {set perms_list [apol_GetPermsByClass $class_name 1]} err]
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" \
					-message $err \
					-parent $parentDlg
			}
      			if {[lsearch -exact $perms_list $perm] == -1} {
      				puts "Invalid permission: $perm.....ignoring."
      				continue	
      			}
      			# This is a valid class and permission for the currently loaded policy.
      			# Get the element name to the perm array list
      			set element [lindex $perm_status_list $j]
      
      			incr j
      			# Get the perm status value from the list
      			set val [lindex $perm_status_list $j]
      			set str "$path_name,perm_status_array,$element"
      			set f_opts($str) $val
      		}
       	}

      	# Now we're ready to parse the excluded intermediate types list
      	incr i
      	set invalid_types ""
      	# ignore an empty list, which is indicated by '{}'
        if {[lindex $query_options $i] != "\{\}"} {
        	# we have to pretend to parse a list here since this is a string and not a TCL list.
        	# First, filter out the open bracket
	        set split_list [split [lindex $query_options $i] "\{"]
	        if {[llength $split_list] == 1} {
	        	# Validate that the type exists in the loaded policy.
     			if {[lsearch -exact $Apol_Types::typelist [lindex $query_options $i]] != -1} {
	        		set f_opts($path_name,master_excl_types_list) [lindex $query_options $i]
	        	} else {
	        		set invalid_types [lappend invalid_types [lindex $query_options $i]]
	     		} 
		} else {
		        # An empty list element will be generated because the first character '{' of string 
		        # is in splitChars, so we ignore the first element of the split list.
		        # Validate that the type exists in the loaded policy.
     			if {[lsearch -exact $Apol_Types::typelist [lindex $split_list 1]] != -1} {
		        	set f_opts($path_name,master_excl_types_list) [lappend f_opts($path_name,master_excl_types_list) \
		        		[lindex $split_list 1]]
		        } else {
	     			set invalid_types [lappend invalid_types [lindex $split_list 1]]
	     		} 
		        # Update our counter variable to the next element in the query options list
		        set i [expr $i + 1]
		        # Loop through the query list, trying to split each element by a close bracket, in order to see
		        # if this is the last element of the permission status list. If the '}' delimter is found in the
		        # element, then the length of the list returned by the TCL split command is greater than 1. At
		        # this point, we then break out of the while loop and then parse this last element of the query 
		        # options list.
		        while {[llength [split [lindex $query_options $i] "\}"]] == 1} {
		        	# Validate that the type exists in the loaded policy.
     				if {[lsearch -exact $Apol_Types::typelist [lindex $query_options $i]] != -1} {
		        		set f_opts($path_name,master_excl_types_list) [lappend f_opts($path_name,master_excl_types_list) \
		        			[lindex $query_options $i]]
		        	} else {
		     			set invalid_types [lappend invalid_types [lindex $query_options $i]]
		     		} 
		        	# Increment to the next element in the query options list
		        	incr i
		        }
		        # This is the end of the list, so grab the first element of the split list, since the last 
		        # element of split list is an empty list element because the last char of the element is a '}'.
		        set end_element [lindex [split [lindex $query_options $i] "\}"] 0]
		        # Validate that the type exists in the loaded policy.
     			if {[lsearch -exact $Apol_Types::typelist $end_element] != -1} {
		        	set f_opts($path_name,master_excl_types_list) [lappend f_opts($path_name,master_excl_types_list) $end_element]
		        } else {
	     			set invalid_types [lappend invalid_types $end_element]
	     		} 
	     		set idx [lsearch -exact $f_opts($path_name,master_excl_types_list) "self"]
			if {$idx != -1} {
				set f_opts($path_name,master_excl_types_list) [lreplace $f_opts($path_name,master_excl_types_list) \
					$idx $idx]
			}
		}
      	}
      	# Display a popup with a list of invalid types
	if {$invalid_types != ""} {
		puts "The following types do not exist in the currently \
			loaded policy and were ignored:\n\n"
		foreach type $invalid_types {
			puts "$type\n"	
		}
	}
      	foreach type $Apol_Types::typelist {
		if {$type != "self"} {
			# Search the master excluded inter types list
			set idx [lsearch -exact $f_opts($path_name,master_excl_types_list) $type]
			if {$idx == -1} {
				# Type was not found in the excluded list, so add to master included list
     				set f_opts($path_name,master_incl_types_list) \
     					[lappend f_opts($path_name,master_incl_types_list) $type]
     			}
     		}
	}   
	# We will filter the list that is displayed later based upon the attribute settings when we update the dialog.
	set f_opts($path_name,filtered_incl_types) $f_opts($path_name,master_incl_types_list) 
	set f_opts($path_name,filtered_excl_types) $f_opts($path_name,master_excl_types_list) 
		
      	# Update our counter variable to the next element in the query options list
      	incr i
      	if {[lindex $query_options $i] != "\{\}"} {
      		set tmp [string trim [lindex $query_options $i] "\{\}"]
      		if {[lsearch -exact $Apol_Types::attriblist $tmp] != -1} {
        		set f_opts($path_name,incl_attrib_combo_value) $tmp
        	} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified attribute $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
		}
        }
        incr i
        if {[lindex $query_options $i] != "\{\}"} {
        	set tmp [string trim [lindex $query_options $i] "\{\}"]
        	if {[lsearch -exact $Apol_Types::attriblist $tmp] != -1} {
        		set f_opts($path_name,excl_attrib_combo_value) $tmp
        	} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified attribute $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
		}
        }
        incr i
        set f_opts($path_name,incl_attrib_cb_sel) [lindex $query_options $i]
        incr i
        set f_opts($path_name,excl_attrib_cb_sel) [lindex $query_options $i]

	return $i	
}

proc Apol_Analysis_dta::parse_name_value_pairs {query_options curr_idx} { 
	variable endtype_sel_state			
	variable end_type_state			
	variable use_filters_state
	
	set i $curr_idx
	while {$i != [llength $query_options]} {
		set tmp [string trim [lindex $query_options $i] "\{\}"]
        	# name:value pairs. 
        	switch -exact -- $tmp {
        		"End_Type_Bool" { 
        			incr i
				set endtype_sel_state [lindex $query_options $i]    
			}
			"End_Type_String" {
				incr i
				if {[lindex $query_options $i] != "\{\}"} {
					set tmp [string trim [lindex $query_options $i] "\{\}"]
			        	set end_type_state $tmp  
			        }
			}
			"Use_Filters_Bool" {
				incr i
			        set use_filters_state [lindex $query_options $i] 
			}
			default {
				puts "Error: Unknown query option name encountered ([lindex $query_options $i])."
			}
        	}
        	incr i
        }
     
	return $i
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::load_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::load_query_options { file_channel parentDlg } {         
        variable type_state		
	variable attribute_state		
	variable attrib_selected_state 
	variable direction_state
	# Forward DTA advanced search variables
	variable f_opts
	variable forward_options_Dlg
		
	set query_options ""
	set query_options_tmp ""
	set path_name $forward_options_Dlg
        while {[eof $file_channel] != 1} {
		gets $file_channel line
		set tline [string trim $line]
		# Skip empty lines and comments
		if {$tline == "" || [string compare -length 1 $tline "#"] == 0} {
			continue
		}
		set query_options_tmp [lappend query_options_tmp $tline]
	}
	if {$query_options_tmp == ""} {
		return -code error "No query parameters were found."
	}
	
	# Re-format the query options list into a string where all elements are seperated
	# by a single space. Then split this string into a list using whitespace as the delimeter.	
	set query_options_tmp [split [join $query_options_tmp " "] " "]
	set query_options [ApolTop::strip_list_of_empty_items $query_options_tmp]
	if {$query_options == ""} {
		return -code error "No query parameters were found."
	}
	
     	if {[lindex $query_options 0] != "\{\}"} {
     		set tmp [string trim [lindex $query_options 0] "\{\}"]
     		# Validate that the type exists in the loaded policy.
     		if {[lsearch -exact $Apol_Types::typelist $tmp] != -1} {
     			set type_state $tmp
     		} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified type starting source domain type $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
     		}     		
     	}
     	if {[lindex $query_options 1] != "\{\}"} {
     		set tmp [string trim [lindex $query_options 1] "\{\}"]
     		if {[lsearch -exact $Apol_Types::attriblist $tmp] != -1} {
     			set attribute_state $tmp
     		} else {
     			tk_messageBox -icon warning -type ok -title "Warning" \
				-message "The specified attribute $tmp does not exist in the currently \
				loaded policy. It will be ignored." \
				-parent $parentDlg
		}
     	}
	set attrib_selected_state [lindex $query_options 2]
	
	if {[lindex $query_options 3] != "\{\}"} {
     		set tmp [string trim [lindex $query_options 3] "\{\}"]
     		set direction_state $tmp
     	}
     	set i 4
     	if {[lindex $query_options $i]} { 
     		set i 5
     		set i [Apol_Analysis_dta::load_dta_advanced_query_options $query_options $i $path_name $parentDlg]
     	}
  	incr i
  	
  	# As of version 1.6 we parse name:value pairs
	Apol_Analysis_dta::parse_name_value_pairs $query_options $i 
								 	
	# After updating any display variables, must configure widgets accordingly
	Apol_Analysis_dta::update_display_variables 
	Apol_Analysis_dta::configure_widgets_for_dta_direction
	Apol_Analysis_dta::config_attrib_comboBox_state	
	Apol_Analysis_dta::config_endtype_state
	
	if {[lindex $query_options 4]} { 
		Apol_Analysis_dta::forward_options_update_dialog $path_name
	}
	
	if { $attribute_state != "" } {
		# Need to change the types list to reflect the currently selected attrib and then reset the 
		# currently selected type in the types combo box. 
		Apol_Analysis_dta::change_types_list  	
		set Apol_Analysis_dta::display_type $type_state
	}
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::save_query_options {module_name file_channel file_name} {
	variable display_type			
	variable display_attribute		
	variable display_attrib_sel
	variable display_direction
	variable endtype_sel			
	variable end_type			
	variable use_filters			   	
	# Forward DTA advanced search variables
	variable f_opts
	variable forward_options_Dlg
		
	if {$Apol_Analysis_dta::display_direction == "forward"} {
		# If the advanced options object has not been created, then create
		if {![array exists f_opts] || [array names f_opts "$forward_options_Dlg,name"] == ""} {
			Apol_Analysis_dta::forward_options_create_object $forward_options_Dlg
		}
					
		set class_perms_list_tmp [array get f_opts "$forward_options_Dlg,perm_status_array,*"]
		set class_perms_list ""
		set len [llength $class_perms_list_tmp]
		set idx [string length "$forward_options_Dlg,perm_status_array,"]
		for {set i 0} {$i < $len} {incr i} {
			set str [string range [lindex $class_perms_list_tmp $i] $idx end]
			incr i
			set class_perms_list [lappend class_perms_list $str [lindex $class_perms_list_tmp $i]]
		}
		
		set options [list \
	     		$display_type \
	     		$display_attribute \
	     		$display_attrib_sel \
	     		$display_direction \
	     		1 \
	     		$class_perms_list \
			$f_opts($forward_options_Dlg,master_excl_types_list) \
			$f_opts($forward_options_Dlg,incl_attrib_combo_value) \
			$f_opts($forward_options_Dlg,excl_attrib_combo_value) \
			$f_opts($forward_options_Dlg,incl_attrib_cb_sel) \
			$f_opts($forward_options_Dlg,excl_attrib_cb_sel) \
	     		"End_Type_Bool" \
	     		$endtype_sel \
	     		"End_Type_String" \
	     		$end_type \
	     		"Use_Filters_Bool" \
	     		$use_filters]
	} else {
		set options [list \
	     		$display_type \
	     		$display_attribute \
	     		$display_attrib_sel \
	     		$display_direction \
	     		0 \
	     		"End_Type_Bool" \
	     		$endtype_sel \
	     		"End_Type_String" \
	     		$end_type \
	     		"Use_Filters_Bool" \
	     		$use_filters]
	}
		 
     	puts $file_channel "$module_name"
	puts $file_channel "$options"
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_current_results_state { } {
	variable display_type			
	variable display_attribute		
	variable display_attrib_sel
	variable display_direction
	variable endtype_sel			
	variable end_type			
	variable use_filters	
	variable dta_tree
	variable dta_info_text
	# Advanced foward options DTA variables
	variable f_opts
	variable forward_options_Dlg
	
	# If the advanced options object has not been created, then create
	if {![array exists f_opts] || [array names f_opts "$forward_options_Dlg,name"] == ""} {
		Apol_Analysis_dta::forward_options_create_object $forward_options_Dlg
	}
	set class_perms_list [array get f_opts "$forward_options_Dlg,perm_status_array,*"]
		     	
     	set options [list \
     		$dta_tree \
     		$dta_info_text \
     		$display_type \
     		$display_attribute \
     		$display_attrib_sel \
     		$display_direction \
     		$class_perms_list \
		$f_opts($forward_options_Dlg,filtered_incl_types) \
		$f_opts($forward_options_Dlg,filtered_excl_types) \
		$f_opts($forward_options_Dlg,master_incl_types_list) \
		$f_opts($forward_options_Dlg,master_excl_types_list) \
		$f_opts($forward_options_Dlg,incl_attrib_combo_value) \
		$f_opts($forward_options_Dlg,excl_attrib_combo_value) \
		$f_opts($forward_options_Dlg,incl_attrib_cb_sel) \
		$f_opts($forward_options_Dlg,excl_attrib_cb_sel) \
		$f_opts($forward_options_Dlg,class_selected_idx) \
		$endtype_sel \
		$end_type \
		$use_filters]
     	return $options
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::set_display_to_results_state { query_options } {     	
     	variable type_state		
	variable attribute_state		
	variable attrib_selected_state 
	variable direction_state
	variable endtype_sel_state			
	variable end_type_state			
	variable use_filters_state	
	variable dta_tree
	variable dta_info_text
	# Advanced foward options DTA variables
	variable f_opts
	variable forward_options_Dlg
			    
	# widget variables
	set dta_tree 			[lindex $query_options 0]
     	set dta_info_text 		[lindex $query_options 1]
     	# query options variables
     	set type_state 			[lindex $query_options 2]
     	set attribute_state  		[lindex $query_options 3]
     	set attrib_selected_state 	[lindex $query_options 4]
     	set direction_state 		[lindex $query_options 5]
     	
     	# At this point we need to handle the data used by the advanced foward DTA options dialog.
        # If the advanced options object doesn't exist, then create it.
	if {![array exists f_opts] || [array names f_opts "$forward_options_Dlg,name"] == ""} {
		Apol_Analysis_dta::forward_options_create_object $forward_options_Dlg
	}
	set obj_perms_list [lindex $query_options 6]
	set len [llength $obj_perms_list]
	if {$len > 0} {
		array unset f_opts "$forward_options_Dlg,perm_status_array,*"
	}
	for {set i 0} {$i < $len} {incr i} {
		set element [lindex $obj_perms_list $i]
		incr i
		set val [lindex $obj_perms_list $i]
		set f_opts($element) $val
	}

        set f_opts($forward_options_Dlg,filtered_incl_types) 		[lindex $query_options 7]
        set f_opts($forward_options_Dlg,filtered_excl_types) 		[lindex $query_options 8]
        set f_opts($forward_options_Dlg,master_incl_types_list) 	[lindex $query_options 9]
        set f_opts($forward_options_Dlg,master_excl_types_list) 	[lindex $query_options 10]
        set f_opts($forward_options_Dlg,incl_attrib_combo_value) 	[lindex $query_options 11]
        set f_opts($forward_options_Dlg,excl_attrib_combo_value) 	[lindex $query_options 12]
        set f_opts($forward_options_Dlg,incl_attrib_cb_sel) 		[lindex $query_options 13]
        set f_opts($forward_options_Dlg,excl_attrib_cb_sel) 		[lindex $query_options 14]
        set f_opts($forward_options_Dlg,class_selected_idx)		[lindex $query_options 15]
        set endtype_sel_state	[lindex $query_options 16]		
	set end_type_state	[lindex $query_options 17]	 	
	set use_filters_state	[lindex $query_options 18]
        set f_opts($forward_options_Dlg,filter_vars_init) 		1
    
	# After updating any display variables, must configure widgets accordingly
	Apol_Analysis_dta::update_display_variables 
	Apol_Analysis_dta::configure_widgets_for_dta_direction
	Apol_Analysis_dta::config_attrib_comboBox_state	
	Apol_Analysis_dta::config_endtype_state
	
	if { $attribute_state != "" } {
		# Need to change the types list to reflect the currently selected attrib and then reset the 
		# currently selected type in the types combo box. 
		Apol_Analysis_dta::change_types_list  	
		set Apol_Analysis_dta::display_type $type_state
	}
	
	if {[winfo exists $Apol_Analysis_dta::forward_options_Dlg]} {
		Apol_Analysis_dta::forward_options_update_dialog $forward_options_Dlg
		raise $Apol_Analysis_dta::forward_options_Dlg
		focus $Apol_Analysis_dta::forward_options_Dlg
	}

     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::free_results_data
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::free_results_data {query_options} {  
	set dta_tree [lindex $query_options 0]
     	set dta_info_text [lindex $query_options 1]

	if {[winfo exists $dta_tree]} {
		$dta_tree delete [$dta_tree nodes root]
		if {[$dta_tree nodes root] != ""} {
			return -1			
		}
		destroy $dta_tree
	} 
	if {[winfo exists $dta_info_text]} {
		$dta_info_text delete 0.0 end
		destroy $dta_info_text
	}
}

proc Apol_Analysis_dta::destroy_progressDlg {} {
	variable progressDlg
	
	if {[winfo exists $progressDlg]} {
		destroy $progressDlg
	}
} 

proc Apol_Analysis_dta::display_progressDlg {} {
     	variable progressDlg
	    		
	set Apol_Analysis_dta::progressmsg "Performing domain transition analysis..."
	set progressBar [ProgressDlg $progressDlg \
		-parent $ApolTop::mainframe \
        	-textvariable Apol_Analysis_dta::progressmsg \
        	-variable Apol_Analysis_dta::progress_indicator \
        	-maximum 3 \
        	-width 45]
        update
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::do_analysis { results_frame } {     
	variable display_type		
	variable display_attribute		
	variable display_attrib_sel 
	variable endtype_sel		
	variable end_type
	variable dta_tree
	variable dta_info_text
	# Advanced foward options DTA variables
	variable f_opts
	variable forward_options_Dlg
	
        if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -code error
        } 
        Apol_Analysis_dta::display_progressDlg
        
        # Initialize local variables
        set reverse 0
	set num_object_classes 0
	set perm_options ""
        set types ""
	set use_filters 0
	
        # Only parse advanced options if this is a forward DTA analysis 
      	if {$Apol_Analysis_dta::display_direction == "forward"} {
      		if {$Apol_Analysis_dta::use_filters} {
			set types $f_opts($forward_options_Dlg,filtered_incl_types)
		     	
			# At this point we need to handle the data used by the advanced foward DTA options dialog.
		        # If the advanced options object doesn't exist, then create it.
			if {![array exists f_opts] || [array names f_opts "$forward_options_Dlg,name"] == ""} {
				Apol_Analysis_dta::forward_options_create_object $forward_options_Dlg
			}
	
			foreach class $f_opts($forward_options_Dlg,class_list) {
				set perms ""
				# Make sure to strip out just the class name, as this may be an excluded class.
				set idx [string first $Apol_Analysis_dta::excluded_tag $class]
				if {$idx == -1} {
					set class_elements [array names f_opts "$forward_options_Dlg,perm_status_array,$class,*"]
					set class_added 0
					foreach element $class_elements {
						set perm [lindex [split $element ","] 3]
						if {[string equal $f_opts($element) "include"]} {
							if {$class_added == 0} {
								incr num_object_classes 
								set perm_options [lappend perm_options $class]
								set class_added 1
							}	
							set perms [lappend perms $perm]
						}
					}
					if {$perms != ""} {
						set perm_options [lappend perm_options [llength $perms]]
						foreach perm $perms {
							set perm_options [lappend perm_options $perm]
						}
					}	
				}
			}
			set use_filters 1
		} 
	} else {
		set reverse 1
	}

     	set rt [catch {set results [apol_DomainTransitionAnalysis \
     		$reverse \
     		$display_type \
     		$use_filters \
     		$num_object_classes \
     		$perm_options \
		$types \
		$endtype_sel \
		$end_type]} err]
	Apol_Analysis_dta::destroy_progressDlg	
     	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 

	set query_args [list \
		$reverse \
     		$display_type \
     		$use_filters \
     		$num_object_classes \
     		$perm_options \
		$types \
		$endtype_sel \
		$end_type]

	set dta_tree [Apol_Analysis_dta::create_resultsDisplay $results_frame $reverse]
	set rt [catch {Apol_Analysis_dta::create_result_tree_structure $dta_tree $results $query_args} err]
	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 
     	return 0
} 

#################################################################################
#################################################################################
##
## The rest of these procs are not interface procedures, but rather internal
## functions to this analysis.
##
#################################################################################
#################################################################################

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::reset_variables { } {  
	# Reset display vars  
    	set Apol_Analysis_dta::display_type		""
	set Apol_Analysis_dta::display_attribute	""
	set Apol_Analysis_dta::display_attrib_sel 	0
	set Apol_Analysis_dta::display_direction	"forward"
	set Apol_Analysis_dta::endtype_sel	0
	set Apol_Analysis_dta::end_type		""
	set Apol_Analysis_dta::use_filters	0
	
	# Reset state vars
	set Apol_Analysis_dta::type_state		""
	set Apol_Analysis_dta::attribute_state		""
	set Apol_Analysis_dta::attrib_selected_state 	0
	set Apol_Analysis_dta::direction_state		"forward"
	set Apol_Analysis_dta::endtype_sel_state	0
	set Apol_Analysis_dta::end_type_state		""
	set Apol_Analysis_dta::use_filters_state	0
	
	# Reset results display variables
	set Apol_Analysis_dta::dta_tree		""	
	set Apol_Analysis_dta::dta_info_text	""
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::update_display_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::update_display_variables {  } {
	variable display_type			
	variable display_attribute		
	variable display_attrib_sel	
	variable display_direction
	variable endtype_sel			
	variable end_type			
	variable use_filters			
	
	set display_type $Apol_Analysis_dta::type_state	
	set display_attribute $Apol_Analysis_dta::attribute_state
	set display_attrib_sel $Apol_Analysis_dta::attrib_selected_state
	set display_direction $Apol_Analysis_dta::direction_state
	set endtype_sel	$Apol_Analysis_dta::endtype_sel_state
	set end_type	$Apol_Analysis_dta::end_type_state
	set use_filters	$Apol_Analysis_dta::use_filters_state
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::populate_ta_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::populate_ta_list { } { 
	variable combo_domain
	variable combo_attribute
	   
	set attrib_typesList $Apol_Types::typelist
	set idx [lsearch -exact $attrib_typesList "self"]
	if {$idx != -1} {
		set attrib_typesList [lreplace $attrib_typesList $idx $idx]
	}
	$combo_domain configure -values $attrib_typesList
     	$combo_attribute configure -values $Apol_Types::attriblist
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::change_types_list { } { 
	variable combo_domain
	variable display_attribute
	
	if { $display_attribute != "" } {	  
            set attrib_typesList [lsort [lindex [apol_GetAttribs $display_attribute] 0 1]]
		$combo_domain configure -values $attrib_typesList
        } else {
        	set attrib_typesList $Apol_Types::typelist
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_domain configure -values $attrib_typesList
        }
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::enable_forward_advanced_button
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::enable_forward_advanced_button { } {  
	variable b_forward_options
	$b_forward_options configure -state normal
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::disable_forward_advanced_button
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::disable_forward_advanced_button { } {  
	variable b_forward_options
	$b_forward_options configure -state disabled
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::configure_widgets_for_dta_direction
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::configure_widgets_for_dta_direction { } {    
     	variable entry_frame 	
	variable cb_attrib
	variable cb_filters
	variable forward_options_Dlg
	if {$Apol_Analysis_dta::display_direction == "forward"} {
		$entry_frame configure -text "Select source domain:"
		$cb_attrib configure -text "Filter source domains to select using attribute:"
		$cb_filters configure -state normal
		Apol_Analysis_dta::on_use_filters_button_selected
	} else {
		$entry_frame configure -text "Select target domain:"
		$cb_attrib configure -text "Filter target domains to select using attribute:"
		$cb_filters deselect
		$cb_filters configure -state disabled
		Apol_Analysis_dta::disable_forward_advanced_button
		Apol_Analysis_dta::forward_options_destroy_dialog $forward_options_Dlg
	}
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::config_attrib_comboBox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::config_attrib_comboBox_state { } {    
     	variable combo_attribute
     	variable combo_domain
	variable display_attrib_sel 	
	
	if { $display_attrib_sel } {
		$combo_attribute configure -state normal -entrybg white
		Apol_Analysis_dta::change_types_list
	} else {
		$combo_attribute configure -state disabled -entrybg  $ApolTop::default_bg_color
		set attrib_typesList $Apol_Types::typelist
        	set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_domain configure -values $attrib_typesList
	}
	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_result_tree_structure
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_result_tree_structure { dta_tree results_list query_args } {
	# Get the source type name and insert into the tree structure as the root node.
	set home_node [Apol_Analysis_dta::insert_src_type_node $dta_tree $query_args]
	# Create target type children nodes.
	set rt [catch {Apol_Analysis_dta::create_target_type_nodes $home_node $dta_tree $results_list} err]
	if {$rt != 0} {	
		return -code error $err
	}
	Apol_Analysis_dta::treeSelect $Apol_Analysis_dta::dta_tree $Apol_Analysis_dta::dta_info_text $home_node
	
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_target_type_nodes
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_target_type_nodes { parent dta_tree results_list } {
	if { [file tail [$dta_tree parent $parent]] == [file tail $parent] } {
		return 
	}
	if { [file tail [$dta_tree parent $parent]] == [file tail $parent] } {
		return 
	}

	if { [$dta_tree nodes $parent] == "" } {
		# Get # of target domain types (if none, then just draw the tree without child nodes)
		set num_target_domains [lindex $results_list 1]
		# If there are any target types then create and insert children nodes for the source_type node 
		set start_idx 2
		for { set x 0 } { $x < $num_target_domains } { incr x } { 
			set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $start_idx]
			if {$end_idx == -1} {
				# Print error 
				return -code error "Error parsing results for type [lindex $results_list $start_idx].\n"
			}
			set target_name [lindex $results_list $start_idx]
			set target_node "${parent}/${target_name}/"
			$dta_tree insert end $parent $target_node -text $target_name \
				-open 0	\
		        	-drawcross allways \
		        	-data [lrange $results_list [expr $start_idx +1] $end_idx]
		        set start_idx [expr $end_idx + 1]
		}
		set nodes [lsort [$dta_tree nodes $parent]]
		$dta_tree reorder $parent $nodes 
	        $dta_tree configure -redraw 1
	}
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::do_child_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::do_child_analysis { dta_tree selected_node } {
	ApolTop::setBusyCursor
	if { [$dta_tree nodes $selected_node] == "" } {
		set query_args [$dta_tree itemcget [$dta_tree nodes root] -data]
		set start_type [file tail $selected_node]
		set rt [catch {set results [apol_DomainTransitionAnalysis \
			[lindex $query_args 0] \
			$start_type \
			[lindex $query_args 2] \
			[lindex $query_args 3] \
			[lindex $query_args 4] \
			[lindex $query_args 5] \
			[lindex $query_args 6] \
			[lindex $query_args 7]]} err]
			
	     	if {$rt != 0} {	
			tk_messageBox -icon error -type ok -title "Error" -message $err
		} 
		set rt [catch {Apol_Analysis_dta::create_target_type_nodes $selected_node $dta_tree $results} err]
		if {$rt != 0} {	
			tk_messageBox -icon error -type ok -title "Error" -message $err
		}
	}
	ApolTop::resetBusyCursor
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::get_target_type_data_end_idx
#
#  This worker function takes a list and extracts from it the idx of the 
#  last data item for the current target.  This proc assumes that the idx is the index
#  of the first element of the current child target type.
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::get_target_type_data_end_idx { results_list idx } {
	# First see if this is the end of the list
	if {$idx >= [llength $results_list]} {
		# return -1 as error code
		return -1
	}
	
	# Determine length of sublist containing type's data
	# 
	# type (name) and (# of pt rules)
	set len 1
	# account for the (pt rules)
	set num_pt [lindex $results_list [expr $idx + $len]]
	# We multiply the number of pt rules by three because each pt rule consists of:
	# 	1. rule
	#	2. line number
	#	3. enabled flag
	incr len [expr $num_pt * 3]
	# (# of file types)
	incr len
	set num_types [lindex $results_list [expr $idx + $len]]
	for {set i 0} { $i < $num_types } { incr i } {
		# (file type) and (# ep rules)
		incr len 2
		# account for (ep rules)
		set num_ep [lindex $results_list [expr $idx + $len]]
		# We multiply the number of ep rules by three because each pt rule consists of:
		# 	1. rule
		#	2. line number
		#	3. enabled flag
		incr len [expr $num_ep * 3]
		# (# ex rules)
		incr len
		# account for (ex rules)
		set num_ex [lindex $results_list [expr $idx + $len]]

		# We multiply the number of ex rules by three because each pt rule consists of:
		# 	1. rule
		#	2. line number
		#	3. enabled flag
		incr len [expr $num_ex * 3]
	}
	# (# addtional rules)
	incr len
	set num_additional [lindex $results_list [expr $idx + $len]]
	# We multiply the number of ex rules by three because each pt rule consists of:
	# 	1. rule
	#	2. line number
	#	3. enabled flag
	incr len [expr $num_additional * 3]
		
	return [expr $len + $idx]
}


# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::render_target_type_data
#
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::render_target_type_data { data dta_info_text dta_tree node} {
	$dta_info_text configure -state normal
        $dta_info_text delete 0.0 end
	$dta_info_text configure -wrap none

	# First see if this is the end of the list
	if { $data == "" } {
	        $dta_info_text configure -state disabled
		return ""
	}
	set target [$dta_tree itemcget $node -text]
	set parent [$dta_tree itemcget [$dta_tree parent $node] -text]
	# Set the mark to 0.0
	$dta_info_text mark set insert 1.0
	set start_idx [$dta_info_text index insert]
	
	$dta_info_text insert end "Domain transition from "
	# The character at $end_idx isn't tagged, so must add 1 to $end_idx argument.
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_tag $start_idx $end_idx
	
	set start_idx [$dta_info_text index insert]
	if {[lindex [$dta_tree itemcget [$dta_tree nodes root] -data] 0]} {
		$dta_info_text insert end $target
	} else {
		$dta_info_text insert end $parent
	}
	set end_idx [$dta_info_text index insert] 
	$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx
	
	set start_idx [$dta_info_text index insert]
	$dta_info_text insert end " to "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_tag $start_idx $end_idx
	
	set start_idx [$dta_info_text index insert]
	if {[lindex [$dta_tree itemcget [$dta_tree nodes root] -data] 0]} {
		$dta_info_text insert end $parent
	} else {
		$dta_info_text insert end $target
	}
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx

	# (# of pt rules)
	$dta_info_text insert end "\n\n"
	set start_idx [$dta_info_text index insert]
	set idx 0
	set num_pt [lindex $data $idx]
	
	$dta_info_text insert end "Process Transition Rules:  "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
	set start_idx $end_idx
	$dta_info_text insert end "$num_pt\n"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx

	for {set i 0} { $i < $num_pt } { incr i } {
		incr idx
		set rule [lindex $data $idx]
		incr idx
		set lineno [lindex $data $idx] 
		
		$dta_info_text insert end "\t"
		set start_idx [$dta_info_text index insert]
		
		# Only display line number hyperlink if this is not a binary policy.
		if {![ApolTop::is_binary_policy]} {
			$dta_info_text insert end "($lineno) "
			set end_idx [$dta_info_text index insert]
			Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
			set start_idx $end_idx
		}
		$dta_info_text insert end "$rule"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
		
		incr idx
		# The next element should be the enabled boolean flag.
		if {[lindex $data $idx] == 0} {
			$dta_info_text insert end "   "
			set startIdx [$dta_info_text index insert]
			$dta_info_text insert end "\[Disabled\]\n"
			set endIdx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
		} else {
			$dta_info_text insert end "\n"
		}
	}
	incr idx
	# (# of file types)
	set num_types [lindex $data $idx ]
	set start_idx $end_idx
	$dta_info_text insert end "\nEntry Point File Types:  "
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
	set start_idx $end_idx
	$dta_info_text insert end "$num_types\n"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
	
	for {set i 0} { $i < $num_types } { incr i } {
		incr idx
		# (file type) 
		set type [lindex $data $idx]
		set start_idx $end_idx
		$dta_info_text insert end "\t$type\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::types_tag $start_idx $end_idx
		incr idx
		set num_ep [lindex $data $idx]
		
		set start_idx $end_idx
		$dta_info_text insert end "\t\tFile Entrypoint Rules:  "
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$dta_info_text insert end "$num_ep\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
		
		for {set j 0 } { $j < $num_ep } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]
			
			$dta_info_text insert end "\t\t"
			set start_idx [$dta_info_text index insert]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dta_info_text insert end "($lineno) "
				set end_idx [$dta_info_text index insert]
				Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$dta_info_text insert end "$rule"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
			
			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$dta_info_text insert end "   "
				set startIdx [$dta_info_text index insert]
				$dta_info_text insert end "\[Disabled\]\n"
				set endIdx [$dta_info_text index insert]
				$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
			} else {
				$dta_info_text insert end "\n"
			}
		}
		incr idx
		set num_ex [lindex $data $idx]
		
		set start_idx $end_idx
		$dta_info_text insert end "\n\t\tFile Execute Rules:  "
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$dta_info_text insert end "$num_ex\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
		
		for { set j 0 } { $j < $num_ex } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]
			
			$dta_info_text insert end "\t\t"
			set start_idx [$dta_info_text index insert]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dta_info_text insert end "($lineno) "
				set end_idx [$dta_info_text index insert]
				Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$dta_info_text insert end "$rule"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
			
			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$dta_info_text insert end "   "
				set startIdx [$dta_info_text index insert]
				$dta_info_text insert end "\[Disabled\]\n"
				set endIdx [$dta_info_text index insert]
				$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
			} else {
				$dta_info_text insert end "\n"
			}
		}
	}
	set reverse [lindex [$dta_tree itemcget [$dta_tree nodes root] -data] 0]
	if {!$reverse && $Apol_Analysis_dta::use_filters} {
		incr idx
		set num_additional [lindex $data $idx]
		
		$dta_info_text insert end "\n"
		set start_idx [$dta_info_text index insert]
		$dta_info_text insert end "The access filters you specified returned the following rules"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::subtitle_tag $start_idx $end_idx
		#set start_idx [$dta_info_text index insert]
		#$dta_info_text insert end $target
		#set end_idx [$dta_info_text index insert] 
		#$dta_info_text tag add $Apol_Analysis_dta::title_type_tag $start_idx $end_idx
		$dta_info_text insert end ": "
		set start_idx [$dta_info_text index insert] 
		$dta_info_text insert end "$num_additional\n"
		set end_idx [$dta_info_text index insert]
		$dta_info_text tag add $Apol_Analysis_dta::counters_tag $start_idx $end_idx
		#$dta_info_text insert end " rules\n"
		for {set j 0 } { $j < $num_additional } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]
			
			$dta_info_text insert end "\t"
			set start_idx [$dta_info_text index insert]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$dta_info_text insert end "($lineno) "
				set end_idx [$dta_info_text index insert]
				Apol_PolicyConf::insertHyperLink $dta_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$dta_info_text insert end "$rule"
			set end_idx [$dta_info_text index insert]
			$dta_info_text tag add $Apol_Analysis_dta::rules_tag $start_idx $end_idx
			
			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$dta_info_text insert end "   "
				set startIdx [$dta_info_text index insert]
				$dta_info_text insert end "\[Disabled\]\n"
				set endIdx [$dta_info_text index insert]
				$dta_info_text tag add $Apol_Analysis_dta::disabled_rule_tag $start_idx $end_idx
			} else {
				$dta_info_text insert end "\n"
			}
		}
	}
		
	$dta_info_text configure -state disabled
	return 0
}

###########################################################################
# ::formatInfoText
#
proc Apol_Analysis_dta::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_dta::title_tag -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_dta::title_type_tag -foreground blue -font {Helvetica 14 bold}
	$tb tag configure $Apol_Analysis_dta::subtitle_tag -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_dta::rules_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_dta::counters_tag -foreground blue -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_dta::types_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_dta::disabled_rule_tag -foreground red 
	
	# Configure hyperlinking to policy.conf file
	Apol_PolicyConf::configure_HyperLinks $tb
}

###########################################################################
# ::display_root_type_info
#
proc Apol_Analysis_dta::display_root_type_info { source_type dta_info_text dta_tree } {

        $dta_info_text configure -state normal
        $dta_info_text delete 0.0 end
        if {[lindex [$dta_tree itemcget $source_type -data] 0]} {
	    $dta_info_text insert end "Reverse Domain Transition Analysis: Starting Type:  "
        } else {
	    $dta_info_text insert end "Forward Domain Transition Analysis: Starting Type:  "
        }

	$dta_info_text tag add ROOT_TITLE 0.0 end
	$dta_info_text tag configure ROOT_TITLE -font {Helvetica 14 bold}
	set start_idx [$dta_info_text index insert]
	$dta_info_text insert end "$source_type"
	set end_idx [$dta_info_text index insert]
	$dta_info_text tag add ROOT_TYPE $start_idx $end_idx
	$dta_info_text tag configure ROOT_TYPE -font {Helvetica 14 bold} -foreground blue
	
	# now add the standard text
	$dta_info_text configure -wrap word
	set start_idx [$dta_info_text index insert]
	if {[lindex [$dta_tree itemcget $source_type -data] 0]} {
		set root_text $Apol_Analysis_dta::dta_root_text_r
	} else {
		set root_text $Apol_Analysis_dta::dta_root_text_f
		
	}
	$dta_info_text insert end $root_text
	$dta_info_text tag add ROOT_TEXT $start_idx end
	$dta_info_text tag configure ROOT_TEXT -font $ApolTop::text_font
	$dta_info_text configure -state disabled
	return 0
}

###########################################################################
# ::treeSelect
#  	- Method is invoked when the user selects a node in the tree widget.
#
proc Apol_Analysis_dta::treeSelect { dta_tree dta_info_text node } {
	# Set the tree selection to the current node.
	$dta_tree selection set $node

	if {$node ==  [$dta_tree nodes root]} {
		Apol_Analysis_dta::display_root_type_info $node $dta_info_text $dta_tree
		return
	}
	Apol_Analysis_dta::render_target_type_data [$dta_tree itemcget $node -data] $dta_info_text $dta_tree $node
	Apol_Analysis_dta::formatInfoText $dta_info_text
	ApolTop::makeTextBoxReadOnly $dta_info_text
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::insert_src_type_node
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::insert_src_type_node { dta_tree query_args } {
	$dta_tree insert end root [lindex $query_args 1] -text [lindex $query_args 1] \
		-open 1	\
        	-drawcross auto \
        	-data $query_args
        return [$dta_tree nodes root]
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::config_endtype_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::config_endtype_state {} {
	variable entry_end
	
        if {$Apol_Analysis_dta::endtype_sel} {
	        $entry_end configure -state normal -background white
	} else {
	        $entry_end configure -state disabled -background $ApolTop::default_bg_color
	}
        return 0
}

proc Apol_Analysis_dta::on_use_filters_button_selected {} {
        if {$Apol_Analysis_dta::use_filters} {
	       Apol_Analysis_dta::enable_forward_advanced_button
	} else {
	       Apol_Analysis_dta::disable_forward_advanced_button
	}
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_options { options_frame } {
	variable combo_domain
	variable combo_attribute
	variable cb_attrib
	variable entry_frame
	variable adv_frame
	variable b_forward_options
	variable entry_end
	variable cb_filters
	
	set left_frame [frame $options_frame.left_frame]
	set right_frame [TitleFrame $options_frame.right_frame -text "Optional result filters"]
	set radio_frame [TitleFrame $left_frame.radio_frame -text "Select direction:"]
	set entry_frame [TitleFrame $left_frame.entry_frame]
	set adv_frame [frame [$right_frame getframe].adv_frame]
	set endtype_frame [frame [$right_frame getframe].endtype_frame]
	
	# Domain transition section
    	set combo_domain [ComboBox [$entry_frame getframe].combo_domain -width 20 \
    		-helptext "Starting Domain" -autopost 1 \
    		-editable 1 \
    		-entrybg white \
    		-textvariable Apol_Analysis_dta::display_type]  
    	set combo_attribute [ComboBox [$entry_frame getframe].combo_attribute  \
    		-textvariable Apol_Analysis_dta::display_attribute \
    		-modifycmd { Apol_Analysis_dta::change_types_list} \
                                -autopost 1]
	set cb_attrib [checkbutton [$entry_frame getframe].trans \
		-variable Apol_Analysis_dta::display_attrib_sel \
		-text "Filter source domains to select using attribute:" \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_dta::config_attrib_comboBox_state }]
		
	set radio_forward [radiobutton [$radio_frame getframe].radio_forward -text "Forward" \
		-variable Apol_Analysis_dta::display_direction \
		-value forward \
		-command {Apol_Analysis_dta::configure_widgets_for_dta_direction}]
	set radio_reverse [radiobutton [$radio_frame getframe].radio_reverse -text "Reverse" \
		-variable Apol_Analysis_dta::display_direction \
		-value reverse \
		-command {Apol_Analysis_dta::configure_widgets_for_dta_direction}]
	
	set b_forward_options [button $adv_frame.b_forward_options -text "Access filters" \
				-command {Apol_Analysis_dta::forward_options_create_dialog \
					$Apol_Analysis_dta::forward_options_Dlg \
					"Access Filters"}]
	set entry_end [Entry $endtype_frame.entry_end \
		-helptext "You may enter a regular expression" \
		-editable 1 -state disabled \
		-textvariable Apol_Analysis_dta::end_type] 
	set cb_endtype [checkbutton $endtype_frame.cb_endtype \
	    	-text "Filter result types using regular expression:" \
		-variable Apol_Analysis_dta::endtype_sel \
		-command {Apol_Analysis_dta::config_endtype_state}]
	set cb_filters [checkbutton $adv_frame.cb_filters \
	    	-text "Use access filters:" \
		-variable Apol_Analysis_dta::use_filters \
		-command {Apol_Analysis_dta::on_use_filters_button_selected}]
	
	pack $cb_endtype -side top -anchor nw
    	pack $entry_end -anchor nw -fill x -expand yes 
    	pack $cb_filters $b_forward_options -side left -anchor nw 				
	pack $left_frame -side left -anchor nw -fill y
	pack $right_frame -side right -anchor nw -fill both -expand yes -pady 5 -padx 3
	pack $radio_frame -side top -anchor nw -pady 5 -fill x 
	pack $entry_frame -side top -anchor nw -pady 5 -fill both -expand yes
	pack $endtype_frame $adv_frame -side top -anchor nw -pady 5 -padx 2 -fill x 
	
	pack $combo_domain -side top -anchor nw -fill x
    	pack $cb_attrib -padx 15 -side top -anchor nw
    	pack $combo_attribute -side top -anchor nw -fill x -padx 15
	
	pack $radio_forward $radio_reverse -side left -anchor nw -padx 5 -fill x -expand yes
	
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::create_resultsDisplay
# ------------------------------------------------------------------------------
proc Apol_Analysis_dta::create_resultsDisplay {results_frame reverse} {
	variable dta_tree
	variable dta_info_text

	# set up paned window
	set pw   [PanedWindow $results_frame.pw -side top]
	set pw_tree [$pw add]
	set pw_info [$pw add -weight 5]
	
	# title frames
        if { $reverse } {
	    set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Reverse Domain Transition Tree"]
	    set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Reverse Domain Transition Information"]	
	} else {
	    set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Forward Domain Transition Tree"]
	    set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Forward Domain Transition Information"]
	}
	set sw_tree [ScrolledWindow [$frm_tree getframe].sw_tree -auto none]		 
	set sw_info [ScrolledWindow [$frm_info getframe].sw_info -auto none]		 

	# tree window
	set dta_tree  [Tree [$sw_tree getframe].dta_tree \
	           -relief flat -borderwidth 0 -width 15 -highlightthickness 0 \
		   -redraw 0 -bg white -showlines 1 -padx 0 \
		   -opencmd  {Apol_Analysis_dta::do_child_analysis $Apol_Analysis_dta::dta_tree}]
	$sw_tree setwidget $dta_tree 

	# info window
	set dta_info_text [text [$sw_info getframe].dta_info_text -wrap none -bg white -font $ApolTop::text_font]
	$sw_info setwidget $dta_info_text
	bind $dta_info_text <Enter> {focus %W}
	
	pack $pw -fill both -expand yes -anchor nw 
	pack $frm_tree -fill both -expand yes -anchor nw
	pack $frm_info -fill both -expand yes
	pack $sw_tree -fill both -expand yes
	pack $sw_info -fill both -expand yes 
	
	$dta_tree bindText  <ButtonPress-1>        {Apol_Analysis_dta::treeSelect $Apol_Analysis_dta::dta_tree $Apol_Analysis_dta::dta_info_text}
    	$dta_tree bindText  <Double-ButtonPress-1> {Apol_Analysis_dta::treeSelect $Apol_Analysis_dta::dta_tree $Apol_Analysis_dta::dta_info_text}
    
	return $dta_tree
}
