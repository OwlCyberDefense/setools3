#############################################################
#  types_relation_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2004 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com> 8-11-2004
# -----------------------------------------------------------
#
# This module implements the two types relationship analysis interface.

##############################################################
# ::Apol_Analysis_tra module namespace
##############################################################
namespace eval Apol_Analysis_tra {
	# GUI variables
	variable descriptive_text "\n\nThe purpose of the Two Types Relationship analysis is to determine if \
				there exists any relationship (or interactions) between two types, namely TypeA and TypeB, \
				and exactly what associations make up that relationship. This type of analysis may be useful in \
				determining whether two policy types are completely isolated from each other or in determining \
				the degree to which a particular type is unique to the other. You can control the \
				analysis to search for any of the following associations between two types:\n\n \
				  - the attribute(s) to which both types are assigned (common attribs) \n \
		 	          - the role(s) which have access to both TypeA and TypeB (common roles) \n \
		 	          - the users which have access to both TypeA and TypeB (common users) \n \
		 	          - all type transition rules from TypeA to TypeB or from TypeB to TypeA. \n \
		 	          - any process interactions between TypeA and TypeB (e.g., allow rules that allow TypeA \
		 	          and TypeB to send signals to each other). \n \
		 	          - object types to which both TypeA and TypeB are granted access. \n \
		 	          - the additional types to which TypeA and TypeB have access. \n \
		 	          - any direct information flows between TypeA and TypeB \n \
		 	          - any transitive information flows between TypeA and TypeB \n \
		 	          - any domain transitions from TypeA to TypeB or from TypeB to TypeA. \n \
		 	          \n\n\This analysis may contain an overwhelming amount of information, so the results \
				  are simplified by listing each aspect of the analysis as a separate element \
				  within the listbox. This allows the user to select any aspect of the analysis \
				  from the listbox and have that specific information displayed within the results \
				  textbox. If desired, all results can be displayed at once by selecting the listbox \
				  item labeled 'Show All Results'.\n\nFor additional information on \
    				  this topic select \"Two Types Relationship Analysis\" from the help menu."
	variable progressmsg		""
	variable progress_indicator	-1
					    	
    	# Query variables
    	variable typeA			""
    	variable typeB			""
    	variable attribA 		""
    	variable attribB 		""
    	variable attribA_sel		0
    	variable attribB_sel		0
    	variable comm_attribs_sel 	1
	variable comm_roles_sel 	1
	variable comm_users_sel 	1
	variable comm_access_sel 	0
	variable unique_access_sel 	0
	variable dta_AB_sel		0
	variable dta_BA_sel		0
	variable trans_flow_AB_sel	0
	variable trans_flow_BA_sel	0
	variable dir_flow_sel		0
	variable other_ttrules_sel	0
	variable process_sel		0
    	
    	# Global widgets 
    	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
        variable cb_attribA
	variable cb_attribB
	variable tra_listbox
	variable tra_info_text
	variable progressDlg
	set progressDlg .progress
	
	# Advanced options dialogs/variables - Not used in this release
	variable forward_options_Dlg
	set forward_options_Dlg .forward_options_Dlg_tra
	variable transflow_options_Dlg
	set transflow_options_Dlg .transflow_options_Dlg_tra
	variable dirflow_options_Dlg
	set dirflow_options_Dlg	.dirflow_options_Dlg
	variable included_dirflow_objs	""
	variable excluded_dirflow_objs	""
	
	# defined tag names for output 
	variable title_tag		TITLE
	variable title_type_tag		TITLE_TYPE
	variable subtitle_tag		SUBTITLES
	variable rules_tag		RULES
	variable counters_tag		COUNTERS
	variable types_tag		TYPE
	variable disabled_rule_tag     	DISABLE_RULE
	
   	Apol_Analysis::register_analysis_modules "Apol_Analysis_tra" "Two Types Relationship"	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_dta_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_dta_options { } {         	 	  
	Apol_Analysis_dta::forward_options_create_dialog \
		$Apol_Analysis_tra::forward_options_Dlg \
		"Types Relationship Domain Transitions Advanced Options"
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_tif_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_tif_options { } { 		  
	Apol_Analysis_fulflow::advanced_filters_create_dialog \
		$Apol_Analysis_tra::transflow_options_Dlg \
		"Types Relationship Transitive Information Flows Options"
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::dirflow_options_include_exclude_objs
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::dirflow_options_include_exclude_objs {remove_list_1 \
						      	      add_list_1 \
						              remove_lbox \
						              add_lbox} {
	upvar #0 $remove_list_1 remove_list
	upvar #0 $add_list_1 add_list
	
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
		    }
		$remove_lbox selection clear 0 end
	}  
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::select_all_lbox_items
#	- Takes a Tk listbox widget as an argument.
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::select_all_lbox_items {lbox} {
        $lbox selection set 0 end
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::clear_all_lbox_items
#	- Takes a Tk listbox widget as an argument.
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::clear_all_lbox_items {lbox} {
        $lbox selection clear 0 end
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_dif_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_dif_options { } { 
	variable dirflow_options_Dlg
	
	if {![ApolTop::is_policy_open]} {
	    tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
	    return -1
        } 
        
	if {[winfo exists $dirflow_options_Dlg]} {
    		raise $dirflow_options_Dlg
    		focus -force $dirflow_options_Dlg
    		return 0
    	}
	
	# Create the top-level dialog and subordinate widgets
    	toplevel $dirflow_options_Dlg 
     	wm withdraw $dirflow_options_Dlg	
    	wm title $dirflow_options_Dlg \
    		"Types Relationship Direct Information Flows Options"
    	wm protocol $dirflow_options_Dlg WM_DELETE_WINDOW \
    		"destroy $dirflow_options_Dlg"
	
	set top_frame [TitleFrame $dirflow_options_Dlg.top_frame \
		-text "Filter results by object class:"]    	 	  
	set objcl_frame [frame [$top_frame getframe].objcl_frame]
	set objcl_frame_1 [frame $objcl_frame.objcl_frame_1]
	set objcl_frame_2 [frame $objcl_frame.objcl_frame_2]
	set objcl_frame_3 [frame $objcl_frame.objcl_frame_3]
	set b_frame_1 [frame $objcl_frame_1.b_frame_1]
	set b_frame_3 [frame $objcl_frame_3.b_frame_3]
	
	set lbl_incl [Label $objcl_frame_1.lbl_incl \
		-text "Include these objects:"]
	set sw_objs_1 [ScrolledWindow $objcl_frame_1.sw_objs_1 -auto both]
        set list_objs_1 [listbox [$sw_objs_1 getframe].list_objs_1 \
        	-height 7 \
        	-highlightthickness 0 \
		-selectmode extended \
		-exportselection 0 -bg white \
		-listvar Apol_Analysis_tra::included_dirflow_objs] 
        $sw_objs_1 setwidget $list_objs_1
        
        set lbl_excl [Label $objcl_frame_3.lbl_excl \
        	-text "Exclude these objects:"]
        set sw_objs_2 [ScrolledWindow $objcl_frame_3.sw_objs_2 -auto both]
        set list_objs_2 [listbox [$sw_objs_2 getframe].list_objs_2 \
        	-height 7 \
        	-highlightthickness 0 \
		-selectmode extended \
		-exportselection 0 -bg white \
		-listvar Apol_Analysis_tra::excluded_dirflow_objs] 
        $sw_objs_2 setwidget $list_objs_2
       
        bindtags $list_objs_1 \
		[linsert [bindtags $list_objs_1] 3 \
		list_objs_1_Tag]
	bindtags $list_objs_2 \
		[linsert [bindtags $list_objs_2] 3 \
		list_objs_2_Tag]
	
	bind list_objs_1_Tag <<ListboxSelect>> "focus -force $list_objs_1"
	bind list_objs_2_Tag <<ListboxSelect>> "focus -force $list_objs_2"
				
        # Buttons
        set include_bttn [Button $objcl_frame_2.include_bttn -text "<--" \
        	-helptext "Include object(s) in the query" -width 8 \
		-command "Apol_Analysis_tra::dirflow_options_include_exclude_objs \
			Apol_Analysis_tra::excluded_dirflow_objs \
	      	      	Apol_Analysis_tra::included_dirflow_objs \
	              	$list_objs_2 \
	              	$list_objs_1"]
	set exclude_bttn [Button $objcl_frame_2.exclude_bttn -text "-->" \
		-helptext "Exclude object(s) from the query" -width 8 \
		-command "Apol_Analysis_tra::dirflow_options_include_exclude_objs \
			Apol_Analysis_tra::included_dirflow_objs \
	      	      	Apol_Analysis_tra::excluded_dirflow_objs \
	              	$list_objs_1 \
	              	$list_objs_2"]
     	
     	set b_incl_all_sel [Button $b_frame_1.b_incl_all_sel \
     		-text "Select All" \
		-command "Apol_Analysis_tra::select_all_lbox_items $list_objs_1"]
	set b_incl_all_clear [Button $b_frame_1.b_incl_all_clear \
		-text "Unselect" \
		-command "Apol_Analysis_tra::clear_all_lbox_items $list_objs_1"]
	set b_excl_all_sel [Button $b_frame_3.b_excl_all_sel \
		-text "Select All" \
		-command "Apol_Analysis_tra::select_all_lbox_items $list_objs_2"]
	set b_excl_all_clear [Button $b_frame_3.b_excl_all_clear \
		-text "Unselect" \
		-command "Apol_Analysis_tra::clear_all_lbox_items $list_objs_2"]
	
        set button_f [frame $dirflow_options_Dlg.button_f]
        # Create and pack close button for the dialog
  	set close_bttn [Button $button_f.close_bttn \
  		-text "Close" \
  		-width 8 \
		-command "destroy $dirflow_options_Dlg"]
	
	pack $b_frame_3 $b_frame_1 -side bottom -anchor center 
	pack $objcl_frame_3 -side right -anchor nw -fill both -expand yes
	pack $objcl_frame_1 -side left -anchor nw -fill both -expand yes
	pack $objcl_frame_2 -side top -anchor center -pady 80 -padx 10 
       	pack $button_f -side bottom -anchor center -expand yes -pady 4 -padx 4
       	pack $objcl_frame -side top -anchor nw -fill both -expand yes -pady 4 -padx 4
       	pack $top_frame -side left -anchor nw -fill both -expand yes -pady 4 -padx 4
       	pack $b_incl_all_sel $b_incl_all_clear $b_excl_all_sel $b_excl_all_clear \
       		-side left -anchor nw -fill x
       	pack $include_bttn $exclude_bttn -side top -anchor center -fill y
       	pack $sw_objs_1 $sw_objs_2 -side bottom -anchor nw -fill both -expand yes \
       		-padx 5 -pady 5
       	pack $lbl_incl $lbl_excl -side top -anchor nw -padx 5 -pady 2
	pack $close_bttn -side left -anchor center
	
	set width 580
	set height 300
	wm geom $dirflow_options_Dlg ${width}x${height}
	wm deiconify $dirflow_options_Dlg
	focus $dirflow_options_Dlg
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::initialize_widgets_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::initialize_widgets_state { } {  
	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
        variable cb_attribA
	variable cb_attribB
		  
     	Apol_Analysis_tra::config_attrib_comboBox_state \
		$cb_attribA $combo_attribA $combo_typeA 0
	Apol_Analysis_tra::config_attrib_comboBox_state \
		$cb_attribB $combo_attribB $combo_typeB 0
	
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::initialize { } {  
	Apol_Analysis_tra::reset_variables
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::do_analysis {results_frame} {  
	variable tra_listbox
	variable typeA		
    	variable typeB
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel		
	variable dta_BA_sel
	variable trans_flow_AB_sel		
	variable trans_flow_BA_sel	
	variable dir_flow_sel		
	variable other_ttrules_sel	
	variable process_sel		
	variable excluded_dirflow_objs
	
	if {![ApolTop::is_policy_open]} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "No current policy file is opened!"
		return -code error
        } 
   
       	if {$typeA == ""} {
       		tk_messageBox -icon error -type ok -title "Error" \
       			-message "TypeA cannot be empty!"
	    	return -code error
       	}
       	if {$typeB == ""} {
       		tk_messageBox -icon error -type ok -title "Error" \
       			-message "TypeB cannot be empty!"
	    	return -code error
       	}
       	
       	if {!$comm_attribs_sel && !$comm_roles_sel && !$comm_users_sel && !$comm_access_sel && \
       	    !$unique_access_sel && !$dta_AB_sel && !$dta_BA_sel && !$trans_flow_AB_sel && \
       	    !$trans_flow_BA_sel && !$dir_flow_sel && !$other_ttrules_sel && !$process_sel} {
       		tk_messageBox -icon error -type ok -title "Error" \
       			-message "You did not select any search items."
	    	return -code error
       	}
       	
	# if a permap is not loaded then load the default permap
        # if an error occurs on open, then skip analysis
        set rt [catch {set map_loaded [Apol_Perms_Map::is_pmap_loaded]} err]
        if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err"
		return -code error
	}
	set do_trans [expr ($trans_flow_AB_sel || $trans_flow_BA_sel)]
	if {[expr (!$map_loaded && ($do_trans || $dir_flow_sel))]} {
	    set rt [catch {Apol_Perms_Map::load_default_perm_map} err]
	    if { $rt != 0 } {
		if {$rt == $Apol_Perms_Map::warning_return_val} {
			tk_messageBox -icon warning -type ok -title "Warning" -message "$err"
		} else {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -code error
		}
	    }
	}
	
	# Initialize dta variables - These options are here for setting advanced options for DTA analysis.
        set dta_reverse 0
	set dta_num_object_classes 0
	set dta_perm_options ""
        set dta_filter_types 0
        set dta_types ""
	set dta_objects_sel 0
		
	# Initialize transitive flow variables - These options are here for setting advanced options for DTA analysis.
	set tif_num_object_classes 0
	set tif_perm_options ""
	set tif_types ""
	set tif_objects_sel 0
	set tif_filter_types 0
	
	# Initialize direct flow variables - These options are here for setting advanced options for DTA analysis.
	set filter_dirflow_objs 0
	
	Apol_Analysis_tra::display_progressDlg			
	set rt [catch {set results [apol_TypesRelationshipAnalysis \
		$typeA \
		$typeB \
     		$comm_attribs_sel \
     		$comm_roles_sel \
     		$comm_users_sel \
     		$comm_access_sel \
     		$unique_access_sel \
		[expr ($dta_AB_sel || $dta_BA_sel)] \
		[expr ($trans_flow_AB_sel || $trans_flow_BA_sel)] \
		$dir_flow_sel \
		$other_ttrules_sel \
		$process_sel \
		$tif_objects_sel \
		$tif_num_object_classes \
		$tif_perm_options \
		$tif_filter_types \
		$tif_types \
		$dta_objects_sel \
		$dta_num_object_classes \
		$dta_perm_options \
		$dta_filter_types \
		$dta_types \
		$filter_dirflow_objs \
		$excluded_dirflow_objs]} err]
		
	Apol_Analysis_tra::destroy_progressDlg	
     	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 

	set tra_listbox [Apol_Analysis_tra::create_resultsDisplay $results_frame]
	set rt [catch {Apol_Analysis_tra::create_results_list_structure $tra_listbox $results} err]
	if {$rt != 0} {	
	        tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -code error
	} 
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_all_results
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_all_results {tra_listbox tra_info_text} {
	set items [$tra_listbox items 0 end]
	$tra_info_text configure -state normal
        $tra_info_text delete 0.0 end
       	$tra_info_text mark set insert 1.0
       
	foreach item $items {
		switch -exact -- $item {
			common_attribs {
				Apol_Analysis_tra::display_common_attribs \
					$tra_listbox \
					$tra_info_text \
					"Common Attributes" \
					[$tra_listbox itemcget $item -data] 
			}
			common_roles {
				Apol_Analysis_tra::display_common_attribs \
					$tra_listbox \
					$tra_info_text \
					"Common Roles" \
					[$tra_listbox itemcget $item -data]
			}
			common_users {
				Apol_Analysis_tra::display_common_attribs \
					$tra_listbox \
					$tra_info_text \
					"Common Users" \
					[$tra_listbox itemcget $item -data]
			}
			tt_rules {
				Apol_Analysis_tra::display_rules \
					$tra_listbox \
					$tra_info_text \
					"Type Transition Rules" \
					[$tra_listbox itemcget $item -data]
			}
			process_rules {
				Apol_Analysis_tra::display_rules \
					$tra_listbox \
					$tra_info_text \
					"Direct Process Interactions" \
					[$tra_listbox itemcget $item -data]
			}
			common_objects {
				Apol_Analysis_tra::display_common_object_info \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data]
			}
			unique_objects {
				Apol_Analysis_tra::display_unique_object_info \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data]
			}
			dir_flows {
				Apol_Analysis_tra::display_direct_flows \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data] \
			}
			trans_flows_A {
				Apol_Analysis_tra::display_transitive_flows \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data] \
					$Apol_Analysis_tra::typeA
			}
			trans_flows_B {
				Apol_Analysis_tra::display_transitive_flows \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data] \
					$Apol_Analysis_tra::typeB
			}
			dta_analysis_A {
				Apol_Analysis_tra::display_dta_info \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data] \
					$Apol_Analysis_tra::typeA
			}
			dta_analysis_B {
				Apol_Analysis_tra::display_dta_info \
					$tra_listbox \
					$tra_info_text \
					[$tra_listbox itemcget $item -data] \
					$Apol_Analysis_tra::typeB
			}
			all {
				# Ignore this 	
			}
			default {
				puts "Invalid listbox item: $item"
				return -1
			}
		}
		$tra_info_text insert end "\n\n"
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::listSelect
# ---------------------------------------------------------
proc Apol_Analysis_tra::listSelect {tra_listbox tra_info_text selected_item} { 
	$tra_info_text configure -state normal
        $tra_info_text delete 0.0 end
       	$tra_info_text mark set insert 1.0
       	
	switch -exact -- $selected_item {
		common_attribs {
			Apol_Analysis_tra::display_common_attribs \
				$tra_listbox \
				$tra_info_text \
				"Common Attributes" \
				[$tra_listbox itemcget $selected_item -data]
		}
		common_roles {
			Apol_Analysis_tra::display_common_attribs \
				$tra_listbox \
				$tra_info_text \
				"Common Roles" \
				[$tra_listbox itemcget $selected_item -data]
		}
		common_users {
			Apol_Analysis_tra::display_common_attribs \
				$tra_listbox \
				$tra_info_text \
				"Common Users" \
				[$tra_listbox itemcget $selected_item -data]
		}
		tt_rules {
			Apol_Analysis_tra::display_rules \
				$tra_listbox \
				$tra_info_text \
				"Type transition rules" \
				[$tra_listbox itemcget $selected_item -data]
		}
		process_rules {
			Apol_Analysis_tra::display_rules \
				$tra_listbox \
				$tra_info_text \
				"Direct Process interactions" \
				[$tra_listbox itemcget $selected_item -data]
		}
		common_objects {
			Apol_Analysis_tra::display_common_object_info \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data]
		}
		unique_objects {
			Apol_Analysis_tra::display_unique_object_info \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data]
		}
		dir_flows {
			Apol_Analysis_tra::display_direct_flows \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
		}
		trans_flows_A {
			Apol_Analysis_tra::display_transitive_flows \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeA
		}
		trans_flows_B {
			Apol_Analysis_tra::display_transitive_flows \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeB
		}
		dta_analysis_A {
			Apol_Analysis_tra::display_dta_info \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeA
		}
		dta_analysis_B {
			Apol_Analysis_tra::display_dta_info \
				$tra_listbox \
				$tra_info_text \
				[$tra_listbox itemcget $selected_item -data] \
				$Apol_Analysis_tra::typeB
		}
		all {
			if {[Apol_Analysis_tra::display_all_results $tra_listbox $tra_info_text] == -1} {
				return -1
			}
		}
		default {
			puts "Invalid listbox item element $selected_item"
			return -1
		}
	}
	ApolTop::makeTextBoxReadOnly $tra_info_text
	$tra_listbox selection set $selected_item
	Apol_Analysis_tra::formatInfoText $Apol_Analysis_tra::tra_info_text
	return 0
}

###########################################################################
# ::formatInfoText
#
proc Apol_Analysis_tra::formatInfoText { tb } {
	$tb tag configure $Apol_Analysis_tra::title_tag -font {Helvetica 12 bold}
	$tb tag configure $Apol_Analysis_tra::title_type_tag -foreground blue -font {Helvetica 12 bold}
	$tb tag configure $Apol_Analysis_tra::subtitle_tag -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_tra::rules_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_tra::counters_tag -foreground blue -font {Helvetica 11 bold}
	$tb tag configure $Apol_Analysis_tra::types_tag -font $ApolTop::text_font
	$tb tag configure $Apol_Analysis_tra::disabled_rule_tag -foreground red
	
	# Configure hyperlinking to policy.conf file
	Apol_PolicyConf::configure_HyperLinks $tb
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_common_attribs
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_common_attribs {tra_listbox tra_info_text header_txt data} {       	
       	if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	
        set num [lindex $data 0]
        set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$header_txt ($num):\n\n"   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	
	if {$num} {  
		set itemlist [lrange $data 1 end]
		
		foreach item $itemlist {
			$tra_info_text insert end "$item\n"
		}
	} 
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_rules
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_rules {tra_listbox tra_info_text header_txt data} {
       	if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set i 0
        set num [lindex $data $i]
        set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$header_txt ($num):\n\n"   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	set curr_idx [expr $i + 1]
	for {set x 0} {$x < $num} {incr x} {
		Apol_Analysis_tra::print_rule $tra_info_text $data $curr_idx
		incr curr_idx
	} 
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::print_rule
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::print_rule {tra_info_text data curr_idx} {	
	set startIdx [$tra_info_text index insert]
	set rule [lindex $data $curr_idx]
	# Get the line number only
	set end_link_idx [string first "\]" [string trim $rule] 0]
	set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
	set lineno [string trim $lineno]

	set rule [string range $rule [expr $end_link_idx + 1] end]
	
	# Only display line number hyperlink if this is not a binary policy.
	if {![ApolTop::is_binary_policy]} {
		$tra_info_text insert end "\[$lineno\]"
		Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
	}
	set startIdx [$tra_info_text index insert]
	$tra_info_text insert end "$rule\n"
	set endIdx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
		
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_common_object_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_common_object_info {tra_listbox tra_info_text data} {
	variable typeA
	variable typeB
	
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
		
	set i 0
        # Get # common objects
	set num_comm_objs [lindex $data $i]
	
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "Common Object Types ($num_comm_objs):\n\n"   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		
	# Get next element index
	set curr_idx [expr $i + 1]
	if {$num_comm_objs} { 
		for { set x 0 } { $x < $num_comm_objs } { incr x } { 
			$tra_info_text insert end "[lindex $data $curr_idx]\n"
			incr curr_idx
		}
		set i $curr_idx
		
		# Get common rules
		set num_comm_rules_A [lindex $data $i]
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "\n$typeA "   
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	
		set start_idx [$tra_info_text index insert] 
		$tra_info_text insert end "Common Object Type Rules ($num_comm_rules_A):\n\n"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx 
		set curr_idx [expr $i + 1]
		for { set x 0 } { $x < $num_comm_rules_A } { incr x } { 
		    	Apol_Analysis_tra::print_rule $tra_info_text $data $curr_idx
			incr curr_idx
		}
	}
	set i $curr_idx
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "\n$typeB "   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
		
	set start_idx [$tra_info_text index insert]
	set num_comm_rules_B [lindex $data $i]
	$tra_info_text insert end "Common Object Type Rules ($num_comm_rules_B):\n\n" 
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	set curr_idx [expr $i + 1]
	for { set x 0 } { $x < $num_comm_rules_B } { incr x } { 
		Apol_Analysis_tra::print_rule $tra_info_text $data $curr_idx
		incr curr_idx
	}

	return 0
}

proc Apol_Analysis_tra::destroy_progressDlg {} {
	variable progressDlg
	
	if {[winfo exists $progressDlg]} {
		destroy $progressDlg
	}
     	return 0
} 

proc Apol_Analysis_tra::display_progressDlg {} {
     	variable progressDlg
	    		
	set Apol_Analysis_tra::progressmsg "Performing types relationship analysis..."
	set progressBar [ProgressDlg $progressDlg \
		-parent $ApolTop::mainframe \
        	-textvariable Apol_Analysis_tra::progressmsg \
        	-variable Apol_Analysis_tra::progress_indicator \
        	-maximum 3 \
        	-width 45]
        update
        bind $progressBar <<AnalysisStarted>> {
        	set Apol_Analysis_fulflow::progress_indicator [expr $Apol_Analysis_fulflow::progress_indicator + 1]
        }
        # TODO: generate virtual events to place onto Tcl's event queue, to capture progress.
	#event generate $Apol_Analysis_fulflow::progressDlg <<AnalysisStarted>> -when head

        return 0
} 
					
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_unique_object_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_unique_object_info {tra_listbox tra_info_text data} {
	variable typeA
	variable typeB
	
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	
        set i 0
        # Get # Unique objects
	set num_unique_objs_A [lindex $data $i]
	
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "$typeA "   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
				
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "Unique Object Types ($num_unique_objs_A):\n\n" 
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		
	# Get next element index
	set curr_idx [expr $i + 1]
	if {$num_unique_objs_A} { 
		for { set x 0 } { $x < $num_unique_objs_A } { incr x } { 
			$tra_info_text insert end "[lindex $data $curr_idx]\n"
			incr curr_idx
		}
		set i $curr_idx
		
		# Get Unique rules
		set num_unique_rules_A [lindex $data $i]
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "\n$typeA "   
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "Unique Object Type Rules ($num_unique_rules_A):\n\n" 
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		set curr_idx [expr $i + 1]
		for { set x 0 } { $x < $num_unique_rules_A } { incr x } { 
			Apol_Analysis_tra::print_rule $tra_info_text $data $curr_idx
			incr curr_idx
		}
	} 
	set i $curr_idx
	set num_unique_objs_B [lindex $data $i]
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "\n\n$typeB "   
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
		
	set start_idx [$tra_info_text index insert]
	$tra_info_text insert end "Unique Object Types ($num_unique_objs_B):\n\n"  
	set end_idx [$tra_info_text index insert]
	$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	if {$num_unique_objs_B} { 	
		set curr_idx [expr $i + 1]
		for { set x 0 } { $x < $num_unique_objs_B } { incr x } { 
			$tra_info_text insert end "[lindex $data $curr_idx]\n"
			incr curr_idx
		}
		set i $curr_idx
		
		set num_unique_rules_B [lindex $data $i]
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "\n$typeB "   
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "Unique Object Type Rules ($num_unique_rules_B):\n\n" 
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		set curr_idx [expr $i + 1]
		for { set x 0 } { $x < $num_unique_rules_B } { incr x } { 
			Apol_Analysis_tra::print_rule $tra_info_text $data $curr_idx
			incr curr_idx
		}
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_direct_flows
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_direct_flows {tra_listbox tra_info_text data} {
	variable typeA
    	variable typeB

        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set start_type $typeA
	set i 0
	
	# Get # of target types 
	set num_target_types [lindex $data $i]
	
	if {$num_target_types == 0} {
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "No direct information flows"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	} else {
		incr i
		set cur_end_type [lindex $data $i]
		incr i
		set flow_dir [lindex $data $i]
		incr i
		set num_objs [lindex $data $i]
		incr i
		set curIdx $i
		set startIdx [$tra_info_text index insert]
			
		$tra_info_text insert end "Information flows both into and out of "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $start_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end " - \[from/to\] "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $cur_end_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx $endIdx
	    
		# If there are any target types then format and display the data				
		for { set x 0 } { $x < $num_target_types } { incr x } { 			
			if {$flow_dir == "both"} {
				# Print label for in flows 
				$tra_info_text insert end "\n\nObject classes for "
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				$tra_info_text insert end "\[IN/OUT\]"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx	 
				set startIdx $endIdx
				$tra_info_text insert end " flows:"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				# Then process inflows   
				for {set i 0} {$i<$num_objs} {incr i} {
					if {[lindex $data $curIdx] == "1"} {
					    incr curIdx
					    $tra_info_text insert end "\n\t"
					    # This should be the object name
					    $tra_info_text insert end [lindex $data $curIdx]
					    set endIdx [$tra_info_text index insert]
					    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
					    incr curIdx
					    set num_rules [lindex $data $curIdx]
					    for {set j 0} {$j<$num_rules} {incr j} {
					    	$tra_info_text insert end "\n\t"
					    	set startIdx [$tra_info_text index insert]
						incr curIdx
						set rule [lindex $data $curIdx]
						# Get the line number only
						set end_link_idx [string first "\]" [string trim $rule] 0]
						set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
						set lineno [string trim $lineno]
					
						set rule [string range $rule [expr $end_link_idx + 1] end]
						
						# Only display line number hyperlink if this is not a binary policy.
						if {![ApolTop::is_binary_policy]} {
							$tra_info_text insert end "\[$lineno\]"
							Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
						}
						set startIdx [$tra_info_text index insert]
						$tra_info_text insert end " $rule"
						set endIdx [$tra_info_text index insert]
						$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
						
						incr curIdx
						# The next element should be the enabled boolean flag.
						if {[lindex $data $curIdx] == 0} {
							$tra_info_text insert end "   "
							set startIdx [$tra_info_text index insert]
							$tra_info_text insert end "\[Disabled\]"
							set endIdx [$tra_info_text index insert]
							$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $startIdx $endIdx
						} 
						set startIdx [$tra_info_text index insert]
					    }
					    
					} 
					incr curIdx
				}
			} else {
				$tra_info_text insert end "\n\nObject classes for "
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				set flow_dir [string toupper $flow_dir]
				$tra_info_text insert end $flow_dir
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx	 
				set startIdx $endIdx
				$tra_info_text insert end " flows:"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
				set startIdx $endIdx
				
				for {set i 0} {$i<$num_objs} {incr i} {
					if { [lindex $data $curIdx] == "1" } {
					    incr curIdx
					    $tra_info_text insert end "\n\t"
					    # This should be the object name
					    $tra_info_text insert end [lindex $data $curIdx]
					    set endIdx [$tra_info_text index insert]
					    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
					    incr curIdx
					    set num_rules [lindex $data $curIdx]
					    for {set j 0} {$j<$num_rules} {incr j} {
					    	$tra_info_text insert end "\n\t"
					    	set startIdx [$tra_info_text index insert]
						incr curIdx
						set rule [lindex $data $curIdx]
						# Get the line number only
						set end_link_idx [string first "\]" [string trim $rule] 0]
						set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
						set lineno [string trim $lineno]
					
						set rule [string range $rule [expr $end_link_idx + 1] end]
						
						# Only display line number hyperlink if this is not a binary policy.
						if {![ApolTop::is_binary_policy]} {
							$tra_info_text insert end "\[$lineno\]"
							Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
						}
						set startIdx [$tra_info_text index insert]
						$tra_info_text insert end " $rule"
						set endIdx [$tra_info_text index insert]
						$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
						
						incr curIdx
						# The next element should be the enabled boolean flag.
						if {[lindex $data $curIdx] == 0} {
							$tra_info_text insert end "   "
							set startIdx [$tra_info_text index insert]
							$tra_info_text insert end "\[Disabled\]"
							set endIdx [$tra_info_text index insert]
							$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $startIdx $endIdx
						}
						set startIdx [$tra_info_text index insert]
					    }
					} 
					incr curIdx
				}
			}
		}
	}

	return 0
}
						
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_transitive_flows
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_transitive_flows {tra_listbox tra_info_text data start_type} { 
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set i 0
	
	# Get # of target types 
	set num_target_types [lindex $data $i]
	if {$num_target_types} {
		incr i
		set end_type [lindex $data $i]
			
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end "Information flows from "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $start_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end " to "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $startIdx $endIdx
		set startIdx [$tra_info_text index insert]
		$tra_info_text insert end $end_type
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $startIdx $endIdx
		set startIdx $endIdx 
	} else {
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "No transitive information flows from $start_type"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	}
	         	    
	# If there are any target types then format and display the data				
	for { set x 0 } { $x < $num_target_types } { incr x } { 
		# the number of paths 
		incr i
	        set currentIdx $i
	        set num_paths [lindex $data $currentIdx]
		
		$tra_info_text insert end "\n\nApol found the following number of information flows: "
		set endIdx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
	        set startIdx $endIdx
		$tra_info_text insert end $num_paths
	        set endIdx [$tra_info_text index insert]
	        $tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
                		
		for {set j 0} {$j < $num_paths} {incr j} {
		    set startIdx [$tra_info_text index insert]
		    $tra_info_text insert end "\n\nFlow"
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
		    set startIdx $endIdx
		    $tra_info_text insert end " [expr $j+1] "
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
		    set startIdx $endIdx
		    $tra_info_text insert end "requires " 
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
		    set startIdx $endIdx 
		    # Increment to the number of flows 
		    incr currentIdx
		    set num_flows [lindex $data $currentIdx]
		    $tra_info_text insert end $num_flows
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
		    set startIdx $endIdx
		    $tra_info_text insert end " step(s)."
		    set endIdx [$tra_info_text index insert]
		    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
		    for {set k 0} {$k < $num_flows} {incr k} {
			# First print the flow number
			$tra_info_text insert end "\n\n\tStep "
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			set startIdx $endIdx
			$tra_info_text insert end [expr $k + 1]
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::counters_tag $startIdx $endIdx
			set startIdx $endIdx
			$tra_info_text insert end ": "
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			set startIdx $endIdx
			$tra_info_text insert end "from "
			# increment to the start type for the flow
			incr currentIdx
			$tra_info_text insert end [lindex $data $currentIdx]
			$tra_info_text insert end " to "
			# Increment to the end type for the flow
			incr currentIdx
			$tra_info_text insert end [lindex $data $currentIdx]
			set endIdx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			set startIdx $endIdx
			# Increment to the # of object classes
			incr currentIdx
			set num_classes [lindex $data $currentIdx]
			for {set l 0} {$l < $num_classes} {incr l} {
			    # Increment to the first object class
		    	    incr currentIdx
			    $tra_info_text insert end "\n\t[lindex $data $currentIdx]"
			    set endIdx [$tra_info_text index insert]
			    $tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $startIdx $endIdx
			    set startIdx $endIdx
			    # Increment to the # of object class rules
			    incr currentIdx
			    set num_rules [lindex $data $currentIdx]
			    for {set m 0} {$m < $num_rules} {incr m} {
			    	# Increment to the next rule for the object
				incr currentIdx
				set rule [lindex $data $currentIdx]
				$tra_info_text insert end "\n\t"
				set startIdx [$tra_info_text index insert]
				# Get the line number only
				set end_link_idx [string first "\]" [string trim $rule] 0]
				set lineno [string range [string trim [string range $rule 0 $end_link_idx]] 1 end-1]
				set lineno [string trim $lineno]
				set rule [string range $rule [expr $end_link_idx + 1] end]
				
				# Only display line number hyperlink if this is not a binary policy.
				if {![ApolTop::is_binary_policy]} {
					$tra_info_text insert end "\[$lineno\]"
					Apol_PolicyConf::insertHyperLink $tra_info_text "$startIdx wordstart + 1c" "$startIdx wordstart + [expr [string length $lineno] + 1]c"
				}
				set startIdx [$tra_info_text index insert]
				$tra_info_text insert end " $rule"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::rules_tag $startIdx $endIdx
				
				incr currentIdx
				# The next element should be the enabled boolean flag.
				if {[lindex $data $currentIdx] == 0} {
					$tra_info_text insert end "   "
					set startIdx [$tra_info_text index insert]
					$tra_info_text insert end "\[Disabled\]"
					set endIdx [$tra_info_text index insert]
					$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $startIdx $endIdx
				} 
				set startIdx [$tra_info_text index insert]
			    } 
			}
		    }
		}
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_dta_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_dta_info {tra_listbox tra_info_text data start_type} {   
        if { $data == "" } {
	        $tra_info_text configure -state disabled
		return 0
	}
	set idx 0

	# Get # of target types 
	set num_target_types [lindex $data $idx]
	if {![string is integer $num_target_types]} {
		puts "Number of target types is not an integer: $num_target_types"
		return
	}
			
	if {$num_target_types} {
		incr idx
		set end_type [lindex $data $idx]
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "Domain transition from "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end $start_type
		set end_idx [$tra_info_text index insert] 
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end " to "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
		
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end $end_type
		set end_idx [$tra_info_text index insert] 
		$tra_info_text tag add $Apol_Analysis_tra::title_type_tag $start_idx $end_idx
	} else {
		set start_idx [$tra_info_text index insert]
		$tra_info_text insert end "No domain transitions"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::title_tag $start_idx $end_idx
	}

	#  are any target types then format and display the data				
	for { set x 0 } { $x < $num_target_types } { incr x } { 
		incr idx
		# (# of pt rules)
		$tra_info_text insert end "\n\n"
		set start_idx [$tra_info_text index insert]
		set num_pt [lindex $data $idx]
		if {![string is integer $num_pt]} {
			puts "Number of process transition rules is not an integer: $num_pt"
			return
		}
			
		$tra_info_text insert end "Process Transition Rules:  "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$tra_info_text insert end "$num_pt\n"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx

		for { set i 0 } { $i < $num_pt } { incr i } {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx] 
			
			$tra_info_text insert end "\t"
			set start_idx [$tra_info_text index insert]
			
			# Only display line number hyperlink if this is not a binary policy.
			if {![ApolTop::is_binary_policy]} {
				$tra_info_text insert end "($lineno) "
				set end_idx [$tra_info_text index insert]
				Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
				set start_idx $end_idx
			}
			$tra_info_text insert end "$rule"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
			
			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$tra_info_text insert end "   "
				set startIdx [$tra_info_text index insert]
				$tra_info_text insert end "\[Disabled\]\n"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
			} else {
				$tra_info_text insert end "\n"
			}
		}
		incr idx
		# (# of file types)
		set num_types [lindex $data $idx]
		if {![string is integer $num_types]} {
			puts "Number of file types is not an integer: $num_types"
			return
		}
			
		set start_idx $end_idx
		$tra_info_text insert end "\nEntry Point File Types:  "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$tra_info_text insert end "$num_types\n"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx
		
		for {set i 0} { $i < $num_types } { incr i } {
			incr idx
			# (file type) 
			set type [lindex $data $idx]
			set start_idx $end_idx
			$tra_info_text insert end "\t$type\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::types_tag $start_idx $end_idx
			incr idx
			set num_ep [lindex $data $idx]
			if {![string is integer $num_ep]} {
				puts "Number of entrypoint access rules is not an integer: $num_ep"
				return
			}
			
			set start_idx $end_idx
			$tra_info_text insert end "\t\tFile Entrypoint Rules:  "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
			set start_idx $end_idx
			$tra_info_text insert end "$num_ep\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx
		
			for {set j 0} {$j < $num_ep} {incr j}  {
				incr idx
				set rule [lindex $data $idx]
				incr idx
				set lineno [lindex $data $idx]

				$tra_info_text insert end "\t\t"
				set start_idx [$tra_info_text index insert]
				
				# Only display line number hyperlink if this is not a binary policy.
				if {![ApolTop::is_binary_policy]} {
					$tra_info_text insert end "($lineno) "
					set end_idx [$tra_info_text index insert]
					Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
					set start_idx $end_idx
				}
				$tra_info_text insert end "$rule"
				set end_idx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
				
				incr idx
				# The next element should be the enabled boolean flag.
				if {[lindex $data $idx] == 0} {
					$tra_info_text insert end "   "
					set startIdx [$tra_info_text index insert]
					$tra_info_text insert end "\[Disabled\]\n"
					set endIdx [$tra_info_text index insert]
					$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
				} else {
					$tra_info_text insert end "\n"
				}
			}
			incr idx
			set num_ex [lindex $data $idx]
			if {![string is integer $num_ex]} {
				puts "Number of execute access rules is not an integer: $num_ex"
				return
			}
			
			set start_idx $end_idx
			$tra_info_text insert end "\n\t\tFile Execute Rules:  "
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
			set start_idx $end_idx
			$tra_info_text insert end "$num_ex\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx
			
			for { set j 0 } { $j < $num_ex } { incr j }  {
				incr idx
				set rule [lindex $data $idx]
				incr idx
				set lineno [lindex $data $idx]
				
				$tra_info_text insert end "\t\t"
				set start_idx [$tra_info_text index insert]
				
				# Only display line number hyperlink if this is not a binary policy.
				if {![ApolTop::is_binary_policy]} {
					$tra_info_text insert end "($lineno) "
					set end_idx [$tra_info_text index insert]
					Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
					set start_idx $end_idx
				}
				$tra_info_text insert end "$rule"
				set end_idx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
				
				incr idx
				# The next element should be the enabled boolean flag.
				if {[lindex $data $idx] == 0} {
					$tra_info_text insert end "   "
					set startIdx [$tra_info_text index insert]
					$tra_info_text insert end "\[Disabled\]\n"
					set endIdx [$tra_info_text index insert]
					$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
				} else {
					$tra_info_text insert end "\n"
				}
			}
		}
		incr idx
		set num_additional [lindex $data $idx]
		if {![string is integer $num_additional]} {
			puts "Number of additional access rules is not an integer: $num_additional"
			return
		}
		
		set start_idx $end_idx
		$tra_info_text insert end "\nPrivileges for this target domain:  "
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::subtitle_tag $start_idx $end_idx
		set start_idx $end_idx
		$tra_info_text insert end "$num_additional\n"
		set end_idx [$tra_info_text index insert]
		$tra_info_text tag add $Apol_Analysis_tra::counters_tag $start_idx $end_idx

		for {set j 0 } { $j < $num_additional } { incr j }  {
			incr idx
			set rule [lindex $data $idx]
			incr idx
			set lineno [lindex $data $idx]
		
			$tra_info_text insert end "\t"
			set start_idx [$tra_info_text index insert]
			$tra_info_text insert end "($lineno) "
			set end_idx [$tra_info_text index insert]
			Apol_PolicyConf::insertHyperLink $tra_info_text "$start_idx wordstart + 1c" "$start_idx wordstart + [expr [string length $lineno] + 1]c"
			set start_idx $end_idx
			$tra_info_text insert end "$rule\n"
			set end_idx [$tra_info_text index insert]
			$tra_info_text tag add $Apol_Analysis_tra::rules_tag $start_idx $end_idx
			
			incr idx
			# The next element should be the enabled boolean flag.
			if {[lindex $data $idx] == 0} {
				$tra_info_text insert end "   "
				set startIdx [$tra_info_text index insert]
				$tra_info_text insert end "\[Disabled\]\n"
				set endIdx [$tra_info_text index insert]
				$tra_info_text tag add $Apol_Analysis_tra::disabled_rule_tag $start_idx $end_idx
			} else {
				$tra_info_text insert end "\n"
			}
		}
	}
			
        $tra_info_text configure -state disabled
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::create_results_list_structure
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::create_results_list_structure {tra_listbox results_list} {
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel
	variable dta_BA_sel		
	variable trans_flow_AB_sel		
	variable trans_flow_BA_sel
	variable dir_flow_sel		
	variable other_ttrules_sel	
	variable process_sel		
	
	# Parse the list and add the list elements as we parse
	# get type strings
	set typeA [lindex $results_list 0]
	set typeB [lindex $results_list 1]
	set i 2
	
	# Get # of common attributes
	set num_common_attribs [lindex $results_list $i]
	set start_idx $i
	# If there are common attribs...
	for { set x 0 } { $x < $num_common_attribs } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$comm_attribs_sel} {
		$tra_listbox insert end common_attribs \
			-text "Common Attributes" \
			-data [lrange $results_list $start_idx $i]  
	}
	
	# Get # of common roles
	incr i
	set num_common_roles [lindex $results_list $i]
	set start_idx $i
	# If there are common roles... 
	for { set x 0 } { $x < $num_common_roles } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$comm_roles_sel} {
		$tra_listbox insert end common_roles \
			-text "Common Roles" \
			-data [lrange $results_list $start_idx $i] 
	}
	
	# Get # of common users
	incr i
	set num_common_users [lindex $results_list $i]
	set start_idx $i
	# If there are common users... 
	for { set x 0 } { $x < $num_common_users } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$comm_users_sel} {
		$tra_listbox insert end common_users \
			-text "Common Users" \
			-data [lrange $results_list $start_idx $i] 
	}
	# Get # of other type transition rules
	incr i
	set num_other_tt_rules [lindex $results_list $i]
	set start_idx $i
	# If there are type transition rules... 
	for { set x 0 } { $x < $num_other_tt_rules } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$other_ttrules_sel} {
		$tra_listbox insert end tt_rules \
			-text "Type Transition Rules" \
			-data [lrange $results_list $start_idx $i] 
	}
	
	# Get # of other process rules
	incr i
	set num_process_rules [lindex $results_list $i]
	set start_idx $i
	# If there are process rules... 
	for { set x 0 } { $x < $num_process_rules } { incr x } { 
		incr i
	}
	# Insert item into listbox 
	if {$process_sel} {
		$tra_listbox insert end process_rules \
			-text "Direct Process Interactions" \
			-data [lrange $results_list $start_idx $i] 
	}
		
	# Get # common objects
	incr i
	set num_comm_objs [lindex $results_list $i]
	set start_idx $i
	for { set x 0 } { $x < $num_comm_objs } { incr x } { 
		incr i
	}
	
	# Get common rules
	incr i
	set num_comm_rules_A [lindex $results_list $i]
	for { set x 0 } { $x < $num_comm_rules_A } { incr x } { 
		incr i
	}
	
	incr i
	set num_comm_rules_B [lindex $results_list $i]
	for { set x 0 } { $x < $num_comm_rules_B } { incr x } { 
		incr i
	}
	
	# Insert item into listbox 
	if {$comm_access_sel} {
		$tra_listbox insert end common_objects \
			-text "Shared access to resources" \
			-data [lrange $results_list $start_idx $i] 
	}
	# Get # uniqe objects
	incr i
	set num_uniqe_objs_A [lindex $results_list $i]
	set start_idx $i
	for { set x 0 } { $x < $num_uniqe_objs_A } { incr x } { 
		incr i
	}
	
	# Get unique rules
	incr i
	set num_uniqe_rules_A [lindex $results_list $i]
	for { set x 0 } { $x < $num_uniqe_rules_A } { incr x } { 
		incr i
	}
	
	incr i
	set num_uniqe_objs_B [lindex $results_list $i]
	for { set x 0 } { $x < $num_uniqe_objs_B } { incr x } { 
		incr i
	}
	incr i
	set num_uniqe_rules_B [lindex $results_list $i]
	for { set x 0 } { $x < $num_uniqe_rules_B } { incr x } { 
		incr i
	}
	
	# Insert item into listbox
	if {$unique_access_sel} { 
		$tra_listbox insert end unique_objects \
			-text "Special access to resources" \
			-data [lrange $results_list $start_idx $i] 
	}
	# Parse dirflow data 
	# Get # of target types
	incr i
	set start_idx $i
	set num_dirflow_target_types [lindex $results_list $i]
	set currentIdx [expr $i + 1]				
	for { set x 0 } { $x < $num_dirflow_target_types } { incr x } { 		        	
		set nextIdx [Apol_Analysis_dirflow::parseList_get_index_next_node $currentIdx $results_list]
		if {$nextIdx == -1} {
			return -code error "Error parsing results"
		}
		set currentIdx $nextIdx
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox 
	if {$dir_flow_sel} {
		$tra_listbox insert end dir_flows \
			-text "Direct Flows Between A and B" \
			-data [lrange $results_list $start_idx [expr $i - 1]] 
	}
	set start_idx $i
	set num_transflow_types_A [lindex $results_list $i]
	set currentIdx [expr $i + 1]				
	for { set x 0 } { $x < $num_transflow_types_A } { incr x } { 		        	
		set nextIdx [Apol_Analysis_fulflow::parseList_get_index_next_node $currentIdx $results_list]
		if {$nextIdx == -1} {
			return -code error "Error parsing Transitive Flow results"
		}
		set currentIdx $nextIdx
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox 
	if {$trans_flow_AB_sel} {
		$tra_listbox insert end trans_flows_A \
			-text "Transitive Flows A->B" \
			-data [lrange $results_list $start_idx [expr $i - 1]] 
	}
	set start_idx $i
	set num_transflow_types_B [lindex $results_list $i]
	set currentIdx [expr $i + 1]				
	for { set x 0 } { $x < $num_transflow_types_B } { incr x } { 		        	
		set nextIdx [Apol_Analysis_fulflow::parseList_get_index_next_node $currentIdx $results_list]
		if {$nextIdx == -1} {
			return -code error "Error parsing Transitive Flow results"
		}
		set currentIdx $nextIdx
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox
	if {$trans_flow_BA_sel} { 
		$tra_listbox insert end trans_flows_B \
			-text "Transitive Flows B->A" \
			-data [lrange $results_list $start_idx [expr $i - 1]] 
	}
	
	set start_idx $i	
	set num_dta_types_A [lindex $results_list $i]
	set currentIdx [expr $i + 1]
	for { set x 0 } { $x < $num_dta_types_A } { incr x } { 
		set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $currentIdx]
		if {$end_idx == -1} {
			# Print error 
			return -code error "Error parsing results for type [lindex $results_list $currentIdx].\n"
		}
	        set currentIdx [expr $end_idx + 1]
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox
	if {$dta_AB_sel} { 
		$tra_listbox insert end dta_analysis_A \
			-text "Domain Transitions A->B" \
			-data [lrange $results_list $start_idx [expr $i - 1]] 
	}
	
	set start_idx $i
	set num_dta_types_B [lindex $results_list $i]
	set currentIdx [expr $i + 1]
	for { set x 0 } { $x < $num_dta_types_B } { incr x } { 
		set end_idx [Apol_Analysis_dta::get_target_type_data_end_idx $results_list $currentIdx]
		if {$end_idx == -1} {
			# Print error 
			return -code error "Error parsing results for type [lindex $results_list $currentIdx].\n"
		}
	        set currentIdx [expr $end_idx + 1]
	}
	# This should be the index of the next item.
	set i $currentIdx
	# Insert item into listbox 
	if {$dta_BA_sel} {
		$tra_listbox insert end dta_analysis_B \
			-text "Domain Transitions B->A" \
			-data [lrange $results_list $start_idx [expr $i - 1]] 
	}						
	# Insert final item into listbox (i.e. display ALL info item 
	$tra_listbox insert end all -text "Summary Report"
	
        $tra_listbox configure -redraw 1
	        
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::close { } {   
	Apol_Analysis_tra::reset_variables
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::open { } { 
	variable attribA 		
    	variable attribB 
	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
        variable cb_attribA
	variable cb_attribB
	    	  
	Apol_Analysis_tra::populate_ta_list
	Apol_Analysis_tra::initialize_widgets_state
	Apol_Analysis_tra::change_types_list $combo_typeA $combo_attribA 1
	Apol_Analysis_tra::change_types_list $combo_typeB $combo_attribB 1
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::display_mod_options { opts_frame } {    
	Apol_Analysis_tra::reset_variables
     	Apol_Analysis_tra::create_options $opts_frame
     	Apol_Analysis_tra::populate_ta_list

     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::get_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::get_analysis_info {} {
     	return $Apol_Analysis_tra::descriptive_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::get_results_raised_tab
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::get_results_raised_tab {} {
     	return $Apol_Analysis_tra::tra_info_text
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::parse_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::parse_query_options_list {query_options curr_idx parentDlg} { 
	# Analysis variables  
	variable attribA 		
    	variable attribB 		
    	variable attribA_sel	
    	variable attribB_sel
	variable typeA		
    	variable typeB
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel		
	variable dta_BA_sel
	variable trans_flow_AB_sel		
	variable trans_flow_BA_sel
	variable dir_flow_sel		
	variable other_ttrules_sel	
	variable process_sel	
	# Global widget identifiers	  
	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
        variable cb_attribA
	variable cb_attribB
	
	Apol_Analysis_tra::reset_variables
	set i $curr_idx
	while {$i != [llength $query_options]} {
        	# name:value pairs. 
        	switch -exact -- [lindex $query_options $i] {
        		"typeA" { 
        			incr i
				if {[lindex $query_options $i] != "\{\}"} {
					set typeA [lindex $query_options $i]      
				}
			}
			"typeB" {
				incr i
				if {[lindex $query_options $i] != "\{\}"} {
			        	set typeB [lindex $query_options $i]    
			        }
			}
			"attribA_sel" {
				incr i
			        set attribA_sel [lindex $query_options $i] 
			}
			"attribB_sel" {
				incr i
			        set attribB_sel [lindex $query_options $i]    
			}
			"attribA" {
				incr i
				if {[lindex $query_options $i] != "\{\}"} {
			        	set attribA [lindex $query_options $i]    
			        }
			}
			"attribB" {
				incr i
				if {[lindex $query_options $i] != "\{\}"} {
			        	set attribB [lindex $query_options $i]    
			        }
			}		
			"comm_attribs_sel" {
				incr i
				set comm_attribs_sel [lindex $query_options $i] 
			}
			"comm_roles_sel" {
				incr i
				set comm_roles_sel [lindex $query_options $i]  
			}
			"comm_users_sel" {
				incr i
				set comm_users_sel [lindex $query_options $i]    
			}
			"comm_access_sel" {
				incr i
				set comm_access_sel [lindex $query_options $i]
			}
			"unique_access_sel" {
				incr i
				set unique_access_sel [lindex $query_options $i]
			}
			"dta_AB_sel" {
				incr i
				set dta_AB_sel [lindex $query_options $i]
			}
			"dta_BA_sel" {
				incr i
				set dta_BA_sel [lindex $query_options $i]
			}
			"trans_flow_AB_sel" {
				incr i
				set trans_flow_AB_sel [lindex $query_options $i]
			}
			"trans_flow_BA_sel" {
				incr i
				set trans_flow_BA_sel [lindex $query_options $i]
			}
			"dir_flow_sel" {
				incr i
				set dir_flow_sel [lindex $query_options $i]
			}
			"other_ttrules_sel" {
				incr i
				set other_ttrules_sel [lindex $query_options $i]
			}
			"process_sel" {
				incr i
				set process_sel [lindex $query_options $i]
			}	
			default {
				puts "Error: Unknown query option name encountered ([lindex $query_options $i])."
			}
        	}
        	incr i
        }
     
        Apol_Analysis_tra::config_attrib_comboBox_state \
		$cb_attribA $combo_attribA $combo_typeA 0
	Apol_Analysis_tra::config_attrib_comboBox_state \
		$cb_attribB $combo_attribB $combo_typeB 0
	Apol_Analysis_tra::change_types_list $combo_typeA $combo_attribA 0
	Apol_Analysis_tra::change_types_list $combo_typeB $combo_attribB 0
	
	return $i
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::load_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::load_query_options { file_channel parentDlg } { 
	# Analysis variables  
	variable attribA 		
    	variable attribB 		
    	variable attribA_sel	
    	variable attribB_sel
	variable typeA		
    	variable typeB
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel
	variable dta_BA_sel
	variable trans_flow_AB_sel
	variable trans_flow_BA_sel		
	variable dir_flow_sel		
	variable other_ttrules_sel	
	variable process_sel	
	# Global widget identifiers	 
	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
        variable cb_attribA
	variable cb_attribB
	
	set query_options_tmp ""
	set query_options ""
        while {[eof $file_channel] != 1} {
		gets $file_channel line
		set tline [string trim $line]
		# Skip empty lines
		if {$tline == ""} {
			continue
		}
		set query_options_tmp [lappend query_options_tmp $tline]
	}

	if {$query_options_tmp == ""} {
		return -code error "No query parameters were found."
	}

	# Re-format the query options list into a string where all elements are seperated
	# by a single space. Then split this string into a list using space and colon characters
	# as the delimeters.	
	set query_options_tmp [split [join $query_options_tmp " "] " :"]
	set query_options [ApolTop::strip_list_of_empty_items $query_options_tmp]
	if {$query_options == ""} {
		return -code error "No query parameters were found."
	}
	# Parse the list starting from the beginning index 0.
	Apol_Analysis_tra::parse_query_options_list $query_options 0 $parentDlg
	
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::get_search_options_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::get_search_options_list {} {
	# Analysis variables  
	variable attribA 		
    	variable attribB 		
    	variable attribA_sel	
    	variable attribB_sel	
	variable typeA		
    	variable typeB
	variable comm_attribs_sel 	
	variable comm_roles_sel 	
	variable comm_users_sel 	
	variable comm_access_sel 	
	variable unique_access_sel 	
	variable dta_AB_sel		
	variable dta_BA_sel
	variable trans_flow_AB_sel		
	variable trans_flow_BA_sel
	variable dir_flow_sel		
	variable other_ttrules_sel	
	variable process_sel	
	   
	set options [list \
		"typeA:" \
		$typeA \
		"typeB:" \
		$typeB \
		"attribA:" \
		$attribA \
		"attribB:" \
		$attribB \
		"attribA_sel:" \
		$attribA_sel \
		"attribB_sel:" \
		$attribB_sel \
		"comm_attribs_sel:" \
		$comm_attribs_sel \
		"comm_roles_sel:" \
		$comm_roles_sel \
		"comm_users_sel:" \
		$comm_users_sel \
		"comm_access_sel:" \
		$comm_access_sel \
		"unique_access_sel:" \
		$unique_access_sel \
		"dta_AB_sel:" \
		$dta_AB_sel \
		"dta_BA_sel:" \
		$dta_BA_sel \
		"trans_flow_AB_sel:" \
		$trans_flow_AB_sel \
		"trans_flow_BA_sel:" \
		$trans_flow_BA_sel \
		"dir_flow_sel:" \
		$dir_flow_sel \
		"other_ttrules_sel:" \
		$other_ttrules_sel \
		"process_sel:" \
		$process_sel]
		
	return $options
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::save_query_options {module_name file_channel file_name} {
	set options [Apol_Analysis_tra::get_search_options_list]
		
     	puts $file_channel "$module_name"
	puts $file_channel "$options"
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::get_current_results_state { } {  
	variable tra_listbox
	variable tra_info_text
	
	set options [Apol_Analysis_tra::get_search_options_list]
	set options [linsert $options 0 $tra_listbox $tra_info_text]

	return $options
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::set_display_to_results_state {query_options} { 
	variable tra_listbox
	variable tra_info_text
	  
	# The trick is to configure the list to look like we have read it in from a file
	# as we do when loading a saved query file.  	
     	foreach item $query_options {
     		set query_options_tmp [lappend query_options_tmp [concat $item]]
     	}
	set query_options_tmp [list $query_options_tmp]

	# Re-format the query options list into a string where all elements are seperated
	# by a single space. Then split this string into a list using space and colon characters
	# as the delimeters.	
	set query_options_tmp [split [join $query_options_tmp " "] " :"]
	set query_options_formatted [ApolTop::strip_list_of_empty_items $query_options_tmp]
	
	set parentDlg [ApolTop::get_toplevel_dialog]
	# widget variables
        set tra_listbox [lindex $query_options_formatted 0]
        set tra_info_text [lindex $query_options_formatted 1]

        # Parse the list starting from the index 2.
	Apol_Analysis_tra::parse_query_options_list $query_options_formatted 2 $parentDlg
             
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::free_results_data
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::free_results_data {query_options} {  
	set tra_listbox [lindex $query_options 0]
        set tra_info_text [lindex $query_options 1]

	if {[winfo exists $tra_listbox]} {
		$tra_listbox delete [$tra_listbox items]
		destroy $tra_listbox
	}
	if {[winfo exists $tra_info_text]} {
		$tra_info_text delete 0.0 end
		destroy $tra_info_text
	}
	return 0
}

#################################################################################
##
## The rest of these procs are not interface procedures, but rather internal
## functions to this analysis.
##
#################################################################################

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::reset_variables { } { 
	set Apol_Analysis_tra::attribA_sel     	0 
        set Apol_Analysis_tra::attribB_sel     	0
	set Apol_Analysis_tra::typeA     	"" 
        set Apol_Analysis_tra::typeB            ""
        set Apol_Analysis_tra::attribA       	""
	set Apol_Analysis_tra::attribB		""	
	set Apol_Analysis_tra::comm_attribs_sel	1
        set Apol_Analysis_tra::comm_roles_sel   1
        set Apol_Analysis_tra::comm_users_sel   1 
        set Apol_Analysis_tra::comm_access_sel    0
        set Apol_Analysis_tra::unique_access_sel  0
        set Apol_Analysis_tra::dta_AB_sel    	  0
        set Apol_Analysis_tra::dta_BA_sel    	  0
        set Apol_Analysis_tra::trans_flow_AB_sel     0
        set Apol_Analysis_tra::trans_flow_BA_sel     0
        set Apol_Analysis_tra::dir_flow_sel       0
        set Apol_Analysis_tra::other_ttrules_sel  0
        set Apol_Analysis_tra::process_sel   	  0
	
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::change_types_list {type_cmbox attrib_cmbox clear_type} { 
	upvar #0 [$attrib_cmbox cget -textvariable] attrib
	
	if {$attrib != ""} {
		if {$clear_type} {
			$type_cmbox configure -text ""		   
		}
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $attrib]} err]	
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -code error
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
#  Command Apol_Analysis_tra::populate_ta_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::populate_ta_list { } { 
	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
	   
	set attrib_typesList $Apol_Types::typelist
	set idx [lsearch -exact $attrib_typesList "self"]
	if {$idx != -1} {
		set attrib_typesList [lreplace $attrib_typesList $idx $idx]
	}
	$combo_typeA configure -values $attrib_typesList
     	$combo_attribA configure -values $Apol_Types::attriblist
     	$combo_typeB configure -values $attrib_typesList
     	$combo_attribB configure -values $Apol_Types::attriblist
     	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::config_attrib_comboBox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::config_attrib_comboBox_state {checkbttn attrib_cbox type_cbox change_list} { 
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
#  Command Apol_Analysis_tra::create_resultsDisplay
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::create_resultsDisplay {results_frame} {
	variable tra_listbox
	variable tra_info_text

	# set up paned window
	set pw   [PanedWindow $results_frame.pw -side top]
	set pw_tree [$pw add]
	set pw_info [$pw add -weight 5]
	
	# title frames
	set frm_tree [TitleFrame [$pw getframe 0].frm_tree -text "Types Relationship Results"]
	set frm_info [TitleFrame [$pw getframe 1].frm_info -text "Types Relationship Information"]	

	set sw_lbox [ScrolledWindow [$frm_tree getframe].sw_lbox -auto none]		 
	set sw_info [ScrolledWindow [$frm_info getframe].sw_info -auto none]		 

	# tree window
	set tra_listbox [ListBox [$sw_lbox getframe].tra_listbox \
	        -relief flat -borderwidth 0 -bg white \
		-selectmode single -deltax 0 \
	        -padx 0 -highlightthickness 0 \
	        -redraw 0]
	$sw_lbox setwidget $tra_listbox 

	# info window
	set tra_info_text [text [$sw_info getframe].tra_info_text \
		-wrap none -bg white -font $ApolTop::text_font]
	$sw_info setwidget $tra_info_text
	bind $tra_info_text <Enter> {focus %W}
	
	pack $pw -fill both -expand yes -anchor nw 
	pack $frm_tree -fill both -expand yes -anchor nw
	pack $frm_info -fill both -expand yes
	pack $sw_lbox -fill both -expand yes
	pack $sw_info -fill both -expand yes 
	
	$tra_listbox bindText  <ButtonPress-1>        {Apol_Analysis_tra::listSelect \
							$Apol_Analysis_tra::tra_listbox \
							$Apol_Analysis_tra::tra_info_text}
    	$tra_listbox bindText  <Double-ButtonPress-1> {Apol_Analysis_tra::listSelect \
    							$Apol_Analysis_tra::tra_listbox \
    							$Apol_Analysis_tra::tra_info_text}
    
	return $tra_listbox
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_tra::create_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_tra::create_options { options_frame } {
     	variable combo_typeA
     	variable combo_typeB
        variable combo_attribA
        variable combo_attribB
	variable cb_attribA
	variable cb_attribB
			
	set entry_frame [frame $options_frame.entry_frame]
        set top_frame [TitleFrame $entry_frame.left_frame \
        	-text "Required parameters"]
        set top  [$top_frame getframe]
	
	set types_f   [frame $top.types_f]
	set ckbttns_f [frame $top.ckbttns_f]
	
        set typeA_frame [frame $types_f.typeA_frame]
        set typeB_frame [frame $types_f.typeB_frame]
	set type_frame_1 [frame $typeA_frame.type_frame_1]
	set type_frame_2 [frame $typeB_frame.type_frame_2]
	set attrib_frame_1 [frame $typeA_frame.ckbttns_frame_2]
	set attrib_frame_2 [frame $typeB_frame.ckbttns_frame_2]
	
	set ckbttns_frame_1 [frame $ckbttns_f.ckbttns_frame_1]
        set ckbttns_frame_2 [frame $ckbttns_f.ckbttns_frame_2]
        set ckbttns_frame_3 [frame $ckbttns_f.ckbttns_frame_3]
	
	# Labels 
	set lbl_typeA [Label $type_frame_1.lbl_typeA -text "Type A:"]
	set lbl_typeB [Label $type_frame_2.lbl_typeB -text "Type B:"]
	set lbl_ckbttns [Label $ckbttns_f.lbl_ckbttns \
		-text "Search for the following associations between the two types:"]
	
	# TypeA and TypeB comboboxes 
    	set combo_typeA [ComboBox $type_frame_1.combo_typeA \
		-editable 1 \
    		-textvariable Apol_Analysis_tra::typeA \
		-entrybg white]  
	set combo_typeB [ComboBox $type_frame_2.combo_typeB \
		-editable 1 \
    		-textvariable Apol_Analysis_tra::typeB \
		-entrybg white]  
	
	# Attribute boxes for selecting type by attribute
	set combo_attribA [ComboBox $attrib_frame_1.combo_attribA \
		-editable 1 \
    		-textvariable Apol_Analysis_tra::attribA \
		-entrybg white \
		-state disabled]
	$combo_attribA configure -modifycmd {Apol_Analysis_tra::change_types_list \
			$Apol_Analysis_tra::combo_typeA $Apol_Analysis_tra::combo_attribA 1}  
	set combo_attribB [ComboBox $attrib_frame_2.combo_attribB \
		-editable 1 \
    		-textvariable Apol_Analysis_tra::attribB \
		-entrybg white \
		-state disabled]
	$combo_attribB configure -modifycmd {Apol_Analysis_tra::change_types_list \
			$Apol_Analysis_tra::combo_typeB $Apol_Analysis_tra::combo_attribB 1}  
	
	# Checkbuttons for enabling disabling attribute comboboxes
	set cb_attribA [checkbutton $attrib_frame_1.cb_attribA \
		-text "Select Type A using attrib:" \
		-variable Apol_Analysis_tra::attribA_sel \
		-offvalue 0 -onvalue 1]
	$cb_attribA configure \
		-command "Apol_Analysis_tra::config_attrib_comboBox_state \
			$cb_attribA $combo_attribA $combo_typeA 1"
	set cb_attribB [checkbutton $attrib_frame_2.cb_attribB \
		-text "Select Type B using attrib:" \
		-variable Apol_Analysis_tra::attribB_sel \
		-offvalue 0 -onvalue 1]
	$cb_attribB configure \
		-command "Apol_Analysis_tra::config_attrib_comboBox_state \
			$cb_attribB $combo_attribB $combo_typeB 1"
		
	# Query-related checkbuttons
        set comm_attribs_cb [checkbutton $ckbttns_frame_1.comm_attribs_cb \
        	-text "Common Attributes" \
		-variable Apol_Analysis_tra::comm_attribs_sel]

        set comm_roles_cb [checkbutton $ckbttns_frame_1.comm_roles_cb \
        	-text "Common Roles" \
		-variable Apol_Analysis_tra::comm_roles_sel]

        set comm_users_cb [checkbutton $ckbttns_frame_1.comm_users_cb \
        	-text "Common Users" \
		-variable Apol_Analysis_tra::comm_users_sel]

        set comm_access_cb [checkbutton $ckbttns_frame_2.comm_access_cb \
        	-text "Shared access to resources" \
		-variable Apol_Analysis_tra::comm_access_sel]

        set unique_access_cb [checkbutton $ckbttns_frame_2.unique_access_cb \
        	-text "Special access to resources" \
		-variable Apol_Analysis_tra::unique_access_sel]

    	set dta_AB_cb [checkbutton $ckbttns_frame_3.dta_AB_cb \
    		-text "Domain Transitions A->B" \
    		-variable Apol_Analysis_tra::dta_AB_sel]
    		
    	set dta_BA_cb [checkbutton $ckbttns_frame_3.dta_BA_cb \
    		-text "Domain Transitions B->A" \
    		-variable Apol_Analysis_tra::dta_BA_sel]
		 
	set trans_flow_AB_cb [checkbutton $ckbttns_frame_3.trans_flow_AB_cb \
		-text "Transitive Flows A->B" \
    		-variable Apol_Analysis_tra::trans_flow_AB_sel]
    		
    	set trans_flow_BA_cb [checkbutton $ckbttns_frame_3.trans_flow_BA_cb \
		-text "Transitive Flows B->A" \
    		-variable Apol_Analysis_tra::trans_flow_BA_sel]
		
	set dir_flow_cb [checkbutton $ckbttns_frame_2.dir_flow_cb \
		-text "Direct Flows Between A and B" \
    		-variable Apol_Analysis_tra::dir_flow_sel]
	
	set other_ttrules_cb [checkbutton $ckbttns_frame_1.other_ttrules_cb \
		-text "Type Transition Rules" \
    		-variable Apol_Analysis_tra::other_ttrules_sel]
		
	set process_cb [checkbutton $ckbttns_frame_2.process_cb \
		-text "Direct Process Interactions" \
    		-variable Apol_Analysis_tra::process_sel]

        # pack all the widgets
	pack $entry_frame -side left -anchor nw -fill both -padx 5 -expand yes
        pack $top_frame -side left -anchor nw -fill both -padx 5 -expand yes
        pack $top -fill x -side top -anchor nw
        pack $ckbttns_f -side bottom -anchor nw -fill both -pady 8 -expand yes
        pack $types_f -side top -anchor nw -fill both -expand yes -pady 4
        pack $comm_attribs_cb $comm_roles_cb $comm_users_cb $other_ttrules_cb \
		-side top -anchor nw -padx 10
        pack $typeA_frame $typeB_frame -side left -anchor nw -fill x -expand yes
        pack $attrib_frame_1 $attrib_frame_2 -side bottom -anchor nw -pady 2
	pack $type_frame_1 $type_frame_2 -side top -anchor nw
	pack $lbl_typeA $lbl_typeB -side top -anchor nw -padx 2
	pack $cb_attribA $cb_attribB -side top -anchor sw -padx 10
	pack $combo_attribA $combo_attribB -side top -anchor sw -padx 10
	pack $combo_typeA $combo_typeB -side left -anchor nw -fill x -padx 5
	pack $lbl_ckbttns -side top -anchor nw -pady 2
	pack $ckbttns_frame_1 $ckbttns_frame_2 $ckbttns_frame_3 -side left -anchor nw -fill both -expand yes 
	pack $process_cb $comm_access_cb $unique_access_cb $dir_flow_cb $trans_flow_AB_cb $trans_flow_BA_cb \
		$dta_AB_cb $dta_BA_cb -side top -anchor nw -padx 2	
	                   	
	# Set binding for the embedded entrybox within the BWidget combobox
        bindtags $combo_typeA.e [linsert [bindtags $combo_typeA.e] 3 combo_typeA_Tag]
        bind combo_typeA_Tag <KeyPress> \
        	{ApolTop::_create_popup $Apol_Analysis_tra::combo_typeA %W %K}

	bindtags $combo_typeB.e [linsert [bindtags $combo_typeB.e] 3 combo_typeB_Tag]
	bind combo_typeB_Tag <KeyPress> \
		{ApolTop::_create_popup $Apol_Analysis_tra::combo_typeB %W %K}
	
	bindtags $combo_attribA.e [linsert [bindtags $combo_attribA.e] 3 combo_attribA_Tag]
        bind combo_attribA_Tag <KeyPress> \
        	{ApolTop::_create_popup $Apol_Analysis_tra::combo_attribA %W %K}

	bindtags $combo_attribB.e [linsert [bindtags $combo_attribB.e] 3 combo_attribB_Tag]
	bind combo_attribB_Tag <KeyPress> \
		{ApolTop::_create_popup $Apol_Analysis_tra::combo_attribB %W %K}
	
	Apol_Analysis_tra::initialize_widgets_state
	
	return 0	
}
