# Copyright (C) 2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 
 
# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets 1.4.1 or greater

##############################################################
# ::Apol_Perms_Map
#  
# Permissions map namespace.
##############################################################
namespace eval Apol_Perms_Map {
	# Widgets for permissions mappings dialog
	variable perms_mappings_lb
	variable class_listbox
	variable b_save
	variable b_saveas_Dflt
	variable perm_mappings_Dlg
	set perm_mappings_Dlg .perm_mappings_Dlg
	variable saveChanges_Dialog
	set saveChanges_Dialog .saveChanges_Dialog
	
	# list to hold the object classes from the permissions map 
	variable mls_classes_list	""
	variable undefined_perm_classes	""
	# holds permission map information for object class
	variable mls_base_perms_array
	variable perm_weights_array
	# holds the selinux permissions for each class from the permission map
	variable selinux_perms_array
	# MLS base permissions definitions
	variable mls_read		"r"
	variable mls_write		"w"
	variable mls_both		"b"
	variable mls_none		"n"
	variable mls_unknown		"u"
	# Indicators for changes to perm map
	variable edit_flag 		0
	variable saved_flag		0
	# Kepp track of loaded vs currently being edited perm map file name
	variable loaded_pmap		""
	variable edited_pmap		""
	variable title_display		""
	variable is_mls_loaded 		0
	# Flag var used to indicate that the current perm map is the default.
	variable dflt_pmap_flg		0
	variable system_dflt_flg	0
	variable user_default_pmap	"[file join "$::env(HOME)" ".apol_perm_mapping"]"
	# Default pmap directory is defined at initialization
	variable sys_dflt_pmap_dir	""
	variable dflt_pmap_display	"User Default Permission Map"
	variable sys_dflt_pmap_display	"System Default Permission Map (Read-Only)"
	# Return value to indicate that perm map loaded successfully, but there were warnings
	variable warning_return_val	"-2"
	variable saveChanges_Dialog_ans ""
	variable selected_class_idx	"-1"
	variable perm_map_id		"apol_perm_mapping_ver"
	variable perm_map_dflt		"apol_perm_mapping"
	# Tag variable 
	variable undefined_tag		UNDEFINED
	# Used to hold the pathname of the spin box which has the input focus to provide for its' 
	# modify command. This is not the most elegant way, but we are forced to do this because 
	# of the limitations in the BWidget spinbox where the modify command doesn't provide the 
	# pathname of the window to which the event was reported.
	variable spinbox_pathname	""
	variable default_weight		1
}	

################################
# Private functions #
################################

##########################################################################
# ::determine_loaded_pmap -- 
#	- initializes perm map editor GUI variables; 
#	- Called before displaying perm map editor GUI
proc Apol_Perms_Map::determine_loaded_pmap { } {
	variable dflt_pmap_flg
	variable system_dflt_flg
	variable loaded_pmap
	variable user_default_pmap
	variable sys_dflt_pmap_dir
	variable title_display
	variable is_mls_loaded

	set sys_dflt_pmap_dir [ApolTop::get_install_dir]
	set Apol_Perms_Map::edit_flag	0
	if {[string equal $loaded_pmap $user_default_pmap]} {
		set dflt_pmap_flg 1
		set system_dflt_flg 0
		set title_display $Apol_Perms_Map::dflt_pmap_display
	} elseif {[string equal [file dirname $loaded_pmap] $sys_dflt_pmap_dir]} {
		set system_dflt_flg 1
		set dflt_pmap_flg 0
		set title_display $Apol_Perms_Map::sys_dflt_pmap_display
	} elseif {$is_mls_loaded} {
		set dflt_pmap_flg 0
		set system_dflt_flg 0
		set title_display "Permission map generated from $Apol_Perms_Map::loaded_pmap"
	} else {
		set dflt_pmap_flg 0
		set system_dflt_flg 0
    		set title_display $Apol_Perms_Map::loaded_pmap
    	}
	return 0
}

########################################################################
# ::set_to_edited_state --
# 	- Called by the perm map editor GUI after an edit.
proc Apol_Perms_Map::set_to_edited_state {} {
	variable b_save
	variable b_saveas_Dflt
	variable dflt_pmap_flg
	variable system_dflt_flg

	if {!$system_dflt_flg} {	
		$b_save configure -state normal
	}
	if {!$dflt_pmap_flg} {
		$b_saveas_Dflt configure -state normal	
	}
	set Apol_Perms_Map::edit_flag 1
	set Apol_Perms_Map::saved_flag 0
	return 0	
}

########################################################################
# ::set_to_unedited_state --
# 	- Called by the perm map editor GUI to refresh edit state.
proc Apol_Perms_Map::set_to_unedited_state {} {
	variable b_save
	variable b_saveas_Dflt
	variable dflt_pmap_flg
	variable system_dflt_flg	
	
	if {$dflt_pmap_flg} {
		$b_saveas_Dflt configure -state disabled	
	} else {
		$b_saveas_Dflt configure -state normal
	}
	$b_save configure -state disabled
	set Apol_Perms_Map::edit_flag 0
	return 0	
}

###############################################################
# ::save_pmap_as_dflt_Dlg --
#	- Saves a permission map to the users' default location 
#	  (i.e $HOME/.apol_perm_mapping)
#	- Called by perm map editor GUI
proc Apol_Perms_Map::save_pmap_as_dflt_Dlg {parentDlg} {	
	variable title_display
	variable user_default_pmap
	variable system_dflt_flg
	variable dflt_pmap_flg
	variable saved_flag
	variable edited_pmap
	variable edit_flag
	
	if {$user_default_pmap != ""} {
		if {$edit_flag} {
			set rt [catch {Apol_Perms_Map::write_edited_pmap_to_file $user_default_pmap} err]
		} else {
			set rt [catch {Apol_Perms_Map::save_permission_map $user_default_pmap} err]
		}
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $parentDlg
			return -1	
		}
		# indicate that user has saved this as his/her default perm map
		set dflt_pmap_flg 1
		set system_dflt_flg 0
		set saved_flag 1
		set edited_pmap $user_default_pmap
		set edit_flag 0
		# Change the display name
		set title_display $Apol_Perms_Map::dflt_pmap_display
		if { [winfo exists $Apol_Perms_Map::perm_mappings_Dlg] } {
	    		wm title $Apol_Perms_Map::perm_mappings_Dlg "Edit Permissions Mappings: $Apol_Perms_Map::title_display"
	    	}
	    	Apol_Perms_Map::set_to_unedited_state
	} 
	return 0
}

########################################################################
# ::save_pmap_as_Dlg --
#	- Saves a permission map as any given file.
#	- Called by perm map editor GUI
proc Apol_Perms_Map::save_pmap_as_Dlg {parentDlg} {	
	variable title_display
	variable edited_pmap
	variable dflt_pmap_flg
	variable system_dflt_flg
	variable saved_flag 
	variable edit_flag
	variable user_default_pmap
	
	set pmap_file ""
        set types {
		{"All files"		*}
    	}
    	set pmap_file [tk_getSaveFile -title "Save As?" -filetypes $types -parent $parentDlg]
	if {$pmap_file != ""} {
		# Check if this is being saved as the users' default perm map.
		if {$pmap_file == $user_default_pmap} {
			set rt [Apol_Perms_Map::save_pmap_as_dflt_Dlg $parentDlg]
			if {$rt != 0} {
				return -1	
			}
		} else {
			if {$edit_flag} {
				set rt [catch {Apol_Perms_Map::write_edited_pmap_to_file $pmap_file} err]
			} else {
				set rt [catch {Apol_Perms_Map::save_permission_map $pmap_file} err]
			}
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" -message "$err"
				return -1	
			}
			set edit_flag 0
			set dflt_pmap_flg 0
			set system_dflt_flg 0
			set saved_flag 1
			set edited_pmap $pmap_file
			set title_display $pmap_file
			wm title $Apol_Perms_Map::perm_mappings_Dlg "Edit Permissions Mappings: $Apol_Perms_Map::title_display"
			Apol_Perms_Map::set_to_unedited_state
		}
	} else {
		# else indicate that the user has hit the cancel button 
		return 1
	}
	return 0
}

###################################################################
# ::save_perm_map_Dlg
#  	- Called by perm map editor GUI
proc Apol_Perms_Map::save_perm_map_Dlg {parentDlg} {
	variable title_display
	variable user_default_pmap
	variable dflt_pmap_display
	variable b_save
	variable edit_flag
	variable saved_flag
	variable edited_pmap
	
	if {!$edit_flag} {
		# No changes to apply
		return 0
	}

	if {$title_display == $dflt_pmap_display} {
		set fileName $user_default_pmap
	} else {
		set fileName $edited_pmap
	}
	
	# Load the changes into memory
	set rt [catch {Apol_Perms_Map::load_pmap_changes} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	
	set rt [catch {Apol_Perms_Map::save_permission_map $fileName} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	$b_save configure -state disabled
	set edit_flag 0
	set saved_flag 1
	set edited_pmap $fileName
	return 0
}

########################################################################
# ::close_Dlg --
#	- 
proc Apol_Perms_Map::close_Dlg {} {
	variable edit_flag 
	
	if {$edit_flag} {
		set ans [tk_messageBox -icon question -type yesno -title "Exit Perm Map Editor?" \
			-parent $Apol_Perms_Map::perm_mappings_Dlg \
			-message "There were unsaved changes to the perm map. \
			Exit without saving changes to the perm map?"]
		if {$ans == "no"} {
			return 
		}
	}
	set Apol_Perms_Map::selected_class_idx "-1"
	set saved_flag 0
	if {[winfo exists $Apol_Perms_Map::perm_mappings_Dlg]} {
		destroy $Apol_Perms_Map::perm_mappings_Dlg
	}
	return 0
}

########################################################################
# ::free_perms_mappings_vars -- 
#	- Resets all TCL variables related to the permission map.
proc Apol_Perms_Map::free_perms_mappings_vars { } {
	variable mls_base_perms_array
	variable perm_weights_array
	variable selinux_perms_array
	variable mls_classes_list
	variable undefined_perm_classes
	
	# Reset permissions mappings variables
	set mls_classes_list ""
	set undefined_perm_classes ""
	array unset mls_base_perms_array
	array unset perm_weights_array
	array unset selinux_perms_array
	return 0
}

########################################################################
# ::init_perms_mappings_vars --
#	- 
proc Apol_Perms_Map::init_perms_mappings_vars { } {
	variable mls_base_perms_array
	variable selinux_perms_array
	variable mls_classes_list
	variable loaded_pmap
	variable undefined_perm_classes
	variable perm_weights_array
	variable default_weight
	
	set rt [catch {set pmap_loaded [Apol_Perms_Map::is_pmap_loaded]} err]
	if {$rt != 0} {
		return -code error $err
	}
	# If the permission mappings are not loaded return error
	if {!$pmap_loaded} {
		return -code error "Permission mappings are not loaded!"		
	}
	Apol_Perms_Map::free_perms_mappings_vars
	set rt [catch {set perm_map [Apol_Perms_Map::get_perm_map]} err]
	if {$rt != 0} {
		return -code error $err
	}

	# Get the number of classes from the perm map list and then remove it
	set num_classes [lindex $perm_map 0]
	if {$num_classes < 1} {
		return -code error "There were no classes retrieved from the permission map."	
	}	
	set perm_map [lreplace $perm_map 0 0]
	set i 0
	for {set j 0} {$j < $num_classes} {incr j} {
		set undefined_flg 0
		set class [lindex $perm_map $i]
		set mls_classes_list [lappend mls_classes_list $class]
		incr i
		set num_perms [lindex $perm_map $i]
		
		set se_perms ""
		for {set k 0} {$k < $num_perms} {incr k} {
			incr i
			set se_perm [lindex $perm_map $i]
			set se_perms [lappend se_perms $se_perm]
			
			incr i 
			set mls_perm [lindex $perm_map $i]
			# Set the default values for our perm map arrays
			set mls_base_perms_array($class,$se_perm) $mls_perm
			
			# Increment to the perm weight value
			incr i
			if {!$undefined_flg && [Apol_Perms_Map::is_mls_perm_undefined $mls_base_perms_array($class,$se_perm)]} {
				set undefined_flg 1
				set undefined_perm_classes [lappend undefined_perm_classes $class]
			}
			# Set the perm weight value. Set weight to default_weight for any unmapped permissions.
			if {[Apol_Perms_Map::is_mls_perm_undefined $mls_base_perms_array($class,$se_perm)]} {
				set perm_weights_array($class,$se_perm) $default_weight
			} else {
				set perm_weight [lindex $perm_map $i]
				set perm_weights_array($class,$se_perm) $perm_weight
			}
		}
		set selinux_perms_array($class) [lsort $se_perms]
		# Increment to the next object class
		incr i
	}
	set mls_classes_list [lsort $mls_classes_list]	
	return 0
}

########################################################################
# ::change_perm_weighting --
# 	- Called when the user hits the up/down arrow in the weighting
#	  spinbox.
#
proc Apol_Perms_Map::change_perm_weighting {} {
	variable perm_weights_array
	variable spinbox_pathname
	
	set spin_path $spinbox_pathname
	if {$spin_path == ""} {
		puts "Could not get spinbox pathname."
		return -1
	}
	
	# getvalue returns the index of the current text in the spinbox starting from 0. 
	# So, the actual weight value will always be the index + 1.
	set spin_value [expr [$spin_path getvalue] + 1]
	if {$spin_value == -1} {
		puts "Spin value not found in the range of values"
		return -1
	}
	# The name of the class permission has been embedded in the pathname of  
	# the spinbox widget, instead of holding these in some global data structure
	# like a tcl array, which would be fairly large. 
	set idx [string last ":" $spin_path]
	if {$idx == -1} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error determinig class permission."
		return -1
	}
	set perm [string range $spin_path [expr $idx + 1] end]

	set tmp_str [string range $spin_path 0 [expr $idx - 1]]
	set idx [string last ":" $tmp_str]
	if {$idx == -1 } {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error determinig class."
		return -1
	}
	set class [string range $tmp_str [expr $idx + 1] end]

	set perm_weights_array($class,$perm) $spin_value
	Apol_Perms_Map::set_to_edited_state
	
	return 0
}

########################################################################
# ::embed_mls_perms_widgets --
# 	- Embeds mls base permission radionbuttons for an object class'
#	  selinux permission.
#
proc Apol_Perms_Map::embed_mls_perms_widgets {list_b class selinux_perm} {
	variable perm_weights_array
	
	# Frames
	set frame [frame $list_b.f:$selinux_perm -bd 0 -bg white]
	
	set lbl_frame [frame $frame.lbl_frame:$selinux_perm -width 20 -bd 1 -bg white]
	set lbl1 [label $lbl_frame.lbl1:$selinux_perm -bg white -justify left -width 20 -anchor nw]
	set lbl2 [label $lbl_frame.lbl2:$selinux_perm -bg white -justify left -width 5 -text "--->"]
	
	set cb_frame [frame $frame.cb_frame:$selinux_perm -width 10 -bd 1 -bg white]
	set spin_frame [frame $frame.spin_frame:$selinux_perm -width 10 -bd 0 -bg white]
	# Radiobuttons. Here we are embedding selinux and mls permissions into the pathname 
	# in order to make them unique radiobuttons.
	set cb_read [radiobutton $cb_frame.read:$selinux_perm -bg white -value $Apol_Perms_Map::mls_read -text "Read" \
		-highlightthickness 0 \
		-variable Apol_Perms_Map::mls_base_perms_array($class,$selinux_perm) \
		-command Apol_Perms_Map::set_to_edited_state]	
	set cb_write [radiobutton $cb_frame.write:$selinux_perm -bg white -value $Apol_Perms_Map::mls_write -text "Write" \
		-highlightthickness 0 \
		-variable Apol_Perms_Map::mls_base_perms_array($class,$selinux_perm) \
		-command Apol_Perms_Map::set_to_edited_state]	
	set cb_both [radiobutton $cb_frame.both:$selinux_perm -bg white -value $Apol_Perms_Map::mls_both -text "Both" \
		-highlightthickness 0 \
		-variable Apol_Perms_Map::mls_base_perms_array($class,$selinux_perm) \
		-command Apol_Perms_Map::set_to_edited_state]	
	set cb_none [radiobutton $cb_frame.none:$selinux_perm -bg white -value $Apol_Perms_Map::mls_none -text "None" \
		-highlightthickness 0 \
		-variable Apol_Perms_Map::mls_base_perms_array($class,$selinux_perm) \
		-command Apol_Perms_Map::set_to_edited_state]
	
	set lbl_weight [Label $spin_frame.lbl_weight:$class:$selinux_perm -bg white \
		-text "Weight:" \
		-padx 10]
			
	# Spin box for perm map weighting
	set spinbox_weight [SpinBox $spin_frame.spinbox_weight:$class:$selinux_perm -bg white \
		-range [list 1 10 1] \
		-editable 0 -entrybg white -width 6 \
		-helptext "Specify a weight (importance) for the permission" \
		-modifycmd {Apol_Perms_Map::change_perm_weighting}]
		
	$spinbox_weight setvalue @[expr $perm_weights_array($class,$selinux_perm) - 1]
	
	# We bind to the enter and leave event in order to hold the pathname of the entered spinbox.
	# We use this pathname in the modify command of the spinbox widget. This is not the most
	# elegant way, but we are force to do this because of the limitations in the BWidget spinbox
	# where the modify command doesn't provide the pathname of the window to which the event was 
	# reported.
	bind $spinbox_weight <Enter> {set Apol_Perms_Map::spinbox_pathname %W}
	bind $spinbox_weight <Leave> {set Apol_Perms_Map::spinbox_pathname ""}
				
	# Placing widgets
	pack $frame -side left -anchor nw -expand yes 
	pack $lbl_frame $cb_frame -side left -anchor nw -expand yes
	pack $spin_frame -side left -padx 15 -anchor nw 
	pack $lbl1 $lbl2 -side left -anchor nw
	pack $cb_read $cb_write $cb_both $cb_none -side left -anchor nw
	pack $lbl_weight $spinbox_weight -side left -anchor nw 
	
	$frame configure -height 8
	
	if {[Apol_Perms_Map::is_mls_perm_undefined $Apol_Perms_Map::mls_base_perms_array($class,$selinux_perm)]} {
		$lbl1 configure -text "$selinux_perm *" -fg red
		#$cb_read configure -state disabled
		#$cb_write configure -state disabled
		#$cb_both configure -state disabled
		#$cb_none configure -state disabled
		#$spinbox_weight configure -state disabled
	} else {
		$lbl1 configure -text "$selinux_perm"
	}
	
	# Return the pathname of the frame to embed.
 	return $frame
}

# ------------------------------------------------------------------------------
# Command Apol_Perms_Map::clear_perms_text 
# ------------------------------------------------------------------------------
proc Apol_Perms_Map::clear_perms_text {} {
	variable perms_mappings_lb
	
	# Enable the text widget. 
	$perms_mappings_lb configure -state normal
	# Clear the text widget and any embedded windows
	foreach emb_win [$perms_mappings_lb window names] {
		if { [winfo exists $emb_win] } {
			set rt [catch {destroy $emb_win} err]
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err"
				return -1
			}
		}
	}
	$perms_mappings_lb delete 1.0 end
	return 0
}

########################################################################
# ::render_perm_mappings --
# 	- Queries for permissions defined for a given class and then 
#	  embeds mls base permission radionbuttons for each permission.
#
proc Apol_Perms_Map::render_perm_mappings {} {
	variable perm_mappings_Dlg
	variable perms_mappings_lb
	variable selinux_perms_array
	variable selected_class_idx
	variable class_listbox
	
	set selected_class_idx [$class_listbox curselection]
	if {$selected_class_idx == ""} {
		return -1
	}
	set class_name [$class_listbox get $selected_class_idx]
	if {$class_name == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "Empty class provided."
		return -1
	}
	Apol_Perms_Map::clear_perms_text
	update idletasks
	# If the class name has a trailing '*', then remove it.
	set class_name [string trimright $class_name " *"]	
	set selinux_perms_list $selinux_perms_array($class_name)
	foreach selinux_perm $selinux_perms_list {  
		$perms_mappings_lb window create end -window [Apol_Perms_Map::embed_mls_perms_widgets $perms_mappings_lb $class_name $selinux_perm] 
		$perms_mappings_lb insert end "\n\n"
	}
	$perms_mappings_lb tag configure $Apol_Perms_Map::undefined_tag -foreground red
	# Disable the text widget. 
	$perms_mappings_lb configure -state disabled
	return 0
}

########################################################################
# ::refresh_perm_mappings --
# 	- Refreshes perm mappings displayed after a perm map has been 
#	  applied and/or saved.
#
proc Apol_Perms_Map::refresh_perm_mappings { } {
	variable selected_class_idx
	
	set sel_idx [$Apol_Perms_Map::class_listbox curselection]
	Apol_Perms_Map::free_perms_mappings_vars 
	set rt [catch {Apol_Perms_Map::init_perms_mappings_vars} err]
	if {$rt != 0} {
		return -code error $err	
	}
	if {$sel_idx != ""} {
		set rt [catch {Apol_Perms_Map::render_perm_mappings} err]
		if {$rt != 0} {
			return -code error $err	
		}
		$Apol_Perms_Map::class_listbox selection set [$Apol_Perms_Map::class_listbox index $sel_idx]
		set selected_class_idx [$Apol_Perms_Map::class_listbox curselection]
	}
	return 0
}

########################################################################
# ::indicate_undef_perm_classes --
# 	- Highlights object classes in the map that have selinux permissions
#	  which are not defined in the permission map file.
#
proc Apol_Perms_Map::indicate_undef_perm_classes {class_listbox} {
	variable mls_classes_list
	variable undefined_perm_classes
	
	# Object classes with unmapped permissions should have a '*'.
	foreach undef_class $undefined_perm_classes {
		set idx [lsearch -exact $mls_classes_list $undef_class]
		if {$idx != -1} {
			set mls_classes_list [lreplace $mls_classes_list $idx $idx "[lindex $mls_classes_list $idx] *"]	
		}
	}
	
	# Object classes with unmapped permissions should be red
	foreach undef_class $undefined_perm_classes {
		set idx [lsearch -exact $mls_classes_list "$undef_class *"]
		if {$idx != -1} {
			$class_listbox itemconfigure $idx -foreground red 
		}
	}
	return 0
}

########################################################################
# ::render_pmap_Dlg --
# 	- creates the permissions mappings dialog.
#
proc Apol_Perms_Map::render_pmap_Dlg { } {
	variable perm_mappings_Dlg
	variable perms_mappings_lb
	variable mls_classes_list
	variable class_listbox
	variable dflt_pmap_flg
	variable system_dflt_flg
	variable title_display
	variable b_save
	variable b_saveas_Dflt
	variable undefined_perm_classes
	
    	if {[winfo exists $perm_mappings_Dlg]} {
		raise $perm_mappings_Dlg
		focus -force $perm_mappings_Dlg
    		return 0
    	} 
	
	# Create the top-level dialog and subordinate widgets
    	toplevel $perm_mappings_Dlg 
     	wm withdraw $perm_mappings_Dlg	
    	wm title $perm_mappings_Dlg "Edit Permissions Mappings: $Apol_Perms_Map::title_display"
        set topf  [frame $perm_mappings_Dlg.topf]
        set pw1   [PanedWindow $topf.pw -side top]
        set pane  [$pw1 add ]
        set search_pane [$pw1 add -weight 3]
        set pw2   [PanedWindow $pane.pw -side left]
        set class_pane 	[$pw2 add -weight 2]
        set classes_box [TitleFrame $class_pane.tbox -text "Object Classes"]
        set results_box [TitleFrame $search_pane.rbox -text "Permission Mappings"]
        pack $classes_box -padx 2 -side left -fill both -expand yes
        pack $results_box -pady 2 -padx 2 -fill both -expand yes
        pack $pw1 -fill both -expand yes
        pack $pw2 -fill both -expand yes	
        pack $topf -fill both -expand yes -padx 10 -pady 10
        set sw_class      [ScrolledWindow [$classes_box getframe].sw -auto none]
        set class_listbox [listbox [$sw_class getframe].lb -height 10 -width 20 -highlightthickness 0 \
        	-bg white -selectmode single -exportselection 0 -listvar Apol_Perms_Map::mls_classes_list] 
        	
        if {$undefined_perm_classes != ""} {
        	set rlbl_frame [frame [$results_box getframe].rlbl_frame]
        	set rlbl_1 [label $rlbl_frame.rlbl_1 -text "*" -font $ApolTop::text_font -fg red]
        	set rlbl_2 [label $rlbl_frame.rlbl_2 -text " - Undefined permission mapping(s)" -font $ApolTop::text_font]
        }
        $sw_class setwidget $class_listbox 
        bindtags $class_listbox [linsert [bindtags $class_listbox] 3 permMap_list_Tag]  
        bind permMap_list_Tag <<ListboxSelect>> {Apol_Perms_Map::render_perm_mappings}
        pack $sw_class -fill both -expand yes -side top
       	if {$undefined_perm_classes != ""} {
        	pack $rlbl_frame -side bottom -anchor nw -padx 5 
       		pack $rlbl_1 -side left -anchor nw 
       		pack $rlbl_2 -side left -anchor nw -fill x -expand yes
       	}
	set sw_list [ScrolledWindow [$results_box getframe].sw_c -auto none]
	set perms_mappings_lb [text [$results_box getframe].perms_mappings_lb \
		-cursor $ApolTop::prevCursor \
		-bg white -font $ApolTop::text_font]
	$sw_list setwidget $perms_mappings_lb
        set botf  [frame $perm_mappings_Dlg.botf]
	set b_exit [button $botf.b_exit -text "Exit" -width 8 -command {Apol_Perms_Map::close_Dlg}]	
	set b_save   [button $botf.b_save -text "Save and Load Changes" -width 20 -command {Apol_Perms_Map::save_perm_map_Dlg $Apol_Perms_Map::perm_mappings_Dlg}]
	set b_saveas [button $botf.b_saveas -text "Save As..." -width 8 -command {Apol_Perms_Map::save_pmap_as_Dlg $Apol_Perms_Map::perm_mappings_Dlg}]	            
	set b_saveas_Dflt [button $botf.b_saveas_Dflt -text "Save As User Default" -width 16 -command {Apol_Perms_Map::save_pmap_as_dflt_Dlg $Apol_Perms_Map::perm_mappings_Dlg}]
	pack $sw_list -fill both -expand yes 
        pack $b_save $b_saveas $b_saveas_Dflt $b_exit -side left -padx 5 -pady 5 -anchor center -expand yes
        pack $botf -side left -expand yes -anchor center 
        
        wm protocol $perm_mappings_Dlg WM_DELETE_WINDOW "Apol_Perms_Map::close_Dlg"
   	
        # Configure top-level dialog specifications
        set width 800
	set height 600
	wm geom $perm_mappings_Dlg ${width}x${height}
	wm deiconify $perm_mappings_Dlg
	focus $perm_mappings_Dlg
	return 0
}

########################################################################
# ::read_next_line -- Reads the next line from a file channel and then 
#		      splits the line into tokens. Uses call-by-reference.
#		      Modifies the local variable(s) in the caller's environment.
#
proc Apol_Perms_Map::read_next_line {file_channel line_num elements} {
	upvar 1 $file_channel f
	upvar 1 $line_num line_no
	upvar 1 $elements line_elements
	 
	# Read next line. Ignore empty lines/commments while also checking for EOF
	while {[eof $f] != 1} {
		gets $f line
		incr line_no
		if {[eof $f] && $line == ""} {
			return -1
		}
		set tline [string trim $line]
		# If the line is a comment line, simply ignore and read the next line 
		# ONLY if the current line is not the EOF line.
		if {[string compare -length 1 $tline "#"] == 0 && [eof $f] != 1} {
			continue
		} elseif {[string compare -length 1 $tline "#"] == 0 && [eof $f]} {
			return -1
		}
		set line_elements [split $tline]
		break
	}
	# Make sure none of the tokens from the split are NULL; if so, remove from token list.
	for {set i 0} {$i < [llength $line_elements]} {incr i} {
		if {[lindex $line_elements $i] == "" || [string is space [lindex $line_elements $i]]} {
			set line_elements [lreplace $line_elements $i $i]
		}
	}
	set i 0
	foreach element $line_elements {
		if {[string equal $element ""] || [string is space $element]} {
			set idx [lsearch -exact $line_elements $element]
			set line_elements [lreplace $line_elements $idx $idx]
		}
		incr i
	}
	return 0
}

########################################################################
# ::reformat_line -- Reformats a line so that each element can be seperated
#		     into tokens. Modifies the local variable(s) in the 
#		     caller's environment.
# 		      
proc Apol_Perms_Map::reformat_line {elements reformatted_flag} {
	upvar 1 $elements line_elements
	upvar 1 $reformatted_flag string_reformatted
	 
	# Re-create the line elements into a string seperated by a single space char.
	set tline [join $line_elements]
	set line_elements [split $tline ":"]

	if {$line_elements != ""} {
		# Trim whitespace from each token.
		for {set i 0} {$i < [llength $line_elements]} {incr i} {
			set line_elements [lreplace $line_elements $i $i [string trim [lindex $line_elements $i]]]
		}
		# Re-format line into a string where each token is seperated by a space character.
		set tline [join $line_elements " : "]
	} 

	set line_elements [split $tline "\{"]
	if {$line_elements != ""} {
		# Trim whitespace from each token.
		for {set i 0} {$i < [llength $line_elements]} {incr i} {
			set line_elements [lreplace $line_elements $i $i [string trim [lindex $line_elements $i]]]
		}
		# Re-format line into a string where each token is seperated by a space character.
		set tline [join $line_elements " \{ "]
	} 

	set line_elements [split $tline "\}"]
	if {$line_elements != ""} {
		# Trim whitespace from each token.
		for {set i 0} {$i < [llength $line_elements]} {incr i} {
			set line_elements [lreplace $line_elements $i $i [string trim [lindex $line_elements $i]]]
		}
		# Re-format line into a string where each token is seperated by a space character.
		set tline [join $line_elements " \} "]
	} 

	# Now that the line has been forced into the format we want (i.e. whitespace seperating each line element),
	# tokenize line into a list by splitting line at each white-space char.
	set line_elements [split $tline]
	# Make sure none of the tokens from the split are empty; if so, remove from token list.
	for {set i 0} {$i < [llength $line_elements]} {incr i} {
		if {[lindex $line_elements $i] == ""} {
			set line_elements [lreplace $line_elements $i $i]
		}
	}
	set string_reformatted 1
	return 0
}

########################################################################
# ::parse_mls_perm --
# 	- This procedure parses 
#	  Modifies the local variable(s) in the caller's environment.
#
proc Apol_Perms_Map::parse_mls_perm {identifier se_perm elements_list file_channel line_num perm_map_list reformatted} {
	# MLS base permissions
	variable mls_read		
	variable mls_write	
	variable mls_both		
	variable mls_none		
	variable mls_unknown		
	
	# links to variables in caller. Used to implement call-by-reference on variables in the calling function.
	upvar 1 $elements_list line_elements
	upvar 1 $file_channel f
	upvar 1 $line_num line_no
	upvar 1 $perm_map_list perm_map 
	upvar 1 $reformatted string_reformatted
	
	while {1} {	
		# Check for more elements on the line.		
		if {[llength $line_elements] >= 1} {
			if {!$string_reformatted} {
				Apol_Perms_Map::reformat_line "line_elements" "string_reformatted"
			}
			# When we get to the mls base permission part, we need to handle the case of permissions within brackets.
			if {[lindex $line_elements 0] != "\{"} {
				switch [lindex $line_elements 0] {
					"read" { 
						lappend perm_map "$se_perm $mls_read"
					}
					"write" {
						lappend perm_map "$se_perm $mls_write"
					}
					"none" {
						lappend perm_map "$se_perm $mls_none"
					}
					default {
						puts "Warning:Unknown mls base permission [lindex $line_elements 0] encountered at line: $line_no."
						lappend perm_map "$se_perm $mls_unknown"
					}
				}
				set line_elements [lreplace $line_elements 0 0]
			} else {
				# Remove this from our line elements list.
				set line_elements [lreplace $line_elements 0 0]
				set first_mls_flag 0
				set sec_mls_flag   0
				while {1} {	
					# Check for more elements on the line.		
					if {[llength $line_elements] >= 1} {
						# First check for a close brace, which would mean that we've come to the end of this statement, so break.
						if {[lindex $line_elements 0] == "\}"} {
							if {$first_mls_flag && $sec_mls_flag} {
								# If the first token starts with an open bracket, then we now parse for read/write permission.
								lappend perm_map "$se_perm $mls_both"
							} elseif {$first_mls_flag} {
								switch $first_perm {
									"read" { 
										lappend perm_map "$se_perm $mls_read"
									}
									"write" {
										lappend perm_map "$se_perm $mls_write"
									}
									"none" {
										lappend perm_map "$se_perm $mls_none"
									}
									default {
										puts "Warning:Unknown mls base permission [lindex $line_elements 0] encountered at line: $line_no."
										lappend perm_map "$se_perm $mls_unknown"
									}
								}
							} else {
								lappend perm_map "$se_perm $mls_none"
							}
							set line_elements [lreplace $line_elements 0 0]
							break
						} 
						if {$first_mls_flag && $sec_mls_flag} {
							puts "Error at line: $line_no. Expected a close brace, but got \'[lindex $line_elements 0].\'"
							return -1
						}
						if {!$first_mls_flag} {
								# Hold onto the first perm so we can match check for duplicate.
								set first_perm [lindex $line_elements 0]
								set line_elements [lreplace $line_elements 0 0]
								set first_mls_flag 1
						}
						if {$first_mls_flag && !$sec_mls_flag} {
							if {$first_perm == "read" || $first_perm == "write"} {
								if {[lindex $line_elements 0] == "read" || [lindex $line_elements 0] == "write"} {
									if {[lindex $line_elements 0] == $first_perm} {
										puts "Duplicate mls base permission [lindex $line_elements 0] encountered."
										return -1
									} 
									set line_elements [lreplace $line_elements 0 0]
									set sec_mls_flag 1
								} else {
									puts "At line: $line_no, unknown mls base permission [lindex $line_elements 0] encountered."
									return -1
								}	
							} else {
								puts "At line: $line_no, incorrect mls base permission [lindex $line_elements 0]."
								return -1
							}
						}
					} else {
						# If this line was also the end of file line, then return error.
						if {[eof $f]} {
							puts "End of file reached before parsing mls base permission."
							return -1
						}
						set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
						if {$rt != 0} {
							return -1
						}
					}
					# If this line was also the end of file line, then break.
					if {[eof $f] && [llength $line_elements] < 1} {
						puts "End of file reached before parsing mls base permission."
						return -1
					}
				}
			}	
			break
		} else {
			# If this line was also the end of file line, then return error.
			if {[eof $f]} {
				puts "End of file reached before parsing mls base permission."
				return -1
			}
			set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
			if {$rt != 0} {
				return -1
			}
			# Re-initialize reformat flag
			set string_reformatted 0
		}
		# If this line was also the end of file line, then break.
		if {[eof $f] && [llength $line_elements] < 1} {
			puts "End of file reached before parsing mls base permission."
			return -1
		}
	}
			
	return 0
}

########################################################################
# ::parse_permission_mapping --
# 	- This procedure parses through the permissions mappings of a 
#	  class or common statement. Dependent upon ::load_perm_map_from_mls
#	  Modifies the local variable(s) in the caller's environment.
#
proc Apol_Perms_Map::parse_permission_mapping {identifier elements file_channel line_num statement_array} {
	# links to variables in caller. Used to implement call-by-reference on variables in the calling function.
	upvar 1 $elements line_elements
	upvar 1 $file_channel f
	upvar 1 $line_num line_no
	upvar 1 $statement_array array_var
	set string_reformatted 0
	# Initialize local variables
	set perm_map ""
	
	# Now we want to look for THE OPEN BRACE. Here we also handle the case if a class/common
	# statement does not have an open brace (e.g class file ). Just return 1 if this is the case.
	# Return 2, if we reach the end of file while searching for the open bracket.
	while {1} {
		if {[llength $line_elements] >= 1} {
			if {[lindex $line_elements 0] == "\{"} {
				set line_elements [lreplace $line_elements 0 0]	
				break
			} else {
				return 1
			}
		} else {
			set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
			if {$rt == -1} {
				return 2
			}
		}
	}
			
	while {1} {
		if {[llength $line_elements] >= 1} {
			# First check for a close brace, which would mean that we've come to the end of this statement, so break.
			if {[lindex $line_elements 0] == "\}"} {
				break
			}
			# We split the line and reformat it into a string that we can work with. This is because we do not want to 
			# assume that whitespace exits between each element of a permission map. So, to solve this and work more
			# conveniently, we re-create the string with whitespace between each element. 
			if {!$string_reformatted} {
				Apol_Perms_Map::reformat_line "line_elements" "string_reformatted"
			}
	
			# So far, all we have done is configured the line. We should still have a line element. So the next element on the
			# line should be the selinux permission. Grab this and then remove from our list.
			if {[lindex $line_elements 0] != ""} {
				set se_perm [lindex $line_elements 0]
				set line_elements [lreplace $line_elements 0 0]
			} else {
				puts "Error: encountered an empty selinux permission at line : $line_no"
				return -1
			}

			# The next line element should be a colon. At this point, however, there may no longer be any
			# elements left on this line, so may need to read next line
			while {1} {
				if {[llength $line_elements] >= 1} {
					if {[string equal [lindex $line_elements 0] ":"]} {
						# remove from token list.
						set line_elements [lreplace $line_elements 0 0]	
						break
					} else {
						puts "Syntax error found at line: $line_no. Expected a colon, \
						but got \"[lindex $line_elements 0]\""	
						return -1
					}
				} else {
					# If this line was also the end of file line, then return error.
					if {[eof $f]} {
						puts "End of file reached before parsing mls base permission."
						return -1
					}
				
					set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
					if {$rt != 0} {
						return -1
					}
				}
				# If this line was also the end of file line, then break.
				if {[eof $f] && [llength $line_elements] < 1} {
					puts "End of file reached before parsing mls base permission."
					return -1
				}
			}

			# Now that we've grabbed the colon, we need to get the mls_base perm. This may be a single perm or may be a list
			# of 1 or more mls_base perms. Send variable names (not a copy of the variables) in our procedure call to imitate 
			# a call-by-reference.
			set rt [Apol_Perms_Map::parse_mls_perm $identifier $se_perm "line_elements" "f" "line_no" "perm_map" "string_reformatted"]
			if {$rt != 0} {
				return -1
			}			
			set array_var($identifier) $perm_map
		} else {
			# If this line was also the end of file line, then return error.
			if {[eof $f]} {
				puts "End of file reached before parsing selinux permission."
				return -1
			}
			set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
			if {$rt != 0} {
				return -1
			}
		}
		# If this line was also the end of file line, then break.
		if {[eof $f] && [llength $line_elements] < 1} {
			puts "End of file reached before parsing selinux permission."
			return -1
		}
	}	

	return 0	
}

##############################################################################################################
# ::write_mls_base_perm_map_file --
# 	- Reads the local array variable from the caller's environment and then writes this info out to a file.
#	  This array must be an array indexed by CLASS_NAME and each value must 
#	  be a TCL list of permission maps strings (i.e. { {selinuxperm1 mls_perm} {selinuxperm2 mls_perm} )... )
#			e.g class_array(CLASS_NAME) $perm_map_list
#	  This funtion takes the following arguments:
#		- classes (required): TCL array where each element is keyed by class name. 
#		  Each element value is a list with 2 elements (i.e. selinux permission and it's mapped mls base permission) 
#		- pmap_file (required): pathname of the permission map file to write to. If it doesn't exist, it will be
#	   	  created.  
#
proc Apol_Perms_Map::write_mls_base_perm_map_file {classes pmap_file {mls_file ""}} {	
	upvar 1 $classes class_info
	set access [list WRONLY CREAT TRUNC]
	
	set rt [catch {set f [::open $pmap_file $access]} err]
	if {$rt != 0} {
		return -code error $err
	}
	set rt [catch {set polversion [apol_GetPolicyVersionString]} err]
	if {$rt != 0} {
		return -code error $err
	}
	if {$mls_file == ""} {
		puts $f "# Auto-generated on [clock format [clock seconds] -format "%b %d, %Y %I:%M:%S %p" -gmt 0]"
	} else {
		puts $f "# Auto-generated from $mls_file on [clock format [clock seconds] -format "%b %d, %Y %I:%M:%S %p" -gmt 0]"
	}
	puts $f "\n"
	puts $f "# Policy version: $polversion"
	puts $f "# Number of object classes."
	puts $f "[array size class_info]"
	puts $f "\n"
	
	if {[array exists class_info]} {
		set classes [array names class_info]
		foreach class $classes {
			set perms_list $class_info($class)
			set num_perms [llength $perms_list]
			puts $f "class $class $num_perms"
			foreach perm $perms_list {
				set split_perms [split [string trim $perm] " "]
				if {[Apol_Perms_Map::is_mls_perm_undefined [lindex $split_perms 1]]} {
					#puts $f [eval format {"%18.18s %5.5s"} "[lindex $split_perms 0]" "#[lindex $split_perms 1]"]
					puts $f [eval format {"%18.18s %5.5s"} "#$perm"]
				} else {
					puts $f [eval format {"%18.18s %5.5s"} $perm]
				}
			}
			puts $f "\n"
		}
	}		
	::close $f
	return 0
}

###########################################################################
# ::write_edited_pmap_to_file --
# 	- Reads the current pmap state and then writes this out to a file.

proc Apol_Perms_Map::write_edited_pmap_to_file {pmap_file} {	
	variable mls_classes_list	
	variable mls_base_perms_array
	variable perm_weights_array
	variable selinux_perms_array
	
	set access [list WRONLY CREAT TRUNC]
	
	set rt [catch {set f [::open $pmap_file $access]} err]
	if {$rt != 0} {
		return -code error $err
	}
	set rt [catch {set polversion [apol_GetPolicyVersionString]} err]
	if {$rt != 0} {
		return -code error $err
	}

	puts $f "# Auto-generated on [clock format [clock seconds] -format "%b %d, %Y %I:%M:%S %p" -gmt 0]"
	puts $f "\n"
	puts $f "# Policy version: $polversion"
	puts $f "# Number of object classes."
	puts $f "[llength $mls_classes_list]"
	puts $f "\n"
	
	if {![array exists mls_base_perms_array] || ![array exists perm_weights_array] || ![array exists selinux_perms_array]} {
		return -code error "Missing necessary perm map information. Cannot save changes."
	}
	foreach class $mls_classes_list {
		# If the class name has a trailing '*', then remove it.
		set class [string trimright $class " *"]
		set perms_list $selinux_perms_array($class) 
		set num_perms [llength $perms_list]
		puts $f "class $class $num_perms"

		foreach perm $perms_list {
			if {[Apol_Perms_Map::is_mls_perm_undefined $mls_base_perms_array($class,$perm)]} {
				puts $f [eval format {"%18.18s %5.5s %5.5s"} "#$perm" "$mls_base_perms_array($class,$perm)" "$perm_weights_array($class,$perm)"]
			} else {
				puts $f [eval format {"%18.18s %5.5s %5.5s"} "$perm" "$mls_base_perms_array($class,$perm)" "$perm_weights_array($class,$perm)"]
			}
		}
		puts $f "\n"
	}	
	::close $f
	return 0
}

###################################################################
# ::create_tmp_file
#  	- creates and returns a unique tmp file name
proc Apol_Perms_Map::create_tmp_file {} {
	set chars "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	set num_chars 8
	set num_tries 8
	set fn_prefix "/tmp/apol-"
	set mypid [pid]
     	for {set i 0} {$i < $num_tries} {incr i} {
 		set fn $fn_prefix
 		for {set j 0} {$j < $num_chars} {incr j} {
 			append fn [string index $chars [expr ([clock clicks] ^ $mypid) % 62]]
		}
		if {[file exists $fn]} {
			# pause and try again
	 	    	after 1
		} else {
			# Success - this is a unique temp file name, so return it
			return $fn
		}
	}
	# If we're here we failed to create the file!
	puts stderr "Failed to create a unique temporary file with prefix $fn_prefix"
	return -code error "Failed to create a unique temporary file with prefix $fn_prefix"
}

########################################################################
# ::is_mls_perm_undefined --
# 	- Determines if the mls permission is undefined. 
#
proc Apol_Perms_Map::is_mls_perm_undefined {mls_perm} {
	# MLS base permissions definitions
	variable mls_read		
	variable mls_write		
	variable mls_both		
	variable mls_none		
	variable mls_unknown		

	if {[string equal $mls_perm $mls_unknown]} {
		return 1
	} else {
		switch -exact -- $mls_perm \
			$mls_read {
				return 0
			} \
			$mls_write {
				return 0
			} \
			$mls_both {
				return 0
			} \
			$mls_none {
				return 0
			} \
			default {
				return 1
			}
			
		return 1
	}
	# Should not get here!!
	return -code error "Problem determining mls base perm!!"
}

####										  ####
#										     # 	
# The following are public interfaces for loading and retrieving a permission map,   #
# checking if a permission map is loaded and writing out a permission map to disk,   #  
# as well as getting the default weight value for a class permission.		     #	
####										  ####

########################################################################
# ::is_pmap_loaded -- Checks to see if a perm map is loaded and returns
#	a boolean value (1 or 0); -1 if encountered an error.
proc Apol_Perms_Map::is_pmap_loaded {} {
	set rt [catch {set pmap_loaded [apol_IsPermMapLoaded]} err]
	if {$rt != 0} {
		return -code error $err
	} 
	return $pmap_loaded
}

########################################################################
# ::get_perm_map -- Retrieves the currently loaded permission map as an 
#	encoded TCL list.
proc Apol_Perms_Map::get_perm_map {} {
	set perm_map ""
	set rt [catch {set pmap_loaded [Apol_Perms_Map::is_pmap_loaded]} err]
	if {$rt != 0} {
		return -code error $err
	}
	if {!$pmap_loaded} {
		return -code error "Permission mappings are not loaded."	
	}
	set rt [catch {set perm_map [apol_GetPermMap]} err]
	if {$rt != 0} {
		return -code error $err	
	} 
	return $perm_map
}

##########################################################################
# ::get_weight_for_class_perm -- Retrieves the weight value for an object 
#	class permission from the perm map.
proc Apol_Perms_Map::get_weight_for_class_perm {obj_class selinux_perm} {
	variable perm_weights_array
	
	if {[array exists perm_weights_array]} {	
		return $perm_weights_array($obj_class,$selinux_perm)
	} else {
		return ""
	}
}

########################################################################
# ::load_perm_map_from_mls --
# 	- This procedure generates a file that contains the default 
#	permission mappings for apol's information flow analysis
#	Calls Apol_Perms_Map::parse_permission_mapping 
#	This is the top-level proc for parsing an mls file and generating 
#	a custom permission map file. Parsing a file calls for good defensive
#	programming, so with this in mind, string lengths in particular need
# 	to be checked so as not to cause any buffer overflows.
#
#   NOTE: If there were warnings generated while loading the perm map, a warning 
#   value is returned. It is up to the caller to determine if warnings were 
#   generated by checking for this return value.		
proc Apol_Perms_Map::load_perm_map_from_mls {mls_file save_file} {
	variable warning_return_val
	variable loaded_pmap
	
	# if MLS FILE doesn't exist, throw error and return
	if {[file exists $mls_file] == 0 } {
		return -code error "$mls_file does not exist. Cannot generate permisson map file."
	}
	# Open the mls file for reading
	set rt [catch {set f [::open $mls_file r]} err]
	if {$rt != 0} {
		return -code error "Cannot open $mls_file file ($rt: $err)"
	}
	# Initialize line number and line elements list vriables.
	set line_no 0
	set line_elements ""
	set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
	if {$rt != 0} {
		puts "End of file reached before parsing first valid class/common statment."
		return -code error "Parsing error. See stdout for more information."
	}
	
	# Check if the line read is the end of file line and if it is empty. If it is the end of file and
	# there are elements on this line, then we need to parse this line before breaking out of the loop.
	while {1} {
		# Make sure the line starts with the 'common' or 'class' statement.
		if {[string equal [lindex $line_elements 0] "common"] || [string equal [lindex $line_elements 0] "COMMON"] || [string equal [lindex $line_elements 0] "class"] || [string equal [lindex $line_elements 0] "CLASS"]} {		
			# Set the statement to lower case letters. We perform a string match on this later. 
			set statement_type [string tolower [lindex $line_elements 0]]
			# Remove 'common' or 'class' statement from the token list. This should be the first element.
			set line_elements [lreplace $line_elements 0 0]

			# Check if the current line is the end of file line and if there are more 
			# elements on the line. If there are no further elements on the line, then 
			# this is an error, because we have not yet gathered the identifier!
			if {[eof $f] && [llength $line_elements] < 1} {
				puts "Error: End of file reached before gathering identifier."	
				return -code error "Parsing error. See stdout for more information."
			}
			# Now that we know there are more elements, gather THE IDENTIFIER and then remove from token list. 
			# A statements' starting brace may not be seperated by whitespace, but we want to 
			# force this format on our line. To do this, we first try to split the 
			# line using an open brace as the splitChar. If the split list is not empty, then we 
			# trim any whitespace from each element and then re-format tline into a string 
			# seperated by a space. Otherwise, at this point, if the split list is empty (meaning there 
			# were either no braces found or the line contained adjacent braces), we simply
			# split the line at each white space char, remove any empty tokens and move on.
			while {1} {
				if {[llength $line_elements] >= 1} {
					set tline [join $line_elements]
					set line_elements [split $tline "\{"]
				
					if {$line_elements != ""} {				
						# Trim whitespace from each token.
						for {set i 0} {$i < [llength $line_elements]} {incr i} {
							set line_elements [lreplace $line_elements $i $i [string trim [lindex $line_elements $i]]]
						}
						# Re-create line by seperating each token with a space, an open brace and another space. 
						set tline [join $line_elements " \{ "]
					} 
					
					# Re-tokenize line into a list by splitting line at each white-space char.
					set line_elements [split $tline]
					# Make sure none of the tokens from the split are empty; if so, remove from token list.
					for {set i 0} {$i < [llength $line_elements]} {incr i} {
						if {[lindex $line_elements $i] == ""} {
							set line_elements [lreplace $line_elements $i $i]
						}
					}
			
					# OK, the identifier should now be the first element. It should not be empty, but make sure.
					if {[string equal [lindex $line_elements 0] "\{"]} {
						puts "Error: Open bracket reached before finding an identifier."	
						return -code error "Parsing error. See stdout for more information."
					} elseif {[lindex $line_elements 0] != ""} {
						set identifier [lindex $line_elements 0]
						set line_elements [lreplace $line_elements 0 0]
						break
					} else {
						puts "Error: Could not determine the identifier for this $statement_type statement."	
						return -code error "Parsing error. See stdout for more information."
					}
				} else {
					set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
					if {$rt != 0} {
						puts "End of file reached before parsing identifier for $statement_type."
						return -code error "Parsing error. See stdout for more information."
					}
				}
			}
					
			# Now, we are ready to parse the permission mappings based on the statement type (class/common).
			# Send variable names (not a copy of the variables) in our procedure call to imitate a call-by-reference.
			if {$statement_type == "common"} {
				# Add identifier to array and initialize 
				set common_perms($identifier) ""
				if {[eof $f] && [llength $line_elements] < 1} {
					break
				}
				set rt [Apol_Perms_Map::parse_permission_mapping $identifier "line_elements" "f" "line_no" "common_perms"]
				if {$rt == 1} {
					# This common perm may not have any perm maps defined, so we look for another class/common statment
					continue
				} elseif {$rt == 2} {
					# This means that a the end of file was reached, but we have a valid statement so no error.
					break
				} elseif {$rt != 0} {
					# This means that a parse error was encountered or the end of file was reached.
					puts "Error: Error parsing line: $line_no"
					return -code error "Parsing error. See stdout for more information."
				} 
			} elseif {$statement_type == "class"} {
				# Add identifier to array and initialize 
				set class_info($identifier) ""
				if {[eof $f] && [llength $line_elements] < 1} {
					break
				}
				set rt [Apol_Perms_Map::parse_permission_mapping $identifier "line_elements" "f" "line_no" "class_info"]
				if {$rt == 1} {
					# This class may not have any perm maps defined, so we look for another class/common statment
					continue
				} elseif {$rt == 2} {
					# This means that a the end of file was reached, but we have a valid statement so no error.
					break
				} elseif {$rt != 0} {
					# This means that a parse error was encountered or the end of file was reached.
					puts "Error: Error parsing line: $line_no"
					return -code error "Parsing error. See stdout for more information."
				} 
			} else {
				# Should never get here, but using as a safety measure and is good defensive programming.
				puts "Determined wrong statement type while trying to set permission map info."	
				return -code error "Parsing error. See stdout for more information."
			}					
		}
		set line_elements ""
		# If this line was also the end of file line, then break.
		if {[eof $f] && $line_elements == ""} {
			break
		}
		set rt [Apol_Perms_Map::read_next_line "f" "line_no" "line_elements"]
		# -1 will be returned if we reach the EOF. If we've reached the EOF, just break.
		if {$rt == -1} {
			break
		}
	} 

	# Expand common permissions if there are any
	if {[array exists common_perms]} {
		foreach class [array names class_info] {
			set rt [catch {set valid_common_perm [apol_GetClassCommonPerm $class]} err]
			if {$rt != 0} {
				puts "Error retrieving common permissions for $class: $err"	
			} else {
				if {$valid_common_perm != ""} {
					set perms_list $class_info($class)
					# See if the valid common permission from the policy is defined in the mls file
					# If it is not, then just ignore. 
					set common_perm [array names common_perms "$valid_common_perm"]
					if {$common_perm != ""} {
						set comm_perms $common_perms($common_perm)
						set perms_list [concat $comm_perms $perms_list]
						set class_info($class) $perms_list
					} 
				}
			}			
		}
		array unset common_perms
	}	
	if {[array exists class_info]} {
		set rt [catch {Apol_Perms_Map::write_mls_base_perm_map_file "class_info" $save_file} err]
		array unset class_info
		if {$rt != 0}  {
	   		return -code error $err
	   	}
	} else {
		return -code error "No class information was found, so could not load perm map from the mls file."	
	}
	::close $f
	if {[file exists $save_file]} {
		# now that we have a perm map located, load it. 
		set rt [catch {Apol_Perms_Map::load_perm_mappings $save_file} msg]
		if {$rt != 0} {
			if {$rt == $warning_return_val} {
				return -code $warning_return_val $msg
			} else {
				return -code error $msg	
			}
		}
	} else {
		return -code error "Could not load temporary permission map file ($save_file). File does not exist."
	}			
	return 0
}

########################################################################
# ::load_default_perm_map --
#	- Locate the default perm map and then load it. Return warnings
#	  flag value if there were warnings during load.
proc Apol_Perms_Map::load_default_perm_map {} {
	variable loaded_pmap
	variable warning_return_val
	variable user_default_pmap
	
	if {![file exists $user_default_pmap]} {
		# Get the policy persion number. 
		set rt [catch {set policy_version [apol_GetPolicyVersionNumber]} err]
		if {$rt != 0} {
			return -code error $err
		} 

		# Flag used to indicate that we already tried to locate the default perm map (apol_perm_mapping)
		# Flag used to indicate that we already tried to locate the default perm map (apol_perm_mapping)
		set default_flg 0
		# The only perm maps we are implicitly loading are perm maps starting from policy ver12 onward. 
		# For any other policies, we try to load the default user perm map. If any of this fails, an
		# error is returned.
		if {$policy_version && $policy_version >= 12} {
			set rt [catch {set pmap_file [apol_GetDefault_PermMap "$Apol_Perms_Map::perm_map_id$policy_version"]} err]
		} else {
			set rt [catch {set pmap_file [apol_GetDefault_PermMap $Apol_Perms_Map::perm_map_dflt]} err]
			set default_flg 1
		}
		
		if {$rt != 0} {
			return -code error $err
		} 
		
		if {$pmap_file == ""} {
			if {!$default_flg} {
				set rt [catch {set pmap_file [apol_GetDefault_PermMap $Apol_Perms_Map::perm_map_dflt]} err]
				if {$rt != 0} {
					return -code error $err
				} 
				if {$pmap_file == ""} {
					return -code error "Could not locate system default perm map. You must explicitly load a perm map. See Advanced menu."	
				}
			}
			return -code error "Could not locate system default perm map. You must explicitly load a perm map. See Advanced menu."	
		}
		set pmap_file [file nativename $pmap_file]
		# now that we have the default perm map located, load it. 
		set rt [catch {Apol_Perms_Map::load_perm_mappings $pmap_file} msg]
		if {$rt != 0} {
			if {$rt == $warning_return_val} {
				return -code $warning_return_val $msg
			} else {
				return -code error $msg	
			}
		}
		set loaded_pmap $pmap_file
	} else {
		# Set perm map pathname to default user location.
		set pmap_file [file nativename $user_default_pmap]	
		# now that we have a perm map located, load it. 
		set rt [catch {Apol_Perms_Map::load_perm_mappings $pmap_file} msg]
		if {$rt != 0} {
			if {$rt == $warning_return_val} {
				return -code $warning_return_val $msg
			} else {
				set ans [tk_messageBox \
				     -icon question \
				     -type yesno \
				     -parent $ApolTop::mainframe \
				     -title "Load system default permission map?" \
				     -message "Your default permission map ($user_default_pmap) is corrupted.\n\nWould you \
				     like to copy to your default permission map with the system default permission map and then load?"]
				if {$ans == "yes"} {
					set user_dflt_dir [file dirname $user_default_pmap]
					# Copy the system default perm map to the default user location (currently, $HOME)
					set rt [catch {file copy -force $pmap_file $user_dflt_dir} err]
					if {$rt != 0} {
						return -code error $err
					}
					set rt [catch {file rename -force [file join $user_dflt_dir [file tail $pmap_file]] $user_default_pmap} err]
					if {$rt != 0} {
						return -code error $err
					}
					# Set perm map pathname to default user location.
					set pmap_file [file nativename $user_default_pmap]
					# now that we have the perm map located, load it. 
					set rt [catch {Apol_Perms_Map::load_perm_mappings $pmap_file} msg]
					if {$rt != 0} {
						if {$rt == $warning_return_val} {
							return -code $warning_return_val $msg
						} else {
							return -code error $msg	
						}
					}
				} else {
					return -code error $msg	
				}
			}
		}
		set loaded_pmap $pmap_file
	}
	return 0
}

########################################################################
# ::load_perm_mappings --
#	- Load a perm map file into memory. Requires a policy to be opened.
proc Apol_Perms_Map::load_perm_mappings {pmap_file} {
	variable loaded_pmap
	variable edited_pmap
	variable edit_flag 
	variable warning_return_val
	
	if {$pmap_file != ""} {
		set warn 0
		set rt [catch {apol_LoadPermMap $pmap_file} msg]
		if {$rt != 0} {
			if {$rt == -2} {
				set warn 1
			} else {
				return -code error $msg	
			}
		} 
		set loaded_pmap $pmap_file
		set edited_pmap $pmap_file
		ApolTop::configure_edit_pmap_menu_item 1
		
		# Update perm mapping variables
		set rt [catch {Apol_Perms_Map::init_perms_mappings_vars} err]
		if {$rt != 0} {
			return -code error $err	
		}
		if {$warn} {
			return -code $warning_return_val $msg	
		}
	} 
	return 0
}

########################################################################
# ::save_permission_map --
#	- Primitive procedure for saving the currently loaded perm map
#  	  out to disk.
#
proc Apol_Perms_Map::save_permission_map {filename} { 
	set rt [catch {apol_SavePermMap $filename} err]
	if {$rt != 0} {
		return -code error $err
	}
	return 0
}

########################################################################
# ::load_pmap_changes --
#	- Primitive procedure for updating perm map in memory.
#
proc Apol_Perms_Map::load_pmap_changes {} { 
	# Create a temporary 
        if { [catch {set tmpfilename [Apol_Perms_Map::create_tmp_file]} err] } {
        	return -code error $err
        }
	set rt [catch {Apol_Perms_Map::write_edited_pmap_to_file $tmpfilename} err]
	if {$rt != 0} {
		# Delete the temporary file from disk
		file delete $tmpfilename
		return -code error $err	
	}
	 	
	set rt [catch {apol_UpdatePermMap $tmpfilename} err]
	if {$rt != 0} {
		# Delete the temporary file from disk
		file delete $tmpfilename
		return -code error $err
	}
	# Delete the temporary file from disk
	file delete $tmpfilename
	return 0
}

########################################################################
# ::load_perm_map_fileDlg -- 
#	- Called from top-level GUI Advanced menu
proc Apol_Perms_Map::load_perm_map_fileDlg {parentDlg} {
	variable warning_return_val
	variable is_mls_loaded
	
	set pmap_file ""
        set types {
		{"All files"		*}
    	}
	set pmap_file [tk_getOpenFile -filetypes $types -title "Select Perm Map to Load..." -parent $parentDlg]
	if {$pmap_file != ""} {
		set rt [catch {Apol_Perms_Map::load_perm_mappings $pmap_file} err]
		if {$rt != 0} {
			if {$rt == $warning_return_val} {
				tk_messageBox -icon warning -type ok -title "Warning" -message "$err"
			} else {
				tk_messageBox -icon error -type ok -title "Error" -message "$err"
				return -1	
			}
		}
		set is_mls_loaded 0
		if {[winfo exists $Apol_Perms_Map::perm_mappings_Dlg]} {
			Apol_Perms_Map::close_Dlg
			Apol_Perms_Map::display_perm_mappings_Dlg
		}
	} 
    	# else the user hit cancel
	return 0
}

########################################################################
# ::load_perm_map_mlsDlg --
#	- Called from top-level GUI Advanced menu
proc Apol_Perms_Map::load_perm_map_mlsDlg {parentDlg} {
	variable warning_return_val
	variable loaded_pmap
	variable is_mls_loaded
	variable title_display
	
	set types {
		{"All files"		*}
    	}
	set mls_file [tk_getOpenFile -filetypes $types -title "Select mls file to convert from..." \
		-initialfile  "mls" -initialdir [file dirname $ApolTop::filename] -parent $parentDlg]
	# Return if the user hits the cancel button
	if {$mls_file == ""} {
		return -1
	}
	# create a temp file channel with WRONLY access only!
        if { [catch {set tmpfilename [Apol_Perms_Map::create_tmp_file]} err] } {
        	tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $parentDlg
		return -1
        }
	if {$tmpfilename == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $parentDlg
		return -1
	} 
	set rt [catch {Apol_Perms_Map::load_perm_map_from_mls $mls_file $tmpfilename} err]
	if {$rt != 0} {
		if {$rt == $warning_return_val} {
			tk_messageBox -icon warning -type ok -title "Warning" -message "$err" -parent $parentDlg
		} else {
			if {[file exists $tmpfilename]} {
				file delete $tmpfilename
			}
			tk_messageBox -icon error -type ok -title "Error" -message "$err" -parent $parentDlg
			return -1	
		}
	}
	# This means success, so check that the temp file exist and if so then delete it. 
	if {[file exists $tmpfilename]} {
		file delete $tmpfilename
	}
	set loaded_pmap $mls_file
	set is_mls_loaded 1
	if {[winfo exists $Apol_Perms_Map::perm_mappings_Dlg]} {
		Apol_Perms_Map::close_Dlg
		Apol_Perms_Map::display_perm_mappings_Dlg
	}
	return 0
}

########################################################################
# ::load_default_perm_map_Dlg --
#	- Called from top-level GUI Advanced menu
proc Apol_Perms_Map::load_default_perm_map_Dlg {parentDlg} {
	variable warning_return_val
	variable is_mls_loaded
	
	set rt [catch {Apol_Perms_Map::load_default_perm_map} err]
	if {$rt != 0} {
		if {$rt == $warning_return_val} {
			tk_messageBox -icon warning -type ok -title "Warning" -message "$err"
		} else {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"	
			return -1
		}
	} 
	set is_mls_loaded 0
	if {[winfo exists $Apol_Perms_Map::perm_mappings_Dlg]} {
		Apol_Perms_Map::close_Dlg
		Apol_Perms_Map::display_perm_mappings_Dlg
	}
	return 0
}

######################################################################################
# The following are public interfaces for creating/destroying perm map editor object #
######################################################################################

########################################################################
# ::display_perm_mappings_Dlg --
# 	- displays the permissions mappings dialog.
#
proc Apol_Perms_Map::display_perm_mappings_Dlg { } {
	variable class_listbox
	variable edit_flag
	variable saved_flag
	
	if {$saved_flag || [expr $edit_flag && !$saved_flag]} {
		# The perm map was either changed but not saved OR was saved, so re-load perm mappings.
		set rt [catch {Apol_Perms_Map::init_perms_mappings_vars} err]
		if {$rt != 0} {
			return -code error $err	
		}
	}
	
	Apol_Perms_Map::determine_loaded_pmap
	set rt [catch {Apol_Perms_Map::render_pmap_Dlg} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}

	# Check for object classes that have undefined selinux permissions in the permission map file.
	Apol_Perms_Map::indicate_undef_perm_classes $class_listbox 
	Apol_Perms_Map::set_to_unedited_state

	return 0
}

########################################################################
# ::close --
#	- 
proc Apol_Perms_Map::close {parentDlg} {
	variable edit_flag
	variable perm_mappings_Dlg
	variable perms_mappings_lb
	variable selected_class_idx
	
	Apol_Perms_Map::free_perms_mappings_vars
	# Reset our edit flag. 
	set edit_flag 0
	set selected_class_idx "-1"
	if {[winfo exists $perm_mappings_Dlg]} {
		if {[winfo exists $perms_mappings_lb]} {
			$perms_mappings_lb delete 1.0 end
		}
		destroy $perm_mappings_Dlg
	}
	if {[winfo exists $Apol_Perms_Map::perm_mappings_Dlg]} {	
		destroy $Apol_Perms_Map::perm_mappings_Dlg
	}
	return 0
}
