# Copyright (C) 2001-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_File_Contexts
#  
# The File Contexts page
##############################################################
namespace eval Apol_File_Contexts {
	# opts(opt), where opt =
	variable opts
	set opts(user)			""
	set opts(class)			""
	set opts(type)			""
	set opts(regEx_user)		0
	set opts(regEx_type)		0
	set opts(regEx_path)		0
	
	# Other vars
	variable attribute_selected	""
	variable user_cb_value		0
	variable class_cb_value		0
	variable type_cb_value		0
	variable path_cb_value		0
	variable progressmsg		""
	variable progress_indicator	-1
	variable db_loaded		0
	variable show_ctxt		1
	variable show_class		1
	
	# Global Widgets
	variable resultsbox
	variable lbl_status
	variable user_combo_box
	variable objclass_combo_box
	variable type_combo_box
	variable progressDlg 		.progress_Dlg
	variable entry_dir
	variable entry_fn
	variable entry_path
	variable create_button
	variable load_button
	variable create_fc_dlg		.fc_db_create_Dlg
	
	variable info_button_text \
{"Creating/Loading an Index File\n\n" \
\
{If the user has not loaded an index file, then all search items will be grayed out \
and a red label indicating that an index file is not loaded is displayed at the top. \
Buttons are presented for creating and loading an index file. Selecting the \
'Load' button displays a file selection dialog from which you can choose a saved index \
file to load. Selecting the 'Create and Load' button will display a dialog for you to specify \
the save file and the directory from which to start the indexing. Upon selecting the 'Create' button, an index \
file will be created and then loaded into apol.} \
\
"\n\nSearching an Index File\n\n" \
\
{Searches on the index file can be done by specifying the user, type, object class, or path \
search criteria to search for using the widgets provided. Drop down lists and entryboxes \
are presented for specifying the search criteria, of which the drop down lists contain items from \
the index file.  You can also use regular expressions, however, this option is not available for \
the object class field.  Additionally, you may use the checkbuttons under the search options frame, \
for indicating whether to include the object class and/or file context within the results. To \
perform a search, click the 'OK' button. Once the search is finished, you should be presented with \
a list of files that matched the criteria, along with their context and/or object type, if specified.}}
}

proc Apol_File_Contexts::display_analysis_info {} {
	set info_Dlg .info_Dlg_fc
	if { [winfo exists $info_Dlg] } {
    		destroy $info_Dlg
    	}
	# Create the top-level dialog and subordinate widgets
    	toplevel $info_Dlg 
   	wm protocol $info_Dlg WM_DELETE_WINDOW " "
    	wm withdraw $info_Dlg
    	wm title $info_Dlg "Analysis Description"
    	set topf  [frame $info_Dlg.topf]
    	set botf  [frame $info_Dlg.botf]
    	set sw [ScrolledWindow $topf.sw  -auto none]
	set descrp_text [text $sw.descrp_text -height 5 -width 20 -font $ApolTop::text_font \
		-bg white -wrap word]
	$sw setwidget $descrp_text
	set b_ok [button $botf.b_ok -text "OK" -width 6 -command "destroy $info_Dlg"]
	pack $topf -side top -fill both -expand yes -padx 5 -pady 5
	pack $botf -side bottom -anchor center 
	pack $b_ok -side left -anchor center -pady 2
	pack $sw -side top -anchor nw -expand yes -fill both 
	set txt ""
	foreach item $Apol_File_Contexts::info_button_text {
		set txt [append txt $item]
	}
	$descrp_text insert 0.0 $txt
	$descrp_text config -state disable
	        
        # Configure top-level dialog specifications
        set width 600
	set height 440
	wm geom $info_Dlg ${width}x${height}
	wm deiconify $info_Dlg
	wm protocol $info_Dlg WM_DELETE_WINDOW "destroy $info_Dlg"
} 

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_File_Contexts::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_File_Contexts::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_File_Contexts::set_Focus_to_Text {} {
	focus $Apol_File_Contexts::resultsbox
	return 0
}

proc Apol_File_Contexts::is_db_loaded {} {
	return $Apol_File_Contexts::db_loaded
}

proc Apol_File_Contexts::init_vars {} {
	variable opts
	
	set opts(user)			""
	set opts(class)			""
	set opts(type)			""
	set opts(regEx_user)		0
	set opts(regEx_type)		0
	set opts(regEx_path)		0
	
	# Other vars
	set Apol_File_Contexts::attribute_selected	""
	set Apol_File_Contexts::user_cb_value		0
	set Apol_File_Contexts::class_cb_value		0
	set Apol_File_Contexts::type_cb_value		0
	set Apol_File_Contexts::progressmsg		""
	set Apol_File_Contexts::progress_indicator	-1
	set Apol_File_Contexts::db_loaded		0
	set Apol_File_Contexts::show_ctxt		1
	set Apol_File_Contexts::show_class		1
	set Apol_File_Contexts::path_cb_value 		0
	return 0
}

proc Apol_File_Contexts::populate_combo_boxes {} {
	variable user_combo_box
	variable objclass_combo_box
	variable type_combo_box
	
	set rt [catch {set types [apol_FC_Index_DB_Get_Items types]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error getting types from file context database: $err.\n"
		return
	} 
	$type_combo_box configure -values $types
	
	set rt [catch {set users [apol_FC_Index_DB_Get_Items users]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error getting users from file context database: $err.\n"
		return
	} 
	$user_combo_box configure -values $users
	
	set rt [catch {set classes [apol_FC_Index_DB_Get_Items classes]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error getting object classes from file context database: $err.\n"
		return
	} 
	$objclass_combo_box configure -values $classes
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::open
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::open { } {
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::clear_combo_box_values
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::clear_combo_box_values { } {
	variable user_combo_box
	variable objclass_combo_box
	variable type_combo_box
	
	$user_combo_box configure -values "" -text ""
	$type_combo_box configure -values "" -text ""
	$objclass_combo_box configure -values "" -text ""
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::initialize
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::initialize { } {
	variable entry_path
	Apol_File_Contexts::change_status_label ""
	Apol_File_Contexts::init_vars
	Apol_File_Contexts::clear_combo_box_values
	ApolTop::change_comboBox_state $Apol_File_Contexts::user_cb_value $Apol_File_Contexts::user_combo_box
	ApolTop::change_comboBox_state $Apol_File_Contexts::type_cb_value $Apol_File_Contexts::type_combo_box
	ApolTop::change_comboBox_state $Apol_File_Contexts::class_cb_value $Apol_File_Contexts::objclass_combo_box
	$entry_path delete 0 end
	Apol_File_Contexts::configure_file_path_entry_widget $Apol_File_Contexts::path_cb_value
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::close
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::close { } {		
	Apol_File_Contexts::close_fc_db
	Apol_File_Contexts::initialize
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::get_fc_files_for_ta
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::get_fc_files_for_ta {which ta} {	
	set types_list ""
	set results ""
	
	if {$which == "type"} {
		set types_list [lappend types_list $ta]
	} else {
		# Get all types for the attribute
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $ta]} err]	
		if {$rt != 0} {
			return -code error $err
		}
		foreach type $attrib_typesList {
			if {$type != "self"} {
				set types_list [lappend types_list $type]
			}	
		}
		set types_list $attrib_typesList
	}
	set rt [catch {set results [apol_Search_FC_Index_DB 1 $types_list 0 "" 0 "" 0 "" 0 0 0]} err]
	if {$rt != 0} {	
		return -code error $err
	} 

	set return_list ""
	set sz [llength $results]
	for {set i 0} {$i < $sz} {incr i} {
		set path [lindex $results $i]
		incr i
		set ctxt [lindex $results $i]
		incr i
		set class [lindex $results $i]
		set return_list [lappend return_list [list $ctxt $class $path]]
	}
	return $return_list
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::search_fc_database
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::search_fc_database { } {
	variable opts
	variable user_cb_value
	variable class_cb_value
	variable type_cb_value
	variable path_cb_value
	variable resultsbox
	variable entry_path
	variable db_loaded
	variable show_ctxt
	variable show_class
	
	if {$type_cb_value && $opts(type) == ""} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "You must specify a type!"
		return
	}	
	if {$user_cb_value && $opts(user) == ""} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "You must specify a user!"
		return
	}	
	if {$class_cb_value && $opts(class) == ""} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "You must specify a class!"
		return
	}
	if {$path_cb_value && [$entry_path get] == ""} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "You must specify a path!"
		return
	}		
	ApolTop::setBusyCursor
	set rt [catch {set results [apol_Search_FC_Index_DB \
		$type_cb_value [list $opts(type)] \
		$user_cb_value [list $opts(user)] \
		$class_cb_value [list $opts(class)] \
		$path_cb_value [list [$entry_path get]] \
		$opts(regEx_user) $opts(regEx_type) $opts(regEx_path)]} err]
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		ApolTop::resetBusyCursor
		return
	} 

	$resultsbox configure -state normal
	$resultsbox delete 0.0 end
	set sz [llength $results]
	set num 0
	for {set i 0} {$i < $sz} {incr i} {
		set path [lindex $results $i]
		incr i
		set ctxt [lindex $results $i]
		incr i
		set class [lindex $results $i]
		
		if {$show_ctxt} {$resultsbox insert end "$ctxt\t     "}
		if {$show_class} {$resultsbox insert end "$class\t     "}
		$resultsbox insert end "$path\n"
		incr num
	}
	$resultsbox insert 1.0 "FILES FOUND ($num):\n\n"
	
	ApolTop::makeTextBoxReadOnly $resultsbox 
	ApolTop::resetBusyCursor
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::display_create_db_dlg
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::display_create_db_dlg {} {
	variable entry_dir
	variable entry_fn
	variable create_fc_dlg
	
	set w $create_fc_dlg
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return
	}
	toplevel $w 
	wm title $w "Create Index File"
	wm protocol $w WM_DELETE_WINDOW " "
    	wm withdraw $w
    	
    	set t_frame [frame $w.t_frame]
    	set f1 [frame $t_frame.f1]
    	set f2 [frame $t_frame.f2]
    	set f3 [frame $t_frame.f3]
    	set lbl_fn 	[Label $f1.lbl_fn -justify left -text "Save file:"]
    	set lbl_dir 	[Label $f1.lbl_dir -justify left -text "Directory to index:"]
	set entry_dir 	[entry $f2.entry_path -width 30 -bg white]
	set browse_dir 	[button $f3.button1 -text "Browse" -width 8 -command {
		set dir_n [tk_chooseDirectory \
			-title "Select Directory to Index..." \
			-parent $ApolTop::mainframe \
			-initialdir "/"]
		if {$dir_n != ""} {
			$Apol_File_Contexts::entry_dir delete 0 end
			$Apol_File_Contexts::entry_dir insert end $dir_n
		}	
	}]
	set entry_fn 	[entry $f2.entry_fn -width 30 -bg white]
	set browse_fn 	[button $f3.button2 -text "Browse" -width 8 -command {
		set file_n [tk_getSaveFile \
			-title "Select File to Save..." \
			-parent $ApolTop::mainframe]
		if {$file_n != ""} {
			$Apol_File_Contexts::entry_fn delete 0 end
			$Apol_File_Contexts::entry_fn insert end $file_n		
		}	
	}]
	$entry_dir insert end "/"
	
	set b_frame [frame $w.b_frame]
     	set b1 [button $b_frame.create -text Create \
     		-command {Apol_File_Contexts::create_fc_db $Apol_File_Contexts::create_fc_dlg} \
     		-width 10]
     	set b2 [button $b_frame.close1 -text Cancel \
     		-command {catch {destroy $Apol_File_Contexts::create_fc_dlg; grab release $Apol_File_Contexts::create_fc_dlg}} \
     		-width 10]
     	
     	pack $b_frame -side bottom -expand yes -anchor center
     	pack $t_frame -side top -fill both -expand yes
     	pack $f1 $f2 $f3 -side left -anchor nw -padx 5 -pady 5
     	pack $b1 $b2 -side left -anchor nw -padx 5 -pady 5 
	pack $lbl_fn $lbl_dir -anchor nw -side top -pady 6
	pack $entry_fn $entry_dir -anchor nw -side top -expand yes -pady 5
	pack $browse_fn $browse_dir -anchor nw -side top -expand yes -pady 3
     
 	wm geometry $w +50+50
 	wm deiconify $w
 	grab $w
 	wm protocol $w WM_DELETE_WINDOW "destroy $w"
}

proc Apol_File_Contexts::destroy_progressDlg {} {
	variable progressDlg
	
	if {[winfo exists $progressDlg]} {
		destroy $progressDlg
	}
	ApolTop::resetBusyCursor
     	return 0
} 

proc Apol_File_Contexts::display_progressDlg {} {
     	variable progressDlg
	    		
	set Apol_File_Contexts::progressmsg "Creating index file...This may take a while."
	set progressBar [ProgressDlg $Apol_File_Contexts::progressDlg \
		-parent $ApolTop::mainframe \
        	-textvariable Apol_File_Contexts::progressmsg \
        	-variable Apol_File_Contexts::progress_indicator \
        	-maximum 3 \
        	-width 45]
	ApolTop::setBusyCursor
	update
        return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::create_and_load_fc_db
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::create_and_load_fc_db {fname dir_str} {
	set rt [catch {apol_Create_FC_Index_File $fname $dir_str} err]
	if {$rt != 0} {
		return -code error $err
	} 
	set rt [catch {apol_Load_FC_Index_File $fname} err]
	if {$rt != 0} {
		return -code error $err
	} 
	Apol_File_Contexts::initialize
	set Apol_File_Contexts::db_loaded 1
	Apol_File_Contexts::change_status_label $fname
	Apol_File_Contexts::populate_combo_boxes
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::create_fc_db
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::create_fc_db {dlg} {
	variable entry_dir
	variable entry_fn
	
	set fname [$entry_fn get]
	set dir_str [$entry_dir get]
		
	Apol_File_Contexts::display_progressDlg	
	set rt [catch {Apol_File_Contexts::create_and_load_fc_db $fname $dir_str} err]
	if {$rt != 0} {
		Apol_File_Contexts::destroy_progressDlg
		tk_messageBox -icon error -type ok -title "Error" \
			-message $err
	}

	Apol_File_Contexts::change_status_label $fname
	Apol_File_Contexts::clear_combo_box_values
	Apol_File_Contexts::populate_combo_boxes	
	Apol_File_Contexts::destroy_progressDlg
	catch {destroy $dlg} 
	grab release $dlg
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::load_fc_db
#  	returns 1 if loaded successfully, otherwise, unsucessful or user canceled
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::load_fc_db { } {
	variable db_loaded
	
    	set db_file [tk_getOpenFile -title "Select Index File to Load..." -parent $ApolTop::mainframe]
	if {$db_file != ""} {	
		set rt [catch {apol_Load_FC_Index_File $db_file} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" \
				-message "Error loading file context database: $err.\n"
			return
		} 
		Apol_File_Contexts::initialize
		set db_loaded 1
		Apol_File_Contexts::change_status_label $db_file
		Apol_File_Contexts::populate_combo_boxes
		return 1
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::close_fc_db
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::close_fc_db { } {
	variable db_loaded
	
	set rt [catch {apol_Close_FC_Index_DB} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error closing file context database: $err.\n"
		return
	}
	set db_loaded 0
	return 0
}

proc Apol_File_Contexts::change_status_label {index_file} {
	variable lbl_status
	
	if {$index_file == ""} {
		set Apol_File_Contexts::index_status "No Index File Loaded"
		$lbl_status configure -fg red
	} else {
		set Apol_File_Contexts::index_status "$index_file"
		$lbl_status configure -fg black
	}
	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_File_Contexts::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_File_Contexts::on_modify_combo_box_value
#
#  Description: This function is called when the user modifies the value of the ComboBox. 
# ----------------------------------------------------------------------------------------
proc Apol_File_Contexts::on_modify_combo_box_value { which } {    
	variable user_combo_box
	variable type_combo_box
	
	switch -exact -- $which \
		"user" {
			if {$Apol_File_Contexts::opts(regEx_user)} {
	        		set Apol_File_Contexts::opts(user) 	"^$Apol_File_Contexts::opts(user)$"
	        		selection clear -displayof $user_combo_box
			} 
			
		} \
		"type" {
			if {$Apol_File_Contexts::opts(regEx_type)} {
				set Apol_File_Contexts::opts(type) 	"^$Apol_File_Contexts::opts(type)$"
				selection clear -displayof $type_combo_box
			} 
		} \
		default {
			puts "Invalid option $which.\n"
		}
	   	    			
   	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::configure_file_path_entry_widget
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::configure_file_path_entry_widget {enable} {
	variable entry_path
	
	if {$enable} {
		$entry_path configure -state normal
	} else {
		$entry_path configure -state disabled
	}
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::create
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::create {nb} {
	variable resultsbox
	variable lbl_status
	variable user_combo_box
	variable objclass_combo_box
	variable type_combo_box
	variable entry_path
	variable create_button
	variable load_button
		
	# Layout frames
	set frame [$nb insert end $ApolTop::file_contexts_tab -text "File Contexts"]
	set topf  [frame $frame.topf]
	set pw    [PanedWindow $topf.pw -side left]
	set options_pane [$pw add -minsize 220 -weight 2]
        set results_pane [$pw add -weight 4 -minsize 130]
        set pw2 [PanedWindow $options_pane.pw2 -side top -weights extra]
        set search_opts [$pw2 add -weight 1 -minsize 170]
        set search_criteria [$pw2 add -weight 5 -minsize 170]
        
	# Title frames
	set s_optionsbox [TitleFrame $search_opts.obox -text "Search Options"]
	set s_criteriabox [TitleFrame $search_criteria.cbox -text "Search Criteria"]
	set rslts_frame	 [TitleFrame $results_pane.rbox -text "Matching Files"]
				    		    
	# Search options subframes
	set ofm [$s_criteriabox getframe]
	set l_innerFrame [LabelFrame $ofm.to -relief sunken -bd 1]
	set c_innerFrame [LabelFrame $ofm.co -relief sunken -bd 1]
	set r_innerFrame [LabelFrame $ofm.ro -relief sunken -bd 1]
	set path_innerFrame [LabelFrame $ofm.po -relief sunken -bd 1]
	set buttons_f    [LabelFrame $ofm.buttons_f]
	
	# Placing inner frames
	# Search options widget items
	set user_combo_box [ComboBox [$l_innerFrame getframe].user_combo_box  \
		-textvariable Apol_File_Contexts::opts(user) \
		-helptext "Type or select a user" \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd {Apol_File_Contexts::on_modify_combo_box_value user}]
	set type_combo_box [ComboBox [$c_innerFrame getframe].type_combo_box  \
		-textvariable Apol_File_Contexts::opts(type) \
		-helptext "Type or select a type" \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd {Apol_File_Contexts::on_modify_combo_box_value type}]
	set objclass_combo_box [ComboBox [$r_innerFrame getframe].objclass_combo_box  \
		-textvariable Apol_File_Contexts::opts(class) \
		-helptext "Type or select an object class" \
		-entrybg $ApolTop::default_bg_color -editable 0]
		
	$user_combo_box configure -state disabled 
	$type_combo_box configure -state disabled 
	$objclass_combo_box configure -state disabled 
	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $user_combo_box.e [linsert [bindtags $user_combo_box.e] 3 fc_user_Tag]
	bind fc_user_Tag <KeyPress> {ApolTop::_create_popup $Apol_File_Contexts::user_combo_box %W %K}
	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $objclass_combo_box.e [linsert [bindtags $objclass_combo_box.e] 3 fc_role_Tag]
	bind fc_role_Tag <KeyPress> {ApolTop::_create_popup $Apol_File_Contexts::objclass_combo_box %W %K}
	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $type_combo_box.e [linsert [bindtags $type_combo_box.e] 3 fc_type_Tag]
	bind fc_type_Tag <KeyPress> {ApolTop::_create_popup $Apol_File_Contexts::type_combo_box %W %K}

	set cb_user [checkbutton [$l_innerFrame getframe].cb_user \
		-variable Apol_File_Contexts::user_cb_value -text "Search Using User" \
		-onvalue 1 -offvalue 0 \
		-command {ApolTop::change_comboBox_state $Apol_File_Contexts::user_cb_value $Apol_File_Contexts::user_combo_box}]
	set cb_type [checkbutton [$c_innerFrame getframe].cb_type \
		-variable Apol_File_Contexts::type_cb_value -text "Search Using Type" \
		-onvalue 1 -offvalue 0 \
		-command {ApolTop::change_comboBox_state $Apol_File_Contexts::type_cb_value $Apol_File_Contexts::type_combo_box}]
	set cb_objclass [checkbutton [$r_innerFrame getframe].cb_objclass \
		-variable Apol_File_Contexts::class_cb_value -text "Search Using Object Class" \
		-onvalue 1 -offvalue 0 \
		-command {ApolTop::change_comboBox_state $Apol_File_Contexts::class_cb_value $Apol_File_Contexts::objclass_combo_box}]
	set cb_path [checkbutton [$path_innerFrame getframe].cb_path \
		-variable Apol_File_Contexts::path_cb_value -text "Search Using File Path" \
		-onvalue 1 -offvalue 0 \
		-command {Apol_File_Contexts::configure_file_path_entry_widget $Apol_File_Contexts::path_cb_value}]
		
	set cb_regEx_user [checkbutton [$l_innerFrame getframe].cb_regEx_user \
		-variable Apol_File_Contexts::opts(regEx_user) \
		-text "Enable regular expressions"]
	set cb_regEx_type [checkbutton [$c_innerFrame getframe].cb_regEx_type \
		-variable Apol_File_Contexts::opts(regEx_type) \
		-text "Enable regular expressions" \
		-onvalue 1 -offvalue 0]
	set cb_regEx_path [checkbutton [$path_innerFrame getframe].cb_regEx_path \
		-variable Apol_File_Contexts::opts(regEx_path) \
		-text "Enable regular expressions" \
		-onvalue 1 -offvalue 0]
	set cb_show_ctxt [checkbutton [$s_optionsbox getframe].cb_show_ctxt \
		-variable Apol_File_Contexts::show_ctxt \
		-text "Show context" \
		-onvalue 1 -offvalue 0]
	set cb_show_class [checkbutton [$s_optionsbox getframe].cb_show_class \
		-variable Apol_File_Contexts::show_class \
		-text "Show object class" \
		-onvalue 1 -offvalue 0]
	
	set status_frame [TitleFrame $options_pane.status_frame -text "File Context Index"]
	set stat_frame [frame [$status_frame getframe].stat_frame]
	set db_buttons_f [frame [$status_frame getframe].db_buttons_f]
	set entry_path [entry [$path_innerFrame getframe].entry_path -width 40 -bg white -state disabled]
    	set lbl_stat_title [Label $stat_frame.lbl_stat_title -text "Loaded Index:"]
    	set lbl_status [Label $stat_frame.lbl_status -textvariable Apol_File_Contexts::index_status]
	
	Apol_File_Contexts::change_status_label ""
			
	# Action Buttons
	set ok_button [button [$buttons_f getframe].ok -text OK -width 6 -command {Apol_File_Contexts::search_fc_database}]
	set create_button [button $db_buttons_f.create -text "Create and Load" -width 15 \
		-state normal \
		-command {Apol_File_Contexts::display_create_db_dlg}]
	set load_button [button $db_buttons_f.load -text "Load" -width 8 \
		-state normal \
		-command {Apol_File_Contexts::load_fc_db}]
	set help_button [button [$buttons_f getframe].help -text "Info" -width 6 \
		-command {Apol_File_Contexts::display_analysis_info}]
	#button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}
	
	# Display results window
	set sw_d [ScrolledWindow [$rslts_frame getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing layout
	pack $topf -fill both -expand yes 
	pack $status_frame -side top -anchor nw -fill x -pady 3
	pack $pw -fill both -expand yes 
	pack $pw2 -fill both -expand yes 
	
	# Placing title frames
	pack $s_optionsbox -padx 2 -fill both -expand yes 
	pack $s_criteriabox -padx 2 -fill both -expand yes 
	pack $rslts_frame -pady 2 -padx 2 -fill both -anchor n -side bottom -expand yes
	
	# Placing all widget items
	pack $db_buttons_f $stat_frame -side left -anchor nw -padx 4 -pady 4
	pack $ok_button $help_button -side top -anchor e -pady 2 -padx 5
	pack $buttons_f -side right -expand yes -fill both -anchor nw -padx 4 -pady 4
	pack $l_innerFrame $r_innerFrame -side left -fill both -anchor nw -padx 4 -pady 4
	pack $c_innerFrame $path_innerFrame -side left -fill both -expand yes -anchor nw -padx 4 -pady 4
	pack $cb_show_ctxt $cb_show_class -side top -anchor nw -padx 4 -pady 4 
	pack $create_button $load_button -side left -padx 2 -pady 2 -anchor nw
	pack $lbl_stat_title $lbl_status -side left -anchor nw -padx 2 -pady 4
	pack $cb_user $cb_type $cb_objclass $cb_path -side top -anchor nw
	pack $entry_path -side top -anchor nw -padx 10 -pady 4
	pack $user_combo_box $type_combo_box $objclass_combo_box -side top -fill x -anchor nw -padx 4
	pack $cb_regEx_user $cb_regEx_type $cb_regEx_path -side top -anchor nw -padx 4 -pady 4 
	pack $sw_d -side left -expand yes -fill both 
		
	return $frame	
}










































































































































