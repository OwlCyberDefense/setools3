# Copyright (C) 2004 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_Cond_Rules
#  
# The Conditional Rules tab namespace
##############################################################
namespace eval Apol_Cond_Rules {
	# Search options
	# search_opts(opt), where opt =
	# 	boolean  	the name of the boolean
	# 	show_rules  	whether to display rules along 
	#		     	with conditional expression
	#	allow_regex  	use regex
	#
	# Currently, only the following types of statements are  
      	# allowed inside of conditional policy blocks:
	# 	incl_teallow	type allow rules
	# 	incl_teaudit	audit rules
	# 	incl_ttrans	type trans rules	
	variable search_opts 
	set search_opts(boolean)	""
	set search_opts(show_rules)	1
	set search_opts(incl_teallow)	1
	set search_opts(incl_teaudit)	0
	set search_opts(incl_ttrans)	0
	set search_opts(allow_regex)	1	
	
	# other
	variable enable_bool_combo_box	0
	
	# Global widgets
	variable resultsbox
	variable cond_bools_listbox
	variable bool_combo_box
}

###############################################################
#  ::cond_rules_search
#
proc Apol_Cond_Rules::cond_rules_search {} {
	variable search_opts
	variable cond_bools_list
	variable resultsbox
	variable enable_bool_combo_box
	
	if {$enable_bool_combo_box} {
		set bool_name $search_opts(boolean)
	} else {
		set bool_name ""
	}
			
	set rt [catch {set results [apol_SearchConditionalRules \
		$bool_name \
		$search_opts(allow_regex) \
		$search_opts(show_rules) \
		$search_opts(incl_teallow) \
		$search_opts(incl_teaudit) \
		$search_opts(incl_ttrans)]} err]
		
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	} else {
		$resultsbox configure -state normal
		$resultsbox delete 0.0 end
		$resultsbox insert end $results
		ApolTop::makeTextBoxReadOnly $resultsbox 
	}

	return 0
}

################################################################
#  ::cond_rules_reset_variables
#
proc Apol_Cond_Rules::cond_rules_reset_variables { } {
	variable search_opts 
	variable enable_bool_combo_box	
	
	set search_opts(boolean)	""
	set search_opts(show_rules)	1
	set search_opts(incl_teallow)	1
	set search_opts(incl_teaudit)	0
	set search_opts(incl_ttrans)	0
	set search_opts(allow_regex)	1
	set enable_bool_combo_box 0
	
	return 0	
}

################################################################
#  ::cond_rules_enable_comboBox
#
proc Apol_Cond_Rules::cond_rules_enable_comboBox {cb_value combo_box} {
	selection clear -displayof $combo_box

	if {$cb_value} {
		$combo_box configure -state normal -entrybg white
	} else {
		$combo_box configure -state disabled -entrybg $ApolTop::default_bg_color
	}
	
	return 0
}

################################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Cond_Rules::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Cond_Rules::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

################################################################
# ::set_Focus_to_Text
# 
proc Apol_Cond_Rules::set_Focus_to_Text {} {
	focus $Apol_Cond_Rules::resultsbox
	return 0
}

################################################################
#  ::open
#
proc Apol_Cond_Rules::open { } {
	set cond_bools_list [apol_GetNames cond_bools]
	set rt [catch {set cond_bools_list [apol_GetNames cond_bools]} err]
	if {$rt != 0} {
		return -code error $err
	}	
	set cond_bools_list [lsort $cond_bools_list] 
	
	$Apol_Cond_Rules::bool_combo_box configure -values $cond_bools_list
	
	return 0
} 

################################################################
#  ::close
#
proc Apol_Cond_Rules::close { } {	
	Apol_Cond_Rules::cond_rules_reset_variables
	
	$Apol_Cond_Rules::bool_combo_box configure -values ""
	Apol_Cond_Rules::cond_rules_enable_comboBox $Apol_Cond_Rules::enable_bool_combo_box $Apol_Cond_Rules::bool_combo_box
	$Apol_Cond_Rules::resultsbox configure -state normal
	$Apol_Cond_Rules::resultsbox delete 0.0 end
	ApolTop::makeTextBoxReadOnly $Apol_Cond_Rules::resultsbox 
	
	return 0	
}

################################################################
#  ::free_call_back_procs
#
proc Apol_Cond_Rules::free_call_back_procs { } {
     
	return 0
}

################################################################
#  ::create
#
proc Apol_Cond_Rules::create {nb} {
	variable bool_combo_box
	variable resultsbox 
	
	# Layout frames
	set frame [$nb insert end $ApolTop::cond_rules_tab -text "Conditional Rules"]
	set pw1 [PanedWindow $frame.pw1 -side left -weights available]
	$pw1 add -minsize 110 
	$pw1 add -weight 3
	set topf  [frame [$pw1 getframe 0].topf]
	set bottomf [frame [$pw1 getframe 1].bottomf]
	
	# Placing layout frames
	pack $pw1 -fill both -expand yes
	pack $topf -fill both -expand yes     
	pack $bottomf -fill both -expand yes
	
	# Major subframes
	set pw2 [PanedWindow $topf.pw2 -side top -weights available]
	$pw2 add -minsize 225
	$pw2 add -weight 3
	
	set obox [TitleFrame [$pw2 getframe 1].obox -text "Search Options"]
	set rules_box [TitleFrame [$pw2 getframe 0].rules_box -text "Rule Selection"]
	set dbox [TitleFrame $bottomf.dbox -text "Conditional Rules Display"]
	
	# Placing major subframes
	pack $pw2 -fill both -expand yes
	pack $obox -side right -anchor w -fill both -padx 5 -expand yes
	pack $rules_box -side left -anchor w -fill both -padx 5 -expand yes
	pack $dbox -side left -fill both -expand yes -anchor e -pady 5 -padx 5
		    	
	# Search options subframes
	set ofm [$obox getframe]
	set rules_fm [frame [$rules_box getframe].tefm]
	set l_innerFrame [LabelFrame $ofm.l_innerFrame]
	set c_innerFrame [LabelFrame $ofm.c_innerFrame]
	set buttons_f    [LabelFrame $ofm.buttons_f]
	
	set rules_inner_left_fm [frame $rules_fm.rules_inner_left_fm]
	set teallow [checkbutton $rules_inner_left_fm.teallow \
		-text "Allow" \
		-variable Apol_Cond_Rules::search_opts(incl_teallow) \
	    	-onvalue 1 -offvalue 0]
	set auallow [checkbutton $rules_inner_left_fm.auallow \
		-text "Audit" \
		-variable Apol_Cond_Rules::search_opts(incl_teaudit) \
	    	-onvalue 1 -offvalue 0]
	set ttrans [checkbutton $rules_inner_left_fm.ttrans \
		-text "Transition" \
		-variable Apol_Cond_Rules::search_opts(incl_ttrans) \
	    	-onvalue 1 -offvalue 0]
	
	    
	set bool_combo_box [ComboBox [$l_innerFrame getframe].bool_combo_box \
		-textvariable Apol_Cond_Rules::search_opts(boolean) \
		-helptext "Type or select a boolean variable" \
		-entrybg $ApolTop::default_bg_color]
	set cb_enable_bool_combo_box [checkbutton [$l_innerFrame getframe].cb_enable_bool_combo_box \
		-variable Apol_Cond_Rules::enable_bool_combo_box \
		-onvalue 1 -offvalue 0 -text "Search using boolean variable" \
		-command {Apol_Cond_Rules::cond_rules_enable_comboBox $Apol_Cond_Rules::enable_bool_combo_box $Apol_Cond_Rules::bool_combo_box}]
	set cb_show_rules [checkbutton [$c_innerFrame getframe].cb_show_rules \
		-variable Apol_Cond_Rules::search_opts(show_rules) \
		-onvalue 1 -offvalue 0 -text "Display rules within conditional expression(s)"]
	set cb_regex [checkbutton [$c_innerFrame getframe].cb_regex \
		-variable Apol_Cond_Rules::search_opts(allow_regex) \
		-onvalue 1 -offvalue 0 -text "Use regular expression"]
	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $bool_combo_box.e [linsert [bindtags $bool_combo_box.e] 3 bool_combo_box_Tag]
	bind bool_combo_box_Tag <KeyPress> { ApolTop::_create_popup $Apol_Cond_Rules::bool_combo_box %W %K }
    
	# Action Buttons
	set ok_button [button [$buttons_f getframe].ok -text OK -width 6 -command {Apol_Cond_Rules::cond_rules_search}]
	#button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}
	
	# Display results window
	set sw_d [ScrolledWindow [$dbox getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing all widget items
	pack $ok_button -side top -anchor e -pady 5 -padx 5
	pack $buttons_f -side right -expand yes -fill both -anchor nw -padx 4 -pady 4
	pack $l_innerFrame $c_innerFrame -side left -fill y -anchor nw -padx 4 -pady 4
	
	pack $cb_enable_bool_combo_box $bool_combo_box -side top -anchor nw -fill x
	pack $cb_show_rules $cb_regex -side top -anchor nw 
	pack $sw_d -side left -expand yes -fill both 
	pack $rules_fm -side left -anchor nw 
	pack $rules_inner_left_fm -side left -anchor nw -fill both -expand yes
	pack $teallow $auallow $ttrans -anchor nw -side top 
    
	return $frame	
}

