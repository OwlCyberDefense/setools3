# Copyright (C) 2003-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets


##############################################################
# ::Apol_PolicyConf
#  
# The policy.conf Rules page
###############################################################
namespace eval Apol_PolicyConf {
	variable textbox_policyConf
	
	# wrap procs
	variable policy_conf_wrap_proc	"Apol_PolicyConf::wrap_proc_policy_conf"
	variable orig_cursor		""
	# used to indicate whether changes to policy conf box allowed
	variable mod_disabled		1
	variable lineno_tag		LINENO
	variable selected_tag		SELECTED

}

##################################################################
# ::wrap_proc_policy_conf
#  	- This overrides the default cmds
#		for text so we can track dirty bit
# NOTE: This proc MUST have same name as $policy_conf_wrap_proc var; it will
# be renamed in create
proc Apol_PolicyConf::wrap_proc_policy_conf { cmd args } {
	switch $cmd {
		insert	- 
		delete	{
			if { $Apol_PolicyConf::mod_disabled == 1 } {
				return 0
			}
		} 
		mark 	{	
			if { [string compare -length 10 $args "set insert"]  == 0 } {
				# in this case, go ahead and directly call the upleve cmd so that
				# the insertion mark is set, allowing us to determine its location.
				# Because we call uplevel, we MUST return from this case.
				uplevel "::${Apol_PolicyConf::textbox_policyConf}_" $cmd $args
				set lpos [$Apol_PolicyConf::textbox_policyConf index insert]
				Apol_PolicyConf::update_positionStatus $lpos
				return 
			}
		} 
	}
	# don't use a return after this!
	uplevel "::${Apol_PolicyConf::textbox_policyConf}_" $cmd $args
}

# ----------------------------------------------------------------------------------------
#  Command Apol_PolicyConf::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_PolicyConf::set_Focus_to_Text {} {
	focus $Apol_PolicyConf::textbox_policyConf
	set ApolTop::policyConf_lineno "Line [$Apol_PolicyConf::textbox_policyConf index insert]"
	
	return 0
}

############################################################################
# ::update_positionStatus
#  	- updates cursor position status infor
# 
proc Apol_PolicyConf::update_positionStatus { pos } { 
	if { [catch {scan $pos" %d.%d" line col} err ] } {
		puts stderr "update_positionStatus: Problem scanning position ($pos): $err"
		return -1
	}
	set ApolTop::policyConf_lineno "Line $line"
	return 0
}

############################################################################
# ::create
#  	- Create policy.conf tab
# 
proc Apol_PolicyConf::create {nb} {
	variable textbox_policyConf
	
	# Create tab for displaying the policy.conf file.
	set frame [$nb insert end $ApolTop::policy_conf_tab -text "policy.conf"]
	# policy.conf window
	set sw [ScrolledWindow $frame.sw -auto none]
	set textbox_policyConf [text [$sw getframe].text -bg white -wrap none]
	$sw setwidget $textbox_policyConf
	rename $textbox_policyConf "::${textbox_policyConf}_"
    	rename $Apol_PolicyConf::policy_conf_wrap_proc "::$textbox_policyConf"
	
    	pack $sw -side left -expand yes -fill both
	
	return 0
}

proc Apol_PolicyConf::open { file } {
	Apol_PolicyConf::display_policy_conf $file
			
	return 0
}

proc Apol_PolicyConf::close { } { 
	variable textbox_policyConf
	variable mod_disabled
	
	# Re-enable textbox and then delete it's contents
        set mod_disabled 0
        $textbox_policyConf delete 0.0 end
        set mod_disabled 1
        	      
	return 0
}

proc Apol_PolicyConf::free_call_back_procs { } {
  
	return 0
}

###################################################################
# Apol_PolicyConf::display_policy_conf
#  	- Display the policy.conf file
# 
proc Apol_PolicyConf::display_policy_conf { path } {
   	variable textbox_policyConf
   	variable mod_disabled
   	
   	set mod_disabled 0
   	$textbox_policyConf delete 0.0 end
   	if {[ApolTop::is_binary_policy]} {
   		$textbox_policyConf insert end "<Binary policy is not available>"
   	} else {
		# Make sure the "policy.conf" file exists and is readable by the user.
		if { [file exists $path] } {
			if { [file readable $path] } {
				set file_channel [::open $path r]
				set data [read $file_channel]
				::close $file_channel
		
				$textbox_policyConf insert end $data 
			} else {
				$textbox_policyConf insert end "<policy.conf file exists but is not readable>"
			}
		} else {
			$textbox_policyConf insert end "<policy.conf file does not exist>"
		} 
	}
	set mod_disabled 1
	$textbox_policyConf see 0.0
	$textbox_policyConf mark set insert 1.0
    	
    	return 0
}

##############################################################
# Apol_PolicyConf::search
#  	- Search text widget for a string
# 
proc Apol_PolicyConf::search { str case_Insensitive regExpr srch_Direction } {
	variable textbox_policyConf
	
	ApolTop::textSearch $textbox_policyConf $str $case_Insensitive $regExpr $srch_Direction
	set ApolTop::policyConf_lineno "Line [$textbox_policyConf index insert]"
	return 0
}

########################################################################
# Apol_PolicyConf::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_PolicyConf::goto_line { line_num } {
	variable textbox_policyConf
	
	ApolTop::goto_line $line_num $textbox_policyConf
	return 0
}
   
# ------------------------------------------------------------------------------
#  Command Apol_PolicyConf::insertHyperLink { tb start end}
# start and end are l.c line positions
proc Apol_PolicyConf::insertHyperLink { tb start end } {
	$tb tag add $Apol_PolicyConf::lineno_tag $start $end
	return 0
}

# -------------------------------------------------------
#  Command Apol_PolicyConf::remove_HyperLink_tags { tb }
#
# -------------------------------------------------------
proc Apol_PolicyConf::remove_HyperLink_tags { tb } {
	$tb tag remove $Apol_PolicyConf::lineno_tag 0.0 end
	$tb tag remove $Apol_PolicyConf::selected_tag 0.0 end
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_PolicyConf::configure_HyperLinks
#	
# ------------------------------------------------------------------------------
proc Apol_PolicyConf::configure_HyperLinks { tb } {
	# Change the color and underline so that it looks like a common hyperlink. Also, change
	# the cursor when the mouse is over the hyperlink.
	$tb tag configure $Apol_PolicyConf::lineno_tag -foreground blue -underline 1
	$tb tag bind $Apol_PolicyConf::lineno_tag <Button-1> "Apol_PolicyConf::findInPolicyConf %W %x %y"
	$tb tag bind $Apol_PolicyConf::lineno_tag <Enter> { set Apol_PolicyConf::orig_cursor [%W cget -cursor]; %W configure -cursor hand2 }
	$tb tag bind $Apol_PolicyConf::lineno_tag <Leave> { %W configure -cursor $Apol_PolicyConf::orig_cursor }
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_PolicyConf::findInPolicyConf
# ------------------------------------------------------------------------------
proc Apol_PolicyConf::findInPolicyConf { tb x y } {
	
	set line_num [eval $tb get [$tb tag prevrange $Apol_PolicyConf::lineno_tag "@$x,$y + 1 char"]]
	$ApolTop::notebook raise $ApolTop::policy_conf_tab
	Apol_PolicyConf::goto_line $line_num
	
	# Change foreground color of hyperlink to indicate that it has been selected.
	set ranges [$tb tag prevrange $Apol_PolicyConf::lineno_tag "@$x,$y + 1 char"]
	$tb tag add $Apol_PolicyConf::selected_tag [lindex $ranges 0] [lindex $ranges 1]
	$tb tag configure $Apol_PolicyConf::selected_tag -foreground red -underline 1
	
	return 0
}

















