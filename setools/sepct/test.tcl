################################################################
# sepct_test.tcl

# -----------------------------------------------------------
#  Copyright (C) 2002-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com, mayerf@tresys.com>

##############################################################
# ::Sepct_Test namespace
#  
##############################################################
namespace eval Sepct_Test {    
	variable progressmsg		""
	variable indicator 		0
	variable MakeOutputTabName	"Sepct_MakeOutputTab"
	variable PolicyConfTabName	"Sepct_PolicyConf"
	
	# Global widgets
	variable notebook
	variable textbox_makeOutput
	variable textbox_policyConf
	variable progressDlg
	set progressDlg .progress
	# buttons
	variable b_test
	variable b_clean
	variable b_install
	variable b_reload
	variable b_view_pc
	
	# misc
	# used to indicate whether changes to policy conf box allowed
	variable mod_disabled		1
	variable policy_conf_opened	0
	variable tmpfilename		""
	
	# wrap procs
	variable policy_conf_wrap_proc	"Sepct_Test::wrap_proc_policy_conf"
	
	# build/make vars
	variable indicator
	variable progressmsg
}


##################################################################
# ::wrap_proc_policy_conf
#  	- This overrides the default cmds
#		for text so we can track dirty bit
# NOTE: This proc MUST have same name as $policy_conf_wrap_proc var; it will
# be renamed in create
proc Sepct_Test::wrap_proc_policy_conf { cmd args } {
	switch $cmd {
		insert	-
		delete	{ 
			set lpos [$Sepct_Test::textbox_policyConf index insert]
			Sepct::update_positionStatus $lpos
			if { $Sepct_Test::mod_disabled  } {
				return
			}
		}
		mark 	{	
			if { [string compare -length 10 $args "set insert"]  == 0 } {
				# in this case, go ahead and directly call the upleve cmd so that
				# the insertion mark is set, allowing us to determine its location.
				# Because we call uplevel, we MUST return from this case.
				uplevel "::${Sepct_Test::textbox_policyConf}_" $cmd $args
				set lpos [$Sepct_Test::textbox_policyConf index insert]
				Sepct::update_positionStatus $lpos
				return 
			}
		}
	}
	# don't use a return after this!
	uplevel "::${Sepct_Test::textbox_policyConf}_" $cmd $args
}

############################################################################
# ::enableMods
# 
proc Sepct_Test::enableMods {} {
	variable mod_disabled
	variable textbox_makeOutput
	
	$textbox_makeOutput configure -state normal
	set mod_disabled 0
	
	return  0
}

############################################################################
# ::disableMods
# 
proc Sepct_Test::disableMods {} {
	variable mod_disabled
	variable textbox_makeOutput
	
	$textbox_makeOutput configure -state disabled
	set mod_disabled 1
	
	return  0
}

############################################################################
# ::save_as
# 
proc Sepct_Test::save_as { } {
	return 0
}

############################################################################
# ::save
# 
proc Sepct_Test::save { } {
	return 0
}

############################################################################
# ::revert_file
# 
proc Sepct_Test::revert_file { } {
	return 0
}

############################################################################
# ::initialize (called on open)
# 
proc Sepct_Test::initialize { } {
	variable b_test
	variable b_clean
	variable b_install
	variable b_reload
	variable b_view_pc
	
	$b_test configure -state normal
	$b_clean configure -state normal
	$b_install configure -state normal
	$b_reload configure -state normal
	$b_view_pc configure -state normal
	
	return 0
}

############################################################################
# ::close
#  	- functions to do on close
# 
proc Sepct_Test::close { } {
	variable b_test
	variable b_clean
	variable b_install
	variable b_reload
	variable b_view_pc
	
	$b_test configure -state disabled
	$b_clean configure -state disabled
	$b_install configure -state disabled
	$b_reload configure -state disabled
	$b_view_pc configure -state disabled
	Sepct_Test::clear_Output

	return 0
}

############################################################################
# ::leave_Tab
#  	- called when Test tab is raised and about to be left
#
proc Sepct_Test::leave_Tab { } {
	# Nothing to do!
	return 0
}
############################################################################
# ::enter_Tab
#  	- called when Test tab is about to be raised
#
proc Sepct_Test::enter_Tab { } {
	variable notebook
	variable textbox_policyConf
	variable textbox_makeOutput
	variable MakeOutputTabName

	if { [$notebook raise] == $MakeOutputTabName } {
		focus $textbox_makeOutput
	} else {
		focus $textbox_policyConf
	}
	if { [Sepct::isPolicyOpened] } {
		$Sepct::mainframe setmenustate ModEditTag disabled
		$Sepct::mainframe setmenustate SaveFileTag disabled
		$Sepct::mainframe setmenustate SaveFileAsTag disabled
		$Sepct::mainframe setmenustate RevertTag disabled
		$Sepct::mainframe setmenustate ConfigTag disabled
	}
	return 0
}

############################################################################
# ::switch_internal_tab
#  	- called when switching between output and policy.conf tabs
#	  just sets focus
#
proc Sepct_Test::switch_internal_tab { tabID } {
    	variable textbox_makeOutput
    	variable textbox_policyConf
    	variable MakeOutputTabName
    	variable policy_conf_opened
  	
  	set tabID [Sepct::get_tabname $tabID]
	if { $tabID == $MakeOutputTabName } {
		focus $textbox_makeOutput
		Sepct::clear_fileStatus
	} else {
		focus $textbox_policyConf
		if { $policy_conf_opened && [file exists [file join $Sepct::policyDir "policy.conf"]]} {
			Sepct::update_fileStatus [file join $Sepct::policyDir "policy.conf"] 0
			Sepct::update_positionStatus [$Sepct_Test::textbox_policyConf index insert]
		} else {
			Sepct::clear_fileStatus
		}
	}
    	return 0
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Sepct_Test::search { str case_Insensitive regExpr srch_Direction } {
	variable notebook
	variable textbox_makeOutput
	variable textbox_policyConf
	variable MakeOutputTabName	
	variable PolicyConfTabName
	
	set raisedPage [$notebook raise]
	
	if { $raisedPage == $MakeOutputTabName } {
		Sepct::textSearch $textbox_makeOutput $str $case_Insensitive $regExpr $srch_Direction
	} elseif { $raisedPage == $PolicyConfTabName } {
		Sepct::textSearch $textbox_policyConf $str $case_Insensitive $regExpr $srch_Direction
	} else {
		return
	}
	
	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in policy.conf text box
# 
proc Sepct_Test::goto_line { line_num} {
	variable notebook
    	variable textbox_policyConf
    	variable MakeOutputTabName
    		
	if { ![Sepct::isPolicyOpened] } {
		return -1
	}
	
	if { [$notebook raise] == $MakeOutputTabName } {
		# goto line doesn't do anything if we're looking at the output results
		return 0
	} 
	
	if {[string is integer -strict $line_num] != 1 || [string is digit -strict $line_num] != 1 || [regexp "\[A-Z\]" $line_num]} {
		tk_messageBox -icon error \
			-type ok  \
			-title "Invalid line number" \
			-message "$line_num is not a valid line number"
		return 0
	}
	$textbox_policyConf mark set insert ${line_num}.0 
	$textbox_policyConf see ${line_num}.0 
	focus -force $textbox_policyConf
	return 0
}


############################################################################
# ::get_LineNum_Info
#  	- 
# 
proc Sepct_Test::get_LineNum_Info {} {
	variable notebook
    	variable textbox_makeOutput
    	variable textbox_policyConf
    	variable MakeOutputTabName
    	variable PolicyConfTabName
	
	if { ![Sepct::isPolicyOpened] } {
		return -1
	}
	
	set raisedPage [$notebook raise]
	if { $raisedPage == $MakeOutputTabName } {
		set tBox $textbox_makeOutput
	} elseif { $raisedPage == $PolicyConfTabName } {
		set tBox $textbox_policyConf		
	}
	
	set indices  [$tBox mark names]
	set line_num [$tBox index [lindex $indices 0]]
	   
    	return $line_num
}

###################################################################
# ::display_Updated_Policy
#  	- 
#	- 
# 
proc Sepct_Test::display_Updated_Policy { } {
	variable textbox_makeOutput
   	variable textbox_policyConf

	if { ![Sepct::isPolicyOpened] } {
		return 1
	}
   	
   	# Display the updated policy.conf file
	set path [file join $Sepct::policyDir "policy.conf"]
	
	# Make sure the "policy.conf" file exists and is readable by the user.
	if { [file exists $path] } {
		if { [file readable $path] } {
			set file_channel [open $path r]
			set data [read $file_channel]
			::close $file_channel
	
			$textbox_policyConf delete 0.0 end
			$textbox_policyConf insert end $data 
			#focus -force $textbox_policyConf
			#$textbox_policyConf mark set insert 0.0 
			#$textbox_policyConf see 0.0
			set data ""
		} else {
			tk_messageBox -icon warning \
			-type ok \
			-title "Permission Problem" \
			-message \
			"You do not have permission to read this file."
		}
	}
    
    	return 0
}

###################################################################
# ::display_test_policy_conf
#  	- 
#	- 
# 
proc Sepct_Test::display_test_policy_conf { } {
   	variable textbox_policyConf
   	variable policy_conf_opened
   	
   	# Display the updated policy.conf file
	set path [file join $Sepct::policyDir "policy.conf"]
	
	# enable mods to box
	Sepct_Test::enableMods
	
	# Make sure the "policy.conf" file exists and is readable by the user.
	$textbox_policyConf delete 0.0 end
	if { [file exists $path] } {
		if { [file readable $path] } {
			set file_channel [::open $path r]
			set data [read $file_channel]
			::close $file_channel
	
			$textbox_policyConf insert end $data 
			set policy_conf_opened 1
		} else {
			$textbox_policyConf insert end "<policy.conf file exists but is not readable>"
			set policy_conf_opened 0
		}
	} else {
		$textbox_policyConf insert end "<policy.conf file does not exist>"
		set policy_conf_opened 0
	}		
	$textbox_policyConf mark set insert 0.0 
	$textbox_policyConf see 0.0
	
	# disable mods to box
	Sepct_Test::disableMods
	if {$policy_conf_opened } {
    		Sepct_Test::switch_internal_tab $Sepct_Test::PolicyConfTabName
    	}
    	
    	return 0
}

###################################################################
# ::open_tmp_file
#  	- creates and returns a opened channel to a unique tmp file for 
#	  write access only
# NOTE: Open as WRONLY only.  This is so we can allow strictly write access for
# 	when this file is passed as stdout/stderr to checkpolicy and load_policy.
#	Later we will re-open for read access to allow us to view results.
proc Sepct_Test::open_tmp_file {  } {
	variable tmpfilename
	
	set chars "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	set num_chars 8
	set num_tries 8
	set fn_prefix "/tmp/sepcut-"
	set mypid [pid]
	set access [list WRONLY CREAT TRUNC EXCL]
	# Unix perms for new file
	set perms 0600
	set opened_channel ""
     	for {set i 0} {$i < $num_tries} {incr i} {
 		set fn $fn_prefix
 		for {set j 0} {$j < $num_chars} {incr j} {
 			append fn [string index $chars [expr ([clock clicks] ^ $mypid) % 62]]
		}
		if {[file exists $fn]} {
			# pause and try again
	 	    	after 1
		} else {
			if {![catch {open $fn $access $perms} opened_channel]} {
				# Success
				# return tmp file name in global
				set tmpfilename $fn
				# return opened channel
				return $opened_channel
		    	}
		    	# try again 
		    	# TODO: prob should make sure dir is writeable before trying again!
		}
	}
	# If we're here we failed to create the file!
	puts stderr "Failed to create a unique temporary file with prefect $fn_prefix"
	error "Failed to create a unique temporary file with prefect $fn_prefix"
}



###################################################################
# ::test_Policy
#  	- calls make, displays results
#	- 
# 
proc Sepct_Test::test_Policy { which button } {
	variable textbox_makeOutput
   	variable textbox_policyConf
   	variable MakeOutputTabName
   	variable notebook
   	variable progressmsg
   	variable progressBar
	variable tmpfilename
	variable saveall_choice
   	variable policy_conf_opened
	variable progressDlg
	
	if { ![Sepct::isPolicyOpened] } {
		return -1
	}
	if {[winfo exists $progressDlg]} {
		# Already in process, so return
		return	
	}
	set canceled [Sepct::checkAndSaveChanges]
	if {$canceled < 0 } {
		return -1
	}
	
	Sepct_Test::enableMods
		
	if { $canceled == 0 } {
		# Change to the given policy directory.
		cd $Sepct::policyDir
		
		# create a temp file channel with WRONLY access only!
                if { [catch {set of [ Sepct_Test::open_tmp_file ] } ] } {
                	return -1
                }
                $button configure -state disabled
		set progressBar [ ProgressDlg $progressDlg -parent $Sepct::mainWindow -title "Making policy..."  \
                	-textvariable Sepct_Test::progressmsg -variable Sepct_Test::indicator -maximum 6]
		set Sepct_Test::indicator 0
		
		switch $which {
			test {
				# Clear policy.conf text and reset open status to 0 
				$textbox_policyConf delete 0.0 end
				set policy_conf_opened 0
				set Sepct_Test::indicator 1
				set Sepct_Test::progressmsg "Compiling policy"
				update idletasks
				set rt [catch {eval [list exec make policy >&@ $of]} err]	
				if {$rt != 0} {
					set msg "Problem making policy.conf"
				}			
			}
			clean {
				# Clear policy.conf text and reset open status to 0 since 
				# we do not want ::switch_internal_tab to update it's file status.
				$textbox_policyConf delete 0.0 end
				set policy_conf_opened 0
				set Sepct_Test::indicator 1
				set Sepct_Test::progressmsg "Cleaning policy"
				update idletasks
				set rt [catch {exec make clean >&@ $of} ]
				if {$rt != 0} {
					set msg "Problem cleaning policy"
				}
					
			}
			install {
				set Sepct_Test::indicator 1
				set Sepct_Test::progressmsg "Installing policy"
				update idletasks
				set rt [catch {eval [list exec make install >&@ $of]} err]
				if {$rt != 0} {
					set msg "Problem installing policy"
				}
			}
			load {
				set Sepct_Test::indicator 1
				set Sepct_Test::progressmsg "Loading policy"
				update idletasks
				set rt [catch {eval [list exec make reload >&@ $of]} err]
				if {$rt != 0} {
					set msg "Problem loading policy"
				}
			}
			relabel {
				set ans [tk_messageBox \
						-icon warning \
						-type yesno \
						-title "Takes Several Minutes" \
						-message "Relabeling files could take several minutes.  Would you like to continue?"]
				if { $ans == "yes" } {
					set Sepct_Test::indicator 1
					set Sepct_Test::progressmsg "Relabeling Files"
					update idletasks
					set rt [catch {eval [list exec make relabel >&@ $of]} err]
					if {$rt != 0} {
						set msg "Problem relabeling policy"
					}
					
				}
			}
			default {
				$button configure -state normal
				destroy $progressBar
				Sepct_Test::disableMods
				return -1
			}		
		}
		set Sepct_Test::indicator 2
		# re-open output file for read, and delete when finised
		set data ""
		::close $of
		set rt [catch {set of [::open $tmpfilename "RDONLY"]} err]
		if {$rt != 0} {
			destroy $progressBar
			$button configure -state normal
		}
		set Sepct_Test::indicator 3
		set rt [catch {set data [::read $of]} err]
		if {$rt != 0} {
			destroy $progressBar
			$button configure -state normal
		}
		set Sepct_Test::indicator 4
		::close $of
		file delete $tmpfilename
		set Sepct_Test::indicator 5
			
		# display make results
		$textbox_makeOutput delete 0.0 end
		$textbox_makeOutput insert end $data
		focus -force $textbox_makeOutput
		$textbox_makeOutput mark set insert 0.0 
		$textbox_makeOutput see 0.0
		set Sepct_Test::indicator 6		
		destroy $progressBar
		$button configure -state normal
	}	
	
	focus $textbox_makeOutput
	Sepct_Test::switch_internal_tab $MakeOutputTabName
	$notebook raise $MakeOutputTabName
	Sepct_Test::disableMods
	return 0
}



###################################################################
# ::clear_Output
#  	- 
# 
proc Sepct_Test::clear_Output { } {
	variable textbox_makeOutput
   	variable textbox_policyConf
   	variable policy_conf_opened
   	
	Sepct_Test::enableMods   	
	$textbox_makeOutput delete 0.0 end
	$textbox_policyConf delete 0.0 end
	set policy_conf_opened 0
	Sepct_Test::disableMods
    
    	return 0
}

##############################################################
# ::createNoteBook
#  	- Creates the notebook widget and all related widgets.
# 	
#
proc Sepct_Test::createNoteBook { tabsBox } {
    variable textbox_makeOutput
    variable textbox_policyConf
    variable notebook
    
    set notebook [NoteBook $tabsBox.nb -side top]
    set c_frame [$notebook insert end $Sepct_Test::MakeOutputTabName -text "Make output"]
    set fc_frame [$notebook insert end $Sepct_Test::PolicyConfTabName -text "policy.conf file"]
    
    # TE file contents tab widgets.
    set sw_c [ScrolledWindow $c_frame.sw_c -auto none]
    set textbox_makeOutput [text [$sw_c getframe].text -bg white -wrap none -font $Sepct::text_font]
    $sw_c setwidget $textbox_makeOutput
    
    # FC file contents tab widgets.
    set sw_fc [ScrolledWindow $fc_frame.sw_fc -auto none]
    set textbox_policyConf [text [$sw_fc getframe].text -bg white -wrap none -font $Sepct::text_font]
    # setup wrap proc
    $sw_fc setwidget $textbox_policyConf
    rename $textbox_policyConf "::${textbox_policyConf}_"
    rename $Sepct_Test::policy_conf_wrap_proc "::$textbox_policyConf"
    
    
    # Placing display widgets
    pack $sw_c -side left -expand yes -fill both  
    pack $sw_fc -side left -expand yes -fill both
    
    $notebook compute_size
    pack $notebook -fill both -expand yes -padx 4 -pady 4
    $notebook raise [$notebook page 0]
    $notebook bindtabs <Button-1> { Sepct_Test::switch_internal_tab }
    
    Sepct_Test::disableMods
     
    return 0
}

###################################################################
# ::create
#  	- Creates all major widgets and frames.
#	- Calls ::createNoteBook method
# 
proc Sepct_Test::create { nb } {
	variable b_test
	variable b_clean
	variable b_install
	variable b_reload
	variable b_view_pc
	variable b_relabel
	
	# Layout frames
	set frame 	[$nb insert end $Sepct::test_tab -text "Test Policy"]
	set rightf  [frame $frame.rightf -width 100 -height 200]
	set leftf   [frame $frame.leftf -width 100 -height 200]
	
	pack $leftf -padx 2 -fill both -expand yes -anchor nw -side left
	pack $rightf -padx 2 -pady 2 -fill y -anchor ne -side left -after $leftf
	
	set b_test    [Button $rightf.test  -text "Test Policy" -width 8 \
		-helptype balloon \
		-helptext "Test build policy.conf to check \nfor policy compile errors"]
	$b_test configure -command "Sepct_Test::test_Policy test $b_test"
	set b_clean   [Button $rightf.clean  -text "Clean Policy" -width 8  \
		-helptype balloon \
		-helptext "Clean policy make directory\n(\"make clean\")"]
	$b_clean configure -command "Sepct_Test::test_Policy clean $b_clean"
	set b_install [Button $rightf.install -text "Install Policy" -width 8   \
		-helptype balloon \
		-helptext "Build binary policy and install\nit, but don't load into running system"]
	$b_install configure -command "Sepct_Test::test_Policy install $b_install"
	set b_reload  [Button $rightf.reload  -text "Load Policy" -width 8  \
		-helptype balloon \
		-helptext "Build binary policy and install\nand load it into running system"]
	$b_reload configure -command "Sepct_Test::test_Policy load $b_reload"
	#set b_relabel [Button $rightf.relabel -text "Relabel Files" -width 8 \
	#	-helptype balloon \
	#	-helptext "Relabel all files according to \ncurrently loaded policy"]
	#$b_test configure -command "Sepct_Test::test_Policy relabel $b_relabel"
	set b_view_pc [Button $rightf.view_pc -text "Open\npolicy.conf"  -width 8 -command \
		{Sepct_Test::display_test_policy_conf; $Sepct_Test::notebook raise $Sepct_Test::PolicyConfTabName }  \
		-helptype balloon -helptext "Load (reload) policy.conf file"]
	set b_clear   [Button $rightf.clear -text "Clear\nOutput" -width 8 -command {Sepct_Test::clear_Output}  \
		-helptype balloon -helptext "Clear all displays on this tab"]
	
	# NoteBook creation
	Sepct_Test::createNoteBook $leftf
	
	pack $b_test $b_clean $b_install $b_reload $b_view_pc $b_clear -side top -anchor center -pady 5
	
	return $frame
}     
