##############################################################
#  db.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2001-2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <mayerf@treys.com>
# -----------------------------------------------------------
#

##############################################################
# ::Sepct_db namespace
#
# This file defines the internal database used to manage 
# policy directory and files.  The database is maintained in 
# a BWidgets "Tree" widget.  
##############################################################
namespace eval Sepct_db {
	# number of data items lfiles
	variable lfiles_num_data 3	
	# main tree; sync'd with browser tab
	variable tree			
	# Array indexed by full file pathnames, which holds modified file contents.
	variable mod_FileArray
	# Public list variable used to access all current modified files in the mod_FileArray. 
	variable mod_FileNames   ""
}


##############################################################
##############################################################
#
# misc utility procs

##############################################################
# ::read_fileContents_fromDisk
#  	-
# 
proc Sepct_db::read_fileContents_fromDisk { path data_var } {
	# Simply read the file off disk.			
	upvar $data_var data
	if { [file exists $path] } {
		if { [file readable $path] } {
			set file_channel [open $path RDONLY]
			set data [read $file_channel]
			::close $file_channel
			return 0
		} else {
			tk_messageBox -icon error \
			-type ok \
			-title "Permission Problem" \
			-message \
			"You do not have permission to read $path."
			return -1
		}
	} else {
		tk_messageBox -icon error \
		-type ok \
		-title "File Does Not Exist" \
		-message "File ($path) does not exist."
		return -1
	}
	
	return 0
}

##############################################################
# ::file_write, the primitative function
#  	- Save data to disk
# 
proc Sepct_db::file_write { data path } {
	set parent [file dirname $path]
	set parent_exists [file isdirectory $parent] 
	set parent_writeable [file writable $parent]
	set file_exists [file exists $path] 
	set file_writeable [file writable $path]
	
	if { $file_exists } {
		if { ! $file_writeable } {
			tk_messageBox -icon error  \
				-type ok \
				-parent $Sepct::mainWindow \
				-title "Save Error (existing file)" \
				-message \
				"You do not have permission to write to $path."
			return -1
		}
	} elseif { $parent_exists } {
		if { ! $parent_writeable } {
			tk_messageBox -icon error  \
				-type ok \
				-parent $Sepct::mainWindow \
				-title "Save Error (new file)" \
				-message \
				"You do not have permission to write the directory $parent."
			return -1	
		}		
	}
			
	set rt [catch { 
		set fileid [open $path "w"]
		puts -nonewline $fileid $data
		::close $fileid} err]
	if { $rt != 0 } {
		tk_messageBox -icon error  \
			-type ok \
			-parent $Sepct::mainWindow \
			-title "Save Error" \
			-message \
			"$err"
		return -1
	} 
	return 0
}


##############################################################
##############################################################
#
# lfiles functions
#
#	lfiles are a list of files and assoicated data stored
#	in a tree node to indicate the files in a dir.  lfiles
#	list contains sets of 4 elements:
#		fn		filename, tail only (string)
#		mod_ctr		modified counter (int)
#		line_pos	line position for cursor
#		col_pos		column position for cursor
#
# The mod_ctr is used track modification for redisplay.  Every
# time mods are recorded to (or saved from) the internal mod
# list, this counter in incremented.  On rediplay of the file,
# the GUI should compare the mod_ctr it had last time it displayed
# if it has increased reload the file 
#
# The 0th element of all lists is a mod counter for the tree node
# itself.
#################################################################

###################################################################
# ::incr_lfiles_mod_cntr
# 	- given a flist from a tree node (which must contain
#	at least one entry, the mod cntr), this proc will
# 	extract the mod cntr, update it, and return the list
#	with the new mod contr.  Return -1 for error
#
proc Sepct_db:incr_lfiles_mod_cntr { lfiles } {
	
	if { [llength $lfiles] < 1 } {
		puts stderr "provided lfiles list had no elements!"
		return -1
	}
	set cntr [lindex $lfiles 0]
	if {![string is integer $cntr] } {
		puts stderr "Tree node mod cntr ($cntr) is not a valid integer!"
		return -1
	}
	incr cntr
	
	set lfiles [lreplace $lfiles 0 0 $cntr]
	return $lfiles	
}


###################################################################
# ::get_file_list
#  	- get file list from a lfiles (by removing mod cntr)
#	 return list
#
proc Sepct_db::get_file_list { lfiles } {
	if { [llength $lfiles] < 1 } {
		# only mod contr; empty list
		return ""
	}
	set files [lreplace $lfiles 0 0 ]
	return $files
}	

###################################################################
# ::search_file_list_for_names
#  	- 
#
proc Sepct_db::search_file_list_for_names { lfiles file_name } {
	set idx 0
	set length [llength $lfiles]
	while {$idx <= $length} {
		if {[string equal [lindex $lfiles $idx] $file_name]} {
			return $idx
		}
		set idx [expr $idx + 4]
	}
	return -1
}

###################################################################
# ::add_file
#  	- adds a file to a Tree node
#	- fn must be full pathname (used to find parent
#
proc Sepct_db::add_file { fn cntr { pos "1.0"} } {
	variable tree
	if { [catch {scan $pos "%d.%d" line col} err ] } {
		puts stderr "update_pos: Problem scanning position ($pos): $err"
		return -1
	}	
	set parent [file dirname $fn]
	set tail [file tail $fn]
	if { ![$tree exists $parent] } {
		return -1
	}
	# get the mod counter and current file list
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]

	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}

	if { $idx != -1 } {
		#if already exists, ignore cntr, and increment file cntr instead
		set cidx [expr $idx + 1]
		set new_cntr [expr [ lindex $files $cidx ] + 1]	
		lreplace $files $cidx [expr $cidx + 2] $new_cntr $line $col	
	} else {
		# append new file, and its data
		lappend files $tail
		set new_cntr   $cntr
		lappend files $cntr	
		lappend files $line	
		lappend files $col
		# reattach list
	}
	# rebuild list by extracting node mod cntr and reattach to new file list
	set node_cntr [lindex $lfiles 0]
	set new_lfiles [linsert $files 0 $node_cntr]
	
	# update tree node mod counter
	set new_lfiles [Sepct_db:incr_lfiles_mod_cntr $new_lfiles]
	if {$lfiles == -1} {
		puts stderr "Add: error incrementing node ($fn) mod counter"
		return -1
	}
	
	# reattach new lfiles list
	$tree itemconfigure $parent -data $new_lfiles
		
	return $new_cntr
}

########################################################################
# ::remove_file
#  	- remove a file from a Tree node
#
proc Sepct_db::remove_file { fn } {
	variable tree
	set parent [file dirname $fn]
	set tail [file tail $fn]
	if { ![$tree exists $parent] } {
		return -1
	}
	
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if { $idx == -1 } {
		#no error, already doesn't exist
		return 0	
	}
	# remove name and its 3 data elements
	set files [lreplace $files $idx [expr $idx + 3 ]]
	
	# rebuild list by extracting node mod cntr and reattach to new file list
	set node_cntr [lindex $lfiles 0]
	set new_lfiles [linsert $files 0 $node_cntr]
	
	# update node mod counter 
	set new_lfiles [Sepct_db:incr_lfiles_mod_cntr $new_lfiles]
	if {$new_lfiles == -1} {
		puts stderr "Remove: error incrementing node ($fn) mod counter"
		return -1
	}
	
	# reattach list
	$tree itemconfigure $parent -data $new_lfiles
	return 0
}

########################################################################
# ::move_file
#  	- moves a file to a Tree node; doesnt move the actual file on disk
#		but does ensure mod list is kept consistent
#
proc Sepct_db::move_file { oldfn newfn } {
	variable tree
	variable lfiles_num_data
	set oldparn [file dirname $oldfn]
	set newparn [file dirname $newfn]
	if { ![$tree exists $oldparn] || ![$tree exists $newparn] } {
		return -1
	}
	# get the oldfn data from current node before deleting
	set fdata [Sepct_db::getFileData $oldfn]
	if { [llength $fdata] < $lfiles_num_data } {
		puts stderr "Problem getting file info data for $oldfn"
		return -1
	}
	# First, check if oldfn is in modlist 
	set rt [Sepct_db::getModFile_Data $oldfn old_data]
	
	if {$rt != -1} {
		# oldfn IS in mod list
		Sepct_db::remove_from_mod_List $oldfn
	}
	
	# Remove the file from its' parent node in the tree 
	if { [Sepct_db::remove_file $oldfn] == -1 } {
		puts stderr "Problem removing $oldfn"
		return -1
	}
	
	# Add the new file to parent node in the tree 
	if {[Sepct_db::add_file $newfn 0] == -1 }  {
		puts stderr "Problem adding $newfn"
		return -1
	}
	
	# Add newfn to the modlist.
	if {$rt != -1} {
		set cnt [Sepct_db::add_to_mod_List $newfn $old_data]
	} else {
		set cnt 0
	}
		
	return $cnt
}

########################################################################
# ::getFileData
#  	- returns the list containing data fields 
#	- return less than lfiles_num_data elements in list for error
#
proc Sepct_db::getFileData { fn } {
	variable tree
	
	set parent [file dirname $fn]
	set tail [file tail $fn]	
	if { ![$tree exists $parent] } {
		return ""
	}
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if {  $idx == -1 } {
		return ""
	}
	set fdata [lrange $files [expr $idx + 1] [expr $idx + 3]]
	return $fdata
}
########################################################################
# ::getFileNames
#  	- returns the list containing only file names
#	- list of one element "-1" is an error
#
proc Sepct_db::getFileNames {node } {
	variable lfiles_num_data
	variable tree
	
	if { ![$tree exists $node] } {
		return "-1"
	}
	set lfiles [$tree itemcget $node -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	set len [llength $files]
	if { $len < 1 } {
		return ""
	}
	for {set x 0} {$x < $len} {incr x} {
		lappend filenames [lindex $files $x]
		# skip over the file file's data
		set x [expr $x + $lfiles_num_data]
	}
	return $filenames
}

########################################################################
# ::update_mod_cntr
#  	- increments the mod counter for given file
#	- returns mod cntr, or -1 for error
#
proc Sepct_db::update_mod_cntr { fn } {
	variable tree
	set parent [file dirname $fn]
	set tail [file tail $fn]	
	if { ![$tree exists $parent] } {
		return  -1
	}
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if {  $idx == -1 } {
		return -1
	}
	set cidx [expr $idx + 1]
	set new_cntr [expr [ lindex $files $cidx ] + 1]
	set files [lreplace $files $cidx $cidx $new_cntr]

	# rebuild list by extracting node mod cntr and reattach to new file list
	set node_cntr [lindex $lfiles 0]
	set new_lfiles [linsert $files 0 $node_cntr]
	
	# reattach list
	$tree itemconfigure $parent -data $new_lfiles
	
	return $new_cntr
}



########################################################################
# ::update_pos
#	- update the position (line, col) indicators for file in tree
#	- returns mod cntr, or -1 for error
#
proc Sepct_db::update_pos { fn { pos "1.0"} } {
	variable tree
	if { [catch {scan $pos "%d.%d" line col} err ] } {
		puts stderr "update_pos: Problem scanning position ($pos): $err"
		return -1
	}
	set parent [file dirname $fn]
	set tail [file tail $fn]	
	if { ![$tree exists $parent] } {
		return  -1
	}
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if {  $idx == -1 } {
		return -1
	}
	set files [lreplace $files [ expr $idx + 2] [ expr $idx + 3] $line $col]
	
	# rebuild list by extracting node mod cntr and reattach to new file list
	set node_cntr [lindex $lfiles 0]
	set new_lfiles [linsert $files 0 $node_cntr]
		
	# reattach list
	$tree itemconfigure $parent -data $new_lfiles
	
	
	return 0
}

########################################################################
# ::get_cntr
#	- returns pos (line.col) of provided file name
#	- returns -1 for error, -2 if file isn;t in db
#
proc Sepct_db::get_cntr { fn  } {
	variable tree
	set parent [file dirname $fn]
	set tail [file tail $fn]	
	if { ![$tree exists $parent] } {
		return  -2
	}
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if {  $idx == -1 } {
		return -1
	}
	set cntr [lindex $files [expr $idx + 1]]
	
	return $cntr
}

########################################################################
# ::get_pos
#	- returns pos (line.col) of provided file name
#	- returns "" for error
#
proc Sepct_db::get_pos { fn  } {
	variable tree
	set parent [file dirname $fn]
	set tail [file tail $fn]	
	if { ![$tree exists $parent] } {
		return  ""
	}
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if {  $idx == -1 } {
		return ""
	}
	set line [lindex $files [expr $idx + 2]]
	set col [lindex $files [expr $idx + 3]]
	
	return "$line.$col"
}

########################################################################
# ::does_fileExists 
# 
proc Sepct_db::does_fileExists  { fn } {
	variable tree
	
	set parent [file dirname $fn]
	set tail [file tail $fn]	
	if { ![$tree exists $parent] } {
		return 0
	}
	set lfiles [$tree itemcget $parent -data]
	# get files from the lfile list
	set files [Sepct_db::get_file_list $lfiles]
	
	if {[string is integer $tail]} {
		set idx [Sepct_db::search_file_list_for_names $files $tail]
	} else {
		set idx [lsearch -exact $files $tail]
	}
	if {  $idx == -1 } {
		return 0
	}
	return 1
}


########################################################################
########################################################################
#
# tree functions
#
#	we use a BWidgets Tree widget as our db
#
#	Note that the db tree is linked to the Broaser tab's tree 
#	(it is in fact the same BWidget object).  Therefore, while
#	we attempt to logically isolate functions, both this
#	and the browser namespace may manipulate this widget.
#	We try to keep the browser focused on display actions
# 	and db focused on data actions.
#
#	The data field for a node contains a list, the first
#	element of which is a mod counter for the node that changes
# 	every time a file is added or removed from node.  The rest
# 	of the list are the names of the files in the node.
########################################################################

########################################################################
# ::close
#  	- functions to perform on policy close
#	- note this does not ensure that any changed files are saved!
# 
proc Sepct_db::close {} {
	variable mod_FileArray
	variable mod_FileNames
	
	array unset mod_FileArray
	set mod_FileNames ""
	$Sepct_db::tree delete [$Sepct_Browse::tree nodes root]  
	return 0
}

###################################################################
# ::get_node_mod_cntr
#	- return -1 for error
#
proc Sepct_db::get_node_mod_cntr { node } {
	variable tree 
	if {![$tree exists $node]} {
		return -1
	}
	set lfiles [$tree itemcget $node -data] 
	if { [llength $lfiles] < 1 } {
		puts stderr "$node lfiles list had no elements!"
		return -1
	}
	set cntr [lindex $lfiles 0]
	return $cntr	
}

########################################################################
# ::mkdir_addTree_node
#  	- adds a node (tail name only) to the tree and creates directory
#	- node must be only the last component of the new dir name
#	- parent must be the full pathname (as stored in the tree)
proc Sepct_db::mkdir_addTree_node { node parent isopen } {
	if { ![file isdirectory $parent] } {
		return 11
	}
	set full_node_name [file join $parent $node]
	if { [file exists $full_node_name] } {
		return 0	# no error if already exists
	}
	set rt [catch {file mkdir $full_node_name} err] 
	if {$rt != 0 }  {
		 tk_messageBox -icon error \
			-type ok  \
			-title "Directory Creation Error" \
			-message \
			"The directory $full_node_name could not be created:\n\n\
			 $err"
		 return -1	
	}
	Sepct_db::addTree_node $full_node_name $isopen 0
        return 0
}

########################################################################
# ::existsTree_node
proc Sepct_db::existsTree_node { node } {
	variable tree
	set rt [$tree exists $node]
	return $rt
}

########################################################################
# ::addTree_node simply adds anode to tree (nothing with assoicated dir)
#	- node must the FULL path name
proc Sepct_db::addTree_node { node isopen isroot} {
	variable tree
	set parent [file dirname $node]
	if { !($isroot) && ![$tree exists $parent] } {
		return -1
	}
	if {$isopen} {
		set img [Bitmap::get openfold]
	} else {
		set img [Bitmap::get folder]
	}
	if {$isroot} {
		#TODO: return error if already a root dir
		set pname "root"
		set nname $node
	} else {
		set pname $parent
		set nname [file tail $node] 
	}
	# the data item is initalized to 0, setting the mod counter
	$tree insert end $pname $node -text $nname \
		-image     $img \
		-open $isopen	\
        	-drawcross auto \
        	-data "0"
        return 0
}

########################################################################
# ::Sepct_db
#  	- removes a node (directory) from the tree
#
proc Sepct_db::removeTree_node { node parent } {
	#TODO: to be done
	return 0
}

########################################################################
# ::moveTree_node
#  	- ,ove a node (directory) to the tree
#
proc Sepct_db::moveTree_node { node new_parent } {
	#TODO: to be done
	return 0
}



########################################################################
########################################################################
#
# mod list functions
#
#	This is an array used to track files that have been changed,
#	but not yet saved/reverted.  
#
#	NOTE: mod list is not same as dirty bits associated with
# 	various text boxes.  The dirty bits indicated whether
#	changes have been recorded in the mod list or not. See tabs
#	for dirty bit implementations.
#
#	Each time a change to the mod list (add, remove) occurs
#	for a given file, we up its mod counter.
########################################################################


##################################################################
# ::remove_from_mod_List
#  	- return cntr or -1 for error, -2 if not in list already
# 
proc Sepct_db::remove_from_mod_List { path } {
	variable mod_FileArray
	variable mod_FileNames
	
	if { [array exists mod_FileArray] && [array names mod_FileArray $path] != ""} {
		array unset mod_FileArray $path
		set mod_FileNames [Sepct_db::getModFileNames]
		set cntr [Sepct_db::update_mod_cntr $path]
		if { $cntr  == -1 } {
			puts stderr "problem updating mod cntr for $path in remove_from_mod_List."
		}
		return $cntr
	}		
    	return  -2
}

##################################################################
# ::add_to_mod_List (update/replace too!)
#  	- will also replace if it already exists in list
# 
proc Sepct_db::add_to_mod_List { path data } {
	variable mod_FileArray
	variable mod_FileNames
	
	set mod_FileArray($path) $data
	set mod_FileNames [Sepct_db::getModFileNames]
	set cntr [Sepct_db::update_mod_cntr $path]
	if { $cntr == -1 } {
		puts stderr "problem updating mod cntr for $path in add_to_mod_List."
	}
    	return $cntr
}



##############################################################
# ::are_there_mod_files
#  	-  return 1 if there are files in mod list, 0 otherwise
# 
proc Sepct_db::are_there_mod_files { } {
	variable mod_FileArray
	if { [array size mod_FileArray] > 0 } {
		return 1
	} else {
		return 0
	}
}


##############################################################
# ::is_in_mod_FileArray
#  	-  
# 
proc Sepct_db::is_in_mod_FileArray { path } {
	variable mod_FileArray
	if { [array exists mod_FileArray] } {
		set mod_File_Path [array names mod_FileArray $path]
		if {  $mod_File_Path != "" } {
		    	return 1
	   	} 
	}
	
	return 0
}

##################################################################
# ::discard_All_File_Changes
#  	- 
# 
proc Sepct_db::discard_All_File_Changes { } {
	set mod_File_Paths [Sepct_db::getModFileNames]
	foreach path $mod_File_Paths {
		Sepct_db::discard_Single_File_Changes $path
	}
	return 0
}


##################################################################
# ::discard_Single_File_Changes
#  	- 
# 
proc Sepct_db::discard_Single_File_Changes { path } {
	if { [Sepct_db::is_in_mod_FileArray $path] } {
		# Unset the file from the mod list array.
		set rt [Sepct_db::remove_from_mod_List $path]
		return $rt
	}
	# not in mod list
    	return -2
}

##################################################################
# ::getModFile_Data - reads contents of file from mod list
# 	- data_var is name of data var uplevel
proc Sepct_db::getModFile_Data {fn data_var} {
	variable mod_FileArray
	upvar $data_var data
	if { [Sepct_db::is_in_mod_FileArray $fn ] } {
		set data $mod_FileArray($fn)
		return 0
	} else {
		return -1		
	}
}



##################################################################
# ::saveFile-- saves from mod list of given file name
#  	- Saves the provided file if mod list
#		return mod cntr, -1 fail, -2 not modified (not in mod list)
proc Sepct_db::saveFile { path {pos "none"} } {
	variable mod_FileArray
	# Now check to see if the file is in the modlist array and if it is, 
	# then we need to unset it.
	if { [Sepct_db::is_in_mod_FileArray $path] } {
		# save to disk
		set rt [Sepct_db::file_write $mod_FileArray($path) $path]
		if {$rt != 0 } {
			return -1
		}
		set cntr [Sepct_db::remove_from_mod_List $path]
		if {$cntr == -1 } {
			puts stderr "Problem removing $path from mod list in saveFile."
			return -1
		}
		if { $pos != "none"} {
			Sepct_db::update_pos $path $pos
		}
		return $cntr
	}
		
	return -2
}
##################################################################
# ::getModFileNames-- get lst of all files in mod list
proc Sepct_db::getModFileNames { } {
	variable mod_FileArray
	
	if { [array exists mod_FileArray] } {
		set list [array names mod_FileArray]
		return $list
	} else {
		return ""
	}
}
