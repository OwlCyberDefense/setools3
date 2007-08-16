# Copyright (C) 2007 Tresys Technology, LLC
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

namespace eval Apol_Prefs {
    variable dialog .apol_prefs
    variable pref_file_name [file join $::env(HOME) .apol]
    variable prefs  ;# array of preferences name/value mappings
}

# initialize all preferences to something sane
proc Apol_Prefs::create {} {
    variable prefs
    array set prefs {
        max_recent_files 5
        recent_files {}
        show_attrib_warning 1
        dialog_font "Helvetica 10"
        general_font "Helvetica 10"
        text_font fixed
        title_font "Helvetica 10 bold italic"
        active_bg white
        active_fg black
        highlight_fg red
        top_width 1000
        top_height 700
    }
    set prefs(disable_bg) [. cget -background]
}

# Return the preference value for the given preference.  Valid names
# are:
#
# Loading policies:
#   "max_recent_files"
#   "recent_files"
#   "show_attrib_warning"
# Tk colors and fonts:
#   "dialog_font"
#   "general_font"
#   "text_font"
#   "title_font"
#   "active_bg"
#   "disable_bg"
#   "active_fg"
#   "highlight_fg"
# Initial window size:
#   "top_width"
#   "top_height"
proc Apol_Prefs::getPref {pref_name} {
    variable prefs
    set prefs($pref_name)
}

# Add a policy path to the recently opened list, trim the menu to
# max_recent_files.
proc Apol_Prefs::addRecent {ppath} {
    variable prefs

    # if ppath is already in recent files list, remove it from there
    set new_recent $ppath
    foreach r $prefs(recent_files) {
        if {[apol_policy_path_compare $r $ppath] != 0} {
            lappend new_recent $r
        }
    }
    set prefs(recent_files) [lrange $new_recent 0 [expr {$prefs(max_recent_files) - 1}]]
}

proc Apol_Prefs::openPrefs {} {
    variable prefs
    variable pref_file_name

    # if it doesn't exist, it will be created later
    if {![file exists $pref_file_name]} {
        return
    }

    if {[catch {::open $pref_file_name r} f]} {
        tk_messageBox -icon error -type ok -title "apol" \
            -message "Could not open $pref_file_name: $f"
        return
    }

    while {![eof $f]} {
        set option [string trim [gets $f]]
        if {$option == {} || [string compare -length 1 $option "\#"] == 0} {
            continue
        }
        set value [string trim [gets $f]]
        if {[eof $f]} {
            puts stderr "EOF reached while reading $option"
            break
        }
        if {$value == {}} {
            puts stderr "Empty value for option $option"
            continue
        }
        switch -- $option {
            "\[window_height\]" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "window_height was not given as an integer and is ignored"
                    break
                }
                set prefs(top_height) $value
            }
            "\[window_width\]" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "window_width was not given as an integer and is ignored"
                    break
                }
                set prefs(top_width) $value
            }
            "\[title_font\]" {
                set prefs(title_font) $value
            }
            "\[dialog_font\]" {
                set prefs(dialog_font) $value
            }
            "\[text_font\]" {
                set prefs(text_font) $value
            }
            "\[general_font\]" {
                set prefs(general_font) $value
            }
            "\[show_fake_attrib_warning\]" {
                set prefs(show_attrib_warning) $value
            }

            # The form of [max_recent_file] is a single line that
            # follows containing an integer with the max number of
            # recent files to keep.  The default is 5 if this is not
            # specified.  The minimum is 2.
            "\[max_recent_files\]" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "max_recent_files was not given as an integer and is ignored"
                } else {
                    if {$value < 2} {
                        set prefs(max_recent_files) 2
                    } else {
                        set prefs(max_recent_files) $value
                    }
                }
            }
            # The form of this key in the .apol file is as such
            #
            # recent_files
            # 5			(# indicating how many file names follow)
            # policy_path_0
            # policy_path_1
            # ...
            "recent_files" {
                if {[string is integer -strict $value] != 1} {
                    puts stderr "Number of recent files was not given as an integer and was ignored."
                    continue
                } elseif {$value < 0} {
                    puts stderr "Number of recent was less than 0 and was ignored."
                    continue
                }
                while {$value > 0} {
                    incr value -1
                    set line [gets $f]
                    if {[eof $f]} {
                        puts stderr "EOF reached trying to read recent files."
                        break
                    }
                    if {[llength $line] == 1} {
                        # reading older recent files, before advent of
                        # policy_path
                        set ppath [new_apol_policy_path_t $::APOL_POLICY_PATH_TYPE_MONOLITHIC $line NULL]
                        $ppath -acquire
                    } else {
                        foreach {path_type primary modules} $line {break}
                        if {[catch {list_to_policy_path $path_type $primary $modules} ppath]} {
                            puts stderr "Invalid policy path line: $line"
                            continue
                        }
                    }
                    lappend prefs(recent_files) $ppath
                }
            }
        }
    }
    close $f
    _apply_prefs
}

proc Apol_Prefs::savePrefs {} {
    variable pref_file_name
    variable prefs

    if {[catch {::open $pref_file_name w} f]} {
        tk_messageBox -icon error -type ok -title "apol" \
            -message "Could not open $pref_file_name for writing: $f"
        return
    }
    puts $f "recent_files"
    puts $f [llength $prefs(recent_files)]
    foreach r $prefs(recent_files) {
        puts $f [policy_path_to_list $r]
    }

    puts $f "\n"
    puts $f "# Font format: family ?size? ?style? ?style ...?"
    puts $f "# Possible values for the style arguments are as follows:"
    puts $f "# normal bold roman italic underline overstrike"
    puts $f "\n"
    puts $f "\[general_font\]\n$prefs(general_font)"
    puts $f "\[title_font\]\n$prefs(title_font)"
    puts $f "\[dialog_font\]\n$prefs(dialog_font)"
    puts $f "\[text_font\]\n$prefs(text_font)"
    puts $f "\n"
    puts $f "\[window_height\]\n[winfo height .]"
    puts $f "\[window_width\]\n[winfo width .]"
    puts $f "\[show_fake_attrib_warning\]\n$prefs(show_attrib_warning)"
    puts $f "\[max_recent_files\]\n$prefs(max_recent_files)"
    close $f
}

proc Apol_Prefs::modifyPreferences {} {
    variable dialog
    variable prefs
    variable temp_prefs
    array set temp_prefs [array get prefs]

    Dialog $dialog -title "Preferences" -separator 1 -parent . \
        -default 0 -modal local
    set policy_frame [TitleFrame $dialog.file -text "Opening Policies"]
    pack $policy_frame -expand 1 -fill both -padx 4 -pady 4

    set max_f [frame [$policy_frame getframe].max]
    set l [label $max_f.l -text "Maximum recent policies: "]
    set e [entry $max_f.e -bg [getPref active_bg] -width 3 \
               -textvariable Apol_Prefs::temp_prefs(max_recent_files) \
               -justify right -validate focus \
               -validatecommand [list Apol_Prefs::_validate_max_recent %P]]
    pack $l -side left -fill none -padx 4
    pack $e -side left -padx 2
    set cb [checkbutton [$policy_frame getframe].attrib \
                -text "Warn when apol generates attribute names" \
                -variable Apol_Prefs::temp_prefs(show_attrib_warning)]
    pack $max_f $cb -anchor w -pady 2

    $dialog add -text "Close"
    $dialog draw
    destroy $dialog

    if {![_validate_max_recent $temp_prefs(max_recent_files)]} {
        set temp_prefs(max_recent_files) 2
    }
    array set prefs [array get temp_prefs]
}


########## private functions below ##########

proc Apol_Prefs::_apply_prefs {} {
    variable prefs

    option add *Font $prefs(general_font)
    option add *TitleFrame.l.font $prefs(title_font)
    option add *Dialog*font $prefs(dialog_font)
    option add *Dialog*TitleFrame.l.font $prefs(title_font)
    option add *text*font $prefs(text_font)
}

proc Apol_Prefs::_validate_max_recent {new_value} {
    if {![string is integer -strict $new_value] ||
        $new_value < 2} {
        return 0
    }
    return 1
}
