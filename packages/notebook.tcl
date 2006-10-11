# this fragment taken from BWidget 1.8 release
proc NoteBook::bindtabs { path event script } {
    if { $script != "" } {
        append script " [NoteBook::_get_page_name [list $path] current 1]"
        $path.c bind "page" $event $script
    } else {
        $path.c bind "page" $event {}
    }
}
