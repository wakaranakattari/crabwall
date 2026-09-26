# crabwall demo (VHS tape). Renders README's demo.gif without root:
# the TUI falls back to demo data when no daemon is reachable.
#
#   vhs packaging/demo/demo.tape   # needs charmbracelet/vhs
#
Output packaging/demo/demo.gif
Set Shell bash
Set FontSize 15
Set Width 1100
Set Height 700
Set Theme "Catppuccin Mocha"

Type "crabwall" Enter
Sleep 3s
# An ask-prompt is on screen (demo feed); answer it.
Type "y"
Sleep 2s
Type "N"
Sleep 2s
Screenshot packaging/demo/prompt.png
Type "q"
Sleep 1s
