//! TUI themes and icon sets.
//!
//! Color is a usability feature, not decoration: allow/deny/ask must be
//! distinguishable at a glance in every theme, including the grayscale
//! `mono` fallback for weak terminals. All palettes use explicit RGB so
//! they render identically on any truecolor terminal; no theme relies on
//! the terminal's own 16-color scheme, which varies wildly. Warm retro
//! (`phosphor`, amber on near-black) is the default for low eye strain;
//! the programmer themes (`gruvbox`, `dracula`, `nord`, `tokyo`,
//! `catppuccin`) reproduce their upstream hex values faithfully.
//!
//! Icon sets come in two flavors because Nerd Font glyphs render as
//! tofu on machines without the font: `plain` is safe everywhere,
//! `nerd` is prettier. Toggle with `i`, cycle themes with `t`.

use ratatui::style::Color;

/// One full TUI palette. All colors are explicit RGB so themes look
/// identical on every terminal with truecolor support.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Unique lowercase id, also the `CRABWALL_THEME` / `--theme` value.
    pub id: &'static str,
    /// Human label for the footer.
    pub label: &'static str,
    pub bg: Color,
    pub fg: Color,
    pub border: Color,
    pub accent: Color,
    pub muted: Color,
    pub allow: Color,
    pub deny: Color,
    pub ask: Color,
}

/// Warm amber CRT. The default: cozy, readable, zero eye-strain.
pub const PHOSPHOR: Theme = Theme {
    id: "phosphor",
    label: "Phosphor",
    bg: Color::Rgb(13, 11, 8),
    fg: Color::Rgb(255, 176, 0),
    border: Color::Rgb(107, 74, 0),
    accent: Color::Rgb(255, 94, 19),
    muted: Color::Rgb(138, 109, 47),
    allow: Color::Rgb(125, 255, 106),
    deny: Color::Rgb(255, 49, 49),
    ask: Color::Rgb(255, 210, 63),
};

/// Retro Gruvbox.
pub const GRUVBOX: Theme = Theme {
    id: "gruvbox",
    label: "Gruvbox",
    bg: Color::Rgb(40, 40, 40),
    fg: Color::Rgb(235, 219, 178),
    border: Color::Rgb(102, 92, 84),
    accent: Color::Rgb(254, 128, 25),
    muted: Color::Rgb(146, 131, 116),
    allow: Color::Rgb(184, 187, 38),
    deny: Color::Rgb(251, 73, 52),
    ask: Color::Rgb(250, 189, 47),
};

/// Dracula for the night owls.
pub const DRACULA: Theme = Theme {
    id: "dracula",
    label: "Dracula",
    bg: Color::Rgb(40, 42, 54),
    fg: Color::Rgb(248, 248, 242),
    border: Color::Rgb(98, 114, 164),
    accent: Color::Rgb(189, 147, 249),
    muted: Color::Rgb(98, 114, 164),
    allow: Color::Rgb(80, 250, 123),
    deny: Color::Rgb(255, 85, 85),
    ask: Color::Rgb(241, 250, 140),
};

/// Nord, calm and cold.
pub const NORD: Theme = Theme {
    id: "nord",
    label: "Nord",
    bg: Color::Rgb(46, 52, 64),
    fg: Color::Rgb(236, 239, 244),
    border: Color::Rgb(76, 86, 106),
    accent: Color::Rgb(136, 192, 208),
    muted: Color::Rgb(76, 86, 106),
    allow: Color::Rgb(163, 190, 140),
    deny: Color::Rgb(191, 97, 106),
    ask: Color::Rgb(235, 203, 139),
};

/// Tokyo Night.
pub const TOKYO: Theme = Theme {
    id: "tokyo",
    label: "Tokyo Night",
    bg: Color::Rgb(26, 27, 38),
    fg: Color::Rgb(192, 202, 245),
    border: Color::Rgb(65, 72, 104),
    accent: Color::Rgb(122, 162, 247),
    muted: Color::Rgb(86, 95, 137),
    allow: Color::Rgb(158, 206, 106),
    deny: Color::Rgb(247, 118, 142),
    ask: Color::Rgb(224, 175, 104),
};

/// Catppuccin Mocha, pastel edition.
pub const CATPPUCCIN: Theme = Theme {
    id: "catppuccin",
    label: "Catppuccin",
    bg: Color::Rgb(30, 30, 46),
    fg: Color::Rgb(205, 214, 244),
    border: Color::Rgb(88, 91, 112),
    accent: Color::Rgb(203, 166, 247),
    muted: Color::Rgb(108, 112, 134),
    allow: Color::Rgb(166, 227, 161),
    deny: Color::Rgb(243, 139, 168),
    ask: Color::Rgb(249, 226, 175),
};

/// Pure grayscale for weak terminals / ssh from a toaster.
pub const MONO: Theme = Theme {
    id: "mono",
    label: "Mono",
    bg: Color::Black,
    fg: Color::Gray,
    border: Color::DarkGray,
    accent: Color::White,
    muted: Color::DarkGray,
    allow: Color::White,
    deny: Color::Gray,
    ask: Color::White,
};

/// All themes in cycle order (`t` in the TUI).
pub const THEMES: &[Theme] = &[PHOSPHOR, GRUVBOX, DRACULA, NORD, TOKYO, CATPPUCCIN, MONO];

/// Look a theme up by id (case-insensitive); falls back to phosphor.
pub fn theme_by_id(id: &str) -> (usize, Theme) {
    let lower = id.to_ascii_lowercase();
    THEMES
        .iter()
        .position(|t| t.id == lower)
        .map(|i| (i, THEMES[i]))
        .unwrap_or((0, PHOSPHOR))
}

/// Small icon vocabulary with two renderings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconSet {
    /// Nerd Font glyphs. Pretty, needs the font.
    Nerd,
    /// Plain ASCII/Unicode. Renders everywhere.
    Plain,
}

impl IconSet {
    /// Parse `CRABWALL_ICONS` / `--icons`; unknown values mean plain.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "nerd" | "nf" => IconSet::Nerd,
            _ => IconSet::Plain,
        }
    }

    /// Short label for the footer.
    pub fn label(self) -> &'static str {
        match self {
            IconSet::Nerd => "nerd",
            IconSet::Plain => "plain",
        }
    }

    /// Toggle between the two sets (`i` in the TUI).
    pub fn toggle(self) -> Self {
        match self {
            IconSet::Nerd => IconSet::Plain,
            IconSet::Plain => IconSet::Nerd,
        }
    }

    /// Status glyphs for answered feed rows: (allow, deny, pending).
    /// Nerd variants are classic Font Awesome codepoints ( -check,
    ///  -times,  -question-circle), present in every Nerd Font.
    pub fn verdict(self) -> (&'static str, &'static str, &'static str) {
        match self {
            IconSet::Nerd => ("\u{f00c} ", "\u{f00d} ", "\u{f059} "),
            IconSet::Plain => ("[+]", "[x]", "[?]"),
        }
    }

    /// App / network / activity prefixes.
    pub fn app(self) -> &'static str {
        match self {
            IconSet::Nerd => "\u{f120} ",
            IconSet::Plain => "> ",
        }
    }

    /// Globe prefix for domains.
    pub fn net(self) -> &'static str {
        match self {
            IconSet::Nerd => "\u{f0ac} ",
            IconSet::Plain => "@ ",
        }
    }

    /// Prompt card bullet (angle-right, universal in Nerd Fonts).
    pub fn bullet(self) -> &'static str {
        match self {
            IconSet::Nerd => "\u{f105} ",
            IconSet::Plain => "* ",
        }
    }
}
