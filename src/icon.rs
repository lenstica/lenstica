//! Menu bar icons, rendered from their SVG source at start-up. The tray glyph
//! is the logo's three lenses (`assets/lenses*.svg`); menu item icons are from
//! Lucide (https://lucide.dev, ISC licence, see `assets/lucide/LICENSE`).
//!
//! On macOS the normal icons are template images (black on alpha) that the
//! system recolours to match the menu bar. The problem icon is a fixed orange
//! that stays visible on any bar. Other platforms have no template images and
//! their trays may be light or dark, so normal icons are drawn in a blue that
//! reads on both.

use resvg::{tiny_skia, usvg};

/// Canvas size in pixels. Tauri's tray (tray-icon 0.25) always draws the image
/// 18 pt tall, so this is a ~2.4x (Retina) image.
pub const SIZE: u32 = 44;

/// Share of the canvas the 24-unit view box spans. The whole canvas is shown at
/// 18 pt and the glyph keeps a ~1.5-unit margin, like Lucide, so filling the
/// canvas gives a ~16 pt glyph, the size of the neighbouring status icons.
const ICON_SCALE: f32 = 1.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Glyph {
    /// Every lens is clear: the three lenses, solid.
    Protected,
    /// A lens found something that needs attention: the three lenses, solid, in orange.
    Problem,
    /// No result yet: the three lenses in outline.
    Checking,
}

impl Glyph {
    fn svg(self) -> &'static str {
        match self {
            Glyph::Protected | Glyph::Problem => include_str!("../assets/lenses.svg"),
            Glyph::Checking => include_str!("../assets/lenses-outline.svg"),
        }
    }

    /// Whether macOS should recolour it to match the menu bar.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn is_template(self) -> bool {
        self != Glyph::Problem
    }

    fn color(self) -> &'static str {
        match self {
            Glyph::Problem => "#ff9500",
            _ if cfg!(target_os = "macos") => "#000000",
            _ => "#4084f5",
        }
    }
}

/// Straight (not premultiplied) RGBA, `SIZE` x `SIZE`.
pub fn rgba(glyph: Glyph) -> Vec<u8> {
    render(
        &glyph.svg().replace("currentColor", glyph.color()),
        SIZE,
        ICON_SCALE,
    )
}

/// Menu item icons: macOS draws them 18 pt tall, so this is a 2x image.
pub const MENU_SIZE: u32 = 36;

/// A coloured icon for a menu item. Colours are mid-tones that read on light
/// and dark menus alike.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MenuIcon {
    Severity(lenstica_lens::Severity),
    /// A lens with nothing needing attention.
    Ok,
    /// A lens with problems, in the colour of the worst one.
    Problem(lenstica_lens::Severity),
    /// A lens that failed to run.
    Failed,
    Running,
    NotRun,
    Copy,
}

fn severity_color(s: lenstica_lens::Severity) -> &'static str {
    use lenstica_lens::Severity::*;
    match s {
        Critical => "#e5484d",
        High => "#f76808",
        Medium => "#f5a524",
        Low => "#3e8ef7",
        Info => "#8e8e93",
    }
}

/// The severity's Lucide icon: a filled octagon for critical, a triangle for high,
/// a circle for medium, `i` for low and a dot for info.
pub fn severity_svg(s: lenstica_lens::Severity) -> &'static str {
    use lenstica_lens::Severity::*;
    match s {
        Critical => include_str!("../assets/lucide/octagon-alert-filled.svg"),
        High => include_str!("../assets/lucide/triangle-alert.svg"),
        Medium => include_str!("../assets/lucide/circle-alert.svg"),
        Low => include_str!("../assets/lucide/info.svg"),
        Info => include_str!("../assets/lucide/circle-dot.svg"),
    }
}

fn dot(fill: &str, stroke: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="6" fill="{fill}" stroke="{stroke}" stroke-width="2"/></svg>"#
    )
}

pub fn menu_rgba(icon: MenuIcon) -> Vec<u8> {
    let (svg, scale) = match icon {
        MenuIcon::Severity(s) => (
            severity_svg(s)
                .replace("currentColor", severity_color(s))
                .replace("stroke-width=\"2\"", "stroke-width=\"2.4\""),
            0.8,
        ),
        MenuIcon::Ok => (dot("#30a46c", "#30a46c"), 1.0),
        MenuIcon::Problem(s) => (dot(severity_color(s), severity_color(s)), 1.0),
        MenuIcon::Failed => (dot("#a18072", "#a18072"), 1.0),
        MenuIcon::Running => (dot("#6e6ef8", "#6e6ef8"), 1.0),
        MenuIcon::NotRun => (dot("none", "#8e8e93"), 1.0),
        MenuIcon::Copy => (
            include_str!("../assets/lucide/clipboard-copy.svg").replace("currentColor", "#8e8e93"),
            0.8,
        ),
    };
    render(&svg, MENU_SIZE, scale)
}

fn render(svg: &str, size: u32, share: f32) -> Vec<u8> {
    let tree = usvg::Tree::from_str(svg, &usvg::Options::default())
        .expect("bundled Lucide SVGs are valid");
    let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("non-zero size");
    let box_px = size as f32 * share;
    let scale = box_px / tree.size().width();
    let offset = (size as f32 - box_px) / 2.0;
    let transform = tiny_skia::Transform::from_row(scale, 0.0, 0.0, scale, offset, offset);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    pixmap
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test icon -- --nocapture` prints each icon for eyeballing.
    #[test]
    fn every_icon_renders_inside_its_padding() {
        for glyph in [Glyph::Protected, Glyph::Problem, Glyph::Checking] {
            let px = rgba(glyph);
            assert_eq!(px.len(), (SIZE * SIZE * 4) as usize);
            let alpha = |x: u32, y: u32| px[((y * SIZE + x) * 4 + 3) as usize];
            let mut art = format!("{glyph:?}\n");
            for y in 0..SIZE {
                for x in 0..SIZE {
                    art.push(match alpha(x, y) {
                        0 => ' ',
                        1..=127 => '+',
                        _ => '#',
                    });
                }
                art.push('\n');
            }
            println!("{art}");
            let opaque = px.chunks(4).filter(|p| p[3] > 127).count();
            assert!(opaque > 150, "{glyph:?} too faint: {opaque} pixels");
            // Nothing in the outer pixel: the glyph fills the canvas without being clipped.
            for i in 0..SIZE {
                for edge in [0, SIZE - 1] {
                    assert_eq!(alpha(i, edge), 0, "{glyph:?} touches row {edge}");
                    assert_eq!(alpha(edge, i), 0, "{glyph:?} touches column {edge}");
                }
            }
        }
        for icon in [
            MenuIcon::Severity(lenstica_lens::Severity::Critical),
            MenuIcon::Severity(lenstica_lens::Severity::Info),
            MenuIcon::Ok,
            MenuIcon::NotRun,
            MenuIcon::Copy,
        ] {
            let px = menu_rgba(icon);
            assert_eq!(px.len(), (MENU_SIZE * MENU_SIZE * 4) as usize);
            assert!(
                px.chunks(4).filter(|p| p[3] > 127).count() > 40,
                "{icon:?} too faint"
            );
        }
        // The problem icon is orange, not black.
        let problem = rgba(Glyph::Problem);
        let lit = problem
            .chunks(4)
            .find(|p| p[3] == 255)
            .expect("an opaque pixel");
        assert_eq!(&lit[..3], &[255, 149, 0]);
    }
}
