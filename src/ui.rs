use crate::{
    app::App,
    model::{quantity, Interface},
};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

const INK: Color = Color::Gray;
const MUTED: Color = Color::DarkGray;
const BORDER: Color = Color::Rgb(91, 139, 148);
const BLUE: Color = Color::Rgb(100, 180, 230);
const GREEN: Color = Color::Rgb(135, 205, 145);
const YELLOW: Color = Color::Rgb(220, 190, 115);

fn style(app: &App, color: Color) -> Style {
    if app.color {
        Style::default().fg(color)
    } else {
        Style::default()
    }
}
fn text(app: &App, value: impl AsRef<str>) -> String {
    if !app.ascii {
        return value.as_ref().into();
    }
    value
        .as_ref()
        .replace('—', "-")
        .replace('…', "...")
        .replace('↓', "v")
        .replace('↑', "^")
        .chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect()
}
fn panel<'a>(app: &App, title: impl Into<Line<'a>>, color: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_set(if app.ascii {
            symbols::border::Set {
                top_left: "+",
                top_right: "+",
                bottom_left: "+",
                bottom_right: "+",
                vertical_left: "|",
                vertical_right: "|",
                horizontal_top: "-",
                horizontal_bottom: "-",
            }
        } else {
            symbols::border::ROUNDED
        })
        .border_style(style(app, color))
        .style(style(app, INK))
}

pub fn draw(f: &mut Frame, app: &App) {
    let screen = f.area();
    f.render_widget(Block::default().style(style(app, INK)), screen);
    if screen.width < 44 || screen.height < 16 {
        f.render_widget(
            Paragraph::new("Resize terminal: minimum 44 x 16\nq / Ctrl-C to quit")
                .style(style(app, MUTED)),
            screen,
        );
        return;
    }
    let area = screen.inner(Margin {
        horizontal: 1,
        vertical: 0,
    });
    let addresses = [
        app.internal_ip().unwrap_or_else(|| "—".into()),
        app.router_ip().unwrap_or("—").into(),
        app.external_ip(),
    ];
    let wide = screen.width >= 80;
    let path_height = if wide {
        2 + addresses
            .iter()
            .map(|s| s.len().div_ceil(((area.width - 4) / 3 - 2) as usize))
            .max()
            .unwrap_or(1) as u16
    } else {
        2 + addresses
            .iter()
            .map(|s| s.len().div_ceil((area.width - 15) as usize))
            .sum::<usize>() as u16
    };
    let sections = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(4),
        Constraint::Length(path_height),
    ])
    .split(area);
    header(f, app, sections[0]);
    interfaces(f, app, sections[1], wide);
    path(f, app, sections[2], &addresses, wide);
    if app.confirm {
        confirmation(f, app, area);
    }
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).split(area);
    let rate = app.primary_interface().map(|i| i.rate).unwrap_or_default();
    for (rect, label, arrow, value, color) in [
        (columns[0], " DOWNLOAD ", "↓", rate.rx, BLUE),
        (columns[1], " UPLOAD ", "↑", rate.tx, GREEN),
    ] {
        let mut block = panel(app, label, color);
        if app.frozen() {
            block = block.title_bottom(Line::from(" pinned ").right_aligned());
        }
        let inner = block.inner(rect);
        f.render_widget(block, rect);
        f.render_widget(
            Paragraph::new(text(app, format!(" {arrow} {}", quantity(value, false))))
                .style(style(app, color).add_modifier(Modifier::BOLD)),
            inner,
        );
    }
}

fn interfaces(f: &mut Frame, app: &App, area: Rect, wide: bool) {
    let interfaces = app.interfaces();
    let mut block = panel(app, " interfaces ", BORDER);
    let inner = block.inner(area);
    let capacity = if wide {
        inner.height.saturating_sub(2) as usize
    } else {
        inner.height as usize / 2
    }
    .max(1);
    let start = app
        .cursor
        .saturating_sub(capacity - 1)
        .min(interfaces.len().saturating_sub(capacity));
    if interfaces.len() > capacity {
        block = block.title_bottom(
            Line::from(format!(
                " {}-{}/{} ",
                start + 1,
                (start + capacity).min(interfaces.len()),
                interfaces.len()
            ))
            .right_aligned(),
        );
    }
    f.render_widget(block, area);
    let primary = app.primary_interface().map(|i| i.name.as_str());
    let name_style = |i: &Interface, selected: bool| {
        let base = style(
            app,
            if primary == Some(i.name.as_str()) {
                GREEN
            } else {
                INK
            },
        );
        if selected {
            base.add_modifier(Modifier::BOLD)
        } else {
            base
        }
    };
    let title =
        |i: &Interface, selected| format!("{} {}", if selected { ">" } else { " " }, i.title());
    let speed = |i: &Interface| {
        text(
            app,
            quantity(
                if i.up == Some(false) {
                    Some(0.)
                } else {
                    i.speed.map(|n| n as f64)
                },
                true,
            ),
        )
    };
    if wide {
        let rows = interfaces
            .iter()
            .enumerate()
            .skip(start)
            .take(capacity)
            .map(|(index, i)| {
                Row::new(vec![
                    Cell::from(title(i, index == app.cursor))
                        .style(name_style(i, index == app.cursor)),
                    Cell::from(Line::from(text(app, quantity(i.rate.rx, false))).right_aligned())
                        .style(style(app, BLUE)),
                    Cell::from(Line::from(text(app, quantity(i.rate.tx, false))).right_aligned())
                        .style(style(app, GREEN)),
                    Cell::from(Line::from(speed(i)).right_aligned()),
                    Cell::from(kind(i)).style(style(app, MUTED)),
                ])
            });
        f.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Min(26),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(9),
                ],
            )
            .header(
                Row::new([
                    "  INTERFACE",
                    "    DOWNLOAD",
                    "      UPLOAD",
                    "        LINK",
                    "TYPE",
                ])
                .style(style(app, BORDER).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
            )
            .column_spacing(1),
            inner,
        );
    } else {
        for (index, i) in interfaces.iter().enumerate().skip(start).take(capacity) {
            let y = inner.y + (index - start) as u16 * 2;
            f.render_widget(
                Paragraph::new(title(i, index == app.cursor))
                    .style(name_style(i, index == app.cursor)),
                Rect::new(inner.x, y, inner.width.saturating_sub(13), 1),
            );
            f.render_widget(
                Paragraph::new(speed(i))
                    .alignment(Alignment::Right)
                    .style(style(app, MUTED)),
                Rect::new(inner.right() - 12, y, 12, 1),
            );
            let rates = Line::from(vec![
                Span::styled(
                    text(app, format!("  ↓ {}", quantity(i.rate.rx, false))),
                    style(app, BLUE),
                ),
                Span::styled(
                    text(app, format!("  ↑ {}", quantity(i.rate.tx, false))),
                    style(app, GREEN),
                ),
            ]);
            f.render_widget(
                Paragraph::new(rates),
                Rect::new(inner.x, y + 1, inner.width - 9, 1),
            );
            f.render_widget(
                Paragraph::new(kind(i))
                    .alignment(Alignment::Right)
                    .style(style(app, MUTED)),
                Rect::new(inner.right() - 8, y + 1, 8, 1),
            );
        }
    }
}
fn kind(interface: &Interface) -> &str {
    if interface.wireless() {
        interface.band.as_deref().unwrap_or("Wi-Fi")
    } else {
        "Ethernet"
    }
}

fn path(f: &mut Frame, app: &App, area: Rect, addresses: &[String; 3], wide: bool) {
    let labels = ["Internal", "Router", "External"];
    let colors = [BLUE, YELLOW, GREEN];
    if wide {
        let columns = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Fill(1),
        ])
        .split(area);
        for index in 0..3 {
            let mut block = panel(app, format!(" {} ", labels[index]), colors[index]);
            if index == 2 {
                if let Some(source) = app.external_source() {
                    block = block.title_bottom(Line::from(format!(" {source} ")).right_aligned());
                }
            }
            f.render_widget(
                Paragraph::new(text(app, &addresses[index]))
                    .block(block)
                    .alignment(Alignment::Center)
                    .wrap(Wrap { trim: false }),
                columns[index * 2],
            );
        }
        for index in [1, 3] {
            f.render_widget(
                Paragraph::new(">")
                    .style(style(app, MUTED))
                    .alignment(Alignment::Center),
                Rect::new(columns[index].x, area.y + 1, 2, 1),
            );
        }
    } else {
        let mut block = panel(app, " network ", BORDER);
        if let Some(source) = app.external_source() {
            block = block.title_bottom(Line::from(format!(" External: {source} ")).right_aligned());
        }
        let inner = block.inner(area);
        f.render_widget(block, area);
        let mut y = inner.y;
        for index in 0..3 {
            let width = inner.width - 12;
            let height = addresses[index].len().div_ceil(width as usize).max(1) as u16;
            f.render_widget(
                Paragraph::new(format!(" {}", labels[index])).style(style(app, colors[index])),
                Rect::new(inner.x, y, 11, height),
            );
            f.render_widget(
                Paragraph::new(text(app, &addresses[index])).wrap(Wrap { trim: false }),
                Rect::new(inner.x + 12, y, width, height),
            );
            y += height;
        }
    }
}

fn confirmation(f: &mut Frame, app: &App, area: Rect) {
    let width = area.width.min(62);
    let rect = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - 12) / 2,
        width,
        12,
    );
    f.render_widget(Clear, rect);
    f.render_widget(Paragraph::new("HTTPS: api.ipify.org / api6.ipify.org\nThe service sees the queried egress IP.\nEnvironment proxy, then system proxy.\nDirect only if no proxy is configured.\nProxy failure never bypasses the proxy.\n5s/family; success cached for 60s.\n\ny / Enter: confirm\nn / Esc: cancel")
        .block(panel(app, " query External IP ", YELLOW)).wrap(Wrap { trim: false }), rect);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::Options,
        model::{Rate, Route},
        public_ip::Probe,
    };
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};
    use std::time::Instant;

    fn fixture() -> App {
        let mut app = App::new(Options {
            interval: 1,
            ascii: false,
        });
        app.color = true;
        app.live.snapshot.interfaces = [
            "Ethernet Adapter (en4)",
            "Ethernet Adapter (en5)",
            "Ethernet Adapter (en6)",
            "Thunderbolt 1",
            "Thunderbolt 2",
            "Thunderbolt 3",
            "Wi-Fi",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| Interface {
            name: format!("en{index}"),
            kind: kind.into(),
            up: Some(index == 6),
            speed: (index == 6).then_some(866_000_000),
            band: (index == 6).then(|| "5 GHz".into()),
            addresses: if index == 6 {
                vec!["192.168.1.103/24".into()]
            } else {
                vec![]
            },
            rate: Rate {
                rx: Some(if index == 6 { 94_300. } else { 0. }),
                tx: Some(if index == 6 { 5_300. } else { 0. }),
            },
            ..Default::default()
        })
        .collect();
        app.live.snapshot.defaults[0] = Some(Route {
            interface: "en6".into(),
            gateway: Some("192.168.1.1".into()),
        });
        app.live.probes[0] = Some(Probe {
            at: Instant::now(),
            generation: 0,
            via_proxy: true,
            result: Ok("199.19.104.129".parse().unwrap()),
        });
        app
    }
    fn render(app: &App, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        terminal.backend().buffer().clone()
    }
    fn output(buffer: &Buffer) -> String {
        buffer
            .content
            .chunks(buffer.area.width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
    #[test]
    fn btop_layout_preserves_content_without_gui_backgrounds() {
        let app = fixture();
        for width in [72, 80, 120] {
            let buffer = render(&app, width, 24);
            let rendered = output(&buffer);
            for value in [
                "DOWNLOAD",
                "UPLOAD",
                "94.3 KB/s",
                "5.30 KB/s",
                "Ethernet Adapter (en4)",
                "Ethernet Adapter (en5)",
                "Ethernet Adapter (en6)",
                "Thunderbolt 1",
                "Thunderbolt 2",
                "Thunderbolt 3",
                "Wi-Fi",
                "866 Mb/s",
                "5 GHz",
                "Internal",
                "Router",
                "External",
                "192.168.1.103",
                "192.168.1.1",
                "199.19.104.129",
                "proxy",
            ] {
                assert!(rendered.contains(value), "missing {value}:\n{rendered}");
            }
            assert!(rendered.contains('╭'));
            assert!(!rendered.contains(['█', '▄', '▀', '♙', '▱']));
            assert!(buffer.content.iter().all(|c| c.bg == Color::Reset));
            for color in [BLUE, GREEN, BORDER] {
                assert!(buffer.content.iter().any(|c| c.fg == color));
            }
            for removed in ["processes", "connections", "history", "filter", "PID"] {
                assert!(!rendered.contains(removed));
            }
            if width == 80 {
                println!("{rendered}");
            }
        }
    }
    #[test]
    fn unqueried_and_changed_network_show_public_query_hint() {
        for width in [44, 52, 72, 80, 120] {
            let mut app = fixture();
            app.live.probes = [None, None];
            assert!(output(&render(&app, width, 24)).contains("p: query"));
            let mut app = fixture();
            app.live.snapshot.generation += 1;
            assert!(output(&render(&app, width, 24)).contains("p: query"));
        }
    }
    #[test]
    fn resizing_scroll_monochrome_pin_confirmation_and_ipv6() {
        for (width, height) in [
            (140, 50),
            (80, 24),
            (72, 24),
            (52, 20),
            (44, 16),
            (20, 8),
            (1, 1),
        ] {
            for ascii in [false, true] {
                let mut app = fixture();
                app.ascii = ascii;
                app.color = !ascii;
                app.cursor = 6;
                let buffer = render(&app, width, height);
                let rendered = output(&buffer);
                if width >= 44 {
                    assert!(rendered.contains("Wi-Fi"), "{rendered}");
                    assert!(rendered.contains("External"), "{rendered}");
                }
                if ascii {
                    assert!(rendered.is_ascii());
                    assert!(buffer
                        .content
                        .iter()
                        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
                }
                app.confirm = true;
                if width >= 44 {
                    assert!(output(&render(&app, width, height)).contains("n / Esc: cancel"));
                }
                app.confirm = false;
                app.live.snapshot.interfaces.last_mut().unwrap().addresses =
                    vec!["2001:db8:1234:5678:abcd:ef01:2345:6789/64".into()];
                render(&app, width, height);
                app.live.snapshot.interfaces.clear();
                render(&app, width, height);
            }
        }
    }
}
