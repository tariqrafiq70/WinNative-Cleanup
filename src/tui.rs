use crate::rules::SafetyLevel;
use crate::scanner::ScanResult;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style, Stylize},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use std::io;

pub struct TuiApp {
    results: Vec<ScanResult>,
    state: ListState,
    selected_indices: Vec<usize>,
}

impl TuiApp {
    pub fn new(results: Vec<ScanResult>) -> Self {
        let mut state = ListState::default();
        state.select(Some(0));
        Self {
            results,
            state,
            selected_indices: Vec::new(),
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        loop {
            terminal.draw(|f| self.ui(f))?;

            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Up => self.previous(),
                        KeyCode::Down => self.next(),
                        KeyCode::Char(' ') => self.toggle_selection(),
                        KeyCode::Char('c') => {
                            if !self.selected_indices.is_empty() {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        Ok(())
    }

    fn ui(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(f.size());

        let title = Paragraph::new(
            " WinNative-Cleanup V2 - Interactive Dashboard "
                .bold()
                .cyan(),
        )
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        let items: Vec<ListItem> = self
            .results
            .iter()
            .enumerate()
            .map(|(i, res)| {
                let prefix = if self.selected_indices.contains(&i) {
                    "[x] "
                } else {
                    "[ ] "
                };
                let content = format!(
                    "{}{:<35} {:>15}",
                    prefix,
                    res.rule_name,
                    human_bytes::human_bytes(res.total_size as f64)
                );

                let color = match res.safety_level {
                    SafetyLevel::Safe => Color::Green,
                    SafetyLevel::Caution => Color::Yellow,
                    SafetyLevel::Warning => Color::Red,
                };

                ListItem::new(content).style(Style::default().fg(color))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().title(" Categories ").borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        f.render_stateful_widget(list, chunks[1], &mut self.state);

        let footer =
            Paragraph::new(" [↑/↓] Navigate | [Space] Select | [c] Clean Selected | [q] Quit ")
                .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, chunks[2]);
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.results.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.results.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn toggle_selection(&mut self) {
        if let Some(i) = self.state.selected() {
            if let Some(pos) = self.selected_indices.iter().position(|&x| x == i) {
                self.selected_indices.remove(pos);
            } else {
                self.selected_indices.push(i);
            }
        }
    }

    pub fn get_selected_results(&self) -> Vec<ScanResult> {
        self.selected_indices
            .iter()
            .map(|&i| self.results[i].clone())
            .collect()
    }
}
