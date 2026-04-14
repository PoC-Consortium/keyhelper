#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod derive;

use eframe::egui;
use std::cell::RefCell;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 640.0])
            .with_min_inner_size([600.0, 520.0])
            .with_title("PoCX Key Helper — offline"),
        ..Default::default()
    };

    eframe::run_native(
        "PoCX Key Helper",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    MainToTest, // primary: mainnet address;  advanced: testnet address + testnet WIF
    TestToMain, // primary: testnet address;  advanced: mainnet address + mainnet WIF
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Mnemonic,
    Xprv,
}

struct App {
    tab: Tab,
    input_mode: InputMode,
    mnemonic: String,
    passphrase: String,
    xprv: String,
    show_words: bool,
    show_passphrase: bool,
    show_xprv: bool,
    reveal_wif: bool,
    ack_risk: bool,
    result: Option<derive::Derived>,
    error: Option<String>,
    clip_clear_at: Option<Instant>,
    last_copy_label: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            tab: Tab::MainToTest,
            input_mode: InputMode::Mnemonic,
            mnemonic: String::new(),
            passphrase: String::new(),
            xprv: String::new(),
            show_words: false,
            show_passphrase: false,
            show_xprv: false,
            reveal_wif: false,
            ack_risk: false,
            result: None,
            error: None,
            clip_clear_at: None,
            last_copy_label: None,
        }
    }
}

impl App {
    fn clear_all(&mut self) {
        self.mnemonic.zeroize();
        self.passphrase.zeroize();
        self.xprv.zeroize();
        self.mnemonic.clear();
        self.passphrase.clear();
        self.xprv.clear();
        self.result = None;
        self.error = None;
        self.reveal_wif = false;
        self.ack_risk = false;
        self.clear_clipboard_now();
    }

    fn compute(&mut self) {
        self.result = None;
        self.error = None;
        let outcome = match self.input_mode {
            InputMode::Mnemonic => {
                if self.mnemonic.trim().is_empty() {
                    return;
                }
                derive::derive_from_mnemonic(&self.mnemonic, &self.passphrase)
            }
            InputMode::Xprv => {
                if self.xprv.trim().is_empty() {
                    return;
                }
                derive::derive_from_xprv(&self.xprv)
            }
        };
        match outcome {
            Ok(d) => self.result = Some(d),
            Err(e) => self.error = Some(e),
        }
    }

    fn copy(&mut self, text: &str, label: &str) {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(text.to_owned());
            self.clip_clear_at = Some(Instant::now() + Duration::from_secs(30));
            self.last_copy_label = Some(label.to_string());
        }
    }

    fn clear_clipboard_now(&mut self) {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(String::new());
        }
        self.clip_clear_at = None;
        self.last_copy_label = None;
    }

    fn maybe_auto_clear_clipboard(&mut self) {
        if let Some(when) = self.clip_clear_at {
            if Instant::now() >= when {
                self.clear_clipboard_now();
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.maybe_auto_clear_clipboard();

        if self.clip_clear_at.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }

        let copy_queue: RefCell<Vec<(String, String)>> = RefCell::new(Vec::new());
        let mut derive_requested = false;
        let mut clear_requested = false;
        let mut paste_requested = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("PoCX Key Helper");
            ui.label(
                egui::RichText::new("Offline tool. No network. Nothing is saved to disk.")
                    .small()
                    .italics(),
            );

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::MainToTest, "  Mainnet -> Testnet  ");
                ui.selectable_value(&mut self.tab, Tab::TestToMain, "  Testnet -> Mainnet  ");
            });
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Input:");
                ui.radio_value(&mut self.input_mode, InputMode::Mnemonic, "24-word mnemonic");
                ui.radio_value(&mut self.input_mode, InputMode::Xprv, "xprv");
            });
            ui.add_space(4.0);

            let input_lost_focus = match self.input_mode {
                InputMode::Mnemonic => {
                    ui.label("24-word recovery phrase:");
                    let resp = ui.add(
                        egui::TextEdit::multiline(&mut self.mnemonic)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY)
                            .password(!self.show_words)
                            .hint_text("word1 word2 word3 ..."),
                    );
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.show_words, "Show words");
                        if ui.button("Paste").clicked() {
                            paste_requested = true;
                        }
                        if ui.button("Clear all").clicked() {
                            clear_requested = true;
                        }
                    });

                    ui.add_space(6.0);
                    ui.label("Optional BIP39 passphrase (leave empty if unused):");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.passphrase)
                                .password(!self.show_passphrase)
                                .desired_width(380.0),
                        );
                        ui.checkbox(&mut self.show_passphrase, "show");
                    });
                    resp.lost_focus()
                }
                InputMode::Xprv => {
                    ui.label("Extended private key (xprv):");
                    let resp = ui.add(
                        egui::TextEdit::multiline(&mut self.xprv)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY)
                            .password(!self.show_xprv)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("xprv... (master — depth 0) or account xprv (depth 3, m/84'/0'/0')"),
                    );
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.show_xprv, "Show xprv");
                        if ui.button("Paste").clicked() {
                            paste_requested = true;
                        }
                        if ui.button("Clear all").clicked() {
                            clear_requested = true;
                        }
                    });
                    ui.label(
                        egui::RichText::new(
                            "Accepts master xprv (applies m/84'/0'/0'/0/0) or BIP84 account xprv \
                             (applies /0/0). The intermediate xprv derived from a mnemonic is never shown.",
                        )
                        .small()
                        .italics()
                        .color(egui::Color32::GRAY),
                    );
                    resp.lost_focus()
                }
            };

            ui.add_space(8.0);
            if ui.button("Derive").clicked() || input_lost_focus {
                derive_requested = true;
            }

            ui.separator();

            if let Some(err) = &self.error {
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
            }

            if let Some(res) = &self.result {
                ui.label(
                    egui::RichText::new(format!("Derivation path: {}", res.path))
                        .small()
                        .italics(),
                );
                ui.add_space(4.0);

                let (primary_label, primary_addr, secondary_label, secondary_addr, wif_label, wif_value, import_cmd) =
                    match self.tab {
                        Tab::MainToTest => (
                            "Mainnet address (plot this)",
                            &res.mainnet_address,
                            "Testnet address",
                            &res.testnet_address,
                            "Testnet WIF",
                            &res.testnet_wif,
                            &res.testnet_import,
                        ),
                        Tab::TestToMain => (
                            "Testnet address (plot this)",
                            &res.testnet_address,
                            "Mainnet address",
                            &res.mainnet_address,
                            "Mainnet WIF",
                            &res.mainnet_wif,
                            &res.mainnet_import,
                        ),
                    };

                ui.strong(primary_label);
                address_row(ui, primary_addr, || {
                    copy_queue
                        .borrow_mut()
                        .push((primary_addr.clone(), primary_label.to_string()));
                });

                ui.add_space(10.0);
                ui.collapsing("Advanced - corresponding address & private key", |ui| {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(60, 20, 20))
                        .inner_margin(egui::Margin::same(10.0))
                        .rounding(egui::Rounding::same(4.0))
                        .show(ui, |ui| {
                            ui.colored_label(
                                egui::Color32::from_rgb(255, 120, 120),
                                egui::RichText::new("CRITICAL SECURITY WARNING").strong(),
                            );
                            ui.label(
                                egui::RichText::new(
                                    "Mainnet and testnet use the SAME private key - only the encoding differs. \
                                     A testnet WIF is NOT safe to share. Anyone who obtains it can trivially \
                                     reconstruct the mainnet WIF by swapping the prefix byte (0xEF -> 0x80) \
                                     and spend your real funds. Treat every WIF shown here as your full \
                                     mainnet private key. Never post it in public chats, bug reports, or screenshots.",
                                )
                                .color(egui::Color32::from_rgb(255, 210, 210)),
                            );
                        });
                    ui.add_space(6.0);

                    ui.strong(secondary_label);
                    address_row(ui, secondary_addr, || {
                        copy_queue
                            .borrow_mut()
                            .push((secondary_addr.clone(), secondary_label.to_string()));
                    });

                    ui.add_space(8.0);
                    ui.strong(wif_label);
                    ui.horizontal(|ui| {
                        ui.checkbox(
                            &mut self.ack_risk,
                            "I understand this key controls real mainnet funds",
                        );
                    });
                    ui.add_enabled_ui(self.ack_risk, |ui| {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.reveal_wif, "Reveal");
                        });
                        let shown = if self.reveal_wif && self.ack_risk {
                            wif_value.clone()
                        } else {
                            "•".repeat(wif_value.len().min(52))
                        };
                        let mut shown_mut = shown;
                        ui.add(
                            egui::TextEdit::singleline(&mut shown_mut)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        if ui
                            .button(format!("Copy {wif_label} (clipboard clears in 30s)"))
                            .clicked()
                        {
                            copy_queue
                                .borrow_mut()
                                .push((wif_value.clone(), wif_label.to_string()));
                        }

                        ui.add_space(8.0);
                        ui.strong("bitcoin-cli import command");
                        ui.label(
                            egui::RichText::new(
                                "Single-key descriptor (wpkh) with BIP-380 checksum. \
                                 Run against the matching network's node.",
                            )
                            .small()
                            .italics()
                            .color(egui::Color32::GRAY),
                        );
                        let shown_cmd = if self.reveal_wif && self.ack_risk {
                            import_cmd.clone()
                        } else {
                            "•".repeat(import_cmd.len().min(80))
                        };
                        let mut cmd_mut = shown_cmd;
                        ui.add(
                            egui::TextEdit::multiline(&mut cmd_mut)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        if ui
                            .button("Copy import command (clipboard clears in 30s)")
                            .clicked()
                        {
                            copy_queue
                                .borrow_mut()
                                .push((import_cmd.clone(), "import command".to_string()));
                        }
                    });
                });
            }

            ui.add_space(8.0);
            if let Some(label) = &self.last_copy_label {
                if let Some(when) = self.clip_clear_at {
                    let remaining = when
                        .saturating_duration_since(Instant::now())
                        .as_secs();
                    ui.label(
                        egui::RichText::new(format!(
                            "📋 Copied {label}. Clipboard will clear in {remaining}s."
                        ))
                        .small(),
                    );
                }
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.label(
                    egui::RichText::new(
                        "Best practice: run this on an air-gapped machine. \
                         Never paste your seed into a device that has been online recently.",
                    )
                    .small()
                    .color(egui::Color32::GRAY),
                );
            });
        });

        if paste_requested {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Ok(t) = cb.get_text() {
                    match self.input_mode {
                        InputMode::Mnemonic => self.mnemonic = t,
                        InputMode::Xprv => self.xprv = t,
                    }
                }
            }
        }

        if clear_requested {
            self.clear_all();
        }

        if derive_requested {
            match self.input_mode {
                InputMode::Mnemonic => {
                    if self.mnemonic.trim().is_empty() {
                        self.result = None;
                        self.error = None;
                    } else if derive::validate_mnemonic(&self.mnemonic) {
                        self.compute();
                    } else {
                        self.error = Some("Mnemonic is not a valid BIP39 phrase.".to_string());
                        self.result = None;
                    }
                }
                InputMode::Xprv => {
                    if self.xprv.trim().is_empty() {
                        self.result = None;
                        self.error = None;
                    } else {
                        self.compute();
                    }
                }
            }
        }

        for (text, label) in copy_queue.into_inner() {
            self.copy(&text, &label);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.clear_all();
    }
}

fn address_row(ui: &mut egui::Ui, addr: &str, on_copy: impl FnOnce()) {
    ui.horizontal(|ui| {
        let mut mutable = addr.to_string();
        ui.add(
            egui::TextEdit::singleline(&mut mutable)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("Copy").clicked() {
            on_copy();
        }
    });
}
