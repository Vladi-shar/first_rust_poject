#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use crate::inject_lib::inject_new_process_apc;
use eframe::{
    egui::{self, CentralPanel, FontId, TextStyle, Vec2},
    run_native, App,
};
use egui::{InnerResponse, Key, RichText, TopBottomPanel};
use regex::Regex;
use std::time::{Duration, Instant};
use windows::{core::*, Win32::System::Diagnostics::ToolHelp::*};

mod inject_lib;

fn exe_name_from_pe32(
    pe32: PROCESSENTRY32W,
) -> std::result::Result<String, std::string::FromUtf16Error> {
    let len = pe32
        .szExeFile
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(pe32.szExeFile.len());
    String::from_utf16(&pe32.szExeFile[..len]).map_err(|e| {
        println!("Failed to get exe name: {}", e);
        e
    })
}

fn get_running_procs() -> Result<Vec<(String, u32)>> {
    let mut running_procs: Vec<(String, u32)> = Vec::default();
    unsafe {
        // let h_proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid).map_err(|e| {
        //     eprintln!("Failed to open process {}: {}", pid, e);
        //     e
        // })?;

        let snap = Owned::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
                println!("CreateToolhelp32Snapshot Error: {}", e);
                e
            })?,
        );

        let mut pe32: PROCESSENTRY32W = PROCESSENTRY32W::default();
        pe32.dwSize = size_of_val(&pe32) as u32;

        Process32FirstW(*snap, &mut pe32).map_err(|e| {
            println!("Process32First Error: {}", e);
            e
        })?;

        loop {
            let exe_name = exe_name_from_pe32(pe32);
            match exe_name {
                Ok(exe) => {
                    running_procs.push((exe, pe32.th32ProcessID));
                }
                Err(_e) => {
                    continue;
                }
            }

            if let Err(_) = Process32NextW(*snap, &mut pe32) {
                break;
            }
        }
    }
    running_procs.sort_by(|(_, p1), (_, p2)| p1.cmp(p2));
    Ok(running_procs)
}

#[derive(PartialEq)]
enum TabId {
    RunningProcess = 1,
    NewProcess,
}

struct InjectorApp {
    dll_path: String,
    exe_path: String,
    pid: u32,
    process_text: String,
    pids: Vec<(String, u32)>,
    last_update: Instant,
    update_interval: Duration,
    tab_id: TabId,
    event_history: Vec<String>,
}

fn render_file_path_input(ui: &mut egui::Ui, label_text: &str, modified_path: &mut String, hover_text: &str) -> InnerResponse<()> {
    return ui.horizontal(|ui| {
        ui.label(label_text);
        ui.add(egui::TextEdit::singleline(modified_path).desired_width(200.0)).on_hover_text(hover_text);
        if ui.button("Browse").on_hover_text(hover_text).clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                *modified_path = path.display().to_string()
            }
        }
    });
}

impl InjectorApp {
    fn new() -> Self {
        Self {
            dll_path: String::new(),
            exe_path: String::new(),
            pid: 0,
            process_text: String::new(),
            pids: get_running_procs().unwrap_or(Vec::default()),
            last_update: Instant::now(),
            update_interval: Duration::from_secs(5),
            tab_id: TabId::RunningProcess,
            event_history: Vec::default(),
        }
    }

    fn update_pids(&mut self) {
        if self.last_update.elapsed() >= self.update_interval {
            println!("updating pids {:?}", Instant::now());
            self.pids = get_running_procs().unwrap_or(Vec::default());
            self.last_update = Instant::now();
        }
    }

    fn filtered_pids(&self) -> Vec<(String, u32)> {
        // Trim the input text
        let filter_text = self.process_text.trim();

        // Define a regex to match the format `[123] some_process.extension`
        let specific_format_regex = Regex::new(r"^\[\d+\](?:\s.+)?$|^\d+\s.+$").unwrap();

        if specific_format_regex.is_match(filter_text) {
            // If the input matches the specific format, return all pids
            self.pids.clone()
        } else {
            // Otherwise, filter the pids
            self.pids
                .iter()
                .filter(|(exe_name, pid)| {
                    if let Ok(input_pid) = filter_text.parse::<u32>() {
                        // If the input is numeric, filter by PID prefix
                        pid.to_string().starts_with(&input_pid.to_string())
                    } else {
                        // Otherwise, filter by process name (case-insensitive)
                        exe_name
                            .to_lowercase()
                            .contains(&filter_text.to_lowercase())
                    }
                })
                .cloned()
                .collect()
        }
    }

    fn render_running_injector(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // File Path Input
            // ui.horizontal(|ui| {
            //     ui.label("File Path:");
            //     ui.add(egui::TextEdit::singleline(&mut self.file_path).desired_width(200.0));
            //     if ui.button("Browse").clicked() {
            //         if let Some(path) = rfd::FileDialog::new().pick_file() {
            //             self.file_path = path.display().to_string();
            //         }
            //     }
            // });
            let _file_path_input = render_file_path_input(ui, "File Path:", &mut self.dll_path, "Path to the dll to be injected.");

            // PID Dropdown and Filtering
            ui.horizontal(|ui| {
                ui.label("PID:");
                let mut text_box = egui::TextEdit::singleline(&mut self.process_text)
                    .hint_text("Filter...")
                    .desired_width(275.0)
                    .show(ui);
                let text_box_response = text_box.response;
                let pid_dropdown_id = ui.make_persistent_id("pid_dropdown");

                if text_box_response.gained_focus() {
                    text_box
                        .state
                        .cursor
                        .set_char_range(Some(egui::text::CCursorRange::two(
                            egui::text::CCursor::new(0),
                            egui::text::CCursor::new(self.process_text.len()),
                        )));
                    text_box.state.store(ctx, text_box_response.id);
                    ui.memory_mut(|mem| mem.toggle_popup(pid_dropdown_id));
                }

                egui::popup_below_widget(
                    ui,
                    pid_dropdown_id,
                    &text_box_response,
                    egui::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_max_width(275.0);
                        ui.set_max_height(275.0);
                        self.update_pids();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for (exe_name, pid) in self.filtered_pids() {
                                let text = format!("[{}] {}", pid, exe_name);
                                if ui.selectable_label(false, text.to_string()).clicked() {
                                    println!("Selected: {}", text); // Debugging output
                                    self.pid = pid;
                                    self.process_text = text;
                                }
                            }
                        });
                    },
                );
            });

            // Inject Button
            if ui.button("Inject").clicked() {
                println!("File Path: {}", self.dll_path);
                println!("PID: {}", self.pid);
                let injected =
                    inject_lib::inject(&self.dll_path, self.pid.clone(), &mut self.event_history);

                match injected {
                    Ok(()) => {
                        self.event_history.push(format!(
                            "Succesfully injected {} into {}",
                            self.dll_path, self.process_text
                        ));
                    }
                    Err(e) => {
                        self.event_history
                            .push(format!("Injection failed, Error: {}", e.message()));
                    }
                }
            }
        });
    }
    fn render_new_process_injector(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // File Path Input
            let _dll_file_path_input = render_file_path_input(ui,  "File Path:", &mut self.dll_path, "Path to the dll to be injected.");
            let _proc_file_path_input = render_file_path_input(ui, "Exe Path:", &mut self.exe_path,"Path to the exe to be launched and injected");

            let mut new_process_triggered = false;
            if ui.button("New Process").clicked() {
                new_process_triggered = true;
            }

            if ui.input(|i| i.key_pressed(Key::Enter)) && !self.dll_path.is_empty() && !self.exe_path.is_empty() {
                new_process_triggered = true;
            }

            if new_process_triggered {
                let injected = inject_new_process_apc(
                    &self.dll_path,
                    &self.exe_path,
                    &mut self.event_history,
                );
                if let Ok(()) = injected {
                    self.event_history.push(format!(
                        "Succesfully injected {} into {}",
                        self.dll_path, self.exe_path
                    ));
                } else if let Err(e) = injected {
                    self.event_history
                        .push(format!("Injection failed, Error: {}", e.message()));
                }
            }
        });
    }
}

impl Default for InjectorApp {
    fn default() -> Self {
        Self {
            dll_path: String::new(),
            exe_path: String::new(),
            pid: 0,
            process_text: String::new(),
            pids: Vec::new(),
            last_update: Instant::now(),
            update_interval: Duration::from_secs(5),
            tab_id: TabId::RunningProcess,
            event_history: Vec::default(),
        }
    }
}

impl App for InjectorApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        let mut style = (*ctx.style()).clone();
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(24.0)),
            (TextStyle::Body, FontId::proportional(18.0)),
            (TextStyle::Monospace, FontId::monospace(18.0)),
            (TextStyle::Button, FontId::proportional(18.0)),
            (TextStyle::Small, FontId::proportional(14.0)),
        ]
        .into();
        ctx.set_style(style);

        TopBottomPanel::top("tabs")
            .min_height(30.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(self.tab_id == TabId::RunningProcess, "Inject Running")
                        .on_hover_ui(|ui| {
                            // ui.style_mut().interaction.selectable_labels = true;
                            ui.style_mut().interaction.tooltip_delay = 0.5f32;
                            ui.label("Inject into an already running process");
                        })
                        .clicked()
                    {
                        self.tab_id = TabId::RunningProcess;
                    }
                    if ui
                        .selectable_label(self.tab_id == TabId::NewProcess, "Inject New")
                        .on_hover_ui(|ui| {
                            // ui.style_mut().interaction.selectable_labels = true;
                            ui.style_mut().interaction.tooltip_delay = 0.5f32;
                            ui.label("Create a new process and inject into it");
                        })
                        .clicked()
                    {
                        self.tab_id = TabId::NewProcess;
                    }
                });
            });

        CentralPanel::default().show(ctx, |ui| match self.tab_id {
            TabId::RunningProcess => {
                self.render_running_injector(ctx, ui);
            }
            TabId::NewProcess => {
                self.render_new_process_injector(ui);
            }
        });

        TopBottomPanel::bottom("log")
            .exact_height(100.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for event in &self.event_history {
                            let styled_label =
                                RichText::new(event).font(FontId::proportional(15.0));
                            ui.label(styled_label);
                        }
                    })
            });
    }
}

fn main() {
    let mut win_option = eframe::NativeOptions::default();
    win_option.viewport.resizable = Option::Some(false);
    win_option.viewport.inner_size = Option::from(Vec2::new(380.0, 380.0));
    let _ = run_native(
        "vladinject",
        win_option,
        Box::new(|_cc| Ok(Box::new(InjectorApp::new()))),
    );
}
