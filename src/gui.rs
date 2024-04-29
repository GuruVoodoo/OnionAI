use gio::prelude::*;
use gtk4::{Application, ApplicationWindow, Button, Entry, Label, TextBuffer, TextView, Notebook, MenuButton};
use gtk4::glib;
use gtk4::prelude::*;
use std::net::SocketAddr;
use crate::config::AppConfig;
use crate::client;
use crate::node;
use std::rc::Rc;
use std::cell::RefCell;
use tokio::sync::oneshot;
use std::sync::{Arc, Mutex};
use gtk4::Builder;
use crate::error_handler::{log_and_display_error, log_warning};

pub fn run_gui(config: AppConfig) {
    let app = Application::builder()
        .application_id("com.example.SecureCommunication")
        .build();
    let config_rc = Rc::new(RefCell::new(config));
    app.connect_activate(move |app| {
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Secure Communication")
            .default_width(800)
            .default_height(600)
            .build();

        let header_bar = gtk4::HeaderBar::new();
        header_bar.set_show_title_buttons(true);
        window.set_titlebar(Some(&header_bar));

        let menu_button = MenuButton::new();
        menu_button.set_icon_name("open-menu-symbolic");
        let builder = Builder::from_file("menu.ui");
        let menu_model: gio::MenuModel = builder.object("menubar").expect("Couldn't get menubar");
        let popover = gtk4::PopoverMenu::from_model(Some(&menu_model));
        menu_button.set_popover(Some(&popover));
        header_bar.pack_end(&menu_button);

        let connect_action = gio::SimpleAction::new("connect", None);
        connect_action.connect_activate(glib::clone!(@weak window, @strong config_rc => move |_, _| {
            let dialog = gtk4::Dialog::with_buttons(
                Some("Connect to Node"),
                Some(&window),
                gtk4::DialogFlags::MODAL,
                &[("Connect", gtk4::ResponseType::Accept), ("Cancel", gtk4::ResponseType::Cancel)],
            );

            let dialog_content_area = dialog.content_area();

            let address_entry = Entry::builder()
                .placeholder_text("Enter address")
                .build();

            let port_entry = Entry::builder()
                .placeholder_text("Enter port")
                .build();

            let entry_box = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(5)
                .build();

            entry_box.append(&address_entry);
            entry_box.append(&port_entry);

            dialog_content_area.append(&entry_box);
            dialog.show();

            glib::MainContext::default().spawn_local({
                let config_rc = config_rc.clone();
                async move {
                    let dialog_response = dialog.run_future().await;
                    match dialog_response {
                        gtk4::ResponseType::Accept => {
                            let address = address_entry.text().to_string();
                            let port = port_entry.text().to_string();

                            let target_addr = format!("{}:{}", address, port);
                            let target_addr: SocketAddr = match target_addr.parse() {
                                Ok(addr) => addr,
                                Err(e) => {
                                    log_and_display_error("Invalid address format", &e);
                                    return;
                                }
                            };

                            let config = config_rc.borrow().clone();
                            let (message_sender, message_receiver) = tokio::sync::mpsc::channel(100);

                            // Create a new tab for the connected session
                            let tab_label = format!("Connection: {}", address);
                            let tab = gtk4::Box::builder()
                                .orientation(gtk4::Orientation::Vertical)
                                .spacing(5)
                                .build();

                            let message_text_view = TextView::builder()
                                .editable(false)
                                .wrap_mode(gtk4::WrapMode::WordChar)
                                .build();

                            let message_buffer = TextBuffer::builder().build();
                            message_text_view.set_buffer(Some(&message_buffer));

                            let scrolled_window = gtk4::ScrolledWindow::new();
                            scrolled_window.set_min_content_height(200);
                            scrolled_window.set_child(Some(&message_text_view));

                            let message_entry = Entry::builder().build();
                            let send_button = Button::builder()
                                .label("Send")
                                .build();

                            let messaging_box = gtk4::Box::builder()
                                .orientation(gtk4::Orientation::Vertical)
                                .spacing(5)
                                .build();

                            messaging_box.append(&scrolled_window);
                            messaging_box.append(&message_entry);
                            messaging_box.append(&send_button);

                            tab.append(&messaging_box);

                            let tab_label_widget = Label::new(Some(&tab_label));
                            let _notebook = window.child().unwrap().downcast::<gtk4::Box>().unwrap().first_child().unwrap().downcast::<Notebook>().unwrap();

                            // Remove the placeholder page if it exists
                            let child = window.child().unwrap();
                            if let Some(box_containing_notebook) = child.dynamic_cast::<gtk4::Box>().ok() {
                                let mut iter = box_containing_notebook.first_child();
                                while let Some(original_widget) = iter {
                                    let widget = original_widget.clone();
                                    if let Some(notebook) = widget.dynamic_cast::<Notebook>().ok() {
                                        if let Some(page) = notebook.nth_page(Some(0)) {
                                            if let Some(placeholder_label) = page.dynamic_cast::<Label>().ok() {
                                                if placeholder_label.label() == "No connections" {
                                                    notebook.remove_page(Some(0));
                                                }
                                            }
                                        }
                                        notebook.append_page(&tab, Some(&tab_label_widget));
                                    }
                                    if let Some(next_widget) = original_widget.next_sibling() {
                                        iter = Some(next_widget);
                                    } else {
                                        break;
                                    }
                                }
                            }

                            let message_sender = Arc::new(Mutex::new(message_sender));

                            send_button.connect_clicked(glib::clone!(@strong message_sender, @weak message_entry, @weak message_buffer => move |_| {
                                let message = message_entry.text().to_string();
                                let sender = message_sender.clone();
                                message_entry.set_text("");

                                glib::MainContext::default().spawn_local(async move {
                                    let sender = match sender.lock() {
                                        Ok(sender) => sender,
                                        Err(e) => {
                                            log_and_display_error("Failed to acquire lock on message sender", &e);
                                            return;
                                        }
                                    };
                                    if let Err(e) = sender.send(message).await {
                                        log_and_display_error("Failed to send message", &e);
                                    }
                                });
                            }));

                            let message_receiver = Arc::new(Mutex::new(Some(message_receiver)));

                            {
                                let message_receiver = message_receiver.clone();
                                let message_buffer_clone = message_buffer.clone();
                                glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                                    let mut receiver = match message_receiver.lock() {
                                        Ok(receiver) => receiver,
                                        Err(e) => {
                                            log_and_display_error("Failed to acquire lock on message receiver", &e);
                                            return glib::ControlFlow::Continue;
                                        }
                                    };
                                    while let Some(message) = receiver.as_mut().unwrap().try_recv().ok() {
                                        let mut end_iter = message_buffer_clone.end_iter();
                                        message_buffer_clone.insert(&mut end_iter, &message);
                                        message_buffer_clone.insert(&mut end_iter, "\n");
                                    }
                                    glib::ControlFlow::Continue
                                });
                            }

                            let message_sender = match message_sender.lock() {
                                Ok(sender) => sender.clone(),
                                Err(e) => {
                                    log_and_display_error("Failed to acquire lock on message sender", &e);
                                    return;
                                }
                            };
                            let message_receiver_clone = Arc::clone(&message_receiver);
                            tokio::spawn(async move {
                                let receiver_in_spawn = match message_receiver_clone.lock() {
                                    Ok(mut receiver) => receiver.take().unwrap(),
                                    Err(e) => {
                                        log_and_display_error("Failed to acquire lock on message receiver", &e);
                                        return;
                                    }
                                };
                                match client::connect_to_node(config, target_addr, message_sender, receiver_in_spawn).await {
                                    Ok(_) => println!("Connected to the server"),
                                    Err(e) => log_and_display_error("Failed to connect to the server", &e),
                                }
                            });
                        }
                        _ => {}
                    }
                }
            });
        }));
        window.add_action(&connect_action);

        let shutdown_sender = Arc::new(Mutex::new(None::<oneshot::Sender<_>>));
        let shutdown_receiver = Arc::new(Mutex::new(None::<oneshot::Receiver<_>>));
        {
            let (sender, receiver) = oneshot::channel();
            if let Err(e) = shutdown_sender.lock().and_then(|mut locked_sender| {
                *locked_sender = Some(sender);
                Ok(())
            }) {
                log_and_display_error("Failed to acquire lock on shutdown_sender", &e);
            }
            if let Err(e) = shutdown_receiver.lock().and_then(|mut locked_receiver| {
                *locked_receiver = Some(receiver);
                Ok(())
            }) {
                log_and_display_error("Failed to acquire lock on shutdown_receiver", &e);
            }
        }

        let server_action = gio::SimpleAction::new_stateful("server", None, &false.into());
        let shutdown_sender_clone = Arc::clone(&shutdown_sender);
        let shutdown_receiver_clone = Arc::clone(&shutdown_receiver);
        server_action.connect_change_state(glib::clone!(@weak config_rc => move |action, state| {
            let is_active = state.unwrap().get::<bool>().expect("Failed to get state");
            action.set_state(&is_active.to_variant());

            if is_active {
                let config = config_rc.borrow().clone();

                // Reinitialize the shutdown_receiver and shutdown_sender
                let (new_sender, new_receiver) = oneshot::channel();
                if let Err(e) = shutdown_sender_clone.lock().and_then(|mut locked_sender| {
                    *locked_sender = Some(new_sender);
                    Ok(())
                }) {
                    log_and_display_error("Failed to acquire lock on shutdown_sender", &e);
                }
                if let Err(e) = shutdown_receiver_clone.lock().and_then(|mut locked_receiver| {
                    *locked_receiver = Some(new_receiver);
                    Ok(())
                }) {
                    log_and_display_error("Failed to acquire lock on shutdown_receiver", &e);
                }

                if let Some(shutdown_receiver) = shutdown_receiver_clone.lock().ok().and_then(|mut locked_receiver| locked_receiver.take()) {
                    tokio::spawn(async move {
                        node::run_server(config, shutdown_receiver).await;
                    });
                } else {
                    log_warning("Failed to get shutdown receiver");
                }
            } else {
                if let Some(shutdown_sender) = shutdown_sender_clone.lock().ok().and_then(|mut locked_sender| locked_sender.take()) {
                    glib::MainContext::default().spawn_local(async move {
                        node::stop_server(shutdown_sender).await;
                    });
                } else {
                    log_warning("Shutdown sender has already been taken");
                }
            }
        }));
        window.add_action(&server_action);

        let configure_action = gio::SimpleAction::new("configure", None);
        configure_action.connect_activate(glib::clone!(@weak window, @weak config_rc => move |_, _| {
            let dialog = gtk4::Dialog::with_buttons(
                Some("Configuration"),
                Some(&window),
                gtk4::DialogFlags::MODAL,
                &[("Save", gtk4::ResponseType::Accept), ("Cancel", gtk4::ResponseType::Cancel)],
            );

            let dialog_content_area = dialog.content_area();

            let config_text_view = TextView::builder()
                .editable(true)
                .build();

            let config_buffer = TextBuffer::builder().build();
            match std::fs::read_to_string("config.ini") {
                Ok(config_content) => config_buffer.set_text(&config_content),
                Err(e) => {
                    log_and_display_error("Failed to read configuration file", &e);
                    config_buffer.set_text("");
                }
            }
            config_text_view.set_buffer(Some(&config_buffer));

            dialog_content_area.append(&config_text_view);
            dialog.show();

            glib::MainContext::default().spawn_local({
                let config_rc = config_rc.clone();
                async move {
                    let dialog_response = dialog.run_future().await;
                    match dialog_response {
                        gtk4::ResponseType::Accept => {
                            let updated_config = config_buffer.text(&config_buffer.start_iter(), &config_buffer.end_iter(), false);
                            if let Err(e) = std::fs::write("config.ini", updated_config) {
                                log_and_display_error("Failed to write updated configuration", &e);
                            } else {
                                // Reload the configuration
                                let new_config = AppConfig::load_from_file("config.ini");
                                *config_rc.borrow_mut() = new_config;
                            }
                        }
                        _ => {}
                    }
                }
            });
        }));
        window.add_action(&configure_action);

        let quit_action = gio::SimpleAction::new("quit", None);
        quit_action.connect_activate(glib::clone!(@weak window => move |_, _| {
            window.close();
        }));
        window.add_action(&quit_action);

        let notebook = Notebook::builder()
            .vexpand(true)
            .build();

        let content_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .valign(gtk4::Align::Fill)
            .build();
        content_box.append(&notebook);

        let placeholder_label = Label::new(Some("No connections"));
        notebook.append_page(&placeholder_label, Some(&Label::new(Some("No connections"))));

        window.set_child(Some(&content_box));
        window.present();
    });

    app.run();
}