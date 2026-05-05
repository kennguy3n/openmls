// #[macro_use]
// extern crate clap;
// use clap::App;

use std::io::{stdin, stdout, StdoutLock, Write};
use termion::input::TermRead;

mod backend;
mod conversation;
mod identity;
mod networking;
mod openmls_rust_persistent_crypto;
mod serialize_any_hashmap;
mod user;

const HELP: &str = "
>>> Available commands:
>>>     - update                                update the client state
>>>     - reset                                 reset the server
>>>     - register {client name}                register a new client
>>>     - save {client name}                    serialize and save the client state
>>>     - load {client name}                    load and deserialize the client state as a new client
>>>     - autosave                              enable automatic save of the current client state upon each update
>>>     - create kp                             create a new key package
>>>     - create group {group name}             create a new group
>>>     - group {group name}                    group operations
>>>         - send {message}                    send message to group
>>>         - invite {client name}              invite a user to the group
>>>         - read                              read messages sent to the group (max 100)
>>>         - update                            update the client state

";

fn update(client: &mut user::User, group_id: Option<String>, stdout: &mut StdoutLock) {
    let messages = client.update(group_id).unwrap();
    stdout.write_all(b" >>> Updated client :)\n").unwrap();
    if !messages.is_empty() {
        stdout.write_all(b"     New messages:\n\n").unwrap();
    }
    messages.iter().for_each(|cm| {
        stdout
            .write_all(format!("         {0} from {1}\n", cm.message, cm.author).as_bytes())
            .unwrap();
    });
    stdout.write_all(b"\n").unwrap();
}

fn main() {
    pretty_env_logger::init();

    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout
        .write_all(b" >>> Welcome to the OpenMLS CLI :)\nType help to get a list of commands\n\n")
        .unwrap();
    let mut client = None;

    loop {
        stdout.flush().unwrap();
        let op = stdin.read_line().unwrap().unwrap();

        // Register a client.
        // There's no persistence. So once the client app stops you have to
        // register a new client.
        if let Some(client_name) = op.strip_prefix("register ") {
            client = Some(user::User::new(client_name.to_string()));
            client.as_mut().unwrap().add_key_package();
            client.as_mut().unwrap().add_key_package();
            client.as_mut().unwrap().register();
            stdout
                .write_all(format!("registered new client {client_name}\n\n").as_bytes())
                .unwrap();
            continue;
        }

        if let Some(client_name) = op.strip_prefix("load ") {
            match user::User::load(client_name.to_string()) {
                Ok(user) => {
                    client = Some(user);
                    stdout
                        .write_all(format!("recovered client {client_name}\n\n").as_bytes())
                        .unwrap();
                }
                Err(e) => stdout
                    .write_all(
                        format!("Error recovering client {client_name} : {e}\n\n").as_bytes(),
                    )
                    .unwrap(),
            }
            continue;
        }

        // Create a new KeyPackage.
        if op == "create kp" {
            if let Some(client) = &mut client {
                client.create_kp();
                stdout
                    .write_all(b" >>> New key package created\n\n")
                    .unwrap();
            } else {
                stdout
                    .write_all(b" >>> No client to update :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Save the current client state.
        if op == "save" {
            if let Some(client) = &mut client {
                client.save();
                let name = &client.identity.borrow().identity_as_string();
                stdout
                    .write_all(format!(" >>> client {name} state saved\n\n").as_bytes())
                    .unwrap();
            } else {
                stdout
                    .write_all(b" >>> No client to update :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Enable automatic saving of the client state.
        if op == "autosave" {
            if let Some(client) = &mut client {
                client.enable_auto_save();
                let name = &client.identity.borrow().identity_as_string();
                stdout
                    .write_all(format!(" >>> autosave enabled for client {name} \n\n").as_bytes())
                    .unwrap();
            } else {
                stdout
                    .write_all(b" >>> No client to update :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Create a new group, optionally with `--security-mode <mode>`.
        if let Some(rest) = op.strip_prefix("create group ") {
            if let Some(client) = &mut client {
                let (group_name, mode) = parse_create_group_args(rest);
                match mode {
                    Ok(mode) => match client.create_group_with_mode(group_name.clone(), mode) {
                        Ok(()) => stdout
                            .write_all(
                                format!(" >>> Created {mode:?} group {group_name} :)\n\n",)
                                    .as_bytes(),
                            )
                            .unwrap(),
                        Err(e) => stdout
                            .write_all(format!(" >>> create group failed: {e}\n\n").as_bytes())
                            .unwrap(),
                    },
                    Err(e) => stdout
                        .write_all(
                            format!(" >>> create group: invalid security mode: {e}\n\n").as_bytes(),
                        )
                        .unwrap(),
                }
            } else {
                stdout
                    .write_all(b" >>> No client to create a group :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Print the local DeviceCapability. Useful for sanity-checking
        // whether `--features xwing` / `--features mldsa` actually
        // turned on the corresponding PQ ciphersuites.
        if op.trim() == "capability" || op.trim() == "show capability" {
            if let Some(client) = &client {
                match client.device_capability() {
                    Ok(cap) => {
                        stdout
                            .write_all(format_capability(&cap).as_bytes())
                            .unwrap();
                    }
                    Err(e) => stdout
                        .write_all(format!(" >>> capability error: {e}\n\n").as_bytes())
                        .unwrap(),
                }
            } else {
                stdout
                    .write_all(b" >>> No client to show capability for :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Show what mode the local capability would negotiate down to
        // when the only peer is the local user (i.e. a "lone client"
        // sanity check). The CLI does not yet store remote
        // capabilities, so this is the most useful demo of the
        // `select_conversation_mode` API the CLI can offer.
        if op.trim() == "select-mode" {
            if let Some(client) = &client {
                match client.select_conversation_mode(&[]) {
                    Ok((mode, cs)) => stdout
                        .write_all(
                            format!(
                                " >>> select_conversation_mode (self only): mode={mode:?}, ciphersuite={cs:?}\n\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap(),
                    Err(e) => stdout
                        .write_all(format!(" >>> select-mode error: {e}\n\n").as_bytes())
                        .unwrap(),
                }
            } else {
                stdout
                    .write_all(b" >>> No client to select mode for :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Group operations.
        if let Some(group_name) = op.strip_prefix("group ") {
            if let Some(client) = &mut client {
                loop {
                    stdout.write_all(b" > ").unwrap();
                    stdout.flush().unwrap();
                    let op2 = stdin.read_line().unwrap().unwrap();

                    // Send a message to the group.
                    if let Some(msg) = op2.strip_prefix("send ") {
                        match client.send_msg(msg, group_name.to_string()) {
                            Ok(()) => stdout
                                .write_all(format!("sent message to {group_name}\n\n").as_bytes())
                                .unwrap(),
                            Err(e) => println!("Error sending group message: {e:?}"),
                        }
                        continue;
                    }

                    // Invite a client to the group.
                    if let Some(new_client) = op2.strip_prefix("invite ") {
                        client
                            .invite(new_client.to_string(), group_name.to_string())
                            .unwrap();
                        stdout
                            .write_all(
                                format!("added {new_client} to group {group_name}\n\n").as_bytes(),
                            )
                            .unwrap();
                        continue;
                    }

                    // Remove a client from the group.
                    if let Some(rem_client) = op2.strip_prefix("remove ") {
                        client
                            .remove(rem_client.to_string(), group_name.to_string())
                            .unwrap();
                        stdout
                            .write_all(
                                format!("Removed {rem_client} from group {group_name}\n\n")
                                    .as_bytes(),
                            )
                            .unwrap();
                        continue;
                    }

                    // Read messages sent to the group.
                    if op2 == "read" {
                        let messages = client.read_msgs(group_name.to_string()).unwrap();
                        if let Some(messages) = messages {
                            stdout
                                .write_all(
                                    format!(
                                        "{} has received {} messages\n\n",
                                        group_name,
                                        messages.len()
                                    )
                                    .as_bytes(),
                                )
                                .unwrap();
                        } else {
                            stdout
                                .write_all(format!("{group_name} has no messages\n\n").as_bytes())
                                .unwrap();
                        }
                        continue;
                    }

                    // Update the client state.
                    if op2 == "update" {
                        update(client, Some(group_name.to_string()), &mut stdout);
                        continue;
                    }

                    // Exit group.
                    if op2 == "exit" {
                        stdout.write_all(b" >>> Leaving group \n\n").unwrap();
                        break;
                    }

                    stdout
                        .write_all(b" >>> Unknown group command :(\n\n")
                        .unwrap();
                }
            } else {
                stdout.write_all(b" >>> No client :(\n\n").unwrap();
            }
            continue;
        }

        // Update the client state.
        if op == "update" {
            if let Some(client) = &mut client {
                update(client, None, &mut stdout);
            } else {
                stdout
                    .write_all(b" >>> No client to update :(\n\n")
                    .unwrap();
            }
            continue;
        }

        // Reset the server and client.
        if op == "reset" {
            backend::Backend::default().reset_server();
            client = None;
            stdout.write_all(b" >>> Reset server :)\n\n").unwrap();
            continue;
        }

        // Print help
        if op == "help" {
            stdout.write_all(HELP.as_bytes()).unwrap();
            continue;
        }

        stdout
            .write_all(b" >>> unknown command :(\n >>> try help\n\n")
            .unwrap();
    }
}

/// Parse the tail of a `create group <name> [--security-mode <mode>]`
/// command. Returns the group name and the parsed mode (or a parse
/// error from [`conversation::CliSecurityMode::parse`]).
///
/// Accepts both `--security-mode <mode>` (long form) and a bare
/// trailing `<mode>` keyword as the second whitespace-separated
/// token, so existing scripts that only pass a group name keep
/// working (mode defaults to Classical in that case). Multi-word
/// group names where no token is a valid security-mode keyword are
/// preserved verbatim — only the long `--security-mode` form is
/// interpreted unconditionally.
fn parse_create_group_args(rest: &str) -> (String, Result<conversation::CliSecurityMode, String>) {
    let trimmed = rest.trim();
    if let Some(idx) = trimmed.find("--security-mode") {
        let group_name = trimmed[..idx].trim().to_string();
        let mode_str = trimmed[idx + "--security-mode".len()..].trim();
        return (group_name, conversation::CliSecurityMode::parse(mode_str));
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    match parts.as_slice() {
        [] => (String::new(), Ok(conversation::CliSecurityMode::Classical)),
        [name] => (
            (*name).to_string(),
            Ok(conversation::CliSecurityMode::Classical),
        ),
        [name, maybe_mode] => {
            // Treat the second token as a security mode only if it
            // actually parses as one. Otherwise fall back to the
            // legacy "the entire tail is the group name" behaviour
            // so two-word names like "MLS Discussions" keep working.
            match conversation::CliSecurityMode::parse(maybe_mode) {
                Ok(mode) => ((*name).to_string(), Ok(mode)),
                Err(_) => (
                    trimmed.to_string(),
                    Ok(conversation::CliSecurityMode::Classical),
                ),
            }
        }
        _ => {
            // Three or more whitespace-separated tokens — treat the
            // whole tail as the group name to preserve the legacy
            // "names with spaces" behaviour.
            (
                trimmed.to_string(),
                Ok(conversation::CliSecurityMode::Classical),
            )
        }
    }
}

/// Pretty-print a [`openmls::credentials::DeviceCapability`] for the
/// CLI `capability` command.
fn format_capability(cap: &openmls::credentials::DeviceCapability) -> String {
    let mut out = String::new();
    out.push_str(" >>> DeviceCapability\n");
    out.push_str(&format!("       mls_version: {}\n", cap.mls_version));
    out.push_str(&format!(
        "       classical_ciphersuites: {:?}\n",
        cap.classical_ciphersuites
    ));
    out.push_str(&format!(
        "       pq_ciphersuites: {:?}\n",
        cap.pq_ciphersuites
    ));
    out.push_str(&format!("       apq_supported: {}\n", cap.apq_supported));
    out.push_str(&format!(
        "       pq_auth_supported: {}\n",
        cap.pq_auth_supported
    ));
    out.push_str(&format!("       provider_id: {}\n", cap.provider_id));
    out.push_str(&format!(
        "       capability_signature: {} bytes\n\n",
        cap.capability_signature.as_slice().len(),
    ));
    out
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use conversation::CliSecurityMode;

    #[test]
    fn parse_security_mode_accepts_canonical_strings() {
        assert_eq!(
            CliSecurityMode::parse("classical").unwrap(),
            CliSecurityMode::Classical
        );
        assert_eq!(
            CliSecurityMode::parse("pq-confidentiality").unwrap(),
            CliSecurityMode::PqConfidentiality
        );
        assert_eq!(
            CliSecurityMode::parse("pq-authenticity").unwrap(),
            CliSecurityMode::PqAuthenticity
        );
    }

    #[test]
    fn parse_security_mode_is_case_insensitive_and_accepts_synonyms() {
        assert_eq!(
            CliSecurityMode::parse("PQ-CONF").unwrap(),
            CliSecurityMode::PqConfidentiality
        );
        assert_eq!(
            CliSecurityMode::parse(" Authenticity ").unwrap(),
            CliSecurityMode::PqAuthenticity
        );
    }

    #[test]
    fn parse_security_mode_rejects_garbage() {
        assert!(CliSecurityMode::parse("nonsense").is_err());
    }

    #[test]
    fn parse_create_group_long_form() {
        let (name, mode) = parse_create_group_args("foo --security-mode pq-confidentiality");
        assert_eq!(name, "foo");
        assert_eq!(mode.unwrap(), CliSecurityMode::PqConfidentiality);
    }

    #[test]
    fn parse_create_group_short_form() {
        let (name, mode) = parse_create_group_args("foo pq-authenticity");
        assert_eq!(name, "foo");
        assert_eq!(mode.unwrap(), CliSecurityMode::PqAuthenticity);
    }

    #[test]
    fn parse_create_group_classical_default() {
        let (name, mode) = parse_create_group_args("foo");
        assert_eq!(name, "foo");
        assert_eq!(mode.unwrap(), CliSecurityMode::Classical);
    }

    #[test]
    fn parse_create_group_preserves_legacy_names_with_spaces() {
        // Existing scripts that pass `create group MLS Discussions`
        // must still get a Classical group with the full multi-word
        // name preserved.
        let (name, mode) = parse_create_group_args("MLS Discussions test");
        assert_eq!(name, "MLS Discussions test");
        assert_eq!(mode.unwrap(), CliSecurityMode::Classical);
    }

    #[test]
    fn parse_create_group_two_word_name_falls_back_to_classical() {
        // Two whitespace-separated tokens where the second token is
        // not a valid security mode keyword must be preserved as a
        // single multi-word group name, not split into name+mode.
        let (name, mode) = parse_create_group_args("MLS Discussions");
        assert_eq!(name, "MLS Discussions");
        assert_eq!(mode.unwrap(), CliSecurityMode::Classical);
    }

    #[test]
    fn user_emits_signed_device_capability() {
        let user = user::User::new("test-cap-user".to_string());
        let cap = user
            .device_capability()
            .expect("device_capability must succeed");
        assert!(
            cap.is_signed(),
            "device_capability should be signed by default"
        );
        assert_eq!(cap.provider_id, "rustcrypto-cli");
        assert_eq!(cap.mls_version, 1);
        assert!(
            !cap.classical_ciphersuites.is_empty(),
            "classical capabilities must be non-empty"
        );
    }

    #[test]
    fn select_conversation_mode_with_only_self_returns_classical_or_pq() {
        let user = user::User::new("test-select-user".to_string());
        let (mode, cs) = user
            .select_conversation_mode(&[])
            .expect("select_conversation_mode with self only must succeed");
        // Without the `xwing` feature the local cap has no PQ suites,
        // so the selected mode must be Classical. With the feature
        // turned on, the selected mode may be higher.
        #[cfg(not(feature = "xwing"))]
        {
            use openmls::ciphersuite::security_mode::SecurityMode;
            assert_eq!(mode, SecurityMode::Classical);
        }
        // The selected ciphersuite must always parse to a known
        // RFC 9420 / draft codepoint we recognise.
        let _ = u16::from(cs);
        // Silence unused-variable warnings when xwing is enabled
        // (mode is not asserted on in that branch).
        let _ = mode;
    }
}

#[test]
#[ignore]
fn basic_test() {
    // Reset the server before doing anything for testing.
    backend::Backend::default().reset_server();

    const MESSAGE_1: &str = "Thanks for adding me Client1.";
    const MESSAGE_2: &str = "Welcome Client3.";
    const MESSAGE_3: &str = "Thanks so much for the warm welcome! 😊";

    // Create one client
    let mut client_1 = user::User::new("Client1".to_string());

    // Create another client
    let mut client_2 = user::User::new("Client2".to_string());

    // Create another client
    let mut client_3 = user::User::new("Client3".to_string());

    // Update the clients to know about the other clients.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 creates a group.
    client_1.create_group("MLS Discussions".to_string());

    // Client 1 adds Client 2 to the group.
    client_1
        .invite("Client2".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Client 2 retrieves messages.
    client_2.update(None).unwrap();

    // Client 2 sends a message.
    client_2
        .send_msg(MESSAGE_1, "MLS Discussions".to_string())
        .unwrap();

    // Client 1 retrieves messages.
    client_1.update(None).unwrap();

    // Check that Client 1 received the message
    assert_eq!(
        client_1.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_1.to_owned(),
            "Client2".to_owned(),
        )])
    );

    // Client 2 adds Client 3 to the group.
    client_2
        .invite("Client3".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 sends a message.
    client_1
        .send_msg(MESSAGE_2, "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Check that Client 2 and Client 3 received the message
    assert_eq!(
        client_2.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );
    assert_eq!(
        client_3.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );

    // Client 3 sends a message.
    client_3
        .send_msg(MESSAGE_3, "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Check that Client 1 and Client 2 received the message
    assert_eq!(
        client_1.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_1.to_owned(), "Client2".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );
    assert_eq!(
        client_2.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_2.to_owned(), "Client1".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );
}
