use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;
use uu_linux_client::config::ClientConfig;
use uu_linux_client::evidence::EvidenceManifest;
use uu_linux_client::tun::LinuxTunBackend;

#[derive(Debug, Parser)]
#[command(name = "uu-linux-client")]
#[command(about = "Headless UU LAN Play Linux client foundation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a local client configuration without touching TUN or the network.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Verify an extracted Windows artifact against a versioned evidence manifest.
    VerifyEvidence {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        path: PathBuf,
    },
    /// Start the native Linux room client.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "uu0")]
        interface: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { config } => check(config),
        Command::VerifyEvidence {
            manifest,
            artifact,
            path,
        } => verify_evidence(manifest, &artifact, path),
        Command::Run { config, interface } => run(config, interface),
    }
}

fn check(path: PathBuf) -> ExitCode {
    match ClientConfig::load(path) {
        Ok(config) => emit(
            0,
            json!({
                "ok": true,
                "config": config.diagnostics(),
                "protocol_implemented": true,
                "live_accepted": false,
                "safe_to_replace_vm": false
            }),
        ),
        Err(error) => emit(
            2,
            json!({"ok": false, "code": "invalid_config", "error": error.to_string()}),
        ),
    }
}

fn verify_evidence(manifest_path: PathBuf, artifact: &str, path: PathBuf) -> ExitCode {
    let manifest = match fs::read_to_string(&manifest_path) {
        Ok(input) => match EvidenceManifest::from_json(&input) {
            Ok(manifest) => manifest,
            Err(error) => {
                return emit(
                    2,
                    json!({"ok": false, "code": "invalid_manifest", "error": error.to_string()}),
                );
            }
        },
        Err(error) => {
            return emit(
                2,
                json!({"ok": false, "code": "manifest_unreadable", "error": error.to_string()}),
            );
        }
    };

    match manifest.verify_artifact(artifact, &path) {
        Ok(()) => emit(
            0,
            json!({"ok": true, "artifact": artifact, "verified": true}),
        ),
        Err(error) => emit(
            3,
            json!({"ok": false, "code": "evidence_mismatch", "error": error.to_string()}),
        ),
    }
}

fn run(config_path: PathBuf, interface: String) -> ExitCode {
    let config = match ClientConfig::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            return emit(
                2,
                json!({"ok": false, "code": "invalid_config", "error": error.to_string()}),
            );
        }
    };
    if let Err(error) = LinuxTunBackend::new(interface.clone()) {
        return emit(
            2,
            json!({"ok": false, "code": "invalid_interface", "error": error.to_string()}),
        );
    }
    if config.vlan_session_for_api().is_none()
        && let Err(error) = config.official_login_credentials()
    {
        return emit(
            2,
            json!({
                "ok": false,
                "code": "credentials_missing",
                "state": "stopped",
                "error": error.to_string()
            }),
        );
    }

    match run_platform(&config, interface) {
        Ok(()) => emit(0, json!({"ok": true, "state": "stopped"})),
        Err(error) => emit(
            4,
            json!({
                "ok": false,
                "code": "runtime_failed",
                "state": "stopped",
                "room_id": config.room_id(),
                "error": error
            }),
        ),
    }
}

#[cfg(target_os = "linux")]
fn run_platform(config: &ClientConfig, interface: String) -> Result<(), String> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use signal_hook::consts::signal::{SIGINT, SIGTERM};
    use uu_linux_client::official_api::OfficialApiClient;
    use uu_linux_client::session::{SessionSettings, TcpRoomSession};
    use uu_linux_client::tun::{
        TunBackend, configure_linux_interface, configure_linux_member_routes,
        linux_interface_commands,
    };
    use uu_linux_client::workers::{BridgeWorkers, WorkerSettings};

    let local_address = match config.overlay_address() {
        IpAddr::V4(address) => address,
        other => return Err(format!("IPv6 overlay addresses are unsupported: {other}")),
    };
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, stop.clone()).map_err(|error| error.to_string())?;
    signal_hook::flag::register(SIGTERM, stop.clone()).map_err(|error| error.to_string())?;
    let (api, joined) = if let Some(vlan_session) = config.vlan_session_for_api() {
        let api = OfficialApiClient::new_with_vlan_session(vlan_session)
            .map_err(|error| error.to_string())?;
        let joined = api
            .resume_room(config.room_id())
            .map_err(|error| error.to_string())?;
        (api, joined)
    } else {
        let credentials = config
            .official_login_credentials()
            .map_err(|error| error.to_string())?;
        let api = OfficialApiClient::new().map_err(|error| error.to_string())?;
        let joined = api
            .login_and_join_first_available(
                &credentials,
                config.room_id(),
                config.room_password_for_api(),
            )
            .map_err(|error| error.to_string())?;
        (api, joined)
    };

    let core_result = (|| {
        let (bootstrap, members) = joined.into_parts();
        if bootstrap.client_lan_ip() != local_address {
            return Err(format!(
                "overlay address mismatch: configured {local_address}, server assigned {}",
                bootstrap.client_lan_ip()
            ));
        }
        let overlay_network = bootstrap.client_lan_net().to_owned();
        linux_interface_commands(&interface, local_address, &overlay_network)
            .map_err(|error| error.to_string())?;
        let endpoint = bootstrap.server_endpoint();
        let request = bootstrap.auth_request();
        let session = TcpRoomSession::connect(
            endpoint,
            &request,
            SessionSettings::new(Duration::from_secs(5), Duration::from_secs(1)),
        )
        .map_err(|error| error.to_string())?;

        let mut backend = LinuxTunBackend::new(interface.clone()).map_err(|e| e.to_string())?;
        let mut tun = backend
            .create(IpAddr::V4(local_address))
            .map_err(|error| error.to_string())?;
        if let Err(error) = configure_linux_interface(&interface, local_address, &overlay_network) {
            let _ = tun.close();
            return Err(error.to_string());
        }
        let mut routed_members = members
            .online()
            .iter()
            .map(|member| member.client_lan_ip())
            .collect::<Vec<_>>();
        if let Err(error) = configure_linux_member_routes(
            &interface,
            local_address,
            &overlay_network,
            &[],
            &routed_members,
        ) {
            let _ = tun.close();
            return Err(error.to_string());
        }

        let workers = match BridgeWorkers::start(
            tun.as_ref(),
            &session,
            local_address,
            &overlay_network,
            &members,
            WorkerSettings::new(Duration::from_millis(2), Duration::from_secs(10)),
        ) {
            Ok(workers) => workers,
            Err(error) => {
                let _ = tun.close();
                return Err(error.to_string());
            }
        };
        println!(
            "{}",
            json!({
                "ok": true,
                "state": "running",
                "room_id": config.room_id(),
                "interface": interface,
                "overlay_address": local_address,
                "live_accepted": false
            })
        );

        let mut failure = None;
        let mut refresh_at = Instant::now() + Duration::from_secs(5);
        let mut refresh_failures = 0_u8;
        while !stop.load(Ordering::Acquire) {
            if let Some(worker_failure) = workers.wait_for_failure(Duration::from_millis(250)) {
                failure = Some(format!(
                    "{:?} worker failed: {}",
                    worker_failure.direction(),
                    worker_failure.error()
                ));
                break;
            }
            if Instant::now() < refresh_at {
                continue;
            }
            refresh_at = Instant::now() + Duration::from_secs(5);
            match api.room_info(config.room_id()) {
                Ok(refreshed) => {
                    refresh_failures = 0;
                    let refreshed_bootstrap = refreshed.bootstrap();
                    if refreshed_bootstrap.server_endpoint() != endpoint
                        || refreshed_bootstrap.client_lan_ip() != local_address
                        || refreshed_bootstrap.client_lan_net() != overlay_network
                    {
                        failure = Some(
                            "room transport assignment changed; restarting before using stale routing"
                                .to_owned(),
                        );
                        break;
                    }
                    let refreshed_members = refreshed
                        .members()
                        .online()
                        .iter()
                        .map(|member| member.client_lan_ip())
                        .collect::<Vec<_>>();
                    if let Err(error) = configure_linux_member_routes(
                        &interface,
                        local_address,
                        &overlay_network,
                        &routed_members,
                        &refreshed_members,
                    ) {
                        failure = Some(error.to_string());
                        break;
                    }
                    if let Err(error) = workers.update_members(refreshed.members()) {
                        failure = Some(error.to_string());
                        break;
                    }
                    routed_members = refreshed_members;
                }
                Err(error) => {
                    refresh_failures = refresh_failures.saturating_add(1);
                    if refresh_failures >= 3 {
                        failure = Some(format!("three consecutive room refreshes failed: {error}"));
                        break;
                    }
                }
            }
        }

        let worker_cleanup = workers.shutdown().map_err(|error| error.to_string());
        let tun_cleanup = tun.close().map_err(|error| error.to_string());
        if let Some(error) = failure {
            return Err(error);
        }
        worker_cleanup?;
        tun_cleanup?;
        Ok(())
    })();

    let offline_result = api.set_offline().map_err(|error| error.to_string());
    match (core_result, offline_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(format!("room stopped but offline update failed: {error}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_platform(_config: &ClientConfig, _interface: String) -> Result<(), String> {
    let _ = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    Err("the native UU client can run only on Linux".to_owned())
}

fn emit(code: u8, value: serde_json::Value) -> ExitCode {
    println!("{value}");
    ExitCode::from(code)
}
