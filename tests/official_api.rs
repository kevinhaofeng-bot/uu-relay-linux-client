use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use serde_json::Value;
use uu_linux_client::official_api::{LoginCredentials, OfficialApiClient};

#[test]
fn existing_vlan_session_reads_current_room_without_bridge_login() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture address");
    let (requests_tx, requests_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture client");
        requests_tx
            .send(read_request(&mut stream))
            .expect("record request");
        stream
            .write_all(join_response().as_bytes())
            .expect("write fixture response");
    });

    let base_url = format!("http://{endpoint}/vlan/api/");
    let client = OfficialApiClient::new_for_loopback_test_with_vlan_session(
        &base_url,
        "fixture-cookie-secret",
    )
    .expect("fixture client");

    let room = client.room_info("AB12345").expect("cookie session works");
    assert!(room.self_is_online());

    let request = requests_rx.recv().expect("room info request");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/vlan/api/room/info");
    assert!(
        request
            .cookie
            .contains("vlan_session=fixture-cookie-secret")
    );
    server.join().expect("fixture server finished");
}

#[test]
fn existing_vlan_session_transitions_offline_self_online() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture address");
    let (requests_tx, requests_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for response in [
            offline_join_response(),
            empty_success_response(),
            join_response(),
        ] {
            let (mut stream, _) = listener.accept().expect("accept fixture client");
            requests_tx
                .send(read_request(&mut stream))
                .expect("record request");
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
        }
    });

    let base_url = format!("http://{endpoint}/vlan/api/");
    let client = OfficialApiClient::new_for_loopback_test_with_vlan_session(
        &base_url,
        "fixture-cookie-secret",
    )
    .expect("fixture client");

    let joined = client
        .resume_room("AB12345")
        .expect("existing room session resumes");
    assert!(joined.self_is_online());
    assert_eq!(requests_rx.recv().unwrap().path, "/vlan/api/room/info");
    assert_eq!(requests_rx.recv().unwrap().path, "/vlan/api/room/online");
    assert_eq!(requests_rx.recv().unwrap().path, "/vlan/api/room/info");
    server.join().expect("fixture server finished");
}

#[test]
fn login_select_first_acceleration_server_and_join_preserve_cookie_session() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture address");
    let (requests_tx, requests_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for response in [
            login_response(),
            accs_response(),
            join_response(),
            join_response(),
            empty_success_response(),
        ] {
            let (mut stream, _) = listener.accept().expect("accept fixture client");
            let request = read_request(&mut stream);
            requests_tx.send(request).expect("record request");
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
        }
    });

    let base_url = format!("http://{endpoint}/vlan/api/");
    let client = OfficialApiClient::new_for_loopback_test(&base_url).expect("fixture client");
    let credentials = LoginCredentials::new("session-fixture", "token-fixture", "13800000000")
        .expect("valid fixture credentials");

    let joined = client
        .login_and_join_first_available(&credentials, "AB12345", "room-fixture")
        .expect("official flow succeeds");

    assert_eq!(joined.bootstrap().room_id(), "AB12345");
    assert_eq!(
        joined.bootstrap().client_lan_ip().to_string(),
        "172.19.163.2"
    );
    assert_eq!(joined.members().online().len(), 1);
    let refreshed = client
        .room_info("AB12345")
        .expect("room info refresh succeeds");
    assert_eq!(refreshed.members().online().len(), 1);
    client.set_offline().expect("offline status succeeds");

    let login = requests_rx.recv().expect("login request");
    assert_eq!(login.method, "POST");
    assert_eq!(login.path, "/vlan/api/login/win/");
    assert_eq!(
        login.json(),
        serde_json::json!({
            "session_id":"session-fixture",
            "token":"token-fixture",
            "mobile":"13800000000"
        })
    );

    let accs = requests_rx.recv().expect("accs request");
    assert_eq!(accs.method, "GET");
    assert_eq!(accs.path, "/vlan/api/accs");
    assert!(accs.cookie.contains("fixture-session=ready"));

    let join = requests_rx.recv().expect("join request");
    assert_eq!(join.method, "POST");
    assert_eq!(join.path, "/vlan/api/room/join");
    assert!(join.cookie.contains("fixture-session=ready"));
    assert_eq!(
        join.json(),
        serde_json::json!({
            "room_id":"AB12345",
            "room_password":"room-fixture",
            "server_id":17
        })
    );

    let room_info = requests_rx.recv().expect("room info request");
    assert_eq!(room_info.method, "GET");
    assert_eq!(room_info.path, "/vlan/api/room/info");
    assert!(room_info.cookie.contains("fixture-session=ready"));

    let offline = requests_rx.recv().expect("offline request");
    assert_eq!(offline.method, "POST");
    assert_eq!(offline.path, "/vlan/api/room/offline");
    assert!(offline.body.is_empty());

    server.join().expect("fixture server finished");
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("session-fixture"));
    assert!(!debug.contains("token-fixture"));
    assert!(!debug.contains("13800000000"));
}

#[test]
fn join_transitions_offline_self_online_before_returning() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture address");
    let (requests_tx, requests_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for response in [
            offline_join_response(),
            empty_success_response(),
            join_response(),
        ] {
            let (mut stream, _) = listener.accept().expect("accept fixture client");
            requests_tx
                .send(read_request(&mut stream))
                .expect("record request");
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });
    let client = OfficialApiClient::new_for_loopback_test(&format!("http://{endpoint}/vlan/api/"))
        .expect("loopback fixture client");

    let joined = client
        .join_room("AB12345", "", None)
        .expect("offline join transitions online");

    assert!(joined.self_is_online());
    assert_eq!(requests_rx.recv().unwrap().path, "/vlan/api/room/join");
    assert_eq!(requests_rx.recv().unwrap().path, "/vlan/api/room/online");
    assert_eq!(requests_rx.recv().unwrap().path, "/vlan/api/room/info");
    server.join().expect("fixture server finished");
}

struct CapturedRequest {
    method: String,
    path: String,
    cookie: String,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("request JSON")
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read fixture request");
        assert!(read > 0, "request ended before headers");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).expect("ASCII request headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
        })
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut chunk).expect("read fixture body");
        assert!(read > 0, "request ended before body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    let request_line = headers.lines().next().expect("request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().expect("method").to_owned();
    let path = request_parts.next().expect("path").to_owned();
    let cookie = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("cookie")
                    .then(|| value.trim().to_owned())
            })
        })
        .unwrap_or_default();
    CapturedRequest {
        method,
        path,
        cookie,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

fn response(body: &str, extra_headers: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
        body.len(),
        extra_headers,
        body
    )
}

fn login_response() -> String {
    response(
        r#"{"code":200,"data":{}}"#,
        "Set-Cookie: fixture-session=ready; Path=/; HttpOnly\r\n",
    )
}

fn accs_response() -> String {
    response(r#"{"code":200,"data":[{"server_id":17}]}"#, "")
}

fn join_response() -> String {
    response(
        r#"{
          "code":200,
          "data":{
            "room":{"room_id":"AB12345","password":"room-secret","members":[
              {"is_self":true,"is_online":true,"client_lan_ip":"172.19.163.2","server_ip":"203.0.113.8","server_port":4013},
              {"is_self":false,"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4014}
            ]},
            "user":{"user_id":"fixture-user"},
            "app":{"client_lan_net":"172.19.163.0/24","acc":"fixture-acc","client":"fixture"}
          }
        }"#,
        "",
    )
}

fn empty_success_response() -> String {
    response(r#"{"code":200,"data":{}}"#, "")
}

fn offline_join_response() -> String {
    response(
        r#"{"code":200,"data":{"room":{"room_id":"AB12345","password":"room-secret","members":[{"is_self":true,"is_online":false,"client_lan_ip":"172.19.163.2","server_ip":"203.0.113.8","server_port":4013}]},"user":{"user_id":"account-user"},"app":{"client_lan_net":"172.19.163.0/24","acc":"acc-secret"}}}"#,
        "",
    )
}
