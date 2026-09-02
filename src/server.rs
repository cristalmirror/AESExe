/* ################# AESExe V 0.4.0 #################
    Archive: server.rs
    Version: 0.4.0
    License: GPL-v3.0
    #################################################

    This archive content all function to create a
    local web server that can do the cipher archves
    by mean of client web in your browser.

    This has create because in LAN networks can use to
    like a web app and don't need install nothing in your
    computer.

    I know that is possible make beter but using freameworks.
    
*/


use crate::{aes::Aes, chacha20::ChaCha20, cipher::BlockCipher, keys, stream};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::Deserialize;
use std::{
    fs,
    io::{self, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    thread,
};

/* define the max users can suport in networks */
const MAX_REQUEST: usize = 8 * 1024 * 1024;
const CORS: &str = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n";

/*
 * Data users definitions:
 *
 * This software has designing to a organization
 * that worked with this users data, may be if
 * need change this in the fure because a login
 * system is realy a best choice actualy.
 */
#[derive(Deserialize)]
struct ApiRequest {
    #[serde(default)]
    cuil: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    algo: String,
    #[serde(default)]
    key: String,
}


/* Loader sever fuction */

pub fn run(ip: &str, port: u16) -> io::Result<()> {
    let config = Arc::new(tls_config()?);
    let listener = TcpListener::bind((ip, port))?;
    println!("[AESExe] servidor HTTPS en https://{ip}:{port}");
    for socket in listener.incoming() {
        let socket = socket?;
        let config = config.clone();
        thread::spawn(move || {
            if let Err(e) = serve(socket, config) {
                eprintln!("[AESExe] conexión: {e}")
            }
        });
    }
    Ok(())
}

/*
 * The loader of SSL/TSL protocol has write to work
 * with certs and keys in local networks but self-signature.
 *
 * I know, this is garbage but the client allways have the reason...
 */
fn tls_config() -> io::Result<ServerConfig> {
    let mut cert = BufReader::new(fs::File::open("server.crt")?);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert).collect::<Result<_, _>>()?;
    let mut key = BufReader::new(fs::File::open("server.key")?);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "server.key no contiene una clave privada",
        )
    })?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)
}

/*
 * Maker of SSL/TSL cipher channel.
 */
fn serve(socket: TcpStream, config: Arc<ServerConfig>) -> io::Result<()> {
    let conn = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, socket);
    let req = read_request(&mut tls)?;
    route(&mut tls, &req)
}

/* read a complete HTTP request */
fn read_request(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    let mut buf = [0; 4096];
    let mut target = None;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
        if all.len() > MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "petición demasiado grande",
            ));
        }
        if target.is_none()
            && let Some(p) = all.windows(4).position(|x| x == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&all[..p]);
            let len = headers
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            target = Some(p + 4 + len)
        }
        if target.is_some_and(|t| all.len() >= t) {
            all.truncate(target.unwrap());
            break;
        }
    }
    Ok(all)
}

/*
 * route of operation:
 *
 * Make a instance of cipher object of the operation
 * need to client.
 */
fn route(w: &mut dyn Write, raw: &[u8]) -> io::Result<()> {
    let split = raw
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP inválido"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("");
    let path = first.next().unwrap_or("");
    let body = &raw[split + 4..];
    match (method, path) { //maybe will be use a freamwork in the future and not this match 
        ("OPTIONS", _) => response(w, 204, "text/plain", b""),
        ("GET", "/") => static_file(w, "client/index/index.html", "text/html"),
        ("GET", "/src/main.js") => static_file(w, "client/src/main.js", "application/javascript"),
        ("GET", "/style/style.css") => static_file(w, "client/style/style.css", "text/css"),
        ("POST", "/encrypt") => encrypt(w, body),
        ("POST", "/decrypt") => decrypt(w, body),
        _ => response(w, 404, "text/plain", b"Not Found"),
    }
}


fn valid_cuil(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}



/* This funcion define the algorithm used in the encrypt or decrypt
 * function.
 */
fn cipher(algo: &str, key: &[u8]) -> io::Result<Box<dyn BlockCipher>> {
    match algo {
        "aes128" | "aes192" | "aes256" => Ok(Box::new(Aes::new(key)?)),
        "chacha20" => Ok(Box::new(ChaCha20::new(key)?)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "algoritmo desconocido",
        )),
    }
}

/* parse to JSON type the request */
fn parse(body: &[u8]) -> Result<ApiRequest, serde_json::Error> {
    serde_json::from_slice(body)
}


fn encrypt(w: &mut dyn Write, body: &[u8]) -> io::Result<()> {
    let req = match parse(body) {
        Ok(v) => v,
        Err(_) => return response(w, 400, "text/plain", b"Invalid JSON"),
    };
    if !valid_cuil(&req.cuil) || req.data.is_empty() {
        return response(w, 400, "text/plain", b"Missing CUIL, data or algo");
    }
    let key = match keys::generate(&req.algo) {
        Ok(k) => k,
        Err(_) => return response(w, 400, "text/plain", b"Unknown algorithm"),
    };
    let mut cipher = cipher(&req.algo, &key)?;
    let mut encrypted = Vec::new();
    stream::process(&mut *cipher, &mut req.data.as_bytes(), &mut encrypted, true)?;
    fs::create_dir_all("store")?;
    fs::write(format!("store/{}.aes", req.cuil), encrypted)?;
    response(w, 200, "application/octet-stream", &key)
}
fn decrypt(w: &mut dyn Write, body: &[u8]) -> io::Result<()> {
    let req = match parse(body) {
        Ok(v) => v,
        Err(_) => return response(w, 400, "text/plain", b"Invalid JSON"),
    };
    if !valid_cuil(&req.cuil) || req.key.is_empty() {
        return response(w, 400, "text/plain", b"Missing CUIL, key or algo");
    }
    let key = match STANDARD.decode(req.key) {
        Ok(k) => k,
        Err(_) => return response(w, 400, "text/plain", b"Invalid key"),
    };
    let encrypted = match fs::read(format!("store/{}.aes", req.cuil)) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return response(
                w,
                404,
                "text/plain",
                b"No encrypted file found for this CUIL",
            );
        }
        Err(e) => return Err(e),
    };
    let mut cipher = match cipher(&req.algo, &key) {
        Ok(c) => c,
        Err(_) => return response(w, 400, "text/plain", b"Invalid key or algorithm"),
    };
    let mut plain = Vec::new();
    stream::process(&mut *cipher, &mut encrypted.as_slice(), &mut plain, false)?;
    response(w, 200, "text/plain; charset=utf-8", &plain)
}
fn static_file(w: &mut dyn Write, path: &str, content_type: &str) -> io::Result<()> {
    match fs::read(Path::new(path)) {
        Ok(data) => response(w, 200, content_type, &data),
        Err(_) => response(w, 404, "text/plain", b"Not Found"),
    }
}

/* Error and Successful response server */
fn response(w: &mut dyn Write, status: u16, ct: &str, body: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    write!(
        w,
        "HTTP/1.1 {status} {reason}\r\n{CORS}Content-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    w.write_all(body)?;
    w.flush()
}
