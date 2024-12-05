// use aes::cipher::generic_array::sequence::GenericSequence;
use aes_gcm::aead::{AeadMutInPlace, KeyInit, Nonce};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use bincode;
use clap::Parser;
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::{env, vec};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream, UdpSocket,
};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
// use generic_array::GenericArray;
// use generic_array::typenum::U32;

#[derive(Parser)]
struct Local {
    #[arg(short = 'l', help = "address to listening", required = false)]
    local: Option<String>,

    #[arg(short = 'p', help = "port to listening")]
    port: Option<String>,

    #[arg(short = 'X', help = "Execute Your Command to client")]
    x: bool,

    #[arg(short = 'u', help = "UDP mode")]
    u: bool,

    #[arg(short = 't', help = "UDP server address")]
    target_ip: Option<String>,

    #[arg(short = 'o', long = "target-port", help = "Port for UDP server")]
    target_port: Option<String>,

    #[arg(short = 'P', help = "send UDP packet to server")]
    udp_client: bool,

    #[arg(
        short = 'f',
        long = "file",
        help = "File, path for the file",
        required = false
    )]
    file_name: Option<String>,

    #[arg(long = "use-file", help = "for using the file flag")]
    use_file: bool,

    #[arg(
        long = "secure-connection",
        short = 'S',
        help = "Secure connection with aes_gcm and rsa"
    )]
    secure: bool,

    #[arg(
        long = "client-secure",
        short = 's',
        help = "compatiable with secure-connection TCP"
    )]
    client_secure: bool,
}

async fn generate_rsa_key() -> Result<(RsaPublicKey, RsaPrivateKey), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate");
    // println!("rsa key: {:?}", private_key);
    let public_key = RsaPublicKey::from(&private_key);
    Ok((public_key, private_key))
}

async fn decryption_aes_gcm(
    nonce: Vec<u8>,
    key: Vec<u8>,
    mut encryption_msg: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    println!("Decrypting the output");
    // println!("2");
    let key = Key::<aes_gcm::Aes256Gcm>::from_slice(&key);
    // println!("4");

    let mut cipher = Aes256Gcm::new(&key);
    // println!("5");

    let nonce = Nonce::<aes_gcm::Aes256Gcm>::from_slice(&nonce);
    // println!("6");

    let _ = cipher.decrypt_in_place(&nonce, b"", &mut encryption_msg);

    // let encrypted_msg_len = encryption_msg.len();
    let decrypted_msg = String::from_utf8(encryption_msg).map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UTF-8 conversion failed: {}", e),
        )) as Box<dyn std::error::Error + Send + Sync>
    })?;

    // println!("cipher text: {}",String::from_utf8_lossy(&encryption_msg[..encrypted_msg_len]));

    Ok(decrypted_msg)
}

async fn dec_key_with_rsa(
    dec_key: Vec<u8>,
    rsa_priv_key: RsaPrivateKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // println!("Decrypting the aes key with rsa");
    let dec_data = rsa_priv_key.decrypt(Pkcs1v15Encrypt, &dec_key)?;
    Ok(dec_data)
}

// client side function
async fn enc_key_with_rsa(
    public_key: Vec<u8>,
    key: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    println!("Encrypting the aes key with rsa encryption.");
    let public_key = RsaPublicKey::from_pkcs1_der(&public_key)?;

    // let key = Key::<aes_gcm::Aes256Gcm>::from_slice(&key);
    let aes_key_bytes = key.as_slice();

    // Encrypt the aes key with rsa.
    let encrypt_aes_key = public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, &aes_key_bytes)?;

    Ok(encrypt_aes_key)
}

async fn encrytion_aes_gcm(
    msg: &[u8],
) -> Result<
    (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, RsaPrivateKey),
    Box<dyn std::error::Error + Send + Sync>,
> {
    println!("Encrypting the Command...");
    let (public_key, private_key) = generate_rsa_key().await.unwrap();

    let key = Aes256Gcm::generate_key(&mut OsRng);

    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut buffer = msg.to_vec();
    cipher
        .encrypt_in_place(&nonce, b"", &mut buffer)
        .expect("encryption failed");

    let encrypted_msg = buffer;

    // let mut comnined_msg = nonce.to_vec();
    // comnined_msg.extend_from_slice(&buffer);

    // convert public_key to Vec<u8> formate.
    let public_key = public_key
        .to_pkcs1_der()
        .expect("failed to convert to DER")
        .as_bytes()
        .to_vec();

    Ok((
        public_key,
        encrypted_msg,
        key.to_vec(),
        nonce.to_vec(),
        private_key,
    ))
}

// Sending file to UDP Server or Client
async fn send_file(
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("6: Entering send_file function.");
    let arg = Local::parse();

    // File name validation from parsed arguments
    let file_name = match arg.file_name {
        Some(file) => file,
        None => {
            eprintln!("Error: `--file` argument is required when `--use-file` is specified.");
            return Err("`--file` argument is required when `--use-file` is specified.".into());
        }
    };

    // Open the specified file asynchronously
    let mut file = tokio::fs::File::open(&file_name).await?;
    let mut buf = vec![0; 4096];

    loop {
        match file.read(&mut buf).await {
            Ok(0) => {
                socket.send_to(b"EOFA", server_addr).await?;
                break;
            }
            Ok(n) => {
                socket.send_to(&buf[..n], server_addr).await?;
            }
            Err(e) => {
                return Err(Box::new(e));
            }
        }
    }

    println!("12: Completed sending file contents.");
    Ok(())
}

// UDP Client for UDP server
async fn send_packets_to_udp_server() -> Result<(), Box<dyn std::error::Error>> {
    let arg = Local::parse();
    // let ip: IpAddr = local.parse().expect("Invalid ip address formate");
    // let port: u16 = port.parse().expect("Invalid port number");

    let t_ip = match arg.target_ip {
        Some(t_ip) => t_ip,
        None => {
            eprintln!("Error: Target ip is messing.");
            return Err("Target ip is missing".into());
        }
    };

    let t_port = match arg.target_port {
        Some(t_port) => t_port,
        None => {
            eprintln!("Error: Target port is missing.");
            return Err("Target port is missing".into());
        }
    };

    let t_ip: IpAddr = t_ip.parse()?;
    let t_port: u16 = t_port.parse()?;

    let server_addr = SocketAddr::new(t_ip, t_port);

    let client_socket = UdpSocket::bind("0.0.0.0:0").await?;

    if arg.use_file {
        let socket_clone = Arc::new(client_socket);
        let socket = socket_clone.clone();

        let handle = tokio::spawn(async move {
            let _ = send_file(socket, server_addr).await;
        });

        handle.await?;
    }
    Ok(())
}

// UDP Server
async fn listening_on_udpsocket(
    local: String,
    port: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip = local.parse().expect("Invalid ip address formate");
    let port = port.parse().expect("Invalid port number");
    let addr = SocketAddr::new(ip, port);
    let socket = UdpSocket::bind(&addr).await?;
    let file = tokio::fs::File::create("1.mkv").await?;
    let mut writer = BufWriter::new(file);
    println!("Listening on UDP = {}", addr);

    let mut buf = vec![0; 4096];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _)) => {
                if &buf[..len] == b"EOFA" {
                    println!("Download completed");
                    break;
                } else {
                    let _ = writer.write_all(&buf[..len]).await?;
                }
            }
            Err(e) => {
                eprintln!("Error receiving data {}", e);
                return Err(Box::new(e));
            }
        }
    }

    Ok(())
}

// Downloading the file to the server.
async fn download_in_bytes(
    shared_read: Arc<Mutex<OwnedReadHalf>>,
    shared_write: Arc<Mutex<OwnedWriteHalf>>,
    command: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = command[2..].to_string();

    if let Err(e) = shared_write
        .lock()
        .await
        .write_all(command.as_bytes())
        .await
    {
        eprintln!("Failed to send message: {}", e);
    }

    let mut file = tokio::fs::File::create(file_name).await.unwrap();
    let mut buffer = vec![0; 1024 * 1024];

    let mut guard_read = shared_read.lock().await;

    loop {
        match guard_read.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if &buffer[..n] == b"EOFA" {
                    break;
                } else {
                    if let Err(e) = file.write_all(&buffer[..n]).await {
                        println!("Error while writing the file: {}", e);
                    }
                }
            }
            Err(e) => return Err(Box::new(e)),
        }
    }
    println!("Sucessfully downloaded the file\n");
    Ok(())
}

// updoad files
async fn upload_in_bytes(
    upload_read_write: Arc<Mutex<TcpStream>>,
    file_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = tokio::fs::File::open(file_name).await.unwrap();

    let mut buffer = vec![0; 1024 * 1024];
    let mut write_guard = upload_read_write.lock().await;
    loop {
        match file.read(&mut buffer).await {
            Ok(0) => {
                println!("Breaking system on");
                write_guard.write_all(b"EOFA").await?;
                break;
            }
            Ok(n) => {
                // Write bytes to the shared write half
                write_guard.write_all(&buffer[..n]).await?;
            }
            Err(e) => return Err(Box::new(e)), // Handle read error
        }
    }
    println!("Sucessfully uploaded the file");
    Ok(())
}

// TCP Secure client server with aes_gcm and rsa.
async fn tcp_secure_connection_for_clent() -> Result<(), Box<dyn std::error::Error>> {
    let arg = Local::parse();

    let local = match arg.local {
        Some(local_addr) => local_addr,
        None => {
            eprintln!("Error: `-l` argument is required for TcpListening.");
            std::process::exit(1);
        }
    };

    let port = match arg.port {
        Some(port) => port,
        None => {
            eprintln!("Error: `-p` argument is required for TcpListening.");
            std::process::exit(1);
        }
    };
    let ip: IpAddr = local.parse().unwrap();
    let port_addr = port.parse().unwrap();
    let addr = SocketAddr::new(ip, port_addr);
    let stream = TcpStream::connect(addr).await?;

    let copy_stream = Arc::new(Mutex::new(stream));
    let stream1 = Arc::clone(&copy_stream);
    let stream2 = Arc::clone(&copy_stream);

    let mut current_dir = env::current_dir().expect("failed to change current dir");

    loop {
        // Grabbing the Encrypted data that comming from server
        let mut length_buf = [0u8; 4]; // this is for storing the serialized_data_len.
        stream1.lock().await.read(&mut length_buf).await?; // read the length of serializad data.
        let serialized_len = u32::from_be_bytes(length_buf) as usize; // converting the length for vector.
        println!("Received serialized_data_len: {:?}", serialized_len);

        // Only proceed if data length is greater than zero
        if serialized_len == 0 {
            eprintln!("No data received - skipping this read cycle.");
            sleep(Duration::from_millis(500)).await;
            continue;
        }

        let mut serialized_buf = vec![0u8; serialized_len]; // for storing the actual serialized data
        let read_bytes = stream1
            .lock()
            .await
            .read(&mut serialized_buf)
            .await
            .unwrap(); // read the actual serialized data
        println!("Grabbing the serialized Data");

        if read_bytes == 0 {
            println!("No data received");
            return Err("No data received".into());
        }

        // deserializing the received data from serialized_buf variable.
        let (public_key, encryption_msg, key, nonce): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
            bincode::deserialize(&serialized_buf).unwrap();
        // println!(
        //     "public key: {:?}\n encryption_msg: {:?}\n key: {:?}\n nonce: {:?}\n",
        //     public_key, encryption_msg, key, nonce
        // );
        println!("Deserializing the serialized data");

        // let await_handle = tokio::spawn(async move {
            // println!("1");
            let decrypted_result = decryption_aes_gcm(nonce, key, encryption_msg).await;
            // println!("3");
        //     Ok::<_, Box<dyn std::error::Error + Send + Sync>>(decrypted_msg)
        // });
        // let decrypted_result = await_handle.await?;
        // println!("dec: {:?}",decrypted_result.unwrap().unwrap().trim());

        // Converting decrypted_result to String.
        let mut command = decrypted_result.unwrap().trim().to_string();
        // .trim()
        // .to_string();

        // Chenging directory to client computer
        if command.starts_with("cd ") {
            let new_dir = command.trim_start_matches("cd ").trim();
            match env::set_current_dir(new_dir) {
                Ok(_) => {
                    current_dir = env::current_dir().expect("failed to change the dir");
                    let success_msg = format!("Change dir to: {}\n", current_dir.display());
                    let _ = stream1.lock().await.write_all(success_msg.as_bytes()).await;
                }
                Err(_) => {
                    let error_msg = format!("failed to change the dir to: {}", new_dir);
                    let _ = stream1.lock().await.write_all(error_msg.as_bytes()).await;
                }
            }
            continue;
        }

        // Downloading files.
        // if command.starts_with("< ") {
        //     let upload_read_write = shared_stream1.clone();
        //     // let upload_write_half = shared_write.clone();
        //     let file_name = command[2..].to_string();
        //     tokio::spawn(async move {
        //         let _ = upload_in_bytes(upload_read_write, file_name).await;
        //     });
        //     continue;
        // }

        // Executing command to client pc
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", &mut command])
                .current_dir(&current_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("failed to execute process")
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(&mut command)
                .current_dir(&current_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("failed to execute process")
        };

        let mut result = output.stdout;
        result.extend(output.stderr);

        // encrypt the result with aes_gcm and rsa function.
        let stream3 = stream2.clone();
        let await_handle = tokio::spawn(async move {
            // Spawning the new thread for encrypting the output.
            match encrytion_aes_gcm(&result).await {
                Ok((_public_key, encryption_msg, key, nonce, _rsa_priv_key)) => {
                    let enc_rsa_key = enc_key_with_rsa(public_key, key).await.unwrap();
                    // let enc_rsa_key_parsed = enc_rsa_key;
                    println!("Aes key with rsa encryption done");
                    match bincode::serialize(&(enc_rsa_key, encryption_msg, nonce)) {
                        Ok(seriali_data) => {
                            let seriali_data_len = seriali_data.len() as u32;
                            println!(
                                "Sending the serialized_data_len to server: {}",
                                seriali_data_len
                            );
                            let write_result_len = stream3
                                .lock()
                                .await
                                .write_all(&seriali_data_len.to_be_bytes())
                                .await;
                            let _ = stream3.lock().await.flush().await;
                            if let Err(e) = write_result_len {
                                eprintln!("Error writing to shared state: {}", e);
                            } else {
                                // if no error then, send the serialized data also.
                                let write_result =
                                    stream3.lock().await.write_all(&seriali_data).await;
                                let _ = stream3.lock().await.flush().await;
                                println!("Sending serizlized data to server: {:?}", seriali_data);
                                if let Err(e) = write_result {
                                    eprintln!("Error writing to shared state: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Serialization error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error during encryption: {}", e);
                }
            }
        });
        await_handle.await?;

        // Sending to server
        // let _ = shared_write.lock().await.write_all(&result).await;
    }

    // Ok(())
}

// Execute command to client server
async fn execute_command_to_client(
    local: String,
    port: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip: IpAddr = local.parse()?;
    let port: u16 = port.parse()?;
    let addr = SocketAddr::new(ip, port);
    let stream = TcpStream::connect(addr).await.unwrap();

    let shared_stream = Arc::new(Mutex::new(stream));

    let shared_stream1 = Arc::clone(&shared_stream);

    let mut current_dir = env::current_dir().expect("failed to change current dir");

    loop {
        let mut buf = vec![0u8; 1024];
        let read_bytes = shared_stream1.lock().await.read(&mut buf).await?;

        if read_bytes == 0 {
            println!("No data received");
            return Err("No data received".into());
        }

        // let n = buf.len();
        let command = String::from_utf8_lossy(&mut buf[..read_bytes]);
        let command = command.trim_end().to_string();
        println!("command: {}", command);

        // Chenging directory to client computer
        if command.starts_with("cd ") {
            let new_dir = command.trim_start_matches("cd ").trim();
            match env::set_current_dir(new_dir) {
                Ok(_) => {
                    current_dir = env::current_dir().expect("failed to change the dir");
                    let success_msg = format!("Change dir to: {}\n", current_dir.display());
                    let _ = shared_stream1
                        .lock()
                        .await
                        .write_all(success_msg.as_bytes())
                        .await;
                }
                Err(_) => {
                    let error_msg = format!("failed to change the dir to: {}", new_dir);
                    let _ = shared_stream1
                        .lock()
                        .await
                        .write_all(error_msg.as_bytes())
                        .await;
                }
            }
            continue;
        }

        // Downloading files.
        if command.starts_with("< ") {
            let upload_read_write = shared_stream1.clone();
            // let upload_write_half = shared_write.clone();
            let file_name = command[2..].to_string();
            tokio::spawn(async move {
                let _ = upload_in_bytes(upload_read_write, file_name).await;
            });
            continue;
        }

        // Executing command to client pc
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", &command])
                .current_dir(&current_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("failed to execute process")
        } else {
            Command::new("sh")
                .args(["-c", &command])
                // .arg(&mut command)
                .current_dir(&current_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("failed to execute process")
        };

        let mut result = output.stdout;
        result.extend(output.stderr);

        let write_to_server = shared_stream1.lock().await.write_all(&mut result).await;
        if let Err(e) = write_to_server {
            eprintln!("failed to send to server: {}", e);
        }
    }
}

// TCP Server with Encryption - Aes_gcm and rsa
async fn tcp_server_with_enc() -> Result<(), Box<dyn std::error::Error>> {
    let arg = Local::parse();

    let local = match arg.local {
        Some(local_value) => local_value,
        None => {
            eprintln!("Error: `-l` argument is required for TcpListening.");
            std::process::exit(1);
        }
    };

    let port = match arg.port {
        Some(port) => port,
        None => {
            eprintln!("Error: `-p` argument is required for TcpListening.");
            std::process::exit(1);
        }
    };

    let addr = format!("{}:{}", local, port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("Listening on {}", addr);

    loop {
        // let rsa_pri_key: Arc<Mutex<Option<RsaPrivateKey>>> = Arc::new(Mutex::new(None));
        let (mut socket, _) = listener.accept().await.unwrap();
        let handle_async = tokio::spawn(async move {
            // Read the command from user.
            let mut command = String::new();
            print!(">> ");
            io::stdout().flush().unwrap();
            std::io::stdin()
                .read_line(&mut command)
                .expect("failed to read line");

            let private_key = match encrytion_aes_gcm(command.as_bytes()).await {
                Ok((public_key, encrypted_msg, key, nonce, private_key)) => {
                    let serialized_data =
                        bincode::serialize(&(public_key, encrypted_msg, key, nonce))
                            .expect("failed to serialize");
                    let serialized_data_len = serialized_data.len() as u32;

                    socket
                        .write_all(&serialized_data_len.to_be_bytes())
                        .await
                        .expect("Failed to send data length");
                    socket
                        .write_all(&serialized_data)
                        .await
                        .expect("Failed to send data");

                    private_key // Return `RsaPrivateKey` directly
                }
                Err(e) => panic!("Encryption Error: {}", e),
            };
            let mut buf = [0; 4];
            let _ = socket.read_exact(&mut buf).await;
            let serilize_data_len = u32::from_be_bytes(buf) as usize;

            let mut serilized_buf = vec![0u8; serilize_data_len];
            let read_byte = socket.read_exact(&mut serilized_buf).await.unwrap();
            let (enc_rsa_key, encryption_msg, nonce): ((Vec<u8>, Vec<u8>, Vec<u8>)) =
                bincode::deserialize(&mut serilized_buf).unwrap();
            let dec_key: Vec<u8> = dec_key_with_rsa(enc_rsa_key, private_key).await.unwrap();
            let decrypted_msg = decryption_aes_gcm(nonce, dec_key, encryption_msg).await.unwrap();
            println!("{}",decrypted_msg);
        });

        handle_async.await?;
    }
}

// Tcp Server
async fn handle_connection(socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let (socket_read, socket_write) = socket.into_split();
    let shared_read = Arc::new(Mutex::new(socket_read));
    let shared_write = Arc::new(Mutex::new(socket_write));
    loop {
        let mut command = String::new();
        print!(">> ");
        io::stdout().flush().unwrap();
        io::stdin()
            .read_line(&mut command)
            .expect("failed to read line");

        // this is for downloading input.
        if command.starts_with("< ") {
            let download_read_half = shared_read.clone();
            let download_write_half = shared_write.clone();
            let coman_clone = command.clone();

            let handle = tokio::spawn(async move {
                let _ =
                    download_in_bytes(download_read_half, download_write_half, coman_clone).await;
            });
            handle.await?;
        // this is for shoutdown the connection.
        } else if command.starts_with("exit") {
            shared_write.lock().await.shutdown().await?;
            std::process::exit(1);
        } else {
            // send the command or msg to client server.
            let com = command.clone();
            let clone_shared_read = shared_read.clone();
            let clone_shared_write = shared_write.clone();

            let write_to_client = clone_shared_write
                .lock()
                .await
                .write_all(com.as_bytes())
                .await;
            if let Err(e) = write_to_client {
                eprintln!("failed to write to client: {}", e);
            }

            let mut buf = vec![0u8; 1024];
            // let read_to_client = clone_shared_read.lock().await.read(&mut buf).await;
            // if let Err(e) = read_to_client {
            //     eprintln!("failed to read to client: {}",e);
            // }

            let read_result = clone_shared_read.lock().await.read(&mut buf).await;
            match read_result {
                Ok(read_byte) => {
                    if read_byte == 0 {
                        break Ok(());
                    }
                    let output = String::from_utf8_lossy(&mut buf[..read_byte]);
                    println!("{}", output);
                }
                Err(e) => {
                    eprintln!("Error reading from client: {}", e);
                    break Err(Box::new(e));
                }
            }
        }
    }
}

// handle the operation that help to act as a server.
async fn handle_opretion() -> Result<(), Box<dyn std::error::Error>> {
    let arg = Local::parse();

    let local = match arg.local {
        Some(local_value) => local_value,
        None => {
            eprintln!("Error: `-l` argument is required for TcpListening.");
            std::process::exit(1);
        }
    };

    let port = match arg.port {
        Some(port) => port,
        None => {
            eprintln!("Error: `-p` argument is required for TcpListening.");
            std::process::exit(1);
        }
    };

    let addr = format!("{}:{}", local, port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("Listening on {}", addr);
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let _ = handle_connection(socket).await;
        });
    }
}

// main function
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = Local::parse();

    if arg.x || arg.u {
        let local = match arg.local {
            Some(local_value) => local_value,
            None => {
                eprintln!("Error: `-l` argument is required for TcpListening.");
                std::process::exit(1);
            }
        };

        let port = match arg.port {
            Some(port) => port,
            None => {
                eprintln!("Error: `-p` argument is required for TcpListening.");
                std::process::exit(1);
            }
        };

        if !local.is_empty() {
            if arg.x {
                execute_command_to_client(local, port).await?;
            } else if arg.u {
                listening_on_udpsocket(local, port).await?;
            }
        } else {
            println!("Address is empty");
        }
    } else if arg.udp_client {
        println!("Launching UDP client...");
        send_packets_to_udp_server().await?;
    } else if arg.secure {
        println!("Lunching TCP secure Connection...");
        tcp_server_with_enc().await?;
    } else if arg.client_secure {
        println!("Lunching client secure connection...");
        tcp_secure_connection_for_clent().await?;
    } else {
        handle_opretion().await?;
    }

    // let local_value = arg.local;
    // let port = arg.port;

    Ok(())
}
