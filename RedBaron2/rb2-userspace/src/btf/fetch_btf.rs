use std::error::Error as StdError;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, copy};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;
use xz2::read::XzDecoder;

const INSTALL_PATH: &str = "/var/cache/downloaded.btf";
const DOWNLOAD_PATH: &str = "/var/cache/downloaded.btf.tar.xz";
const SYS_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const OS_RELEASE_PATH: &str = "/etc/os-release";
const BTFHUB_URL_BASE: &str = "https://raw.githubusercontent.com/aquasecurity/btfhub-archive/main";

#[derive(Debug)]
pub enum BtfError {
    Io(io::Error),
    HttpStatus(u16),
    HttpRequest(String),
    EmptyArchive,
    SystemInfo(String),
    UnsupportedDistro(String),
    Utf8Error(std::string::FromUtf8Error),
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "IO error: {}", err),
            Self::HttpStatus(status) => write!(f, "HTTP error: status {}", status),
            Self::HttpRequest(msg) => write!(f, "HTTP request error: {}", msg),
            Self::EmptyArchive => write!(f, "No files found in BTF archive"),
            Self::SystemInfo(msg) => write!(f, "Failed to detect system info: {}", msg),
            Self::UnsupportedDistro(name) => write!(f, "Unsupported distribution: {}", name),
            Self::Utf8Error(err) => write!(f, "UTF-8 conversion error: {}", err),
        }
    }
}

impl StdError for BtfError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Utf8Error(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for BtfError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<std::string::FromUtf8Error> for BtfError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(err)
    }
}

impl From<ureq::Error> for BtfError {
    fn from(err: ureq::Error) -> Self {
        Self::HttpRequest(err.to_string())
    }
}

/// Returns the path to an available BTF file, downloading it if necessary
pub fn get_btf_file() -> Result<PathBuf, BtfError> {
    // Check if system BTF file exists
    let sys_btf = Path::new(SYS_BTF_PATH);
    if sys_btf.exists() {
        return Ok(sys_btf.to_path_buf());
    }

    // Check if cached BTF file exists
    let install_path = Path::new(INSTALL_PATH);
    if install_path.exists() {
        return Ok(install_path.to_path_buf());
    }

    // Download and extract BTF file
    let url = get_url()?;
    download_btf(&url)?;
    extract_btf()?;

    // Clean up the archive file
    let _ = fs::remove_file(DOWNLOAD_PATH);

    Ok(install_path.to_path_buf())
}

/// Downloads the BTF file from the given URL
fn download_btf(url: &str) -> Result<(), BtfError> {
    let mut response = ureq::get(url).call()?;

    if !response.status().is_success() {
        return Err(BtfError::HttpStatus(response.status().as_u16()));
    }

    let mut output_file = File::create(DOWNLOAD_PATH)?;

    if let Err(e) = std::io::copy(
        &mut response.body_mut().as_reader(),
        &mut BufWriter::new(&mut output_file),
    ) {
        fs::remove_file(DOWNLOAD_PATH).unwrap();
        return Err(BtfError::Io(e));
    }

    Ok(())
}

/// Extracts the BTF file from the downloaded archive
fn extract_btf() -> Result<(), BtfError> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(INSTALL_PATH).parent() {
        fs::create_dir_all(parent)?;
    }

    // Open and extract the archive
    let file = File::open(DOWNLOAD_PATH)?;
    let xz = XzDecoder::new(file);
    let mut archive = Archive::new(xz);

    // Extract the single file
    let mut entries = archive.entries()?;
    if let Some(entry) = entries.next() {
        let mut entry = entry?;
        let mut output_file = File::create(INSTALL_PATH)?;
        copy(&mut entry, &mut output_file)?;

        Ok(())
    } else {
        Err(BtfError::EmptyArchive)
    }
}

/// Detect the appropriate BTF download URL
fn get_url() -> Result<String, BtfError> {
    let (distro, release) = get_distro_and_release().ok_or_else(|| {
        BtfError::SystemInfo("Could not determine Linux distribution info".to_string())
    })?;

    let distro = check_distro_support(&distro).ok_or(BtfError::UnsupportedDistro(distro))?;

    let arch = match get_architecture() {
        Some(arch) => arch,
        None => {
            eprintln!("Unknown/unsupported arch for btf fetching, defaulting to x86_64");
            "x86_64".to_string()
        }
    };

    let kernel = get_kernel_version()
        .ok_or_else(|| BtfError::SystemInfo("Unknown/no kernel version found".to_string()))?;

    Ok(format!(
        "{}/{}/{}/{}/{}.btf.tar.xz",
        BTFHUB_URL_BASE, distro, release, arch, kernel
    ))
}

fn check_distro_support(distro: &str) -> Option<String> {
    let supported_distros = [
        "amzn", "centos", "debian", "fedora", "ol", "rhel", "sles", "ubuntu",
    ];

    if supported_distros.contains(&distro) {
        Some(distro.to_string())
    } else {
        None
    }
}

/// Extract a field from the /etc/os-release file
fn get_os_release_field(field: &str) -> Option<String> {
    let file = File::open(OS_RELEASE_PATH).ok()?;
    let reader = BufReader::new(file);

    for line_result in reader.lines().map_while(Result::ok) {
        if let Some((key, value)) = line_result.split_once('=')
            && key == field
        {
            return Some(value.trim_matches('"').to_string());
        }
    }

    None
}

/// Get distribution ID and version from /etc/os-release
fn get_distro_and_release() -> Option<(String, String)> {
    let id = get_os_release_field("ID")?;
    let version_id = get_os_release_field("VERSION_ID")?;

    // Validate version ID format
    if !version_id.chars().all(|c| c.is_ascii_digit() || c == '.') {
        eprintln!("VERSION_ID '{}' contains invalid characters", version_id);
        return None;
    }

    Some((id, version_id))
}

/// Get system architecture using uname
fn get_architecture() -> Option<String> {
    let output = Command::new("uname").arg("-m").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match arch.as_str() {
        "x86_64" | "arm64" => Some(arch),
        _ => {
            eprintln!("Unsupported architecture '{}'", arch);
            None
        }
    }
}

/// Get kernel version using uname
fn get_kernel_version() -> Option<String> {
    let output = Command::new("uname").arg("-r").output().ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
