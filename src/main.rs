use reqwest::{self, Client};
use tokio;

#[tokio::main]
async fn main() {
    // Input URL
    println!("Lebokne URL COK (contoh: https://example.com):");
    let mut url = String::new();
    std::io::stdin().read_line(&mut url).expect("Gagal membaca input");
    let url = url.trim();

    // Mulai scanning
    match scan_vulnerabilities(url).await {
        Ok(_) => println!("Scanning Mari."),
        Err(e) => eprintln!("Onok Salah: {}", e),
    }
}

async fn scan_vulnerabilities(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // Check if the URL is reachable
    println!("[1/8] Mengecek aksesibilitas URL...");
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        eprintln!("Gagal mengakses URL: Status {}", response.status());
        return Ok(());
    }

    println!("URL dapat diakses.");

    // Scan for HTTP headers vulnerabilities
    println!("[2/8] Memeriksa header HTTP...");
    let headers = response.headers();
    check_http_headers(headers);

    // Scan for basic security issues (e.g., missing HTTPS)
    println!("[3/8] Memeriksa konfigurasi dasar keamanan...");
    if !url.starts_with("https://") {
        println!("Peringatan: HTTPS tidak digunakan. Pertimbangkan untuk mengaktifkan HTTPS.");
    }

    // Test for SQL Injection
    println!("[4/8] Menguji kerentanan SQL Injection...");
    test_sql_injection(url, &client).await?;

    // Test for XSS
    println!("[5/8] Menguji kerentanan Cross-Site Scripting (XSS)...");
    test_xss(url, &client).await?;

    // Test for Command Injection
    println!("[6/8] Menguji kerentanan Command Injection...");
    test_command_injection(url, &client).await?;

    // Test for Directory Traversal
    println!("[7/8] Memeriksa kerentanan Directory Traversal...");
    test_directory_traversal(url, &client).await?;

    // Check outdated software and open ports
    println!("[8/8] Memeriksa komponen aplikasi...");
    check_outdated_software();
    Ok(())
}

fn check_http_headers(headers: &reqwest::header::HeaderMap) {
    let required_headers = vec!["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"];
    
    for header in required_headers {
        if !headers.contains_key(header) {
            println!("Peringatan: Header {} hilang.", header);
        } else {
            println!("Header {} ditemukan.", header);
        }
    }
}

async fn test_sql_injection(url: &str, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let test_payloads = vec!["' OR '1'='1", "' UNION SELECT NULL, NULL --", "; DROP TABLE users; --"];
    for payload in test_payloads {
        let test_url = format!("{}?input={}" , url, payload);
        let response = client.get(&test_url).send().await?;

        if response.status().is_success() {
            println!("Kemungkinan kerentanan SQL Injection dengan payload: {}", payload);
        }
    }
    Ok(())
}

async fn test_xss(url: &str, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let test_payloads = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ];
    for payload in test_payloads {
        let test_url = format!("{}?input={}" , url, payload);
        let response = client.get(&test_url).send().await?;

        if response.status().is_success() {
            let body = response.text().await?;
            if body.contains("<script>alert(1)</script>") || body.contains("alert(1)") {
                println!("Kemungkinan kerentanan XSS dengan payload: {}", payload);
            }
        }
    }
    Ok(())
}

async fn test_command_injection(url: &str, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let test_payloads = vec!["; ls ", "&& whoami ", "| cat /etc/passwd "];
    for payload in test_payloads {
        let test_url = format!("{}?cmd={}", url, payload);
        let response = client.get(&test_url).send().await?;

        if response.status().is_success() {
            println!("Kemungkinan kerentanan Command Injection dengan payload: {}", payload);
        }
    }
    Ok(())
}

async fn test_directory_traversal(url: &str, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let test_payloads = vec!["../../../../etc/passwd ", "../etc/shadow "]; // Memperbaiki prefix
    for payload in test_payloads {
        let test_url = format!("{}?file={}", url, payload);
        let response = client.get(&test_url).send().await?;

        if response.status().is_success() {
            let body = response.text().await?;
            if body.contains("root:") {
                println!("Kemungkinan kerentanan Directory Traversal dengan payload: {}", payload);
            }
        }
    }
    Ok(())
}

fn check_outdated_software() {
   println!("Pemeriksaan versi software belum diimplementasikan.");
    // Placeholder for checking outdated software. Requires integration with CVE databases.
}
