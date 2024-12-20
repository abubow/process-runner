use regex::Regex;
use std::collections::HashMap;

#[derive(Debug)]
struct Option {
    current_setting: String,
    required: String,
    description: String,
}

#[derive(Debug)]
struct Exploit {
    module: String,
    options: HashMap<String, Option>,
}

fn extract_module_options(input: &str) -> Vec<Exploit> {
    let re_module = Regex::new(r"Module options \(([^)]+)\):\s*(.*?)\s*Payload options").unwrap();
    let re_option = Regex::new(r"(\S+)\s+(\S+)\s+(\S+)\s+(.*)").unwrap();
    
    let mut exploits = Vec::new();

    for module_caps in re_module.captures_iter(input) {
        let module_name = module_caps[1].to_string();
        let module_content = module_caps[2].to_string();

        let mut options = HashMap::new();
        for cap in re_option.captures_iter(&module_content) {
            let name = cap[1].to_string();
            let current_setting = cap[2].to_string();
            let required = cap[3].to_string();
            let description = cap[4].to_string();

            options.insert(
                name,
                Option {
                    current_setting,
                    required,
                    description,
                },
            );
        }

        exploits.push(Exploit {
            module: module_name,
            options,
        });
    }

    exploits
}

fn extract_payload_options(input: &str) -> HashMap<String, Option> {
    let re_payload = Regex::new(r"Payload options \(([^)]+)\):\s*(.*?)\s*Exploit target").unwrap();
    let re_option = Regex::new(r"(\S+)\s+(\S+)\s+(\S+)\s+(.*)").unwrap();

    let mut payload_options = HashMap::new();
    if let Some(payload_caps) = re_payload.captures(input) {
        let payload_content = payload_caps[2].to_string();

        for cap in re_option.captures_iter(&payload_content) {
            let name = cap[1].to_string();
            let current_setting = cap[2].to_string();
            let required = cap[3].to_string();
            let description = cap[4].to_string();

            payload_options.insert(
                name,
                Option {
                    current_setting,
                    required,
                    description,
                },
            );
        }
    }

    payload_options
}

fn extract_exploit_targets(input: &str) -> Vec<(String, String)> {
    let re_target = Regex::new(r"Exploit target:\s*Id\s+Name\s+--\s+----\s*(.*?)\s*").unwrap();
    let re_target_row = Regex::new(r"(\d+)\s+(.+)").unwrap();

    let mut targets = Vec::new();
    if let Some(target_caps) = re_target.captures(input) {
        let target_content = target_caps[1].to_string();

        for cap in re_target_row.captures_iter(&target_content) {
            let id = cap[1].to_string();
            let name = cap[2].to_string();
            targets.push((id, name));
        }
    }

    targets
}

fn main() {
    let input = r#"
Module options (exploit/windows/wins/ms04_045_wins):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   42               yes       The target port (TCP)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.18.0.2       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2000 English
"#;

    // Extract module options
    let exploits = extract_module_options(input);
    for exploit in &exploits {
        println!("Module: {}", exploit.module);
        for (name, option) in &exploit.options {
            println!("Option: {}, Current Setting: {}, Required: {}, Description: {}", 
                name, option.current_setting, option.required, option.description);
        }
    }

    // Extract payload options
    let payload_options = extract_payload_options(input);
    println!("\nPayload Options:");
    for (name, option) in &payload_options {
        println!("Option: {}, Current Setting: {}, Required: {}, Description: {}", 
            name, option.current_setting, option.required, option.description);
    }

    // Extract exploit targets
    let targets = extract_exploit_targets(input);
    println!("\nExploit Targets:");
    for (id, name) in targets {
        println!("Id: {}, Name: {}", id, name);
    }
}
