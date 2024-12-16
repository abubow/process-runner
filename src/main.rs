use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use colored::Colorize;
use regex::{Match, Regex};
use serde::Serialize;

struct Process {
    process: std::process::Child,
    stdin: std::process::ChildStdin,
    output_buf: Arc<Mutex<Vec<String>>>,
    readable: Arc<Condvar>,
    err_readable: Arc<Condvar>,
    err_buf: Arc<Mutex<Vec<String>>>,
}

impl Process {
    pub fn new(command: &str, args: Option<&[&str]>) -> Self {
        let mut process;
        if args.is_none() {
            process = std::process::Command::new(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn process");
        } else {
            process = std::process::Command::new(command)
                .args(args.unwrap())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn process");
        }

        let stdin = process.stdin.take().expect("Failed to get stdin");

        Self {
            process,
            stdin,
            output_buf: Arc::new(Mutex::new(Vec::new())),
            err_buf: Arc::new(Mutex::new(Vec::new())),
            readable: Arc::new(Condvar::new()),
            err_readable: Arc::new(Condvar::new()),
        }
    }

    pub fn write(&mut self, data: &str) -> std::io::Result<()> {
        writeln!(self.stdin, "{}", data).expect("Failed to write to stdin");
        self.stdin.flush().expect("Failed to flush stdin");
        Ok(())
    }

    pub fn start_reader(&mut self) -> thread::JoinHandle<()> {
        let out = self.process.stdout.take().expect("Failed to get stdout");
        let output_buf = Arc::clone(&self.output_buf);
        let readable = Arc::clone(&self.readable);
        thread::spawn(move || {
            let reader = BufReader::new(out);
            for line in reader.lines() {
                let ln = match line {
                    Ok(output) => output,
                    Err(e) => {
                        eprintln!("Error reading output: {}", e);
                        return;
                    }
                };
                let ln: Vec<String> = ln
                    .split("\n")
                    .map(|s| String::from_utf8(strip_ansi_escapes::strip(s)).unwrap())
                    .collect();
                // println!("{}", ln.join(" \n"));
                let mut output_buf = output_buf.lock().unwrap();
                output_buf.push(ln.join(" \n"));
                readable.notify_one();
            }
        })
    }

    pub fn start_error_reader(&mut self) -> thread::JoinHandle<()> {
        let stderr = self.process.stderr.take().expect("Failed to get stderr");
        let err_buf = Arc::clone(&self.err_buf);
        let err_readable = Arc::clone(&self.err_readable);
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let ln = match line {
                    Ok(output) => output,
                    Err(e) => {
                        eprintln!("Error reading output: {}", e);
                        return;
                    }
                };
                let ln_vec: Vec<u8> = strip_ansi_escapes::strip(&ln);
                let striped_line = String::from_utf8(ln_vec).unwrap();
                // println!("{}", ln);
                let mut output_buf = err_buf.lock().unwrap();
                output_buf.push(striped_line);
                err_readable.notify_one();
            }
        })
    }

    pub fn read(&mut self) -> String {
        let mut output_buf = self.readable.wait(self.output_buf.lock().unwrap()).unwrap();
        let res = output_buf.join("\n");
        output_buf.clear();
        res
    }

    pub fn read_err(&mut self) -> String {
        let mut err_buf = self
            .err_readable
            .wait(self.err_buf.lock().unwrap())
            .unwrap();
        let res = err_buf.iter().cloned().collect();
        err_buf.clear();
        res
    }

    pub fn read_buf_size(&mut self) -> usize {
        let output_buf = self.output_buf.lock().unwrap();
        output_buf.len()
    }

    pub fn clear(&mut self) {
        let mut output_buf = self.output_buf.lock().unwrap();
        output_buf.clear();
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        println!("Sending Kill signal to process");
        self.process.kill().expect("Failed to kill process");
        println!("Process dropped");
    }
}

#[derive(Serialize, Clone)]
struct Exploit {
    name: String,
    payload: String,
    options: Vec<String>,
}
#[derive(Serialize, Clone)]
struct ExploitOptions {}
struct MSFProcess {
    process: Process,
    reader: thread::JoinHandle<()>,
    err_reader: thread::JoinHandle<()>,
    output: Vec<String>,
    err: Vec<String>,
}

impl MSFProcess {
    pub fn new() -> Self {
        let mut process = Process::new("msfconsole", None);
        let reader = process.start_reader();
        let err_reader = process.start_error_reader();

        let mut read_line = process.read();
        while !read_line.contains("Metasploit Documentation:") {
            read_line = process.read();
            // println!("{}", read_line);
        }
        thread::sleep(std::time::Duration::from_secs(1));
        println!("MSF started\n{}", read_line);
        Self {
            process,
            reader,
            err_reader,
            output: Vec::new(),
            err: Vec::new(),
        }
    }

    pub fn run_command(&mut self, command: &str) {
        println!("Running command: {}", command);
        self.process.clear();
        self.process.write(command);
        self.process.write("ping");
        let mut read_line = "".to_string();
        let mut read_line_err = "".to_string();
        let mut lines_vec = Vec::new();
        while !read_line_err.contains("ping: usage error:") {
            read_line = self.process.read() + " ";
            read_line_err = self.process.read_err();
            lines_vec.push(read_line.clone());
            println!("RUN COMMAND: {}\n\n", read_line);
        }
        self.output = lines_vec;
    }

    pub fn clear(&mut self) {
        self.process.clear();
        self.output.clear();
    }
    fn extract_exploit_names(input: &str) -> Vec<String> {
        let re = Regex::new(r"exploit/([a-zA-Z0-9_/]+)").unwrap();

        let exploit_names: Vec<String> = re
            .captures_iter(input)
            .filter_map(|cap| {
                cap.get(1)
                    .map(|m| "exploit/".to_owned() + &m.as_str().to_string())
            })
            .collect();

        exploit_names
    }
    pub fn get_exploits(&mut self) -> Vec<Exploit> {
        self.run_command("show exploits");

        let lines_vec = self.output.clone();
        let line = lines_vec.join(" \n");

        let exploit_names = Self::extract_exploit_names(line.as_str());
        let exploits: Vec<Exploit> = exploit_names
            .into_iter()
            .map(|name| Exploit {
                name,
                options: Vec::new(),
                payload: "".to_string(),
            })
            .collect();
        self.clear();

        exploits
    }

    fn parse_option(input: Vec<&str>) -> Vec<Vec<String>> {
        println!("Parsing: {:#?}", input);
        let mut res = Vec::new();
        let mut input = VecDeque::from(input);
        loop {
            println!("Len: {}", input.len());
            let last;
            if input.len() == 3 {
                last = "|-line-|";
            } else {
                last = &input[3];
            }
            let mut options = Vec::new();
            println!("first: {}", input[0]);
            if last.to_string() == "|-line-|" {
                options.push(VecDeque::pop_front(&mut input).unwrap().to_string());
                options.push("".to_string());
                options.push(VecDeque::pop_front(&mut input).unwrap().to_string());
                options.push(VecDeque::pop_front(&mut input).unwrap().to_string());
                if input.len() != 0 && input[0].to_string() == "|-line-|" {
                    VecDeque::pop_front(&mut input).unwrap();
                }
            } else {
                for i in 0..4 {
                    options.push(VecDeque::pop_front(&mut input).unwrap().to_string());
                }
                if input.len() != 0 && input[0].to_string() == "|-line-|" {
                    VecDeque::pop_front(&mut input).unwrap();
                }
            }
            res.push(options);
            if input.len() == 0 {
                break;
            }
        }
        res
    }
    fn extract_options_and_payloads(input: &str) {
        println!("Extracting from: {:#?}", input);
        let payload_str;
        let module_option_sub;
        let exploit_targets_sub;
        let payload_search_str = "Payload options (";
        let exploit_search_str = "Exploit target:";
        let exploit_search_end_str = "\n\n\n\n";
        let exploit_end_idx = input.find(exploit_search_end_str).unwrap();
        let payload_idx_res = input.find(payload_search_str);

        if payload_idx_res.is_none() {
            let exp_idx = input.find(exploit_search_str).unwrap();

            payload_str = "";
            module_option_sub = &input[..exp_idx];
            exploit_targets_sub = &input[exp_idx..exploit_end_idx];
        } else {
            let payload_idx = payload_idx_res.unwrap();
            let payload_end_idx = input[payload_idx..].find("):").unwrap();
            let exp_idx = input[payload_idx..].find(exploit_search_str).unwrap();

            println!("Start: {} \nEnd: {}", payload_idx, payload_end_idx);
            payload_str =
                &input[payload_idx + payload_search_str.len()..payload_idx + payload_end_idx];
            module_option_sub = &input[..payload_idx];
            exploit_targets_sub =
                &input[payload_idx + exp_idx + exploit_search_str.len()..exploit_end_idx];
        }

        let sep = " -----------\n";
        let module_options_unparsed =
            &module_option_sub[module_option_sub.find(sep).unwrap() + sep.len()..];
        let sep = " ----\n";
        let exploit_target_unparsed =
            &exploit_targets_sub[exploit_targets_sub.find(sep).unwrap() + sep.len()..];

        let mod_lines: Vec<&str> = module_options_unparsed
            .split("\n")
            .filter(|w| w.to_string() != "")
            .collect();
        let newline = mod_lines.join("  |-line-|  ");
        let module_options_vec: Vec<&str> = newline
            .split("  ")
            .map(|w| w.trim())
            .filter(|w| w.to_string() != "")
            .collect();

        let module_options = MSFProcess::parse_option(module_options_vec);

        let exploit_target: Vec<&str> = exploit_target_unparsed
            .split("  ")
            .map(|w| w.trim())
            .filter(|w| w.to_string() != "")
            .collect();
        println!("--------------------------------");
        println!("Module sections: {:#?}\n\n", module_options);
        println!("Payload: {}\n\n", payload_str);
        println!("Exploits section: {:#?}", exploit_target);
        println!("--------------------------------");
    }
    pub fn add_options(&mut self, exploit: &mut Exploit) {
        let use_command = format!("use {}", exploit.name);
        self.run_command(&use_command);
        self.clear();

        let show_options = "show options";
        self.run_command(&show_options);
        let output = self.output.clone();
        let text = output.join(" ");
        println!("vec: {:#?}\ntext:{}", output, text);
        let options = MSFProcess::extract_options_and_payloads(text.as_str());

        let back = "back";
        self.run_command(&back);
        self.clear()
    }
}
impl Drop for MSFProcess {
    fn drop(&mut self) {
        println!("Dropping MSFProcess");
    }
}

fn main() -> std::io::Result<()> {
    let mut exploits;
    {
        println!("Starting MSF");
        let mut msf = MSFProcess::new();

        println!("MSF started");
        msf.clear();

        exploits = msf.get_exploits();
        for i in 0..13 {
            let mut exploit = &mut exploits[i];
            println!("Adding details to: {}", exploit.name);
            msf.add_options(&mut exploit);
        }
    }
    // write to file
    let mut file = std::fs::File::create("exploits.json").unwrap();
    serde_json::to_writer_pretty(file, &exploits).unwrap();

    println!("Done writing to exploits.json");

    println!("MSF dropped");
    // timeout for 10 seconds
    thread::sleep(std::time::Duration::from_secs(10));

    Ok(())
}
