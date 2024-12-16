use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use colored::Colorize;
use regex::Regex;
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
                let ln_vec: Vec<u8> = strip_ansi_escapes::strip(&ln);
                let striped_line = String::from_utf8(ln_vec).unwrap();
                println!("{}", ln);
                let mut output_buf = output_buf.lock().unwrap();
                output_buf.push(striped_line);
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
                println!("{}", ln);
                let mut output_buf = err_buf.lock().unwrap();
                output_buf.push(striped_line);
                err_readable.notify_one();
            }
        })
    }

    pub fn read(&mut self) -> String {
        let mut output_buf = self.readable.wait(self.output_buf.lock().unwrap()).unwrap();
        let res = output_buf.iter().cloned().collect();
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
    options: Vec<String>
}
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
            read_line = self.process.read();
            read_line_err = self.process.read_err();
            lines_vec.push(read_line.clone());
            // println!("{}\n\n", read_line);
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
        let line = lines_vec.join("\n");
        
        let exploit_names = Self::extract_exploit_names(line.as_str());
        let exploits: Vec<Exploit> = exploit_names
            .into_iter()
            .map(|name| Exploit { name, options:Vec::new()})
            .collect();
        self.clear();

        exploits
    }
    fn extract_options_and_payloads(input: &str){
        // let mut result = Vec::new();
    
        // Regex for capturing the payload and options
        let payload_re = Regex::new(r"Payload options \((.*?)\):").unwrap();
        let module_option_re = Regex::new(r"(Module options.*?)Exploit target").unwrap();
        let target_option_re = Regex::new(r"(\S+)\s+(\S+)\s+(yes|no)\s+(.*)").unwrap(); // Pattern for capturing options
    
        // Extract payloads value from string
        let payload_match = payload_re.find(input).unwrap();
        let payload_str = payload_match.as_str();
        let payload_idx = payload_match.start();

        // create substring till first instance of "Payload options"
        let module_option_sub = &input[..payload_idx];
        let module_options = module_option_re.captures_iter(&module_option_sub).map(|c| c.get(0).unwrap().as_str());
        for i in module_options {
            println!("{}\n\n\n", i);
        }
    }
    pub fn add_options(&mut self, exploit: &mut Exploit) {

        let use_command = format!("use {}", exploit.name);
        self.run_command(&use_command);
        self.clear();

        let show_options = "show options";
        self.run_command(&show_options);    
        let output = self.output.clone();
        let text = output.join("\n");
        let options = MSFProcess::extract_exploit_names(text.as_str());

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
    println!("Starting MSF");
    let mut msf = MSFProcess::new();

    println!("MSF started");
    msf.clear();


    let mut exploits = msf.get_exploits();
    for i in 0..3{
        let mut exploit = &mut exploits[i];
        msf.add_options(&mut exploit);
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
