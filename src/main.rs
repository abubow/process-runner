use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;
use std::sync::{Arc, Condvar, Mutex};
use std::{env, thread};

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
    options: Vec<Vec<String>>,
    target: Vec<String>,
}
#[derive(Serialize, Clone)]
struct ExploitOptions {}
struct MSFProcess {
    process: Process,
    reader: thread::JoinHandle<()>,
    err_reader: thread::JoinHandle<()>,
    output: Vec<String>,
    err: Vec<String>,
    exploits: Vec<Exploit>,
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
            exploits: Vec::new(),
        }
    }

    pub fn run_command(&mut self, command: &str) {
        println!("Running command: {}", command);
        self.process.clear();
        self.process.write(command);
        self.process.write("ping");
        let mut read_line;
        let mut read_line_err = "".to_string();
        let mut lines_vec = Vec::new();
        while !read_line_err.contains("ping: usage error:") {
            read_line = self.process.read() + " ";
            read_line_err = self.process.read_err();
            lines_vec.push(read_line.clone());
            // println!("RUN COMMAND: {}\n\n", read_line);
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
        if self.exploits.len() > 0 {
            return self.exploits.clone();
        }
        self.run_command("show exploits");

        let lines_vec = self.output.clone();
        let line = lines_vec.join(" \n");

        let exploit_names = Self::extract_exploit_names(line.as_str());
        let exploits: Vec<Exploit> = exploit_names
            .into_iter()
            .map(|name| Exploit {
                name,
                options: Vec::new(),
                target: Vec::new(),
                payload: "".to_string(),
            })
            .collect();
        self.clear();

        exploits
    }

    fn parse_option(input: Vec<String>) -> Vec<Vec<String>> {
        // println!("Parsing: {:#?}", input);
        let mut res = Vec::new();
        let mut input = VecDeque::from(input);
        loop {
            // println!("Len: {}", input.len());
            let last;
            if input.len() == 3 {
                last = "|-line-|";
            } else {
                last = &input[3];
            }
            let mut options = Vec::new();
            // println!("first: {}", input[0]);
            if last.to_string() == "|-line-|" {
                options.push(VecDeque::pop_front(&mut input).unwrap());
                options.push("".to_string());
                options.push(VecDeque::pop_front(&mut input).unwrap());
                options.push(VecDeque::pop_front(&mut input).unwrap());
                if input.len() != 0 && input[0] == "|-line-|" {
                    VecDeque::pop_front(&mut input).unwrap();
                }
            } else {
                for _ in 0..4 {
                    options.push(VecDeque::pop_front(&mut input).unwrap());
                }
                if input.len() != 0 && input[0] == "|-line-|" {
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

    fn extract_options_and_payloads(
        input: &str,
    ) -> Option<(String, Vec<Vec<String>>, Vec<String>)> {
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
            if input.len() >= exp_idx {
                return None;
            }
            module_option_sub = &input[..exp_idx];
            if input.len() <= exploit_end_idx {
                return None;
            }
            exploit_targets_sub = &input[exp_idx..exploit_end_idx];
        } else {
            let payload_idx = payload_idx_res.unwrap();
            let payload_end_idx = input[payload_idx..].find("):");
            if payload_end_idx.is_none() {
                return None;
            }
            let payload_end_idx = payload_end_idx.unwrap();
            let exp_idx = input[payload_idx..].find(exploit_search_str);
            if exp_idx.is_none() {
                return None;
            }
            let exp_idx = exp_idx.unwrap();

            if payload_idx >= input.len() {
                return None;
            }
            if payload_idx + payload_end_idx >= input.len() {
                return None;
            }
            if exploit_end_idx >= input.len() {
                return None;
            }

            payload_str =
                &input[payload_idx + payload_search_str.len()..payload_idx + payload_end_idx];
            module_option_sub = &input[..payload_idx];
            exploit_targets_sub =
                &input[payload_idx + exp_idx + exploit_search_str.len()..exploit_end_idx];
        }

        let sep = " -----------\n";
        let module_options_start = module_option_sub.find(sep);
        if module_options_start.is_none() {
            return None;
        }
        let module_options_start = module_options_start.unwrap();
        let module_options_unparsed = &module_option_sub[module_options_start + sep.len()..];
        let sep = " ----\n";
        let exploits_start = exploit_targets_sub.find(sep);
        if exploits_start.is_none() {
            return None;
        }
        let exploits_start = exploits_start.unwrap();
        let exploit_target_unparsed = &exploit_targets_sub[exploits_start + sep.len()..];

        let mod_lines: Vec<String> = module_options_unparsed
            .split("\n")
            .map(|w| w.replace(". ", "."))
            .filter(|w| w.to_string() != "")
            .collect();
        let newline = mod_lines.join("  |-line-|  ");
        let mut module_options_vec: Vec<String> = newline
            .split("  ")
            .map(|w| {
                w.trim().to_string()
            })
            .collect();

        // fixing for multi line sections
        let mut line_section_count = 0;
        let mut section_indexes = [0, 0, 0, 0];
        let mut previous_section_indexes = [0, 0, 0, 0];
        let mut last_line_index = 0;
        let mut sections_to_remove = Vec::new();
        for i in 0..module_options_vec.len() {
            if module_options_vec[i] == "|-line-|" {
                if line_section_count == 1 || line_section_count == 2 {
                    // Has only second section
                    if module_options_vec[i - 1] == "" {
                        // Add to 2nd section
                        let previous_string = module_options_vec[previous_section_indexes[1]]
                            .to_string()
                            .clone();
                        let current_string = module_options_vec[section_indexes[0]].clone();
                        let combined_string = previous_string + &current_string;
                        module_options_vec[previous_section_indexes[1]] = combined_string;
                    }
                    // Has both sections
                    else if section_indexes[1] != 0 {
                        // Add to 2nd section
                        let previous_string = module_options_vec[previous_section_indexes[1]]
                            .to_string()
                            .clone();
                        let current_string = module_options_vec[section_indexes[0]].clone();
                        let combined_string = previous_string + &current_string;
                        module_options_vec[previous_section_indexes[1]] = combined_string;

                        // Add to 4th section
                        let previous_string = module_options_vec[previous_section_indexes[3]]
                            .to_string()
                            .clone();
                        let current_string = module_options_vec[section_indexes[1]].clone();
                        let combined_string = previous_string + &current_string;
                        module_options_vec[previous_section_indexes[3]] = combined_string;
                    }
                    // Has only 4th section
                    else {
                        // Add to 4th section
                        let previous_string = module_options_vec[previous_section_indexes[3]]
                            .to_string()
                            .clone();
                        let current_string = module_options_vec[section_indexes[0]].clone();
                        let combined_string = previous_string + &current_string;
                        module_options_vec[previous_section_indexes[3]] = combined_string;
                    }
                    sections_to_remove.push((last_line_index, i));
                    last_line_index = i;
                }
                line_section_count = 0;
                previous_section_indexes = section_indexes;
                section_indexes = [0, 0, 0, 0];
            } else if module_options_vec[i] != "" {
                section_indexes[line_section_count] = i;
                line_section_count += 1;
            }
        }

        // remove sections
        let mut offseted_size: i32 = 0;
        for i in sections_to_remove {
            let start_index = (i.0 as i32 + offseted_size) as usize;
            let end_index = (i.1 as i32 + offseted_size) as usize;
            module_options_vec.drain(start_index..end_index + 1);
            offseted_size -= i.1 as i32 - i.0 as i32;
        }

        let module_options_vec: Vec<String> = module_options_vec
            .iter()
            .map(|w| w.to_string())
            .filter(|w| w != "")
            .collect();
        let module_options = MSFProcess::parse_option(module_options_vec);

        let exploit_target: Vec<String> = exploit_target_unparsed
            .split("  ")
            .map(|w| w.trim().to_string())
            .filter(|w| w != "")
            .collect();

        Some((payload_str.to_string(), module_options, exploit_target))
    }

    pub fn add_options(&mut self, exploit: &mut Exploit, retries: Option<usize>) -> Result<(), ()> {
        let use_command = format!("use {}", exploit.name);
        self.run_command(&use_command);
        self.clear();

        let retries = match retries {
            Some(retries) => retries,
            None => 3,
        };

        let mut try_i = 0;
        loop {
            let show_options = "show options";
            self.run_command(&show_options);
            let output = self.output.clone();
            let text = output.join("\n");
            // println!("vec: {:#?}\ntext:{}", output, text);
            let options = MSFProcess::extract_options_and_payloads(text.as_str());
            if options.is_none() {
                try_i += 1;
                if try_i >= retries {
                    return Err(());
                }
                continue;
            }
            let options = options.unwrap();
            exploit.payload = options.0;
            exploit.options = options.1;
            exploit.target = options.2;
            break;
        }

        let back = "back";
        self.run_command(&back);
        self.clear();

        Ok(())
    }
}
impl Drop for MSFProcess {
    fn drop(&mut self) {
        println!("Dropping MSFProcess");
    }
}

fn main() -> std::io::Result<()> {
    let exploits;
    {
        println!("Starting MSF");
        let mut msf = MSFProcess::new();

        println!("MSF started");
        msf.clear();

        exploits = msf.get_exploits();
        // for i in 0..exploits.len() {
        //     let mut exploit = &mut exploits[i];
        //     println!("{}: Adding details to: {}", i, exploit.name);
        //     msf.add_options(&mut exploit);
        // }
    }

    // create args number of threads with an msf process of their own to run a portion of the exploits
    // using the offset of the exploits array depending on the number of threads (first argument) for
    // each process of msf
    let args = env::args().collect::<Vec<String>>();
    let mut num_threads_per_process = 1;
    let mut num_process = 20;
    if args.len() > 2 {
        num_threads_per_process = args[1].parse().unwrap();
        num_process = args[2].parse().unwrap();
    }

    let exp_len = exploits.len();
    let exploits_per_process = exp_len / num_process;
    let exploits_per_thread = exploits_per_process / num_threads_per_process;

    let mut process_threads = Vec::new();
    let mut output_exploits = Arc::new(Mutex::new(Vec::new()));
    for proc in 0..num_process {
        let process_start = proc * exploits_per_process;
        let process_end = (proc + 1) * exploits_per_process;
        println!("Process {} - {} to {}", proc, process_start, process_end);
        let output_exploits_outer = Arc::clone(&output_exploits);
        let thread = thread::spawn(move || {
            let mut msf = Arc::new(Mutex::new(MSFProcess::new()));
            let mut threads = Vec::new();
            // spawn threads
            for thr_idx in 0..num_threads_per_process {
                let msf_clone = Arc::clone(&msf);
                let output_exploits_clone = Arc::clone(&output_exploits_outer);
                let thread = thread::spawn(move || {
                    let thread_start = process_start + thr_idx * exploits_per_thread;
                    let mut thread_end = process_start + (thr_idx + 1) * exploits_per_thread;
                    if (thr_idx == num_threads_per_process - 1) && ((proc + 1) == num_process) {
                        thread_end = exp_len;
                    }
                    println!("Thread {} - {} to {}", thr_idx, thread_start, thread_end);
                    let mut msf = msf_clone.lock().unwrap();
                    let mut exploits = msf.get_exploits();
                    for i in thread_start..thread_end {
                        let mut exploit = &mut exploits[i];
                        let res = msf.add_options(&mut exploit, Some(5));
                        if res.is_err() {
                            eprintln!(
                                "{} adding options to exploit: {}",
                                "Error:".red(),
                                exploit.name
                            );
                            continue;
                        }
                    }
                    let mut output_exploits = output_exploits_clone.lock().unwrap();
                    output_exploits.append(&mut exploits[thread_start..thread_end].to_vec());
                });
                threads.push(thread);
            }
            for thread in threads {
                thread.join().unwrap();
            }
        });
        process_threads.push(thread);
    }

    for process in process_threads {
        process.join();
    }

    println!("Done adding options");
    let mut exploits = output_exploits.lock().unwrap().clone();
    println!("Exploits: {}", exploits.len());

    println!("Writing to exploits.json");
    // write to file
    let file = std::fs::File::create("exploits.json").unwrap();
    serde_json::to_writer_pretty(file, &exploits).unwrap();
    println!("Done writing to exploits.json");

    println!("MSF dropped");
    // timeout for 10 seconds
    thread::sleep(std::time::Duration::from_secs(10));

    Ok(())
}
