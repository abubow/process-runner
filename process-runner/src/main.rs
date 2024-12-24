use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::{debug, error, info, warn};
use num_cpus;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;
use std::{env, thread};

use colored::Colorize;
use env_logger;
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
                // thread::sleep(std::time::Duration::from_millis(1));
                let ln = match line {
                    Ok(output) => output,
                    Err(e) => {
                        error!("Error reading output: {}", e);
                        return;
                    }
                };
                let ln: Vec<String> = ln
                    .split("\n")
                    .map(|s| String::from_utf8(strip_ansi_escapes::strip(s)).unwrap())
                    .collect();
                // eprintln!("{}", ln.join(" \n"));
                let mut output_buf = output_buf.lock().unwrap();
                output_buf.push(ln.join("\n"));
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
                // thread::sleep(std::time::Duration::from_millis(1));
                let ln = match line {
                    Ok(output) => output,
                    Err(e) => {
                        error!("Error reading output: {}", e);
                        return;
                    }
                };
                let ln_vec: Vec<u8> = strip_ansi_escapes::strip(&ln);
                let striped_line = String::from_utf8(ln_vec).unwrap();
                // eprintln!("{}", ln);
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
        // eprintln!("Sending Kill signal to process");
        self.process.kill().expect("Failed to kill process");
        // eprintln!("Process dropped");
    }
}

#[derive(Serialize, Clone)]
struct Exploit {
    name: String,
    payload: String,
    options: Option<Vec<Vec<String>>>,
    target: Option<Vec<String>>,
}
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
        let mut read_line_err = process.read_err();
        thread::sleep(std::time::Duration::from_secs(1));
        let _ = process.write("ping");
        while !read_line_err.contains("ping: usage error:") {
            read_line = process.read();
            read_line_err = process.read_err();
            debug!("{}", read_line);
        }
        debug!("MSF started\n{}", read_line);
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
        // info!("Running command: {}", command);
        self.process.clear();
        let _ = self.process.write(command);
        thread::sleep(std::time::Duration::from_millis(10));
        let _ = self.process.write("ping");
        let mut read_line;
        let mut read_line_err = "".to_string();
        let mut lines_vec = Vec::new();
        while !read_line_err.contains("ping: usage error:") {
            read_line = self.process.read() + " ";
            read_line_err = self.process.read_err();
            lines_vec.push(read_line.clone());
            // eprintln!("RUN COMMAND: {}\n\n", read_line);
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
        let line = lines_vec.join("\n");

        let exploit_names = Self::extract_exploit_names(line.as_str());
        let exploits: Vec<Exploit> = exploit_names
            .into_iter()
            .map(|name| Exploit {
                name,
                options: None,
                target: None,
                payload: "".to_string(),
            })
            .collect();
        self.clear();

        exploits
    }

    fn parse_option(input: Vec<String>) -> Option<Vec<Vec<String>>> {
        // eprintln!("Parsing: {:#?}", input);
        let mut res = Vec::new();
        let mut input = VecDeque::from(input);
        loop {
            let mut options = Vec::new();
            for i in 0..4 {
                let popped = VecDeque::pop_front(&mut input).unwrap();
                if popped=="|-line-|" && i == 3{
                    options.insert(1, "".to_string());
                }
                options.push(popped);
                if input.len() == 0 {
                    break;
                }
            }
            if input.len() != 0 && input[0] == "|-line-|" {
                VecDeque::pop_front(&mut input).unwrap();
            }

            res.push(options);
            if input.len() == 0 {
                break;
            }
        }
        Some(res)
    }

    fn extract_options_and_payloads(
        input: &str,
    ) -> Result<(String, Option<Vec<Vec<String>>>, Vec<String>), String> {
        // eprintln!("Extracting from: {:#?}", input);
        let payload_str;
        let module_option_sub;
        let exploit_targets_sub;
        let payload_search_str = "Payload options (";
        let exploit_search_str = "Exploit target:";
        let exploit_search_end_str = "\n\n\n\n";
        let exploit_end_idx = input.find(exploit_search_end_str);
        if exploit_end_idx.is_none() {
            let exploit_search_end_str = "\n\n\n";
            let exploit_end_idx = input.find(exploit_search_end_str);
            if exploit_end_idx.is_none() {
                let msg = format!(
                    "{}:No exploit target end found.\nInput:{:#?}",
                    "Error".red(),
                    input
                );
                warn!("{}", msg);
                return Err(msg);
            }
        }
        let exploit_end_idx = exploit_end_idx.unwrap();
        let payload_idx_res = input.find(payload_search_str);

        if payload_idx_res.is_none() {
            let exp_idx = input.find(exploit_search_str);
            if exp_idx.is_none() {
                let msg = format!("{}:No exploit found.\nInput:{:#?}", "Error".red(), input);
                warn!("{}", msg);
                return Err(msg);
            }
            let exp_idx = exp_idx.unwrap();

            payload_str = "";
            if input.len() <= exp_idx {
                let msg = format!("{}:Out of bounds. Looking for module options substring. \nInput len:{} idx:{}\n {:#?}", "Error".red(), input.len(), exp_idx, input);
                warn!("{}", msg);
                return Err(msg);
            }
            module_option_sub = &input[..exp_idx];
            if input.len() <= exploit_end_idx {
                let msg = format!("{}:Out of bounds. Looking for exploit targets substring. \nInput len:{} idx:{}\n {:#?}", "Error".red(), input.len(), exploit_end_idx, input);
                warn!("{}", msg);
                return Err(msg);
            }
            exploit_targets_sub = &input[exp_idx..exploit_end_idx];
        } else {
            let payload_idx = payload_idx_res.unwrap();
            let payload_end_idx = input[payload_idx..].find("):");
            if payload_end_idx.is_none() {
                let msg = format!("{}:No payload found.\nInput:{:#?}", "Error".red(), input);
                warn!("{}", msg);
                return Err(msg);
            }
            let payload_end_idx = payload_end_idx.unwrap();
            let exp_idx = input[payload_idx..].find(exploit_search_str);
            if exp_idx.is_none() {
                let msg = format!("{}:No exploit found.\nInput:{:#?}", "Error".red(), input);
                warn!("{}", msg);
                return Err(msg);
            }
            let exp_idx = exp_idx.unwrap();

            if payload_idx >= input.len() {
                let msg = format!("{}:Out of bounds. Looking for payload substring. \nInput len:{} idx:{}\n {:#?}", "Error".red(), input.len(), payload_idx, input);
                warn!("{}", msg);
                return Err(msg);
            }
            if payload_idx + payload_end_idx >= input.len() {
                let msg =  format!("{}:Out of bounds. Looking for payload end substring. \nInput len:{} idx:{}\n {:#?}", "Error".red(), input.len(), payload_idx + payload_end_idx, input);
                warn!("{}", msg);
                return Err(msg);
            }
            if exploit_end_idx >= input.len() {
                let msg = format!("{}:Out of bounds. Looking for exploit end substring. \nInput len:{} idx:{}\n {:#?}", "Error".red(), input.len(), exploit_end_idx, input);
                warn!("{}", msg);
                return Err(msg);
            }

            payload_str =
                &input[payload_idx + payload_search_str.len()..payload_idx + payload_end_idx];
            module_option_sub = &input[..payload_idx];
            exploit_targets_sub =
                &input[payload_idx + exp_idx + exploit_search_str.len()..exploit_end_idx];
        }

        let sep = " -----------\n";
        let mut non_module_options_expliot = false;
        let mut module_options_start = module_option_sub.find(sep);
        if module_options_start.is_none() {
            let sep = " ----------- ";
            module_options_start = module_option_sub.find(sep);
            if module_options_start.is_none() {
                let msg = format!(
                    "{}:No module options found.\nmodule_option_sub:{:#?}",
                    "Error".red(),
                    module_option_sub
                );
                non_module_options_expliot = true;
            }
        }
        let sep = " ----\n";
        let mut exploits_start = exploit_targets_sub.find(sep);
        if exploits_start.is_none() {
            let sep = " ---- \n";
            exploits_start = exploit_targets_sub.find(sep);
            if exploits_start.is_none() {
                let msg = format!(
                    "{}:No exploit targets found.\nmodule_option_sub:{:#?}",
                    "Error".red(),
                    module_option_sub
                );
                warn!("{}", msg);
                return Err(msg);
            }
        }
        let exploits_start = exploits_start.unwrap();
        let exploit_target_unparsed = &exploit_targets_sub[exploits_start + sep.len()..];

        let module_options;
        if !non_module_options_expliot {
            let module_options_start = module_options_start.unwrap();
            let module_options_unparsed = &module_option_sub[module_options_start + sep.len()..];
            let mod_lines: Vec<String> = module_options_unparsed
                .split("\n")
                .map(|w| w.replace(". ", "."))
                .filter(|w| w.to_string() != "")
                .collect();
            let newline = mod_lines.join("  |-line-|  ");
            let mut module_options_vec: Vec<String> =
                newline.split("  ").map(|w| w.trim().to_string()).collect();

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
                    } else {
                        previous_section_indexes = section_indexes;
                    }
                    line_section_count = 0;
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
            let module_options_o = MSFProcess::parse_option(module_options_vec.clone());
            if module_options_o.is_none() {
                return Err(format!(
                    "{}:No options found.\n\nmodule_option_sub:{:#?}\n\nmodule_options_vec:{:#?}\n\nmodule_options_o:{:#?}",
                    "Error".red(),
                    module_option_sub,
                    module_options_vec,
                    module_options_o
                ));
            }
            module_options = module_options_o;
        } else {
            module_options = None;
        }

        let exploit_target: Vec<String> = exploit_target_unparsed
            .split("  ")
            .map(|w| w.trim().to_string())
            .filter(|w| w != "")
            .collect();

        Ok((payload_str.to_string(), module_options, exploit_target))
    }

    pub fn add_options(
        &mut self,
        exploit: &mut Exploit,
        retries: Option<usize>,
    ) -> Result<(), String> {
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
            // eprintln!("vec: {:#?}\ntext:{}", output, text);
            let options = MSFProcess::extract_options_and_payloads(text.as_str());
            if options.is_err() {
                try_i += 1;
                if try_i >= retries {
                    return Err(options.unwrap_err());
                }
                continue;
            }
            let options = options.unwrap();
            exploit.payload = options.0;
            exploit.options = options.1;
            exploit.target = Some(options.2);
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
        // eprintln!("Dropping MSFProcess");
        info!("Dropping MSFProcess");
        info!("Dropped MSFProcess");
    }
}

fn main() -> std::io::Result<()> {
    // create args number of threads with an msf process of their own to run a portion of the exploits
    // using the offset of the exploits array depending on the number of threads (first argument) for
    // each process of msf
    let args = env::args().collect::<Vec<String>>();
    let mut num_threads_per_process = 1;
    // get number of processor as process count
    let mut num_process = num_cpus::get() / 2;
    if args.len() > 2 {
        num_threads_per_process = args[1].parse().unwrap();
        num_process = args[2].parse().unwrap();
    }
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .build();
    let level = logger.filter();
    let multi_progress = Arc::new(MultiProgress::new());
    info!("Getting exploits");
    let exploits;
    {
        let mut msf = MSFProcess::new();

        info!("MSF started");
        msf.clear();

        exploits = msf.get_exploits();
    }

    let exp_len = exploits.len();
    let exploits_per_process = exp_len / num_process;
    let exploits_per_thread = exploits_per_process / num_threads_per_process;

    let mut process_threads = Vec::new();
    let output_exploits = Arc::new(Mutex::new(Vec::new()));
    let running_process = Arc::new(Mutex::new(Vec::from([9999usize])));

    let process_bar = Arc::new(multi_progress.add(ProgressBar::new((num_process + 1) as u64)));

    process_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}/{len} Processes")
            .unwrap(),
    );
    LogWrapper::new((*multi_progress).clone(), logger)
        .try_init()
        .unwrap();
    log::set_max_level(level);

    let start = Instant::now();
    process_bar.inc(1);
    for proc in 0..num_process {
        let process_start = proc * exploits_per_process;
        let process_end = (proc + 1) * exploits_per_process;
        info!("Process {} - {} to {}", proc, process_start, process_end);
        let output_exploits_outer = Arc::clone(&output_exploits);
        let running_proc = Arc::clone(&running_process);

        let thread_bar;
        if proc == num_process - 1 {
            let num = exp_len - process_start;
            thread_bar = multi_progress.add(ProgressBar::new(num as u64))
        } else {
            thread_bar = multi_progress.add(ProgressBar::new(exploits_per_thread as u64))
        }
        thread_bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{prefix} {spinner:.green} [{wide_bar:.magenta/blue}] {pos}/{len} Exploits",
                )
                .unwrap(),
        );
        let process_bar = Arc::clone(&process_bar);
        let process_thread = thread::spawn(move || {
            let msf = Arc::new(Mutex::new(MSFProcess::new()));
            {
                let mut lck = running_proc.lock().unwrap();
                lck.insert(0, proc);
            }
            let mut threads = Vec::new();
            // spawn threads
            for thr_idx in 0..num_threads_per_process {
                let msf_clone = Arc::clone(&msf);
                let output_exploits_clone = Arc::clone(&output_exploits_outer);
                let thread_bar_clone = thread_bar.clone();

                let thread = thread::spawn(move || {
                    let thread_start = process_start + thr_idx * exploits_per_thread;
                    let mut thread_end = process_start + (thr_idx + 1) * exploits_per_thread;
                    if (thr_idx == num_threads_per_process - 1) && ((proc + 1) == num_process) {
                        thread_end = exp_len;
                    }
                    info!("Thread {} - {} to {}", thr_idx, thread_start, thread_end);

                    let prefix = format!("Process {}, Thread {}", proc, thr_idx);
                    thread_bar_clone.set_prefix(prefix);

                    let mut msf = msf_clone.lock().unwrap();
                    let mut exploits = msf.get_exploits();
                    for i in thread_start..thread_end {
                        let mut exploit = &mut exploits[i];
                        let res = msf.add_options(&mut exploit, Some(5));
                        if res.is_err() {
                            error!(
                                "{} {} proc {}: adding options to exploit: {}",
                                "Error thread".red(),
                                thr_idx,
                                proc,
                                exploit.name
                            );
                            error!("{}", res.unwrap_err());
                            continue;
                        }
                        thread_bar_clone.inc(1);
                    }
                    let mut output_exploits = output_exploits_clone.lock().unwrap();
                    output_exploits.append(&mut exploits[thread_start..thread_end].to_vec());
                });
                threads.push(thread);
            }
            // eprintln!("{} {} waiting for threads", "Process".green(), proc);
            for thread in threads {
                let _ = thread.join().unwrap();
            }
            // eprintln!("{} {} done waiting for threads", "Process".green(), proc);
            thread_bar.finish_with_message(format!("Process {} Complete", proc));
            process_bar.inc(1);
            {
                let mut lck = running_proc.lock().unwrap();
                // remove the current proc from list
                let index = lck.iter().position(|x| *x == proc).unwrap();
                lck.remove(index);
                // eprintln!("Remaining running process {:#?}", lck);
            }
        });
        process_threads.push(process_thread);
    }

    // join threads
    let process_count = process_threads.len();
    // eprintln!("Started and now waiting for {} processes", process_count);
    for process in process_threads {
        let _ = process.join().unwrap();
        // eprintln!("Process joined");
    }

    info!("Done waiting for {} processes", process_count);
    process_bar.finish_with_message("All processes completed!");

    let end = Instant::now();
    let duration = end - start;
    info!("Done Getting Options in {} seconds", duration.as_secs());

    info!("Done adding options");
    let exploits = output_exploits.lock().unwrap().clone();
    let exp_len = exploits.len() as u64;
    info!("Exploits: {}", exp_len);

    // create new bar to write concurrently to the file while showing progress
    let process_bar = Arc::new(multi_progress.add(ProgressBar::new(exp_len)));
    process_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}/{len} Exploits")
            .unwrap(),
    );

    info!("Writing to exploits.json");
    let start = Instant::now();

    let write_thread = thread::spawn(move || {
        // write to file
        let file = std::fs::File::create("exploits.json").unwrap();
        serde_json::to_writer_pretty(file, &exploits).unwrap();
        info!("Done writing to exploits.json");
    });

    let speed = Arc::new(AtomicUsize::new(10));
    let exp_len_arc = Arc::new(exp_len);
    let speed_clone = Arc::clone(&speed);
    let exp_len_clone = Arc::clone(&exp_len_arc);
    let process_bar = Arc::clone(&process_bar);
    let process_bar_clone = Arc::clone(&process_bar);
    
    let progress_thread = thread::spawn(move || loop {
        let speed = speed_clone.load(Ordering::Relaxed);
        let speed = format!("{} Exploits/s", speed);
        process_bar_clone.set_prefix(speed);
        std::thread::sleep(std::time::Duration::from_millis(10));
        process_bar_clone.inc(1);
        speed_clone.fetch_add(1, Ordering::Relaxed);
        if process_bar_clone.length().unwrap() == *exp_len_clone {
            break;
        }
    });

    let _ = progress_thread.join().unwrap();
    let _ = write_thread.join().unwrap();

    process_bar.finish_with_message("Done writing to file!");

    let end = Instant::now();
    let duration = end - start;
    info!("Done writing to file in {} seconds", duration.as_secs());

    info!("Exploits options added successfully!");
    thread::sleep(std::time::Duration::from_secs(1));

    Ok(())
}
