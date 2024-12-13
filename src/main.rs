use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

struct Process {
    process: std::process::Child,
    stdin: std::process::ChildStdin,
    output_buf: Arc<Mutex<Vec<String>>>,
    readable: Arc<Condvar>,
    // stderr: std::process::ChildStderr,
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
        // let stderr = process.stderr.take().expect("Failed to get stderr");

        Self {
            process,
            stdin,
            output_buf: Arc::new(Mutex::new(Vec::new())),
            readable: Arc::new(Condvar::new()),
            // stderr,
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
                let ln_vec:Vec<u8> = strip_ansi_escapes::strip(&ln);
                let striped_line = String::from_utf8(ln_vec).unwrap();
                let mut output_buf = output_buf.lock().unwrap();
                output_buf.push(striped_line);
                readable.notify_one();
            }
        })
    }

    pub fn read(&mut self) -> String {
        let mut output_buf = self.readable.wait(self.output_buf.lock().unwrap()).unwrap();
        let res = output_buf.iter().cloned().collect();
        output_buf.clear();
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
    pub fn drop(&mut self) {
        self.process.kill().expect("Failed to kill process");
    }
}

struct MSFProcess {
    process: Process,
    reader: thread::JoinHandle<()>,
    output: Vec<String>,
}

impl MSFProcess {
    pub fn new() -> Self {
        let mut process = Process::new("msfconsole", None);
        let reader = process.start_reader();
        
        let mut read_line = process.read();
        while !read_line.contains("msf"){
            read_line = process.read();
            println!("{}", read_line);
        }
        Self {
            process,
            output: Vec::new(),
            reader,
        }
    }

    pub fn run_command(&mut self, command: &str){
        self.process.clear();
        self.process.write(command);
        let mut read_line = "".to_string();
        let mut lines_vec = Vec::new();
        while !read_line.contains("msf6"){
            read_line = self.process.read();
            lines_vec.push(read_line.clone());
            println!("{}\n\n", read_line);
        };
        self.output = lines_vec;

    }

    pub fn clear(&mut self) {
        self.process.clear();
        self.output.clear();
    }

    pub fn drop(&mut self) {
        self.process.drop();
    }
}

fn main() -> std::io::Result<()> {
    println!("Starting MSF");
    let mut msf = MSFProcess::new();

    println!("MSF started");
    msf.clear();
    
    println!("Running command: show exploits");
    msf.run_command("show exploits");

    let lines_vec = msf.output;

    // write to file 
    let mut file = std::fs::File::create("exploits.json").unwrap();
    file.write_all(lines_vec.join("\n").as_bytes()).unwrap();
    file.flush().unwrap();

    println!("Done writing to exploits.json");

    println!("MSF dropped");

    Ok(())
}
