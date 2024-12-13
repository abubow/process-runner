use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, Condvar};
use std::thread;

struct Process {
    process: std::process::Child,
    stdin: std::process::ChildStdin,
    output_buf: Arc<Mutex<Vec<String>>>,
    readable: Arc<Condvar>,
    stderr: std::process::ChildStderr,
}

impl Process {
    pub fn new(command: &str, args: &[&str]) -> Self {
        let mut process = std::process::Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn process");

        let stdin = process.stdin.take().expect("Failed to get stdin");
        let stderr = process.stderr.take().expect("Failed to get stderr");

        Self {
            process,
            stdin,
            output_buf: Arc::new(Mutex::new(Vec::new())),
            readable: Arc::new(Condvar::new()),
            stderr,
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
                    },
                };
                let mut output_buf = output_buf.lock().unwrap();
                output_buf.push(ln.clone()); 
                readable.notify_one();
            }
        })
    }

    pub fn read(&mut self) -> String {
        let mut output_buf = self.output_buf.lock().unwrap();
        let res = output_buf.iter().cloned().collect();
        output_buf.clear();
        res
    }

    pub fn read_buf_size(&mut self) -> usize {
        let output_buf = self.output_buf.lock().unwrap();
        output_buf.len()
    }

    pub fn drop(&mut self) {
        self.process.kill().expect("Failed to kill process");
    }
}

fn main() -> std::io::Result<()> {
    let mut process = Process::new("python3", &["-i"]);
    let reader = process.start_reader();
    process.write("print('Hello from Python')")?;
    process.write("x = 42")?;
    process.write("print(f'The answer is {x}')")?;
    process.write("import time; time.sleep(1)")?; // Simulate a delay
    process.write("print('Goodbye from Python')")?;
    process.write("exit()")?;

    let mut i = 0;
    while i < 6 {
        process.readable.wait(process.output_buf.lock().unwrap()).unwrap();
        println!("{}", process.read());
        i += 1;
    }

    process.drop();

    reader.join().unwrap();
    Ok(())
}
